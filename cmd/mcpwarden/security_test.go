package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres/pgtest"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

const (
	panelOrigin  = "https://panel.example.test"
	testPassword = "synthetic owner passphrase"
)

// ownerFixture runs the real account session, access-key and owner security
// routes on a storage database: SQLite by default, PostgreSQL under
// TestOwnerFlowsOnPostgres. All credentials are synthetic.
type ownerFixture struct {
	t        *testing.T
	driver   string
	pg       *pgtest.Database // postgres only
	raw      *sql.DB          // sqlite only: a second connection to the file
	store    catalog.Repository
	cfg      config.Config
	backend  *storageBackend
	stopped  context.Context
	accounts *accountAuth
	access   *accessManager
	api      *securityAPI
	mux      *http.ServeMux
	owners   map[string]string // username -> owner ID
	cookies  map[string]string // username -> session token
	keys     map[string]string // key name -> token
	keyIDs   map[string]string
	entry    catalog.Entry // alice's HTTP connector
	toolID   string
	cek      []byte
	// destination overrides the public default of credentialRecord.
	destination *secret.Destination
}

// fixtureDriver runs the owner flows on PostgreSQL when invoked from
// TestOwnerFlowsOnPostgres.
func fixtureDriver(t *testing.T) string {
	if strings.HasPrefix(t.Name(), "TestOwnerFlowsOnPostgres/") {
		return "postgres"
	}
	return "sqlite"
}

// newOwnerFixture takes an optional connector URL; the default is never dialed.
func newOwnerFixture(t *testing.T, endpoint ...string) *ownerFixture {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(randBytes(32))
	f := &ownerFixture{t: t, driver: fixtureDriver(t), owners: map[string]string{}, cookies: map[string]string{}, keys: map[string]string{}, keyIDs: map[string]string{}}
	f.cfg = config.Config{Accounts: &config.Accounts{}, Origins: []string{panelOrigin}, OwnerSecurity: &config.OwnerSecurity{},
		Storage: &config.Storage{Driver: f.driver, Key: key}}
	if f.driver == "postgres" {
		f.pg = pgtest.New(t)
		if _, err := f.pg.Admin.Exec(t.Context(), "SET search_path=mcpwarden_security"); err != nil {
			t.Fatal(err)
		}
		f.cfg.Storage.DatabaseURL = f.pg.RuntimeDSN
	} else {
		f.cfg.Storage.Path = filepath.Join(t.TempDir(), "mcpwarden.db")
	}
	f.start()
	if f.driver == "sqlite" {
		raw, err := sql.Open("sqlite", f.cfg.Storage.Path+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { raw.Close() })
		f.raw = raw
	}
	for _, username := range []string{"alice", "bob"} {
		salt := randBytes(16)
		hash, _ := pbkdf2.Key(sha256.New, testPassword, salt, 1000, 32)
		account := catalog.Account{ID: "account:" + randomToken(), Username: username, Salt: salt, PasswordHash: hash, Iterations: 1000}
		if err := f.store.AddAccount(account); err != nil {
			t.Fatal(err)
		}
		f.owners[username] = account.ID
		f.cookies[username] = f.session(username)
	}
	f.entry = catalog.Entry{Owner: f.owners["alice"], Name: "remote", URL: append(endpoint, "https://example.com/mcp")[0], AuthType: "bearer", HeaderNames: []string{"Authorization"}}
	if err := f.store.Add(f.entry); err != nil {
		t.Fatal(err)
	}
	for _, e := range f.store.List(f.owners["alice"]) {
		f.entry = e
	}
	tools := []*mcp.Tool{{Name: "search", Description: "Synthetic search", InputSchema: map[string]any{"type": "object"}}, {Name: "write", Description: "Synthetic write", InputSchema: map[string]any{"type": "object"}}}
	if err := f.store.SetDiscovery(f.owners["alice"], "remote", tools); err != nil {
		t.Fatal(err)
	}
	f.toolID = identity.Derive(f.entry.ID, "search")
	for _, key := range []struct{ name, owner, role string }{{"agent", "alice", "client"}, {"admin-agent", "alice", "admin"}, {"other-agent", "alice", "client"}, {"bob-agent", "bob", "client"}} {
		token, publicID := identity.NewAccessToken()
		record := catalog.AccessRecord{ID: identity.New(), PublicID: publicID, Owner: f.owners[key.owner], Name: key.name, Kind: "api_key", Role: key.role, SecretHash: tokenHash(token), ExpiresAt: time.Now().Add(24 * time.Hour)}
		if err := f.store.AddAccess(record); err != nil {
			t.Fatal(err)
		}
		f.keys[key.name], f.keyIDs[key.name] = token, record.ID
	}
	f.cek = randBytes(32)
	return f
}

func (f *ownerFixture) session(username string) string {
	token := randomToken()
	record := catalog.AccessRecord{ID: identity.New(), Owner: f.owners[username], Name: "Firefox on Linux", Kind: "browser", Role: "admin", SecretHash: tokenHash(token), ExpiresAt: time.Now().Add(12 * time.Hour)}
	if err := f.store.AddAccess(record); err != nil {
		f.t.Fatal(err)
	}
	return token
}

// start runs the gateway's real storage backend, as run() does. No guards
// are set: the repository coordinates with the lease service itself.
func (f *ownerFixture) start() {
	f.t.Helper()
	pol, _ := policy.New(config.Policy{Default: "allow"})
	ctx, fail := context.WithCancelCause(f.t.Context())
	b, err := openStorage(ctx, f.cfg, pol, slog.New(slog.NewTextHandler(io.Discard, nil)), fail)
	if err != nil {
		f.t.Fatal(err)
	}
	f.backend, f.stopped, f.api, f.store, f.accounts = b, ctx, b.security, b.repo, b.accounts
	f.access = newAccessManager(b.repo)
	f.t.Cleanup(func() {
		if f.api == b.security {
			b.close()
		}
	})
	f.mux = http.NewServeMux()
	b.security.register(f.mux)
	f.mux.Handle("/api/auth/", originOnly(http.HandlerFunc(f.accounts.authHandler), f.cfg.Origins))
	f.mux.Handle("/api/access/", f.accounts.protect(http.HandlerFunc(f.access.handler), true))
}

func (f *ownerFixture) restart() {
	f.backend.close()
	f.api = nil
	f.start()
}

// row reads the database directly as its owner. SQL uses bare table names.
func (f *ownerFixture) row(query string, args ...any) interface{ Scan(...any) error } {
	if f.pg != nil {
		return f.pg.Admin.QueryRow(f.t.Context(), query, args...)
	}
	return f.raw.QueryRowContext(f.t.Context(), query, args...)
}

func (f *ownerFixture) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.row(query, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *ownerFixture) text(query string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.row(query, args...).Scan(&s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// holdOwner holds the owner's durable lock. awaitWaiter returns once a store
// transaction waits behind it. PostgreSQL holds the row from another session
// and reports the lock wait. SQLite locks the whole database, so the hold is
// an owner transaction of the store itself, and awaitWaiter gives the request
// a moment to reach it.
func (f *ownerFixture) holdOwner(owner string) (awaitWaiter, release func()) {
	t := f.t
	t.Helper()
	if f.pg != nil {
		tx, err := f.pg.Admin.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), "SELECT owner_id FROM owners WHERE owner_id=$1 FOR UPDATE", owner); err != nil {
			t.Fatal(err)
		}
		awaitWaiter = func() {
			t.Helper()
			deadline := time.Now().Add(1500 * time.Millisecond)
			for {
				var waiting bool
				if _, err := tx.Exec(t.Context(), "SELECT pg_stat_clear_snapshot()"); err != nil {
					t.Fatal(err)
				}
				if err := tx.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='mcpwarden-security' AND wait_event_type='Lock')").Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("mutation never waited for the owner lock")
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		var once sync.Once
		return awaitWaiter, func() {
			once.Do(func() {
				if err := tx.Commit(context.Background()); err != nil {
					t.Error(err)
				}
			})
		}
	}
	held, done := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- f.api.store.WithOwner(context.Background(), owner, func(lease.Tx) error {
			close(held)
			<-done
			return nil
		})
	}()
	<-held
	var once sync.Once
	return func() { time.Sleep(200 * time.Millisecond) }, func() {
		once.Do(func() {
			close(done)
			if err := <-result; err != nil {
				t.Error(err)
			}
		})
	}
}

// lose ends the store's database session: PostgreSQL terminates it, and the
// SQLite file is moved away from its path.
func (f *ownerFixture) lose() {
	f.t.Helper()
	if f.pg != nil {
		if _, err := f.pg.Admin.Exec(f.t.Context(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mcpwarden-security' AND datname=current_database()"); err != nil {
			f.t.Fatal(err)
		}
		return
	}
	if err := os.Rename(f.cfg.Storage.Path, f.cfg.Storage.Path+".moved"); err != nil {
		f.t.Fatal(err)
	}
}

type req struct {
	method, path, body string
	user, key          string
	origin, site       string
	csrf, idempotency  string
	skipCSRF           bool
}

func (f *ownerFixture) do(r req) *httptest.ResponseRecorder {
	f.t.Helper()
	if r.method == "" {
		r.method = http.MethodGet
	}
	if r.origin == "" {
		r.origin = panelOrigin
	}
	unsafe := r.method != http.MethodGet && r.method != http.MethodHead
	if unsafe && r.user != "" && r.csrf == "" && !r.skipCSRF {
		out := f.do(req{path: "/api/security/csrf", user: r.user})
		var token struct {
			Token string `json:"token"`
		}
		if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &token) != nil {
			f.t.Fatalf("csrf token unavailable: %d", out.Code)
		}
		r.csrf = token.Token
	}
	hr := httptest.NewRequest(r.method, panelOrigin+r.path, strings.NewReader(r.body))
	if r.body != "" {
		hr.Header.Set("Content-Type", "application/json")
	}
	if r.origin != "none" {
		hr.Header.Set("Origin", r.origin)
	}
	if r.site != "" {
		hr.Header.Set("Sec-Fetch-Site", r.site)
	}
	if r.user != "" {
		hr.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookies[r.user]})
		hr.Header.Set("X-MCPWarden-Request", "browser")
	}
	if r.key != "" {
		hr.Header.Set("Authorization", "Bearer "+f.keys[r.key])
	}
	if r.csrf != "" {
		hr.Header.Set("X-CSRF-Token", r.csrf)
	}
	if r.idempotency != "" {
		hr.Header.Set("Idempotency-Key", r.idempotency)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, hr)
	return w
}

func (f *ownerFixture) expect(r req, status int, out any) {
	f.t.Helper()
	w := f.do(r)
	if w.Code != status {
		f.t.Fatalf("%s %s: status %d, want %d: %s", r.method, r.path, w.Code, status, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		f.t.Fatalf("%s %s: sensitive response is cacheable", r.method, r.path)
	}
	if out != nil && json.Unmarshal(w.Body.Bytes(), out) != nil {
		f.t.Fatalf("%s %s: invalid JSON", r.method, r.path)
	}
}

func encode(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func randomEncoded(n int) string { return base64.RawURLEncoding.EncodeToString(randBytes(n)) }

// Wrapper ciphertext is opaque to the server; only the credential envelope is
// authenticated at activation, so it alone uses a real test key.
func rootFixture(owner string) vault.Root {
	r := vault.Root{OwnerID: owner, RootID: identity.New(), RootVersion: "1", WrapperRevision: "1"}
	for _, method := range []string{"passphrase", "recovery"} {
		var k any = secret.RecoveryKDF{Suite: "HKDF-SHA256", OutputBytes: 32, HKDFInfo: secret.RecoveryInfo}
		if method == "passphrase" {
			k = secret.PassphraseKDF{Suite: "ARGON2ID-HKDF-SHA256", ArgonVersion: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: randomEncoded(16), OutputBytes: 32, HKDFInfo: secret.PassphraseInfo}
		}
		kdf, _ := json.Marshal(k)
		w := secret.RootWrapper{Format: "mcpwarden.root-wrap.v1", Algorithm: secret.Algorithm, Purpose: "vault-root", RootContext: secret.RootContext{OwnerID: owner, RootID: r.RootID, RootVersion: "1", WrapperID: identity.New(), Method: method}, KDF: kdf, Nonce: randomEncoded(12), Ciphertext: randomEncoded(48)}
		raw, _ := json.Marshal(w)
		if method == "passphrase" {
			r.Passphrase = raw
		} else {
			r.Recovery = raw
		}
	}
	return r
}

func (f *ownerFixture) credentialRecord(root vault.Root, credentialID, epoch, revision string, key []byte) vault.Record {
	r := vault.Record{CredentialContext: secret.CredentialContext{OwnerID: root.OwnerID, RootID: root.RootID, RootVersion: root.RootVersion, ConnectorID: f.entry.ID, CredentialID: credentialID, Epoch: epoch}, Revision: revision,
		Destination: secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: f.entry.URL, HeaderNames: []string{"authorization"}, Network: "public", PrivatePrefixes: []string{}}}
	if f.destination != nil {
		r.Destination = *f.destination
	}
	r.WrappedKey, _ = json.Marshal(secret.CredentialWrapper{Format: "mcpwarden.credential-wrap.v1", Algorithm: secret.Algorithm, Purpose: "credential-key", CredentialContext: r.CredentialContext, Nonce: randomEncoded(12), Ciphertext: randomEncoded(48)})
	digest, err := r.Destination.Digest()
	if err != nil {
		f.t.Fatal(err)
	}
	header := secret.Header{Format: secret.Format, Algorithm: secret.Algorithm, Purpose: "upstream-credential", OwnerID: r.OwnerID, ConnectorID: r.ConnectorID, CredentialID: credentialID, Epoch: epoch, Revision: revision, DestinationDigest: digest}
	raw, _ := json.Marshal(header)
	aad, _ := jsoncanonicalizer.Transform(raw)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	plain := []byte(`{"kind":"header_bundle","headers":[{"name":"Authorization","value":"Bearer SYNTHETIC_OWNER_TOKEN"}]}`)
	r.Envelope, _ = json.Marshal(secret.Envelope{Header: header, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plain, aad))})
	return r
}

// provision creates alice's vault root and one encrypted credential for her
// connector, and optionally switches her approval policy.
func (f *ownerFixture) provision(mode string) (vault.Root, vault.Record) {
	f.t.Helper()
	root := rootFixture(f.owners["alice"])
	f.expect(req{method: "POST", path: "/api/vault/setup", user: "alice", body: encode(map[string]any{"current_password": testPassword, "root": root})}, 201, nil)
	record := f.credentialRecord(root, identity.New(), "1", "1", f.cek)
	f.expect(req{method: "PUT", path: "/api/vault/credentials/" + record.CredentialID, user: "alice", body: encode(map[string]any{"expected": nil, "record": record})}, 201, nil)
	if mode == "none" {
		f.expect(req{method: "PUT", path: "/api/security/approval-policy", user: "alice", body: encode(map[string]string{"mode": "none", "expected_revision": "1", "current_password": testPassword})}, 200, nil)
	}
	return root, record
}

func (f *ownerFixture) requestAccess(key, credentialID string) requestView {
	f.t.Helper()
	var out requestView
	body := encode(map[string]any{"credential_id": credentialID, "duration_seconds": 900, "tools": []map[string]any{{"tool_id": f.toolID, "constraints": []map[string]any{{"pointer": "/repo", "operator": "equals", "value": "example"}}}}})
	f.expect(req{method: "POST", path: "/api/access-requests", key: key, body: body}, 201, &out)
	return out
}

func (f *ownerFixture) ownerRequest(id string) requestView {
	f.t.Helper()
	var out requestView
	f.expect(req{path: "/api/access-requests/" + id, user: "alice"}, 200, &out)
	return out
}

func (f *ownerFixture) activation(r requestView, key []byte) string {
	return encode(map[string]string{"gateway_boot_id": r.GatewayBootID, "request_digest": r.RequestDigest, "challenge": r.Challenge, "credential_id": r.Credential.CredentialID, "credential_epoch": r.Credential.Epoch, "cek": base64.RawURLEncoding.EncodeToString(key)})
}

func (f *ownerFixture) events(user string) []lease.Event {
	f.t.Helper()
	var out struct {
		Items []lease.Event `json:"items"`
	}
	f.expect(req{path: "/api/security/events?limit=200", user: user}, 200, &out)
	return out.Items
}

func countEvents(events []lease.Event, kind, reason string) int {
	n := 0
	for _, e := range events {
		if e.Type == kind && (reason == "" || e.Reason == reason) {
			n++
		}
	}
	return n
}

func TestOwnerRoutesRequireInteractiveBrowserSession(t *testing.T) {
	f := newOwnerFixture(t)
	_, record := f.provision("none")
	request := f.requestAccess("agent", record.CredentialID)
	owner := f.ownerRequest(request.ID)
	body := f.activation(owner, f.cek)
	// Neither a client nor an admin MCP key can release a key, even in mode none.
	for _, key := range []string{"agent", "admin-agent"} {
		f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", key: key, idempotency: identity.New(), body: body}, 403, nil)
		f.expect(req{method: "POST", path: "/api/vault/lock-execution", key: key, body: `{}`}, 403, nil)
		f.expect(req{method: "PUT", path: "/api/security/approval-policy", key: key, body: `{}`}, 403, nil)
	}
	// A browser cookie does not help a request that also carries a key.
	w := f.do(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", key: "admin-agent", idempotency: identity.New(), body: body, skipCSRF: true})
	if w.Code != 403 {
		t.Fatal("key plus cookie reached activation", w.Code)
	}
	if n := countEvents(f.events("alice"), "owner_route.rejected", "api_key"); n < 2 {
		t.Fatal("rejected key attempts were not audited", n)
	}
	for name, r := range map[string]req{
		"missing csrf":      {skipCSRF: true},
		"wrong csrf":        {csrf: "forged"},
		"foreign origin":    {origin: "https://evil.example"},
		"missing origin":    {origin: "none"},
		"plain http origin": {origin: "http://panel.example.test"},
		"cross site fetch":  {site: "cross-site"},
	} {
		r.method, r.path, r.user, r.idempotency, r.body = "POST", "/api/approvals/"+request.ID+"/activate", "alice", identity.New(), body
		if w := f.do(r); w.Code != 403 {
			t.Fatalf("%s accepted: %d", name, w.Code)
		}
	}
	for _, contentType := range []string{"text/plain", "application/jsonp", "application/x-www-form-urlencoded"} {
		csrf := func() string {
			var token struct {
				Token string `json:"token"`
			}
			f.expect(req{path: "/api/security/csrf", user: "alice"}, 200, &token)
			return token.Token
		}()
		hr := httptest.NewRequest("POST", panelOrigin+"/api/vault/lock-execution", strings.NewReader("{}"))
		hr.Header.Set("Content-Type", contentType)
		hr.Header.Set("Origin", panelOrigin)
		hr.Header.Set("X-CSRF-Token", csrf)
		hr.Header.Set("X-MCPWarden-Request", "browser")
		hr.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookies["alice"]})
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, hr)
		if w.Code != 415 {
			t.Fatalf("%s body accepted: %d", contentType, w.Code)
		}
	}
	if w := f.do(req{path: "/api/vault/state", user: "alice"}); w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("owner response is cacheable")
	}
	if w := f.do(req{method: "POST", path: "/api/vault/lock-execution", user: "alice", body: "{}", origin: "http://127.0.0.1:8080"}); w.Code != 204 {
		t.Fatal("loopback development origin rejected", w.Code)
	}
	if w := f.do(req{path: "/api/vault/state"}); w.Code != 401 {
		t.Fatal("anonymous owner read", w.Code)
	}
	// Sensitive changes need the current account password, not just a session.
	f.expect(req{method: "PUT", path: "/api/security/approval-policy", user: "alice", body: encode(map[string]string{"mode": "confirm", "expected_revision": "2", "current_password": "wrong password value"})}, 403, nil)
	f.expect(req{method: "PUT", path: "/api/security/approval-policy", user: "alice", body: `{"mode":"confirm","expected_revision":"2","current_password":"x","extra":1}`}, 400, nil)
	f.expect(req{method: "PUT", path: "/api/security/approval-policy", user: "alice", body: `{"mode":"confirm","mode":"none","expected_revision":"2","current_password":"x"}`}, 400, nil)
}

func TestOwnerActivationReplayAndOwnerIsolation(t *testing.T) {
	f := newOwnerFixture(t)
	_, record := f.provision("none")
	request := f.requestAccess("agent", record.CredentialID)
	if request.Challenge != "" || request.RequestDigest != "" || request.GatewayBootID != "" {
		t.Fatal("requester view exposes owner binding fields")
	}
	if request.ApprovalMode != "none" || request.State != "pending" {
		t.Fatalf("unexpected request %+v", request)
	}
	// The same scope from the same caller is deduplicated, not re-prompted.
	if again := f.requestAccess("agent", record.CredentialID); again.ID != request.ID {
		t.Fatal("duplicate request created")
	}
	// Keys see only their own requests; another owner cannot see it at all.
	f.expect(req{path: "/api/access-requests/" + request.ID, key: "other-agent"}, 404, nil)
	f.expect(req{path: "/api/access-requests/" + request.ID, key: "bob-agent"}, 404, nil)
	f.expect(req{path: "/api/access-requests/" + request.ID, user: "bob"}, 404, nil)
	var others []requestView
	f.expect(req{path: "/api/access-requests", key: "other-agent"}, 200, &others)
	if len(others) != 0 {
		t.Fatal("key listed another caller's request")
	}
	// A key cannot request on behalf of another key.
	body := encode(map[string]any{"requester_access_id": f.keyIDs["agent"], "credential_id": record.CredentialID, "duration_seconds": 900, "tools": []map[string]any{{"tool_id": f.toolID}}})
	f.expect(req{method: "POST", path: "/api/access-requests", key: "other-agent", body: body}, 403, nil)
	// Another owner cannot request against alice's credential.
	f.expect(req{method: "POST", path: "/api/access-requests", key: "bob-agent", body: encode(map[string]any{"credential_id": record.CredentialID, "duration_seconds": 900, "tools": []map[string]any{{"tool_id": f.toolID}}})}, 409, nil)

	owner := f.ownerRequest(request.ID)
	// Bob's session cannot confirm, deny or activate alice's request.
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "bob", idempotency: identity.New(), body: f.activation(owner, f.cek)}, 404, nil)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/deny", user: "bob", body: "{}"}, 404, nil)

	wrong := make([]byte, 32)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(owner, wrong)}, 422, nil)
	tampered := owner
	tampered.Challenge = randomEncoded(32)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(tampered, f.cek)}, 409, nil)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", body: f.activation(owner, f.cek)}, 400, nil)

	operation := identity.New()
	var first, replay leaseView
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: operation, body: f.activation(owner, f.cek)}, 200, &first)
	if !first.RuntimeAvailable || first.AuthorizationSource != "client_activation" || first.Client.AccessID != f.keyIDs["agent"] || !first.ExpiresAt.Equal(first.ActivatedAt.Add(900*time.Second)) {
		t.Fatalf("unexpected lease %+v", first)
	}
	time.Sleep(20 * time.Millisecond)
	// An identical retry returns the same window without resetting its clock.
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: operation, body: f.activation(owner, f.cek)}, 200, &replay)
	if replay.LeaseID != first.LeaseID || !replay.ActivatedAt.Equal(first.ActivatedAt) || !replay.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("activation replay reset or duplicated the window")
	}
	// A new operation cannot start a second window from the same request.
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(owner, f.cek)}, 409, nil)
	events := f.events("alice")
	if countEvents(events, "lease.activated", "") != 1 || countEvents(events, "activation.rejected", "key") != 1 || countEvents(events, "activation.rejected", "stale") < 2 {
		t.Fatal("activation audit mismatch")
	}
	for _, e := range events {
		if e.OwnerID != f.owners["alice"] {
			t.Fatal("cross-owner event")
		}
	}
	// Bob's own probe is audited to him as not_found, without alice's IDs.
	for _, e := range f.events("bob") {
		if e.OwnerID != f.owners["bob"] || e.RequestID != "" || e.LeaseID != "" {
			t.Fatalf("bob's audit leaks alice's objects: %+v", e)
		}
	}

	var mine, theirs, all []leaseView
	f.expect(req{path: "/api/leases", key: "agent"}, 200, &mine)
	f.expect(req{path: "/api/leases", key: "other-agent"}, 200, &theirs)
	f.expect(req{path: "/api/leases", user: "alice"}, 200, &all)
	if len(mine) != 1 || len(theirs) != 0 || len(all) != 1 {
		t.Fatal("lease visibility wrong", len(mine), len(theirs), len(all))
	}
	f.expect(req{method: "DELETE", path: "/api/leases/" + first.LeaseID, key: "other-agent"}, 403, nil)
	f.expect(req{method: "DELETE", path: "/api/leases/" + first.LeaseID, user: "bob"}, 404, nil)
	// Signing out (browser lock) does not stop approved agent work.
	f.expect(req{method: "POST", path: "/api/auth/logout", user: "alice", body: "{}"}, 204, nil)
	f.cookies["alice"] = f.session("alice")
	f.expect(req{path: "/api/leases", key: "agent"}, 200, &mine)
	if len(mine) != 1 || !mine[0].RuntimeAvailable {
		t.Fatal("logout ended the access window")
	}
	f.expect(req{method: "DELETE", path: "/api/leases/" + first.LeaseID, key: "agent"}, 204, nil)
	f.expect(req{path: "/api/leases", user: "alice"}, 200, &all)
	if len(all) != 0 {
		t.Fatal("revoked lease still active")
	}
}

func TestOwnerConfirmModeAndPolicyChange(t *testing.T) {
	f := newOwnerFixture(t)
	_, record := f.provision("confirm")
	request := f.requestAccess("agent", record.CredentialID)
	owner := f.ownerRequest(request.ID)
	if owner.ApprovalMode != "confirm" {
		t.Fatal("default mode is not confirm")
	}
	// Confirmation is required before key release, and is digest-bound.
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(owner, f.cek)}, 409, nil)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/begin", user: "alice", body: encode(map[string]string{"request_digest": randomEncoded(32)})}, 403, nil)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/begin", key: "admin-agent", body: encode(map[string]string{"request_digest": owner.RequestDigest})}, 403, nil)
	var approved requestView
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/begin", user: "alice", body: encode(map[string]string{"request_digest": owner.RequestDigest})}, 200, &approved)
	if approved.State != "approved" || approved.ActivationDeadline == nil {
		t.Fatal("confirmation not recorded")
	}
	var active leaseView
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(owner, f.cek)}, 200, &active)
	if active.AuthorizationSource != "owner_confirmation" || !active.RenewalRequiresConfirm {
		t.Fatal("confirm lease metadata wrong")
	}
	pending := f.requestAccess("other-agent", record.CredentialID)
	// A stale expected revision is rejected; a policy change commits together
	// with stale requests and revoked windows before success is reported.
	f.expect(req{method: "PUT", path: "/api/security/approval-policy", user: "alice", body: encode(map[string]string{"mode": "none", "expected_revision": "7", "current_password": testPassword})}, 409, nil)
	var p policyView
	f.expect(req{method: "PUT", path: "/api/security/approval-policy", user: "alice", body: encode(map[string]string{"mode": "none", "expected_revision": "1", "current_password": testPassword})}, 200, &p)
	if p.Mode != "none" || p.Revision != "2" {
		t.Fatal("policy not saved", p)
	}
	var leases []leaseView
	f.expect(req{path: "/api/leases", user: "alice"}, 200, &leases)
	if len(leases) != 0 {
		t.Fatal("policy change left a live window")
	}
	if got := f.ownerRequest(pending.ID); got.State != "stale" {
		t.Fatal("policy change left a pending decision", got.State)
	}
	events := f.events("alice")
	if countEvents(events, "policy.changed", "") != 1 || countEvents(events, "lease.revoked", "") != 1 || countEvents(events, "request.stale", "") != 1 {
		t.Fatal("policy change audit mismatch")
	}
	// Deny needs no key and ends a fresh request.
	next := f.requestAccess("agent", record.CredentialID)
	var denied requestView
	f.expect(req{method: "POST", path: "/api/approvals/" + next.ID + "/deny", user: "alice"}, 200, &denied)
	if denied.State != "denied" {
		t.Fatal("deny not recorded")
	}
	f.expect(req{method: "POST", path: "/api/approvals/" + next.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(next.ID), f.cek)}, 409, nil)
}

func TestOwnerVaultCredentialLifecycleAndRestart(t *testing.T) {
	f := newOwnerFixture(t)
	root, record := f.provision("none")
	// Setup happens once; wrapper changes need the expected revision and password.
	f.expect(req{method: "POST", path: "/api/vault/setup", user: "alice", body: encode(map[string]any{"current_password": testPassword, "root": rootFixture(f.owners["alice"])})}, 409, nil)
	rewrapped := rootFixture(f.owners["alice"])
	rewrapped.RootID, rewrapped.WrapperRevision = root.RootID, "2"
	for _, w := range []*json.RawMessage{&rewrapped.Passphrase, &rewrapped.Recovery} {
		var wrapper secret.RootWrapper
		_ = json.Unmarshal(*w, &wrapper)
		wrapper.RootID = root.RootID
		*w, _ = json.Marshal(wrapper)
	}
	f.expect(req{method: "PUT", path: "/api/vault/wrappers", user: "alice", body: encode(map[string]any{"current_password": testPassword, "expected_wrapper_revision": "1", "root": rewrapped})}, 200, nil)
	f.expect(req{method: "PUT", path: "/api/vault/wrappers", user: "alice", body: encode(map[string]any{"current_password": testPassword, "expected_wrapper_revision": "1", "root": rewrapped})}, 409, nil)
	// Bob cannot write into alice's vault or connector.
	bobRecord := record
	bobRecord.OwnerID = f.owners["bob"]
	f.expect(req{method: "PUT", path: "/api/vault/credentials/" + record.CredentialID, user: "bob", body: encode(map[string]any{"expected": nil, "record": bobRecord})}, 400, nil)
	// The destination must match the connector URL and its header names.
	mismatch := f.credentialRecord(root, identity.New(), "1", "1", f.cek)
	mismatch.Destination.Endpoint = "https://attacker.example/mcp"
	f.expect(req{method: "PUT", path: "/api/vault/credentials/" + mismatch.CredentialID, user: "alice", body: encode(map[string]any{"expected": nil, "record": mismatch})}, 400, nil)
	// Replacement under CAS invalidates open windows; stale writes are refused.
	request := f.requestAccess("agent", record.CredentialID)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, nil)
	newKey := randBytes(32)
	rotated := f.credentialRecord(root, record.CredentialID, "2", "1", newKey)
	f.expect(req{method: "PUT", path: "/api/vault/credentials/" + record.CredentialID, user: "alice", body: encode(map[string]any{"expected": map[string]string{"epoch": "1", "revision": "1"}, "record": rotated})}, 200, nil)
	f.expect(req{method: "PUT", path: "/api/vault/credentials/" + record.CredentialID, user: "alice", body: encode(map[string]any{"expected": map[string]string{"epoch": "1", "revision": "1"}, "record": rotated})}, 409, nil)
	var leases []leaseView
	f.expect(req{path: "/api/leases", user: "alice"}, 200, &leases)
	if len(leases) != 0 {
		t.Fatal("rotation left an old-epoch window")
	}
	// The old key no longer opens the new epoch; the new one does.
	request = f.requestAccess("agent", record.CredentialID)
	owner := f.ownerRequest(request.ID)
	if owner.Credential.Epoch != "2" {
		t.Fatal("request not bound to the new epoch")
	}
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(owner, f.cek)}, 422, nil)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(owner, newKey)}, 200, nil)

	// Restart: committed custody reloads, old windows are suspended, and no
	// runtime key survives. A new owner activation is required.
	f.restart()
	var state struct {
		Configured     bool                `json:"configured"`
		Credentials    []credentialSummary `json:"credentials"`
		ApprovalPolicy policyView          `json:"approval_policy"`
		ActiveLeases   int                 `json:"active_leases"`
		Root           rootView            `json:"root"`
	}
	f.expect(req{path: "/api/vault/state", user: "alice"}, 200, &state)
	if !state.Configured || state.Root.WrapperRevision != "2" || len(state.Credentials) != 1 || state.Credentials[0].Epoch != "2" || state.ApprovalPolicy.Mode != "none" || state.ActiveLeases != 0 {
		t.Fatalf("restart state wrong: %+v", state)
	}
	f.expect(req{path: "/api/leases", user: "alice"}, 200, &leases)
	if len(leases) != 0 {
		t.Fatal("restart kept an old window active")
	}
	var wrappers struct {
		Root        rootView            `json:"root"`
		Credentials []credentialSummary `json:"credentials"`
	}
	f.expect(req{path: "/api/vault/wrappers", user: "alice"}, 200, &wrappers)
	if len(wrappers.Root.Passphrase) == 0 || len(wrappers.Credentials) != 1 || len(wrappers.Credentials[0].WrappedKey) == 0 {
		t.Fatal("wrappers missing")
	}
	var selectable []credentialSummary
	f.expect(req{path: "/api/vault/credentials", key: "agent"}, 200, &selectable)
	if len(selectable) != 1 || len(selectable[0].Tools) != 2 || selectable[0].WrappedKey != nil {
		t.Fatal("selectable credential view wrong")
	}
	request = f.requestAccess("agent", record.CredentialID)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), newKey)}, 200, nil)
	// Deletion keeps a tombstone and ends the window; the ID cannot return.
	f.expect(req{method: "DELETE", path: "/api/vault/credentials/" + record.CredentialID, user: "alice", body: encode(map[string]any{"expected": map[string]string{"epoch": "2", "revision": "1"}})}, 200, nil)
	f.expect(req{path: "/api/leases", user: "alice"}, 200, &leases)
	if len(leases) != 0 {
		t.Fatal("deletion left a live window")
	}
	f.expect(req{method: "PUT", path: "/api/vault/credentials/" + record.CredentialID, user: "alice", body: encode(map[string]any{"expected": nil, "record": f.credentialRecord(root, record.CredentialID, "1", "1", f.cek)})}, 409, nil)
	f.expect(req{method: "POST", path: "/api/access-requests", key: "agent", body: encode(map[string]any{"credential_id": record.CredentialID, "duration_seconds": 900, "tools": []map[string]any{{"tool_id": f.toolID}}})}, 409, nil)
	events := f.events("alice")
	for kind, want := range map[string]int{"vault.created": 1, "vault.rewrapped": 1, "credential.created": 1, "credential.rotated": 1, "credential.deleted": 1, "lease.suspended": 1} {
		if got := countEvents(events, kind, ""); got != want {
			t.Fatalf("%s events: %d, want %d", kind, got, want)
		}
	}
}

func TestOwnerConcurrentMutationsAndKeyRevocation(t *testing.T) {
	f := newOwnerFixture(t)
	root, record := f.provision("none")
	// Two writers with the same expected version: exactly one wins.
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A same-epoch update keeps the wrapped key and replaces the envelope.
			next := f.credentialRecord(root, record.CredentialID, "1", "2", f.cek)
			next.WrappedKey = record.WrappedKey
			w := f.do(req{method: "PUT", path: "/api/vault/credentials/" + record.CredentialID, user: "alice", body: encode(map[string]any{"expected": map[string]string{"epoch": "1", "revision": "1"}, "record": next})})
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()
	if count(codes, 200) != 1 || count(codes, 409) != len(codes)-1 {
		t.Fatal("concurrent credential writes", codes)
	}
	// Concurrent activations of one request with different operations produce
	// one window; the rest are rejected.
	request := f.requestAccess("agent", record.CredentialID)
	owner := f.ownerRequest(request.ID)
	body := f.activation(owner, f.cek)
	csrf := func() string {
		var token struct {
			Token string `json:"token"`
		}
		f.expect(req{path: "/api/security/csrf", user: "alice"}, 200, &token)
		return token.Token
	}()
	codes = make([]int, 6)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = f.do(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", csrf: csrf, idempotency: identity.New(), body: body}).Code
		}(i)
	}
	wg.Wait()
	if count(codes, 200) != 1 || count(codes, 409) != len(codes)-1 {
		t.Fatal("concurrent activations", codes)
	}
	if windows := f.count("SELECT count(*) FROM leases WHERE request_id=$1", request.ID); windows != 1 {
		t.Fatal("duplicate durable windows", windows)
	}
	// Revoking the caller's key ends its window before the catalog write.
	f.expect(req{method: "DELETE", path: "/api/access/" + f.keyIDs["agent"], user: "alice", skipCSRF: true}, 204, nil)
	if state := f.text("SELECT state FROM leases WHERE request_id=$1", request.ID); state != "revoked" {
		t.Fatal("key revocation left the window active", state)
	}
	if w := f.do(req{path: "/api/leases", key: "agent"}); w.Code != 401 {
		t.Fatal("revoked key still authenticates", w.Code)
	}
}

func count(codes []int, want int) int {
	n := 0
	for _, c := range codes {
		if c == want {
			n++
		}
	}
	return n
}

func TestOwnerSecurityRequestLimitsAndBodies(t *testing.T) {
	f := newOwnerFixture(t)
	_, record := f.provision("none")
	large := `{"credential_id":"` + record.CredentialID + `","duration_seconds":900,"tools":[{"tool_id":"` + f.toolID + `","constraints":[{"pointer":"/x","operator":"equals","value":"` + strings.Repeat("a", maxSecurityBody) + `"}]}]}`
	f.expect(req{method: "POST", path: "/api/access-requests", key: "agent", body: large}, 413, nil)
	f.expect(req{method: "POST", path: "/api/access-requests", key: "agent", body: `{"credential_id":"` + record.CredentialID + `","duration_seconds":7200,"tools":[{"tool_id":"` + f.toolID + `"}]}`}, 400, nil)
	f.expect(req{method: "POST", path: "/api/access-requests", key: "agent", body: `{"credential_id":"` + record.CredentialID + `","duration_seconds":60,"tools":[]}`}, 400, nil)
	// Hidden tools cannot enter a scope.
	if err := f.store.SetVisibility(f.owners["alice"], "remote", catalog.Visibility{Mode: "selected", Enabled: []string{"remote__write"}}); err != nil {
		t.Fatal(err)
	}
	f.expect(req{method: "POST", path: "/api/access-requests", key: "agent", body: `{"credential_id":"` + record.CredentialID + `","duration_seconds":60,"tools":[{"tool_id":"` + f.toolID + `"}]}`}, 409, nil)
	limited := 0
	for i := 0; i < keyRouteLimit+5; i++ {
		if f.do(req{path: "/api/leases", key: "other-agent"}).Code == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("key route budget not enforced")
	}
	// Another key keeps its own budget.
	f.expect(req{path: "/api/leases", key: "admin-agent"}, 200, nil)
}
