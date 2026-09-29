package postgres

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/approval"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/audit/audittest"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/proxy"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

type encryptedSource struct {
	owner, id string
	record    secret.Record
}

type dispatchAuthority struct {
	*authority
	other lease.Caller
}

func (a dispatchAuthority) Caller(owner, id string) (lease.Caller, bool) {
	if owner == a.other.Owner && id == a.other.AccessID {
		return a.other, true
	}
	return a.authority.Caller(owner, id)
}

func (s encryptedSource) Current(owner, id string) (secret.Record, bool) {
	return s.record, owner == s.owner && id == s.id
}

func encryptedFixture(t *testing.T, owner string, k lease.Credential, d secret.Destination, key []byte) secret.Record {
	t.Helper()
	header := secret.Header{Format: secret.Format, Algorithm: secret.Algorithm, Purpose: "upstream-credential", OwnerID: owner, ConnectorID: k.ConnectorID, CredentialID: k.ID, Epoch: k.Epoch, Revision: k.Revision, DestinationDigest: k.DestinationDigest}
	raw, _ := json.Marshal(header)
	aad, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	plain := []byte(`{"kind":"header_bundle","headers":[{"name":"Authorization","value":"Bearer SYNTHETIC_LEASE_TOKEN"}]}`)
	envelope := secret.Envelope{Header: header, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plain, aad))}
	raw, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	clear(plain)
	return secret.Record{Envelope: raw, Destination: d}
}

type forbiddenApprover struct{ t *testing.T }

func (a forbiddenApprover) Approve(context.Context, approval.Request) (bool, error) {
	a.t.Error("leased call invoked per-call approval provider")
	return false, errors.New("unexpected approval")
}

type actorTransport struct{ actor string }

func (t actorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	c.Header.Set("Authorization", t.actor)
	return http.DefaultTransport.RoundTrip(c)
}

func TestEncryptedDispatchThroughMCPAndPostgres(t *testing.T) {
	for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(protocol, func(t *testing.T) {
			db := testDatabase(t)
			store := db.store(t)
			tool := &mcp.Tool{Name: "echo", Description: "Synthetic leased tool", InputSchema: map[string]any{"type": "object"}, OutputSchema: map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"type": "boolean"}}, "required": []string{"ok"}}}
			remote := mcp.NewServer(&mcp.Implementation{Name: "encrypted-fixture", Version: "1"}, nil)
			var calls, requests, exfiltrated atomic.Int64
			var failCompletion, redirect, loseResponse atomic.Bool
			toolHandler := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				// Query using a different connection: admission must be committed
				// before the upstream sees the actual call and performs its effect.
				var count int
				err := db.admin.QueryRow(ctx, `SELECT count(*) FROM mcpwarden_security.invocation_events WHERE event_type=$1`, audit.DispatchAdmitted).Scan(&count)
				if err != nil || int64(count) != calls.Load()+1 {
					t.Error("upstream executed before durable admission")
				}
				calls.Add(1)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "synthetic-success"}}, StructuredContent: map[string]any{"ok": true}}, nil
			}
			remote.AddTool(tool, toolHandler)
			exfil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { exfiltrated.Add(1); w.WriteHeader(200) }))
			defer exfil.Close()
			remoteHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote }, nil)
			upstreamHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "Bearer SYNTHETIC_LEASE_TOKEN" {
					t.Error("upstream credential missing or incorrect")
					http.Error(w, "unauthorized", 401)
					return
				}
				if redirect.Load() {
					http.Redirect(w, r, exfil.URL+"/mcp", http.StatusTemporaryRedirect)
					return
				}
				if loseResponse.Load() {
					raw, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(raw))
					var rpc struct {
						Method string `json:"method"`
					}
					_ = json.Unmarshal(raw, &rpc)
					if rpc.Method == "tools/call" {
						recorder := httptest.NewRecorder()
						remoteHandler.ServeHTTP(recorder, r)
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							_ = conn.Close()
						}
						return
					}
				}
				remoteHandler.ServeHTTP(w, r)
			}))
			defer upstreamHTTP.Close()
			reg := registry.NewForOwner("alice")
			connector, credentialID := identity.New(), identity.New()
			reg.SetProviderID("remote", connector)
			pol, _ := policy.New(config.Policy{Default: "allow"})
			denials := &audittest.Memory{}
			var diagnostics bytes.Buffer
			p := proxy.New(reg, pol, forbiddenApprover{t}, denials, slog.New(slog.NewTextHandler(&diagnostics, nil)))
			p.Owner = "alice"
			p.Changed("remote", []*mcp.Tool{tool}, true)
			p.Changed("remote", nil, false) // Metadata exists while credential execution is locked.
			entry, ok := reg.Lookup("remote__echo")
			if !ok {
				t.Fatal("cached tool missing")
			}
			raw, _ := json.Marshal(entry.Tool)
			definition, _ := lease.DefinitionDigest(raw)
			destination := secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: upstreamHTTP.URL + "/mcp", HeaderNames: []string{"authorization"}, Network: "private", PrivatePrefixes: []string{"127.0.0.1/32"}, AllowLoopbackHTTP: true}
			digest, err := destination.Digest()
			if err != nil {
				t.Fatal(err)
			}
			a := &authority{caller: lease.Caller{Actor: identity.Actor{Owner: "alice", AccessID: identity.New(), Kind: "api_key", PublicID: identity.NewPublicID(), Label: "Actual caller"}, Active: true}, browser: lease.Caller{Actor: identity.Actor{Owner: "alice", AccessID: identity.New(), Kind: "browser"}, Active: true, Interactive: true}, credential: lease.Credential{ID: credentialID, ConnectorID: connector, Epoch: "1", Revision: "3", DestinationDigest: digest, PolicyRevision: "1", ConnectorSecurityRevision: "1", ApprovalPolicyRevision: "1", ApprovalMode: "none", Enabled: true, Tools: map[string]lease.Tool{entry.ID: {ID: entry.ID, DefinitionDigest: definition, Allowed: true, Visible: true}}}}
			key := make([]byte, 32)
			_, _ = rand.Read(key)
			defer clear(key)
			source := &vault.Cache{}
			other := a.caller.Actor
			other.AccessID = identity.New()
			other.PublicID = identity.NewPublicID()
			service, err := lease.New(t.Context(), store, dispatchAuthority{authority: a, other: lease.Caller{Actor: other, Active: true}}, secret.Activator{Records: source}, lease.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			root := vaultRootFixture(t, "alice")
			persisted := vault.Record{CredentialContext: secret.CredentialContext{OwnerID: "alice", RootID: root.RootID, RootVersion: "1", ConnectorID: connector, CredentialID: credentialID, Epoch: "1"}, Destination: destination}
			wrapFixture(&persisted)
			err = service.ChangeAtomic(t.Context(), "alice", func(tx lease.Tx) (func() error, error) {
				vtx := tx.(vault.Tx)
				if err := vtx.PutVaultRoot(root, ""); err != nil {
					return nil, err
				}
				var previous *vault.Pointer
				for _, revision := range []string{"1", "2", "3"} {
					persisted.Revision = revision
					credential := a.credential
					credential.Revision = revision
					persisted.Envelope = encryptedFixture(t, "alice", credential, destination, key).Envelope
					if err := vtx.PutCredentialRecord(persisted, previous); err != nil {
						return nil, err
					}
					previous = &vault.Pointer{Epoch: "1", Revision: revision}
				}
				// Feed the activator only bytes read through the storage adapter.
				current, err := vtx.CredentialRecord(credentialID)
				if err != nil {
					return nil, err
				}
				return source.Prepare(current)
			})
			if err != nil {
				t.Fatal(err)
			}
			p.Security = &proxy.LeasedExecution{Service: service, Credential: func(owner, id string) (string, bool) { return credentialID, owner == "alice" && id == connector }, Complete: func(ctx context.Context, r audit.Record) error {
				if failCompletion.Load() {
					return errors.New("SYNTHETIC_PRIVATE_STORAGE_ERROR")
				}
				return store.Complete(ctx, r)
			}, Timeout: func(registry.Entry) time.Duration { return 5 * time.Second }}
			gatewayHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
				if r.URL.Path == "/admin" {
					return p.AdminServer
				}
				return p.Server
			}, nil)
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actor := a.caller.Actor
				if r.Header.Get("Authorization") == "test-other-key" {
					actor = other
				}
				gatewayHandler.ServeHTTP(w, r.WithContext(identity.WithActor(r.Context(), actor)))
			}))
			defer gateway.Close()
			connect := func(path, actor string) *mcp.ClientSession {
				client := mcp.NewClient(&mcp.Implementation{Name: "downstream-fixture", Version: "1"}, nil)
				s, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: gateway.URL + path, HTTPClient: &http.Client{Transport: actorTransport{actor: actor}}, MaxRetries: -1, DisableStandaloneSSE: true}, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.Close() })
				return s
			}
			client := connect("/mcp", "test-key")
			list, err := client.ListTools(t.Context(), nil)
			if err != nil || len(list.Tools) != 1 {
				t.Fatal("locked cached tool omitted from MCP inventory")
			}
			call := func(s *mcp.ClientSession, n int) *mcp.CallToolResult {
				result, err := s.CallTool(t.Context(), &mcp.CallToolParams{Name: "remote__echo", Arguments: map[string]any{"n": n, "actor_access_id": "forged"}})
				if err != nil {
					t.Fatal("downstream protocol error:", err)
				}
				return result
			}
			result := call(client, -1)
			if !result.IsError || result.StructuredContent != nil || requests.Load() != 0 {
				t.Fatal("locked call executed or violated advertised output schema")
			}
			callerCtx := identity.WithActor(t.Context(), a.caller.Actor)
			browserCtx := identity.WithActor(t.Context(), a.browser.Actor)
			scope := lease.Scope{Schema: lease.ScopeSchema, OwnerID: "alice", RequesterAccessID: a.caller.AccessID, ConnectorID: connector, CredentialID: credentialID, CredentialEpoch: "1", Purpose: "tool_use", DurationSeconds: 900, PolicyRevision: "1", ConnectorSecurityRevision: "1", DestinationDigest: digest, Tools: []lease.ToolScope{{ToolID: entry.ID, DefinitionDigest: definition, Constraints: []lease.Constraint{}}}}
			raw, _ = json.Marshal(scope)
			request, err := service.Request(callerCtx, raw)
			if err != nil {
				t.Fatal(err)
			}
			input := func(k []byte) lease.ActivationInput {
				return lease.ActivationInput{RequestID: request.ID, RequestDigest: request.RequestDigest, OperationID: identity.New(), Key: bytes.Clone(k)}
			}
			if _, err := service.Activate(callerCtx, input(key)); err != lease.ErrDenied {
				t.Fatal("MCP caller activated itself")
			}
			if _, err := service.Activate(browserCtx, input(make([]byte, 32))); err != lease.ErrKey {
				t.Fatal("unauthenticated CEK accepted")
			}
			active, err := service.Activate(browserCtx, input(key))
			if err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 0 {
				t.Fatal("activation performed provider I/O")
			}
			for i := 0; i < 25; i++ {
				if i == 12 {
					_ = client.Close()
					client = connect("/admin", "test-key")
				}
				if result := call(client, i); result.IsError {
					t.Fatalf("leased call %d failed: %v", i, result.Content)
				}
			}
			if calls.Load() != 25 {
				t.Fatal("multi-call window did not execute exactly 25 times")
			}
			var count int
			if err := db.admin.QueryRow(t.Context(), `SELECT count(*) FROM mcpwarden_security.invocation_events WHERE metadata->>'actor_access_id'=$1 AND metadata->>'credential_revision'='3' AND metadata->>'lease_id'=$2`, a.caller.AccessID, active.ID).Scan(&count); err != nil || count != 50 {
				t.Fatal("durable invocation attribution mismatch")
			}
			var expiry time.Time
			var admitted int64
			if err := db.admin.QueryRow(t.Context(), `SELECT expires_at,admitted_calls FROM mcpwarden_security.leases WHERE owner_id='alice' AND lease_id=$1`, active.ID).Scan(&expiry, &admitted); err != nil || admitted != 25 || !expiry.Equal(active.ExpiresAt) {
				t.Fatal("traffic/reconnect changed fixed deadline or budget")
			}
			before := requests.Load()
			if !call(connect("/mcp", "test-other-key"), 26).IsError || requests.Load() != before {
				t.Fatal("second API key borrowed first caller's lease")
			}
			failCompletion.Store(true)
			if call(client, 27).IsError || calls.Load() != 26 {
				t.Fatal("completion failure replaced upstream success or retried")
			}
			failCompletion.Store(false)
			loseResponse.Store(true)
			if !call(client, 28).IsError || calls.Load() != 27 {
				t.Fatal("lost result retried or claimed success")
			}
			loseResponse.Store(false)
			redirect.Store(true)
			if !call(client, 29).IsError || exfiltrated.Load() != 0 || calls.Load() != 27 {
				t.Fatal("redirect forwarded private credentials or executed")
			}
			redirect.Store(false)
			changed := *tool
			changed.Description = "Changed authority"
			remote.AddTool(&changed, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				t.Error("changed definition dispatched")
				return nil, nil
			})
			if !call(client, 30).IsError || calls.Load() != 27 {
				t.Fatal("changed tool definition dispatched under old scope")
			}
			if err := service.Revoke(browserCtx, active.ID); err != nil {
				t.Fatal(err)
			}
			before = requests.Load()
			if !call(client, 31).IsError || requests.Load() != before {
				t.Fatal("revoked lease performed provider I/O")
			}
			// A real deferred PostgreSQL commit rejection after authorized setup
			// must never reach tools/call or fall back to the legacy manager.
			remote.AddTool(tool, toolHandler)
			request, err = service.Request(callerCtx, raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = service.Activate(browserCtx, input(key)); err != nil {
				t.Fatal(err)
			}
			_, err = db.admin.Exec(t.Context(), `CREATE FUNCTION mcpwarden_security.reject_dispatch_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit rejection'; END $$;
CREATE CONSTRAINT TRIGGER reject_dispatch_fixture AFTER INSERT ON mcpwarden_security.invocation_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.reject_dispatch_fixture()`)
			if err != nil {
				t.Fatal("could not install isolated commit failure fixture")
			}
			if !call(client, 32).IsError || calls.Load() != 27 {
				t.Fatal("failed admission dispatched a tool")
			}
			before = requests.Load()
			if !call(client, 33).IsError || requests.Load() != before {
				t.Fatal("storage failure did not lock material")
			}
			if strings.Contains(diagnostics.String(), "SYNTHETIC_LEASE_TOKEN") || strings.Contains(diagnostics.String(), "SYNTHETIC_PRIVATE_STORAGE_ERROR") || strings.Contains(diagnostics.String(), "forged") {
				t.Fatal("private data reached diagnostics")
			}
		})
	}
}
