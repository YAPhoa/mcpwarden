package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

// The owner flows run on SQLite by default. This runs the same tests on
// PostgreSQL; fixtureDriver picks the driver from the test name.
func TestOwnerFlowsOnPostgres(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"routes", TestOwnerRoutesRequireInteractiveBrowserSession},
		{"activation", TestOwnerActivationReplayAndOwnerIsolation},
		{"confirm", TestOwnerConfirmModeAndPolicyChange},
		{"vault", TestOwnerVaultCredentialLifecycleAndRestart},
		{"revocation", TestOwnerConcurrentMutationsAndKeyRevocation},
		{"limits", TestOwnerSecurityRequestLimitsAndBodies},
		{"session-wait", TestOwnerMutationRechecksSessionAfterDatabaseWait},
		{"provider-changes", TestStorageProviderChangesEndAuthority},
		{"loss", TestStorageLossStopsGateway},
		{"guarded-execution", TestGuardedHeaderExecution},
		{"stale-sessions", TestStorageStaleSessionsEnd},
	} {
		t.Run(test.name, test.run)
	}
}

// MCP sessions left open by a gateway that stopped are ended when the next
// gateway starts, before it serves anything; new sessions stay open.
func TestStorageStaleSessionsEnd(t *testing.T) {
	f := newOwnerFixture(t)
	alice := f.owners["alice"]
	var stale []string
	for i := range 3 {
		a := catalog.AccessRecord{ID: identity.New(), Owner: alice, Name: "session", Kind: "mcp", Role: "client", ParentID: f.keyIDs["agent"], SecretHash: tokenHash(randomToken()), ExpiresAt: time.Now().Add(time.Hour)}
		if i == 2 {
			a.Owner, a.ParentID = f.owners["bob"], f.keyIDs["bob-agent"]
		}
		if err := f.store.AddAccess(a); err != nil {
			t.Fatal(err)
		}
		stale = append(stale, a.Owner+"/"+a.ID)
	}
	f.restart()
	for _, key := range stale {
		owner, id, _ := strings.Cut(key, "/")
		if a, ok := f.store.AccessByID(owner, id); !ok || a.EndedAt.IsZero() {
			t.Fatal("MCP session still open after restart:", key, ok)
		}
	}
	next := catalog.AccessRecord{ID: identity.New(), Owner: alice, Name: "session", Kind: "mcp", Role: "client", ParentID: f.keyIDs["agent"], SecretHash: tokenHash(randomToken()), ExpiresAt: time.Now().Add(time.Hour)}
	if err := f.store.AddAccess(next); err != nil {
		t.Fatal(err)
	}
	if a, ok := f.store.AccessByID(alice, next.ID); !ok || !a.EndedAt.IsZero() {
		t.Fatal("new MCP session not open:", ok)
	}
	for _, name := range []string{"agent", "bob-agent"} {
		owner := alice
		if name == "bob-agent" {
			owner = f.owners["bob"]
		}
		if a, ok := f.store.AccessByID(owner, f.keyIDs[name]); !ok || !a.EndedAt.IsZero() {
			t.Fatal("API key ended at startup:", name)
		}
	}
}

// Disabling a provider or hiding its tools ends the connector's windows and
// pending requests in the same commit and moves the revision scopes bind, so
// undoing the change revives neither. A repeated setting changes nothing.
func TestStorageProviderChangesEndAuthority(t *testing.T) {
	f := newOwnerFixture(t)
	alice := f.owners["alice"]
	_, record := f.provision("none")
	window := func() leaseView {
		t.Helper()
		request := f.requestAccess("agent", record.CredentialID)
		var active leaseView
		f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, &active)
		return active
	}
	admit := func() error {
		t.Helper()
		caller, _ := f.store.AccessByID(alice, f.keyIDs["agent"])
		ctx := identity.WithActor(t.Context(), identity.Actor{Owner: alice, AccessID: caller.ID, PublicID: caller.PublicID, Kind: "api_key", Label: caller.Name})
		definition := ""
		if tools, ok := f.api.authority.SelectableTools(alice, record.CredentialID); ok {
			for _, tool := range tools {
				if tool.ID == f.toolID {
					definition = tool.DefinitionDigest
				}
			}
		}
		args := []byte(`{"repo":"example"}`)
		r := audit.NewInvocation(ctx, alice)
		r.ToolID, r.Tool, r.UpstreamID, r.Upstream = f.toolID, "remote__search", f.entry.ID, "remote"
		r.ArgsSHA256 = audit.HashArgs(json.RawMessage(args))
		admission, err := f.api.service.Admit(ctx, record.CredentialID, f.toolID, definition, args, r)
		if err != nil {
			return err
		}
		return admission.Run(func(context.Context) error { return nil })
	}
	state := func(active leaseView) string {
		t.Helper()
		return f.text("SELECT state FROM leases WHERE lease_id=$1", active.LeaseID)
	}
	revision := func() string { return f.backend.repo.ConnectorSecurityRevision(alice, f.entry.ID) }

	active := window()
	if err := admit(); err != nil {
		t.Fatal("admission before the change", err)
	}
	// A repeated setting is not a change.
	if err := f.store.SetProviderEnabled(alice, "remote", true); err != nil || state(active) != "active" || revision() != "1" {
		t.Fatal("unchanged availability ended the window", err, state(active), revision())
	}
	pending := f.requestAccess("agent", record.CredentialID)
	if err := f.store.SetProviderEnabled(alice, "remote", false); err != nil {
		t.Fatal(err)
	}
	if state(active) != "revoked" || f.ownerRequest(pending.ID).State != "stale" || revision() != "2" {
		t.Fatal("disabling kept authority", state(active), f.ownerRequest(pending.ID).State, revision())
	}
	if err := admit(); err == nil {
		t.Fatal("admitted under a window of a disabled provider")
	}
	// Re-enabling revives neither the window nor the pending request.
	if err := f.store.SetProviderEnabled(alice, "remote", true); err != nil {
		t.Fatal(err)
	}
	if err := admit(); err == nil {
		t.Fatal("admitted under a window ended by disabling")
	}
	if w := f.do(req{method: "POST", path: "/api/approvals/" + pending.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(pending.ID), f.cek)}); w.Code == 200 {
		t.Fatal("request from before the change activated")
	}

	// Hiding tools is the same kind of change.
	active = window()
	if err := admit(); err != nil {
		t.Fatal("admission under a new window", err)
	}
	if err := f.store.SetVisibility(alice, "remote", catalog.Visibility{Mode: "all"}); err != nil || state(active) != "active" {
		t.Fatal("unchanged visibility ended the window", err)
	}
	if err := f.store.SetVisibility(alice, "remote", catalog.Visibility{Mode: "selected", Enabled: []string{"remote__write"}}); err != nil {
		t.Fatal(err)
	}
	if state(active) != "revoked" || revision() != "4" {
		t.Fatal("hiding a tool kept the window", state(active), revision())
	}
	if err := f.store.SetVisibility(alice, "remote", catalog.Visibility{Mode: "all"}); err != nil {
		t.Fatal(err)
	}
	if err := admit(); err == nil {
		t.Fatal("admitted under a window ended by hiding a tool")
	}
	if revoked := f.count("SELECT count(*) FROM security_events WHERE owner_id=$1 AND event_type='lease.revoked'", alice); revoked != 2 {
		t.Fatal("window ends not audited", revoked)
	}
}

// Every catalog change commits with its security event. Storage loss stops
// the gateway: nothing authenticates from the stale view, revocation cannot
// pretend to succeed, and there is no file fallback.
func TestStorageLossStopsGateway(t *testing.T) {
	f := newOwnerFixture(t)
	alice := f.owners["alice"]
	// Key revocation ends the owner's windows, so it comes first.
	f.expect(req{method: "DELETE", path: "/api/access/" + f.keyIDs["other-agent"], user: "alice", skipCSRF: true}, 204, nil)
	_, record := f.provision("none")
	request := f.requestAccess("agent", record.CredentialID)
	var active leaseView
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, &active)
	if w := f.do(req{method: "POST", path: "/api/auth/password", user: "alice", body: `{"current_password":"` + testPassword + `","new_password":"replacement synthetic password"}`}); w.Code != 204 {
		t.Fatal("password change", w.Code, w.Body.String())
	}
	keyed := catalog.Entry{ID: identity.New(), Owner: alice, Name: "keyed", URL: "https://example.com/keyed-mcp", AuthType: "api_key", HeaderNames: []string{"X-API-Key"}}
	if err := f.store.Add(keyed); err != nil {
		t.Fatal(err)
	}
	live := audit.Record{Owner: alice, Tool: "remote__search", ToolID: f.toolID, Upstream: "remote", Decision: "allow", Status: "ok", TS: time.Now().UTC(), ArgsSHA256: strings.Repeat("a", 64)}
	if err := f.backend.history.Write(live); err != nil {
		t.Fatal(err)
	}
	// The fixture created the first connector.
	for event, want := range map[string]int{"access.revoked": 1, "account.password_changed": 1, "connector.created": 2} {
		if n := f.count("SELECT count(*) FROM security_events WHERE owner_id=$1 AND event_type=$2", alice, event); n != want {
			t.Fatal("missing security event", event, n)
		}
	}

	f.lose()
	deadline := time.Now().Add(10 * time.Second)
	for !errors.Is(context.Cause(f.stopped), errCatalogFailed) {
		if time.Now().After(deadline) {
			t.Fatal("storage loss did not stop the gateway")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := authenticateAPIKey(f.store, f.keys["agent"]); ok {
		t.Fatal("key authenticated after storage loss")
	}
	if w := f.do(req{method: "DELETE", path: "/api/access/" + f.keyIDs["agent"], user: "alice", skipCSRF: true}); w.Code == 204 {
		t.Fatal("revocation reported success without storage")
	}
}

// A stdio client runs the gateway without HTTP routes, so it cannot serve
// the database-backed modes; the storage section refuses it before opening
// the database.
func TestStorageRefusesStdio(t *testing.T) {
	t.Setenv("TEST_STORAGE_KEY", base64.StdEncoding.EncodeToString(randBytes(32)))
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "storage:\n  path: " + filepath.Join(dir, "mcpwarden.db") + "\n  key_env: TEST_STORAGE_KEY\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(path, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "--stdio") {
		t.Fatal("stdio accepted with storage", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mcpwarden.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("database created for a refused stdio start", err)
	}
}

// Operator mode runs on the database too: the executor coordinates the
// catalog without accounts or owner routes, and the catalog and history
// survive a restart.
func TestStorageOperatorMode(t *testing.T) {
	cfg := config.Config{Storage: &config.Storage{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "mcpwarden.db"), Key: base64.StdEncoding.EncodeToString(randBytes(32))}}
	pol, _ := policy.New(config.Policy{Default: "allow"})
	open := func() *storageBackend {
		t.Helper()
		b, err := openStorage(t.Context(), cfg, pol, slog.New(slog.NewTextHandler(io.Discard, nil)), func(error) {})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := open()
	if b.accounts != nil {
		t.Fatal("accounts started in operator mode")
	}
	if err := b.repo.Add(catalog.Entry{Owner: "local", Name: "open", URL: "https://example.com/mcp", AuthType: "none"}); err != nil {
		t.Fatal(err)
	}
	if err := b.history.Write(audit.Record{Owner: "local", Tool: "open__search", Upstream: "open", Decision: "allow", Status: "ok", TS: time.Now().UTC(), ArgsSHA256: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	b.close()
	b = open()
	defer b.close()
	if entries := b.repo.List("local"); len(entries) != 1 || entries[0].Name != "open" {
		t.Fatal("connector lost across restart", entries)
	}
	if rows, _, _, _, err := b.history.QueryHistoryPerformance(audit.HistoryFilter{Owner: "local", Page: 1, Size: 10}); err != nil || len(rows) != 1 {
		t.Fatal("history lost across restart", len(rows), err)
	}
}
