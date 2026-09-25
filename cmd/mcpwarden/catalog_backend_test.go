package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/pgcatalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"golang.org/x/oauth2"
)

// The owner security flows run unchanged on the PostgreSQL catalog after a
// real import and cutover. The file-mode database-loss test is replaced by
// the PostgreSQL rule below: with the catalog in PostgreSQL, storage loss
// stops the gateway instead of letting file revocations continue.
func TestOwnerFlowsOnPostgresCatalog(t *testing.T) {
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
		{"provider-changes", testPostgresProviderChangesEndAuthority},
		{"loss-and-rollback", testPostgresCatalogLossAndRollback},
	} {
		t.Run(test.name, test.run)
	}
}

// Disabling a provider or hiding its tools ends the connector's windows and
// pending requests in the same commit and moves the revision scopes bind, so
// undoing the change revives neither. A repeated setting changes nothing.
func testPostgresProviderChangesEndAuthority(t *testing.T) {
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
		var out string
		if err := f.db.Admin.QueryRow(t.Context(), "SELECT state FROM mcpwarden_security.leases WHERE lease_id=$1", active.LeaseID).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	revision := func() string { return f.pg.repo.ConnectorSecurityRevision(alice, f.entry.ID) }

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
	var revoked int
	if err := f.db.Admin.QueryRow(t.Context(), "SELECT count(*) FROM mcpwarden_security.security_events WHERE owner_id=$1 AND event_type='lease.revoked'", alice).Scan(&revoked); err != nil || revoked != 2 {
		t.Fatal("window ends not audited", revoked, err)
	}
}

func testPostgresCatalogLossAndRollback(t *testing.T) {
	f := newOwnerFixture(t)
	if f.backend != "postgres" {
		t.Fatal("fixture is not on the PostgreSQL catalog")
	}
	alice := f.owners["alice"]
	ctx := t.Context()
	// Security changes made after cutover, and a real approved window. Key
	// revocation ends the owner's windows, so it comes first.
	f.expect(req{method: "DELETE", path: "/api/access/" + f.keyIDs["other-agent"], user: "alice", skipCSRF: true}, 204, nil)
	_, record := f.provision("none")
	request := f.requestAccess("agent", record.CredentialID)
	owner := f.ownerRequest(request.ID)
	var active leaseView
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(owner, f.cek)}, 200, &active)
	if w := f.do(req{method: "POST", path: "/api/auth/password", user: "alice", body: `{"current_password":"` + testPassword + `","new_password":"replacement synthetic password"}`}); w.Code != 204 {
		t.Fatal("password change", w.Code, w.Body.String())
	}
	oauthEntry := catalog.Entry{ID: identity.New(), Owner: alice, Name: "oauth", URL: "https://example.com/oauth-mcp", AuthType: "oauth", OAuth: &catalog.OAuthSettings{}}
	if err := f.store.Add(oauthEntry); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveOAuth(alice, oauthEntry.ID, "", catalog.OAuthGrant{ID: identity.New(), Token: oauth2.Token{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh"}}); err != nil {
		t.Fatal(err)
	}
	live := audit.Record{Owner: alice, Tool: "remote__search", ToolID: f.toolID, Upstream: "remote", Decision: "allow", Status: "ok", TS: time.Now().UTC(), ArgsSHA256: strings.Repeat("a", 64)}
	if err := f.pg.history.Write(live); err != nil {
		t.Fatal(err)
	}
	// Every change committed with its security event.
	for _, event := range []string{"access.revoked", "account.password_changed", "connector.created", "connector.oauth_saved"} {
		var n int
		if err := f.db.Admin.QueryRow(ctx, "SELECT count(*) FROM mcpwarden_security.security_events WHERE owner_id=$1 AND event_type=$2", alice, event).Scan(&n); err != nil || n != 1 {
			t.Fatal("missing security event", event, n, err)
		}
	}

	// Storage loss stops the gateway: nothing authenticates from the stale
	// view, revocation cannot pretend to succeed, and there is no file fallback.
	if _, err := f.db.Admin.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mcpwarden-security' AND datname=current_database()"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
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
	f.pg.close()
	f.api = nil

	// Rollback reconciles instead of restoring the pre-cutover file.
	src := pgcatalog.Sources{CatalogPath: f.cfg.Managed.Path, CatalogKey: f.cfg.Managed.Key, HistoryPath: f.cfg.Audit.Path}
	m, err := pgcatalog.Rollback(ctx, f.db.Admin, src)
	if err != nil {
		t.Fatal(err)
	}
	if m.SuspendedLeases != 1 || m.LiveHistory != 1 || !slices.Equal(m.Reauthorize, []string{oauthEntry.ID}) {
		t.Fatalf("rollback manifest: %+v", m)
	}
	var suspended int
	if err := f.db.Admin.QueryRow(ctx, "SELECT count(*) FROM mcpwarden_security.security_events WHERE event_type='lease.suspended' AND boot_id=$1", m.RollbackID).Scan(&suspended); err != nil || suspended != 1 {
		t.Fatal("rollback suspension not audited", suspended, err)
	}
	pol, _ := policy.New(config.Policy{Default: "allow"})
	if _, err := openPostgresCatalog(ctx, f.cfg, pol, slog.New(slog.NewTextHandler(io.Discard, nil)), func(error) {}); !errors.Is(err, pgcatalog.ErrNotActive) {
		t.Fatal("PostgreSQL gateway started after rollback", err)
	}

	store, err := catalog.Open(src.CatalogPath, src.CatalogKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := authenticateAPIKey(store, f.keys["other-agent"]); ok {
		t.Fatal("rollback revived a revoked key")
	}
	if _, ok := authenticateAPIKey(store, f.keys["agent"]); !ok {
		t.Fatal("rollback lost an active key")
	}
	for _, e := range store.List(alice) {
		if e.ID == oauthEntry.ID && (e.OAuth == nil || e.OAuth.Grant != nil) {
			t.Fatal("rotated OAuth grant was exported instead of requiring reauthorization")
		}
	}
	accounts := newAccountAuth(store, config.Config{Accounts: &config.Accounts{}})
	login := func(password string) int {
		r := httptest.NewRequest("POST", "http://localhost/api/auth/login", strings.NewReader(`{"username":"alice","password":"`+password+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-MCPWarden-Request", "browser")
		w := httptest.NewRecorder()
		accounts.authHandler(w, r)
		return w.Code
	}
	if login(testPassword) != 401 || login("replacement synthetic password") != 200 {
		t.Fatal("rollback did not keep the changed password")
	}
	history, err := audit.Open(src.HistoryPath)
	if err != nil {
		t.Fatal(err)
	}
	records, _, _, err := history.QueryHistory(audit.HistoryFilter{Owner: alice, Page: 1, Size: 10})
	history.Close()
	if err != nil || len(records) != 1 || records[0].Tool != live.Tool {
		t.Fatal("post-cutover history was not preserved", len(records), err)
	}
	store.Close()

	// The file gateway may reopen with owner security, and an older copy of
	// the catalog cannot be started in place of the export.
	api, err := openSecurity(ctx, config.Config{Accounts: &config.Accounts{}, OwnerSecurity: f.cfg.OwnerSecurity}, store, pol, accounts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := fileAuthority(ctx, api.store); err != nil {
		t.Fatal(err)
	}
	api.close()
	old, err := os.ReadFile(filepath.Join(pgcatalog.SnapshotDir(src, m.ImportID), "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src.CatalogPath, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Open(src.CatalogPath, src.CatalogKey); err == nil || !strings.Contains(err.Error(), "revive") {
		t.Fatal("pre-cutover catalog started after rollback", err)
	}
}

func TestFileGatewayRefusesActivePostgresCatalog(t *testing.T) {
	f := newOwnerFixture(t)
	src := pgcatalog.Sources{CatalogPath: f.cfg.Managed.Path, CatalogKey: f.cfg.Managed.Key, HistoryPath: f.cfg.Audit.Path}
	f.api.close()
	f.api = nil
	// A running file gateway blocks the import.
	running, err := catalog.Open(src.CatalogPath, src.CatalogKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgcatalog.Import(t.Context(), f.db.Admin, src, pgcatalog.Options{}); !errors.Is(err, pgcatalog.ErrLocked) {
		t.Fatal("import ran beside a file gateway", err)
	}
	running.Close()
	f.store.Close()
	if _, err := pgcatalog.Import(t.Context(), f.db.Admin, src, pgcatalog.Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := pgcatalog.Cutover(t.Context(), f.db.Admin, src); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Open(src.CatalogPath, src.CatalogKey); err == nil {
		t.Fatal("file backend opened after cutover")
	}
	// Even with the marker removed, a file gateway with owner security refuses.
	if err := os.Remove(catalog.MarkerPath(src.CatalogPath)); err != nil {
		t.Fatal(err)
	}
	store, err := catalog.Open(src.CatalogPath, src.CatalogKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pol, _ := policy.New(config.Policy{Default: "allow"})
	api, err := openSecurity(t.Context(), f.cfg, store, pol, newAccountAuth(store, f.cfg), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer api.close()
	if err := fileAuthority(t.Context(), api.store); err == nil {
		t.Fatal("file gateway accepted an active PostgreSQL catalog")
	}
}
