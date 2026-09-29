package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

func TestAccessRolesAndRevocableMCPSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg := config.Config{Accounts: &config.Accounts{}}
	db := testStorage(t, &cfg)
	store := db.repo
	for _, owner := range []string{"alice", "bob"} {
		if err := store.AddAccount(catalog.Account{ID: owner, Username: owner}); err != nil {
			t.Fatal(err)
		}
	}
	clientToken, clientPublicID := identity.NewAccessToken()
	keys := []struct{ id, owner, role, token string }{{"admin", "alice", "admin", "mw_admin"}, {"client", "alice", "client", clientToken}, {"bob", "bob", "client", "mw_bob"}}
	for _, k := range keys {
		publicID := ""
		if k.token == clientToken {
			publicID = clientPublicID
		}
		if err := store.AddAccess(catalog.AccessRecord{ID: k.id, PublicID: publicID, Owner: k.owner, Role: k.role, Name: k.id, Kind: "api_key", SecretHash: tokenHash(k.token), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	account := db.accounts
	pol, _ := policy.New(config.Policy{Default: "allow"})
	rs := newRuntimes(ctx, cfg, pol, db.history, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rs.close()
	_, remote := upstreamForUser(t, "echo")
	defer func() { rs.close(); remote.Close() }()
	if err := rs.add(catalog.Entry{Owner: "alice", Name: "remote", URL: remote.URL}); err != nil {
		t.Fatal(err)
	}
	awaitRuntime(t, func() bool { e, ok := rs.get("alice").proxy.Registry.Lookup("remote__echo"); return ok && e.Healthy })
	mux := http.NewServeMux()
	mux.Handle("/mcp", account.protect(rs.access.bindMCP(mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		p := rs.get(requestOwner(r)).proxy
		a, _ := accessFrom(r.Context())
		if a.Role == "admin" {
			return p.AdminServer
		}
		return p.Server
	}, nil)), false))
	mux.Handle("/api/history", account.protect(http.HandlerFunc(rs.history), true))
	mux.Handle("/api/access", account.protect(http.HandlerFunc(rs.access.handler), true))
	mux.Handle("/api/access/", account.protect(http.HandlerFunc(rs.access.handler), true))
	mux.Handle("/api/discovery/", account.protect(http.HandlerFunc(rs.discovery), true, true))
	mux.Handle("/api/connections", account.protect(http.HandlerFunc(rs.connections), true))
	server := httptest.NewServer(mux)
	defer server.Close()
	defer server.CloseClientConnections()
	request := func(method, path, token, body, session string) *http.Response {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if session != "" {
			r.Header.Set("Mcp-Session-Id", session)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	for _, path := range []string{"/api/access", "/api/connections", "/api/history"} {
		res := request("GET", path, clientToken, "", "")
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("client management request: %d", res.StatusCode)
		}
	}
	res := request("POST", "/api/access", clientToken, `{"name":"escalate","role":"admin","expires_days":1}`, "")
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("client minted admin key")
	}
	refreshResponse := request("POST", "/api/discovery/remote/refresh", clientToken, "", "")
	refreshResponse.Body.Close()
	if refreshResponse.StatusCode != 200 {
		t.Fatal("client HTTP refresh denied")
	}
	connect := func(name, token string) *mcp.ClientSession {
		t.Helper()
		client := mcp.NewClient(&mcp.Implementation{Name: name, Version: "1"}, nil)
		s, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: privateClient(token)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	admin, client := connect("Admin app", "mw_admin"), connect("Laptop client", clientToken)
	// The workspace cap applies across credentials, not separately per key.
	var extra []*mcp.ClientSession
	for i := 0; i < catalog.MaxMCPSessions-2; i++ {
		extra = append(extra, connect("Additional device", clientToken))
	}
	overflowClient := mcp.NewClient(&mcp.Implementation{Name: "Overflow", Version: "1"}, nil)
	if overflow, err := overflowClient.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: privateClient("mw_admin")}, nil); err == nil {
		overflow.Close()
		t.Fatal("eleventh MCP connection was accepted")
	}
	for _, s := range extra {
		s.Close()
	}
	awaitRuntime(t, func() bool {
		count := 0
		for _, r := range store.AccessList("alice") {
			if r.Kind == "mcp" && r.Active() {
				count++
			}
		}
		return count == 2
	})

	defer admin.Close()
	defer func() { client.Close() }()
	names := func(s *mcp.ClientSession) map[string]bool {
		t.Helper()
		list, err := s.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, tool := range list.Tools {
			out[tool.Name] = true
		}
		return out
	}
	userTools, adminTools := names(client), names(admin)
	if len(userTools) != 2 || !userTools["remote__echo"] || !userTools["warden_refresh_provider"] {
		t.Fatalf("client tools: %v", userTools)
	}
	for _, name := range []string{"warden_add_provider", "warden_remove_provider", "warden_set_provider_enabled", "warden_set_tool_visibility", "warden_list_providers"} {
		if userTools[name] || !adminTools[name] {
			t.Fatalf("bad tool separation: %s", name)
		}
	}
	if result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "warden_set_provider_enabled", Arguments: map[string]any{"provider": "remote", "enabled": false}}); err == nil && !result.IsError {
		t.Fatal("client invoked management tool")
	}
	// Same-account privilege changes and cross-owner reuse must both fail.
	for _, key := range []string{clientToken, "mw_bob"} {
		res := request("POST", "/mcp", key, `{"jsonrpc":"2.0","id":90,"method":"tools/list","params":{}}`, admin.ID())
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("session reuse: %d", res.StatusCode)
		}
	}
	call := func(s *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
		t.Helper()
		result, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	if call(client, "remote__echo", map[string]any{"actor_access_id": "admin", "label": "Admin app"}).IsError {
		t.Fatal("upstream call failed")
	}
	entry, _ := rs.get("alice").proxy.Registry.Lookup("remote__echo")
	history := request("GET", "/api/history?tool_id="+entry.ID, "mw_admin", "", "")
	content, _ := io.ReadAll(history.Body)
	history.Body.Close()
	if history.StatusCode != 200 || !strings.Contains(string(content), `"total":1`) || strings.Contains(string(content), "args_sha256") || strings.Contains(string(content), `"owner"`) || strings.Contains(string(content), `"session"`) {
		t.Fatalf("unsafe or missing history: %s", content)
	}
	if err := store.AddAccess(catalog.AccessRecord{ID: "bob-admin", Owner: "bob", Role: "admin", Name: "bob-admin", Kind: "api_key", SecretHash: tokenHash("mw_bob_admin")}); err != nil {
		t.Fatal(err)
	}
	history = request("GET", "/api/history?tool_id="+entry.ID, "mw_bob_admin", "", "")
	content, _ = io.ReadAll(history.Body)
	history.Body.Close()

	for _, query := range []string{"status=invalid", "from=bad", "from=2026-09-22T00:00:00Z&to=2026-09-21T00:00:00Z", "page=-1"} {
		invalid := request("GET", "/api/history?"+query, "mw_admin", "", "")
		invalid.Body.Close()
		if invalid.StatusCode != 400 {
			t.Fatalf("invalid filter accepted: %s", query)
		}
	}
	if !strings.Contains(string(content), `"total":0`) {
		t.Fatal("cross-user history exposed")
	}
	rows, total, err := historyPage(db.history, "alice", entry.ID)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].ActorAccessID != "client" || rows[0].ActorPublicID != clientPublicID || rows[0].ActorLabel != "client" {
		t.Fatal("MCP arguments or clientInfo replaced the authenticated caller")
	}
	if err := store.UpdateAccess("alice", "client", "Renamed caller", false); err != nil {
		t.Fatal(err)
	}
	if call(client, "remote__echo", map[string]any{}).IsError {
		t.Fatal("renamed caller failed")
	}
	reconnected := connect("Spoofed administrator label", clientToken)
	if call(reconnected, "remote__echo", map[string]any{}).IsError {
		t.Fatal("reconnected caller failed")
	}
	reconnected.Close()
	if call(admin, "remote__echo", map[string]any{}).IsError {
		t.Fatal("second caller failed")
	}
	rows, total, err = historyPage(db.history, "alice", entry.ID)
	if err != nil || total != 4 || len(rows) != 4 || rows[0].ActorAccessID != "admin" || rows[1].ActorAccessID != "client" || rows[1].ActorLabel != "Renamed caller" || rows[2].ActorLabel != "Renamed caller" || rows[3].ActorLabel != "client" {
		t.Fatal("caller identity or historical label changed across requests/reconnects")
	}
	filtered := request("GET", "/api/history?actor_access_id=client&tool_id="+entry.ID, "mw_admin", "", "")
	filteredBody, _ := io.ReadAll(filtered.Body)
	filtered.Body.Close()
	if filtered.StatusCode != 200 || !strings.Contains(string(filteredBody), `"total":3`) || strings.Contains(string(filteredBody), clientToken) || strings.Contains(string(filteredBody), tokenHash(clientToken)) {
		t.Fatal("actor history filter failed or exposed secret material")
	}
	if call(client, "warden_refresh_provider", map[string]any{"provider": "remote"}).IsError {
		t.Fatal("client could not refresh")
	}
	if call(admin, "warden_set_provider_enabled", map[string]any{"provider": "remote", "enabled": false}).IsError {
		t.Fatal("admin could not disable")
	}
	if names(client)["remote__echo"] {
		t.Fatal("disabled upstream still broadcast")
	}
	if !call(client, "warden_refresh_provider", map[string]any{"provider": "remote"}).IsError {
		t.Fatal("refresh enabled disabled provider")
	}
	if call(admin, "warden_set_provider_enabled", map[string]any{"provider": "remote", "enabled": true}).IsError {
		t.Fatal("admin could not enable")
	}
	if call(admin, "warden_add_provider", map[string]any{"name": "added", "url": remote.URL}).IsError {
		t.Fatal("admin could not add")
	}
	if call(admin, "warden_remove_provider", map[string]any{"provider": "added"}).IsError {
		t.Fatal("admin could not remove")
	}
	var recordID string
	for _, r := range store.AccessList("alice") {
		if r.Kind == "mcp" && r.Name == "Laptop client" {
			recordID = r.ID
			if r.Device == "" || r.CreatedAt.IsZero() || r.LastUsedAt.IsZero() {
				t.Fatal("missing device/timestamps")
			}
		}
	}
	if recordID == "" {
		t.Fatal("MCP session not recorded")
	}
	res = request("DELETE", "/api/access/"+recordID, "mw_admin", "", "")
	res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatal("session not revoked")
	}
	wait := make(chan struct{})
	go func() { _ = client.Wait(); close(wait) }()
	select {
	case <-wait:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked MCP session stayed connected")
	}
	// Revoking a connection leaves its key usable for a new connection.
	client = connect("Reconnected client", clientToken)
	res = request("DELETE", "/api/access/client", "mw_admin", "", "")
	res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatal("key not revoked")
	}
	wait = make(chan struct{})
	go func() { _ = client.Wait(); close(wait) }()
	select {
	case <-wait:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked key session stayed connected")
	}
	res = request("POST", "/mcp", clientToken, `{}`, "")
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("revoked key accepted")
	}
	res = request("GET", "/api/access", "mw_admin", "", "")
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("access response can be cached")
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if strings.Contains(string(raw), "secret_hash") || strings.Contains(string(raw), "mw_admin") {
		t.Fatal("credential leaked")
	}
	rs.audit = rejectAdmissionStore{db.history}
	if !call(admin, "warden_remove_provider", map[string]any{"provider": "remote"}).IsError {
		t.Fatal("management action ignored admission failure")
	}
	if len(store.List("alice")) != 1 || store.List("alice")[0].Name != "remote" {
		t.Fatal("management action executed after admission failure")
	}
	var payload struct{ Items []catalog.AccessRecord }
	if json.Unmarshal(raw, &payload) != nil {
		t.Fatal("invalid access response")
	}
	for _, r := range payload.Items {
		if r.Owner != "alice" {
			t.Fatal("cross-owner access records")
		}
	}
}

// Inject a failure before dispatch while retaining a real durable history reader.
type rejectAdmissionStore struct{ audit.Store }

func (s rejectAdmissionStore) Write(r audit.Record) error {
	if r.EventType == audit.DispatchAdmitted {
		return errors.New("synthetic audit outage")
	}
	return s.Store.Write(r)
}

func TestNamedKeyMintAndAuthenticationPaths(t *testing.T) {
	cfg := config.Config{Accounts: &config.Accounts{}}
	db := testStorage(t, &cfg)
	store := db.repo
	if err := store.AddAccount(catalog.Account{ID: "alice", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddAccess(catalog.AccessRecord{ID: "bootstrap", Owner: "alice", Name: "Bootstrap", Kind: "api_key", Role: "admin", SecretHash: tokenHash("mw_bootstrap")}); err != nil {
		t.Fatal(err)
	}
	manager := newAccessManager(store)
	accounts := db.accounts
	req := httptest.NewRequest("POST", "http://localhost/api/access", strings.NewReader(`{"name":"Laptop", "role":"client", "expires_days":1}`))
	req.Header.Set("Authorization", "Bearer mw_bootstrap")
	out := httptest.NewRecorder()
	accounts.protect(http.HandlerFunc(manager.handler), true).ServeHTTP(out, req)
	var minted struct {
		ID       string `json:"id"`
		PublicID string `json:"public_id"`
		Token    string `json:"token"`
	}
	if out.Code != 201 || json.Unmarshal(out.Body.Bytes(), &minted) != nil {
		t.Fatal("key mint failed")
	}
	if publicID, ok := identity.ParseAccessToken(minted.Token); !ok || publicID != minted.PublicID {
		t.Fatal("invalid minted key format")
	}
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record, ok := accessFrom(r.Context())
		if !ok || record.ID != minted.ID || record.Owner != "alice" || record.PublicID != minted.PublicID || record.SecretHash != "" {
			t.Error("incorrect authenticated access record")
		}
		w.WriteHeader(204)
	})
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no fallback", 401) })
	for _, handler := range []http.Handler{accounts.protect(probe, false), manager.keys(probe, false, fallback)} {
		for _, token := range []string{minted.Token, minted.Token[:80], minted.Token + "=", "mcpw_" + identity.NewPublicID() + minted.Token[37:]} {
			request := httptest.NewRequest("POST", "http://localhost/mcp", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			want := 401
			if token == minted.Token {
				want = 204
			}
			if response.Code != want {
				t.Fatalf("authentication status: %d, want %d", response.Code, want)
			}
		}
	}
	// Even a matching full-token verifier cannot authenticate a mismatched public ID.
	otherToken, _ := identity.NewAccessToken()
	if err := store.AddAccess(catalog.AccessRecord{ID: "mismatched", Owner: "alice", PublicID: identity.NewPublicID(), Name: "Mismatch", Kind: "api_key", Role: "client", SecretHash: tokenHash(otherToken)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := authenticateAPIKey(store, otherToken); ok {
		t.Fatal("public ID mismatch accepted")
	}
	for _, record := range store.AccessList("alice") {
		if record.SecretHash != "" {
			t.Fatal("verifier exposed")
		}
	}
}

func TestLegacyAuthenticationHashesDoNotEnterAuditActor(t *testing.T) {
	for _, record := range []catalog.AccessRecord{
		{ID: "operator:" + tokenHash("synthetic"), Owner: "local", Kind: "operator", Role: "admin"},
		{ID: tokenHash("synthetic-oauth"), Owner: "external-owner", Kind: "oauth", Role: "client"},
	} {
		ctx := withAccess(context.Background(), record)
		actor, ok := identity.ActorFrom(ctx)
		if !ok || actor.AccessID != "" || actor.PublicID != "" || actor.Kind != record.Kind {
			t.Fatal("legacy verifier became an audit identifier")
		}
	}
}
