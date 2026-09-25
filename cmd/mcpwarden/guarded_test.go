package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/secret"
)

// headerUpstream is a real MCP server that records which credential reached
// it. It serves the fixture's "search" and "write" tools.
type headerUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	seen   map[string]int // Authorization value -> requests
	calls  atomic.Int32
}

func newHeaderUpstream(t *testing.T) *headerUpstream {
	u := &headerUpstream{seen: map[string]int{}}
	s := mcp.NewServer(&mcp.Implementation{Name: "remote", Version: "1"}, nil)
	for _, name := range []string{"search", "write"} {
		s.AddTool(&mcp.Tool{Name: name, Description: "Synthetic " + name, InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			u.calls.Add(1)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "upstream " + name}}}, nil
		})
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen[r.Header.Get("Authorization")]++
		u.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *headerUpstream) requests(value string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.seen[value]
}

// guardedGateway is the gateway's runtime and MCP endpoint in client_release
// mode, wired as run() wires them.
type guardedGateway struct {
	rs      *runtimes
	server  *httptest.Server
	history audit.Store
}

func (f *ownerFixture) guardedGateway() *guardedGateway {
	f.t.Helper()
	cfg := f.cfg
	security := *cfg.OwnerSecurity
	security.CustodyMode = config.CustodyClientRelease
	cfg.OwnerSecurity = &security
	pol, _ := policy.New(config.Policy{Default: "allow"})
	var history audit.Store
	if f.pg != nil {
		history = f.pg.history
	} else {
		log, err := audit.Open(f.t.TempDir() + "/audit.jsonl")
		if err != nil {
			f.t.Fatal(err)
		}
		f.t.Cleanup(func() { _ = log.Close() })
		history = log
	}
	rs := newRuntimes(f.t.Context(), cfg, pol, history, f.store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rs.guarded = &guardedCustody{api: f.api, store: f.store, history: history}
	f.api.onCredential = rs.converted
	mux := http.NewServeMux()
	mux.Handle("/mcp", f.accounts.protect(rs.access.bindMCP(mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return rs.get(requestOwner(r)).proxy.Server
	}, nil)), false))
	mux.Handle("/api/discovery/", f.accounts.protect(http.HandlerFunc(rs.discovery), true, true))
	g := &guardedGateway{rs: rs, server: httptest.NewServer(mux), history: history}
	f.t.Cleanup(func() { g.server.Close(); rs.close() })
	return g
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func (g *guardedGateway) client(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1"}, nil)
	s, err := c.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: g.server.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func callText(t *testing.T, s *mcp.ClientSession, tool string) (string, bool) {
	t.Helper()
	res, err := s.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"repo": "example"}})
	if err != nil {
		t.Fatal(err)
	}
	return res.Content[0].(*mcp.TextContent).Text, res.IsError
}

func listed(t *testing.T, s *mcp.ClientSession) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	res, err := s.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		out[tool.Name] = true
	}
	return out
}

// TestGuardedHeaderExecution drives one header connector from legacy custody
// through conversion, an access window, a restart and credential deletion.
// After conversion no request may carry the server-held header.
func TestGuardedHeaderExecution(t *testing.T) {
	upstream := newHeaderUpstream(t)
	f := newOwnerFixture(t, upstream.server.URL+"/mcp")
	f.destination = &secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: f.entry.URL, HeaderNames: []string{"authorization"}, Network: "private", PrivatePrefixes: []string{"127.0.0.1/32"}, AllowLoopbackHTTP: true}
	alice := f.owners["alice"]
	const legacy, owner = "Bearer legacy-synthetic", "Bearer SYNTHETIC_OWNER_TOKEN"

	// Without a vault credential the connector stays on legacy custody.
	g := f.guardedGateway()
	awaitRuntime(t, func() bool { e, ok := g.rs.get(alice).proxy.Registry.Lookup("remote__search"); return ok && e.Healthy })
	agent := g.client(t, f.keys["agent"])
	if text, failed := callText(t, agent, "remote__search"); failed || text != "upstream search" || upstream.requests(legacy) == 0 {
		t.Fatalf("legacy call failed: %q", text)
	}

	// Storing a vault credential converts the connector at once.
	_, record := f.provision("none")
	legacyRequests, calls := upstream.requests(legacy), upstream.calls.Load()
	states := g.rs.get(alice).manager.States()
	if len(states) != 1 || states[0].Custody != "vault" || states[0].Healthy {
		t.Fatalf("connector not moved to vault custody: %+v", states)
	}
	if !listed(t, agent)["remote__search"] {
		t.Fatal("locked connector's cached tools left tools/list")
	}
	if text, failed := callText(t, agent, "remote__search"); !failed || !strings.HasPrefix(text, "MCPWARDEN_LEASE_REQUIRED") {
		t.Fatalf("locked call: %q", text)
	}
	refresh := httptest.NewRequest(http.MethodPost, "/api/discovery/remote/refresh", nil)
	refresh.Header.Set("Authorization", "Bearer "+f.keys["agent"])
	w := httptest.NewRecorder()
	g.server.Config.Handler.ServeHTTP(w, refresh)
	if w.Code != http.StatusConflict {
		t.Fatalf("legacy refresh of a vault connector: %d", w.Code)
	}

	// An owner-activated window runs the call with the vault header only.
	request := f.requestAccess("agent", record.CredentialID)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, nil)
	if text, failed := callText(t, agent, "remote__search"); failed || text != "upstream search" {
		t.Fatalf("leased call: %q", text)
	}
	if upstream.requests(owner) == 0 || upstream.calls.Load() != calls+1 {
		t.Fatal("leased call did not reach the upstream with the vault credential")
	}
	// The window's scope names one tool; another tool stays locked.
	if _, failed := callText(t, agent, "remote__write"); !failed {
		t.Fatal("call outside the window's scope ran")
	}
	rows, _, _, _, err := g.history.QueryHistoryPerformance(audit.HistoryFilter{Owner: alice, Page: 1, Size: 25})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.EventType == audit.DispatchCompleted && r.Status == "ok" && r.LeaseID != "" && r.CredentialID == record.CredentialID {
			found = true
		}
	}
	if !found {
		t.Fatal("leased call missing from call history")
	}

	// A disabled connector's tools leave tools/list.
	if err := f.store.SetProviderEnabled(alice, "remote", false); err != nil {
		t.Fatal(err)
	}
	if listed(t, agent)["remote__search"] {
		t.Fatal("disabled vault connector still listed")
	}
	if err := f.store.SetProviderEnabled(alice, "remote", true); err != nil {
		t.Fatal(err)
	}

	// A restart starts locked: tools are listed from the cache, nothing
	// connects in the background and the old window does not come back.
	f.restart()
	g = f.guardedGateway()
	agent = g.client(t, f.keys["agent"])
	if states := g.rs.get(alice).manager.States(); len(states) != 1 || states[0].Custody != "vault" {
		t.Fatalf("restart put the connector back on legacy custody: %+v", states)
	}
	if !listed(t, agent)["remote__search"] {
		t.Fatal("restart dropped cached tools")
	}
	if text, failed := callText(t, agent, "remote__search"); !failed || !strings.HasPrefix(text, "MCPWARDEN_LEASE_REQUIRED") {
		t.Fatalf("call after restart: %q", text)
	}

	// Deleting the vault credential leaves a tombstone that stays locked.
	f.expect(req{method: "DELETE", path: "/api/vault/credentials/" + record.CredentialID, user: "alice", body: encode(map[string]any{"expected": map[string]string{"epoch": "1", "revision": "1"}})}, 200, nil)
	if text, failed := callText(t, agent, "remote__search"); !failed || !strings.HasPrefix(text, "MCPWARDEN_LEASE_REQUIRED") {
		t.Fatalf("call after deletion: %q", text)
	}
	if upstream.requests(legacy) != legacyRequests {
		t.Fatal("the server-held header reached the upstream after conversion")
	}
}

// Stdio mode never opens the owner security executor, so it must refuse a
// mode whose converted connectors would otherwise run on legacy custody.
func TestStdioRefusesClientRelease(t *testing.T) {
	t.Setenv("TEST_GUARDED_KEY", "synthetic-key")
	t.Setenv("TEST_GUARDED_DSN", "postgres://runtime@127.0.0.1/unused")
	dir := t.TempDir()
	path := dir + "/config.yaml"
	body := "accounts: {}\nmanaged_upstreams:\n  path: " + dir + "/catalog.enc\n  key_env: TEST_GUARDED_KEY\naudit:\n  path: " + dir + "/audit.jsonl\nowner_security:\n  database_url_env: TEST_GUARDED_DSN\n  custody_mode: client_release\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(path, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "--stdio") {
		t.Fatalf("stdio accepted client_release: %v", err)
	}
}
