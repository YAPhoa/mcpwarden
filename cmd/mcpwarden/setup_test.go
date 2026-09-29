package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/secret"
)

// TestConnectAndInspect drives the owner's setup discovery against a real MCP
// upstream: a five-minute window only the owner's browser can request, start
// and run, one connection that lists tools and calls none, the save committed
// with the end of the window, and publication to the owner's runtime.
func TestConnectAndInspect(t *testing.T) {
	upstream := newHeaderUpstream(t)
	f := newOwnerFixture(t, upstream.server.URL+"/mcp")
	f.destination = &secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: f.entry.URL, HeaderNames: []string{"authorization"}, Network: "private", PrivatePrefixes: []string{"127.0.0.1/32"}, AllowLoopbackHTTP: true}
	alice := f.owners["alice"]
	const owner = "Bearer SYNTHETIC_OWNER_TOKEN"
	g := f.guardedGateway()
	agent := g.client(t, f.keys["agent"])
	_, record := f.provision("none")

	// A new upstream release adds a tool; nothing sees it until an inspect.
	upstream.mcp.AddTool(&mcp.Tool{Name: "deploy", Description: "Synthetic deploy", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		upstream.calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deployed"}}}, nil
	})
	refresh := httptest.NewRequest(http.MethodPost, "/api/discovery/remote/refresh", nil)
	refresh.Header.Set("Authorization", "Bearer "+f.keys["agent"])
	w := httptest.NewRecorder()
	g.server.Config.Handler.ServeHTTP(w, refresh)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Connect and inspect") {
		t.Fatalf("refresh of a vault connector: %d %s", w.Code, w.Body.String())
	}

	setup := func(extra map[string]any) map[string]any {
		body := map[string]any{"purpose": "setup_discovery", "credential_id": record.CredentialID, "duration_seconds": 300}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	// Keys cannot ask for, start or run a setup window.
	f.expect(req{method: "POST", path: "/api/access-requests", key: "agent", body: encode(setup(nil))}, 403, nil)
	f.expect(req{method: "POST", path: "/api/access-requests", key: "admin-agent", body: encode(setup(map[string]any{"requester_access_id": f.keyIDs["admin-agent"]}))}, 403, nil)
	// It names no tools or call budget and lasts at most five minutes.
	f.expect(req{method: "POST", path: "/api/access-requests", user: "alice", body: encode(setup(map[string]any{"duration_seconds": 301}))}, 400, nil)
	f.expect(req{method: "POST", path: "/api/access-requests", user: "alice", body: encode(setup(map[string]any{"max_calls": 1}))}, 400, nil)
	f.expect(req{method: "POST", path: "/api/access-requests", user: "alice", body: encode(setup(map[string]any{"tools": []map[string]any{{"tool_id": f.toolID}}}))}, 400, nil)

	start := func() leaseView {
		t.Helper()
		var request requestView
		f.expect(req{method: "POST", path: "/api/access-requests", user: "alice", body: encode(setup(nil))}, 201, &request)
		if request.Purpose != "setup_discovery" || len(request.Tools) != 0 || request.MaxCalls != nil || !request.Requester.Current {
			t.Fatalf("setup request: %+v", request)
		}
		var window leaseView
		f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, &window)
		if window.Purpose != "setup_discovery" || window.ExpiresAt.Sub(window.ActivatedAt).Seconds() != 300 || !window.Client.Current {
			t.Fatalf("setup window: %+v", window)
		}
		return window
	}
	window := start()
	// The window grants the agent nothing and dials nothing by itself.
	if text, failed := callText(t, agent, "remote__search"); !failed || !strings.HasPrefix(text, "MCPWARDEN_LEASE_REQUIRED") {
		t.Fatalf("call during a setup window: %q", text)
	}
	if upstream.total() != 0 {
		t.Fatal("a setup window dialed before the owner ran it")
	}
	discover := "/api/leases/" + window.LeaseID + "/discover"
	f.expect(req{method: "POST", path: discover, key: "agent", body: "{}"}, 403, nil)
	// Another account does not see the window at all.
	f.expect(req{method: "POST", path: discover, user: "bob", body: "{}"}, 409, nil)

	var result struct {
		Provider  string   `json:"provider"`
		ToolCount int      `json:"tool_count"`
		Tools     []string `json:"tools"`
	}
	f.expect(req{method: "POST", path: discover, user: "alice", body: "{}"}, 200, &result)
	if result.Provider != "remote" || result.ToolCount != 3 || !slices.Equal(result.Tools, []string{"deploy", "search", "write"}) {
		t.Fatalf("inspect result: %+v", result)
	}
	if upstream.calls.Load() != 0 || upstream.total() == 0 || upstream.total() != upstream.requests(owner) {
		t.Fatal("inspect called a tool or reached the upstream without the vault credential")
	}
	saved, ok := f.store.Discovery(alice, "remote")
	if !ok || len(saved.Tools) != 3 {
		t.Fatalf("discovery not saved: %+v", saved)
	}
	if !listed(t, agent)["remote__deploy"] {
		t.Fatal("inspected tools were not published to the owner's runtime")
	}
	ended := false
	for _, e := range f.events("alice") {
		ended = ended || e.LeaseID == window.LeaseID && e.Type == "lease.revoked" && e.Source == "setup_completed"
	}
	if !ended {
		t.Fatal("the inspect window did not end with its save")
	}
	f.expect(req{method: "POST", path: discover, user: "alice", body: "{}"}, 409, nil)
	if upstream.calls.Load() != 0 {
		t.Fatal("inspect called a tool")
	}

	// A failed inspect ends its window and keeps the saved tools.
	window = start()
	upstream.down.Store(true)
	var failure struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	f.expect(req{method: "POST", path: "/api/leases/" + window.LeaseID + "/discover", user: "alice", body: "{}"}, 502, &failure)
	upstream.down.Store(false)
	if failure.Error != "discovery_failed" || strings.Contains(failure.Message, "503") {
		t.Fatalf("failure response: %+v", failure)
	}
	failedEnd := false
	for _, e := range f.events("alice") {
		failedEnd = failedEnd || e.LeaseID == window.LeaseID && e.Type == "lease.revoked" && e.Source == "setup_failed"
	}
	if !failedEnd {
		t.Fatal("a failed inspect kept its window")
	}
	if kept, _ := f.store.Discovery(alice, "remote"); len(kept.Tools) != 3 {
		t.Fatal("a failed inspect changed the saved tools")
	}
	f.expect(req{method: "POST", path: "/api/leases/" + window.LeaseID + "/discover", user: "alice", body: "{}"}, 409, nil)
}
