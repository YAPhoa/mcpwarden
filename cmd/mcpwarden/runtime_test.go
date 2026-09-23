package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type repositoryProbe struct {
	catalog.Repository
	listed bool
}

func (r *repositoryProbe) List(string) []catalog.Entry {
	r.listed = true
	return nil
}

func TestRuntimeUsesRepositoryBoundary(t *testing.T) {
	repository := &repositoryProbe{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol, err := policy.New(config.Policy{Default: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs := newRuntimes(ctx, config.Config{}, pol, auditLog, repository, logger)
	defer rs.close()
	rs.get("alice")
	if !repository.listed {
		t.Fatal("runtime bypassed repository boundary")
	}
}

func privateClient(token string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		copyReq := r.Clone(r.Context())
		copyReq.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultTransport.RoundTrip(copyReq)
	})}
}

func upstreamForUser(t *testing.T, toolName, apiKey string) (*mcp.Server, *httptest.Server) {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: toolName, Version: "1"}, nil)
	s.AddTool(&mcp.Tool{Name: toolName, InputSchema: json.RawMessage(`{"type":"object"}`)}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: toolName}}}, nil
	})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	return s, httpServer
}

func TestPersonalUpstreamsAndStoredDiscovery(t *testing.T) {
	aliceUpstream, aliceHTTP := upstreamForUser(t, "alice_only", "alice-key")
	defer aliceHTTP.Close()
	_, bobHTTP := upstreamForUser(t, "bob_only", "bob-key")
	defer bobHTTP.Close()
	path := t.TempDir() + "/connections.enc"
	store, err := catalog.Open(path, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol, err := policy.New(config.Policy{Default: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs := newRuntimes(ctx, config.Config{}, pol, auditLog, store, logger)
	defer rs.close()
	for _, e := range []catalog.Entry{
		{Owner: "alice", Name: "remote", URL: aliceHTTP.URL, Headers: map[string]string{"X-Api-Key": "alice-key"}, CallTimeout: "1s"},
		{Owner: "bob", Name: "remote", URL: bobHTTP.URL, Headers: map[string]string{"X-Api-Key": "bob-key"}, CallTimeout: "1s"},
	} {
		if err := rs.add(e); err != nil {
			t.Fatal(err)
		}
	}
	verifier := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		if token != "alice" && token != "bob" {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: token, Scopes: []string{"mcp:tools"}, Expiration: time.Now().Add(time.Hour)}, nil
	}
	protect := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{Scopes: []string{"mcp:tools"}})
	mux := http.NewServeMux()
	mux.Handle("/mcp", protect(mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return rs.get(requestOwner(r)).proxy.Server
	}, nil)))
	mux.Handle("/api/providers", protect(http.HandlerFunc(rs.providers)))
	mux.Handle("/api/providers/", protect(http.HandlerFunc(rs.providerTools)))
	server := httptest.NewServer(mux)
	defer server.Close()
	clients := map[string]*mcp.ClientSession{}
	listChanged := make(chan struct{}, 8)
	for _, owner := range []string{"alice", "bob"} {
		client := mcp.NewClient(&mcp.Implementation{Name: owner, Version: "1"}, &mcp.ClientOptions{ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			if owner == "alice" {
				select {
				case listChanged <- struct{}{}:
				default:
				}
			}
		}})
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: privateClient(owner)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		clients[owner] = session
	}
	awaitRuntime(t, func() bool {
		return len(rs.get("alice").proxy.Registry.Names()) == 1 && len(rs.get("bob").proxy.Registry.Names()) == 1
	})
	for owner, want := range map[string]string{"alice": "remote__alice_only", "bob": "remote__bob_only"} {
		list, err := listUpstreamTools(ctx, clients[owner])
		if err != nil || len(list.Tools) != 1 || list.Tools[0].Name != want {
			t.Fatalf("%s tools: %+v, %v", owner, list, err)
		}
		res, err := clients[owner].CallTool(ctx, &mcp.CallToolParams{Name: want, Arguments: map[string]any{}})
		if err != nil || res.IsError {
			t.Fatalf("%s call: %+v, %v", owner, res, err)
		}
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/providers/bob/tools?search=bob", nil)
	request.Header.Set("Authorization", "Bearer alice")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("Alice could query Bob's provider: %d", response.StatusCode)
	}
	aliceUpstream.AddTool(&mcp.Tool{Name: "new_tool", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	if err := rs.get("alice").manager.Refresh(ctx, "remote"); err != nil {
		t.Fatal(err)
	}
	awaitRuntime(t, func() bool {
		_, ok := rs.get("alice").proxy.Registry.Lookup("remote__new_tool")
		return ok
	})
	if _, ok := rs.get("bob").proxy.Registry.Lookup("remote__new_tool"); ok {
		t.Fatal("Alice's discovery reached Bob")
	}
	if cached, ok := store.Discovery("alice", "remote"); !ok || len(cached.Tools) != 2 {
		t.Fatalf("discovery was not saved: %+v, %v", cached, ok)
	}
	apiRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/providers/remote/tools?search=new", nil)
	apiRequest.Header.Set("Authorization", "Bearer alice")
	apiResponse, err := http.DefaultClient.Do(apiRequest)
	if err != nil {
		t.Fatal(err)
	}
	var found []map[string]any
	if err := json.NewDecoder(apiResponse.Body).Decode(&found); err != nil {
		t.Fatal(err)
	}
	apiResponse.Body.Close()
	if len(found) != 1 || !strings.Contains(found[0]["name"].(string), "new_tool") {
		t.Fatalf("provider search: %+v", found)
	}
	for len(listChanged) > 0 {
		<-listChanged
	}
	visibilityRequest, _ := http.NewRequest(http.MethodPut, server.URL+"/api/providers/remote/visibility", strings.NewReader(`{"mode":"selected","enabled":["remote__alice_only"]}`))
	visibilityRequest.Header.Set("Authorization", "Bearer alice")
	visibilityRequest.Header.Set("Content-Type", "application/json")
	visibilityResponse, err := http.DefaultClient.Do(visibilityRequest)
	if err != nil {
		t.Fatal(err)
	}
	visibilityResponse.Body.Close()
	if visibilityResponse.StatusCode != http.StatusOK {
		t.Fatalf("set visibility: %d", visibilityResponse.StatusCode)
	}
	select {
	case <-listChanged:
	case <-time.After(5 * time.Second):
		t.Fatal("visibility change did not notify downstream")
	}
	aliceList, err := listUpstreamTools(ctx, clients["alice"])
	if err != nil || len(aliceList.Tools) != 1 || aliceList.Tools[0].Name != "remote__alice_only" {
		t.Fatalf("selected tools: %+v, %v", aliceList, err)
	}
	bobList, err := listUpstreamTools(ctx, clients["bob"])
	if err != nil || len(bobList.Tools) != 1 || bobList.Tools[0].Name != "remote__bob_only" {
		t.Fatalf("Bob's tools changed: %+v, %v", bobList, err)
	}
	denied, err := clients["alice"].CallTool(ctx, &mcp.CallToolParams{Name: "remote__new_tool", Arguments: map[string]any{}})
	if err != nil || !denied.IsError {
		t.Fatalf("hidden tool call: %+v, %v", denied, err)
	}

	original := rs.get("alice").proxy.ToolItems("remote", "alice_only")[0]
	if original.ID == "" || original.DisplayName != "alice_only" || original.UpstreamID != store.List("alice")[0].ID {
		t.Fatal("tool metadata missing stable identity")
	}
	setEnabled := func(enabled bool) {
		t.Helper()
		body := `{"enabled":false}`
		if enabled {
			body = `{"enabled":true}`
		}
		req, _ := http.NewRequest(http.MethodPut, server.URL+"/api/providers/remote/enabled", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer alice")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("toggle: %d", res.StatusCode)
		}
	}
	setEnabled(false)
	disabledList, err := listUpstreamTools(ctx, clients["alice"])
	if err != nil || len(disabledList.Tools) != 0 {
		t.Fatal("disabled provider still discoverable")
	}
	blocked, err := clients["alice"].CallTool(ctx, &mcp.CallToolParams{Name: "remote__alice_only", Arguments: map[string]any{}})
	if err != nil || !blocked.IsError {
		t.Fatal("disabled provider allowed call")
	}
	if rs.get("alice").manager.States()[0].Enabled {
		t.Fatal("connection not disabled")
	}
	if !rs.get("bob").manager.Ready() {
		t.Fatal("disabling Alice affected Bob")
	}
	if len(rs.get("alice").proxy.ToolItems("remote", "")) != 2 {
		t.Fatal("disabled inventory lost")
	}
	setEnabled(true)
	awaitRuntime(t, func() bool { e, _ := rs.get("alice").proxy.Registry.Lookup("remote__alice_only"); return e.Healthy })
	restoredList, err := listUpstreamTools(ctx, clients["alice"])
	if err != nil || len(restoredList.Tools) != 1 || restoredList.Tools[0].Name != "remote__alice_only" {
		t.Fatal("reenabling lost selection")
	}
	if rs.get("alice").proxy.ToolItems("remote", "alice_only")[0].ID != original.ID {
		t.Fatal("toggle changed UUID")
	}
	setEnabled(false)
	rs.close()
	aliceHTTP.Close()
	reopened, err := catalog.Open(path, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	cacheOnly := newRuntimes(ctx, config.Config{}, pol, auditLog, reopened, logger)
	defer cacheOnly.close()
	if cacheOnly.get("alice").manager.States()[0].Enabled {
		t.Fatal("disabled provider restarted")
	}
	if cacheOnly.get("alice").proxy.ToolItems("remote", "alice_only")[0].ID != original.ID {
		t.Fatal("restart changed tool UUID")
	}
	entry, ok := cacheOnly.get("alice").proxy.Registry.Lookup("remote__new_tool")
	if !ok || entry.Healthy {
		t.Fatalf("cached discovery missing or incorrectly healthy: %+v, %v", entry, ok)
	}
	if cacheOnly.get("alice").proxy.ToolItems("remote", "new")[0].Visible {
		t.Fatal("visibility setting was not restored")
	}
}

func awaitRuntime(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func listUpstreamTools(ctx context.Context, session *mcp.ClientSession) (*mcp.ListToolsResult, error) {
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		return result, err
	}
	tools := result.Tools[:0]
	for _, tool := range result.Tools {
		if strings.Contains(tool.Name, "__") {
			tools = append(tools, tool)
		}
	}
	result.Tools = tools
	return result, nil
}
