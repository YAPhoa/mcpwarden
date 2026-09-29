package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

type listFunc func(r *http.Request, cursor string, w http.ResponseWriter, id json.RawMessage)

// rawUpstream answers MCP JSON-RPC by hand, so a probe can return lists an SDK
// server would never send.
type rawUpstream struct {
	server  *httptest.Server
	mu      sync.Mutex
	methods []string
	calls   atomic.Int32
}

func newRawUpstream(t *testing.T, list listFunc) *rawUpstream {
	u := &rawUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor          string `json:"cursor"`
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"params"`
		}
		if json.Unmarshal(body, &msg) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		u.mu.Lock()
		u.methods = append(u.methods, msg.Method)
		u.mu.Unlock()
		if msg.Method == "tools/call" {
			u.calls.Add(1)
		}
		if len(msg.ID) == 0 || msg.Method == "" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		switch msg.Method {
		case "initialize":
			writeRPC(w, msg.ID, map[string]any{"protocolVersion": msg.Params.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "raw", "version": "1"}})
		case "tools/list":
			list(r, msg.Params.Cursor, w, msg.ID)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, msg.ID)
		}
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *rawUpstream) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.methods...)
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any) {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func rawTool(name string) map[string]any {
	return map[string]any{"name": name, "description": "Synthetic " + name, "inputSchema": map[string]any{"type": "object"}}
}

func rawTools(prefix string, n int) []any {
	out := make([]any, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, rawTool(fmt.Sprintf("%s%d", prefix, i)))
	}
	return out
}

// inspectProbe is an owner fixture with one vault credential and helpers for
// setup windows.
type inspectProbe struct {
	f            *ownerFixture
	g            *guardedGateway
	credentialID string
}

func newInspectProbe(t *testing.T, url string) *inspectProbe {
	f := newOwnerFixture(t, url)
	f.destination = &secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: f.entry.URL, HeaderNames: []string{"authorization"}, Network: "private", PrivatePrefixes: []string{"127.0.0.1/32"}, AllowLoopbackHTTP: true}
	g := f.guardedGateway()
	_, record := f.provision("none")
	return &inspectProbe{f: f, g: g, credentialID: record.CredentialID}
}

func (p *inspectProbe) window() string {
	f := p.f
	f.t.Helper()
	var request requestView
	f.expect(req{method: "POST", path: "/api/access-requests", user: "alice", body: encode(map[string]any{"purpose": "setup_discovery", "credential_id": p.credentialID, "duration_seconds": 60})}, 201, &request)
	var window leaseView
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, &window)
	return window.LeaseID
}

func (p *inspectProbe) inspect(id string) *httptest.ResponseRecorder {
	return p.f.do(req{method: "POST", path: "/api/leases/" + id + "/discover", user: "alice", body: "{}"})
}

func (p *inspectProbe) source(id string) string {
	for _, e := range p.f.events("alice") {
		if e.LeaseID == id && e.Type == "lease.revoked" {
			return e.Source
		}
	}
	return ""
}

func (p *inspectProbe) state(id string) string {
	var windows []leaseView
	p.f.expect(req{path: "/api/leases?include=ended", user: "alice"}, 200, &windows)
	for _, l := range windows {
		if l.LeaseID == id {
			return l.State
		}
	}
	return "missing"
}

func (p *inspectProbe) saved() []string {
	d, _ := p.f.store.Discovery(p.f.owners["alice"], "remote")
	names := []string{}
	for _, t := range d.Tools {
		names = append(names, t.Name)
	}
	return names
}

func (p *inspectProbe) csrf() string {
	out := p.f.do(req{path: "/api/security/csrf", user: "alice"})
	var token struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(out.Body.Bytes(), &token)
	return token.Token
}

// discoverWith sends the discover request with a context the caller controls,
// as a browser tab would.
func (p *inspectProbe) discoverWith(ctx context.Context, id string) int {
	hr := httptest.NewRequest(http.MethodPost, panelOrigin+"/api/leases/"+id+"/discover", strings.NewReader("{}")).WithContext(ctx)
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Origin", panelOrigin)
	hr.AddCookie(&http.Cookie{Name: sessionCookie, Value: p.f.cookies["alice"]})
	hr.Header.Set("X-MCPWarden-Request", "browser")
	hr.Header.Set("X-CSRF-Token", p.csrf())
	w := httptest.NewRecorder()
	p.f.mux.ServeHTTP(w, hr)
	return w.Code
}

// TestConnectAndInspectBounds sends lists an SDK server would never send. Each
// bound, and each tool the gateway could not register, fails the whole run with
// 502, ends the window with setup_failed and saves nothing; no tool is called.
func TestConnectAndInspectBounds(t *testing.T) {
	paged := func(pages int) listFunc {
		return func(_ *http.Request, cursor string, w http.ResponseWriter, id json.RawMessage) {
			k := 0
			fmt.Sscanf(cursor, "p%d", &k)
			next := ""
			if k+1 < pages {
				next = fmt.Sprintf("p%d", k+1)
			}
			writeRPC(w, id, map[string]any{"tools": []any{rawTool(fmt.Sprintf("t%d", k))}, "nextCursor": next})
		}
	}
	one := func(tools ...any) listFunc {
		return func(_ *http.Request, _ string, w http.ResponseWriter, id json.RawMessage) {
			writeRPC(w, id, map[string]any{"tools": tools})
		}
	}
	var loops atomic.Int32
	big := func(n int) map[string]any {
		t := rawTool(fmt.Sprintf("big%d", loops.Add(1)))
		t["description"] = strings.Repeat("x", n)
		return t
	}
	cases := []struct {
		name string
		list listFunc
		want int
	}{
		{"duplicate name", one(rawTool("a"), rawTool("a")), 502},
		{"empty name", one(rawTool(""), rawTool("a")), 502},
		{"256 tools", one(rawTools("t", 256)...), 200},
		{"257 tools", one(rawTools("t", 257)...), 502},
		{"257 tools over two pages", func(_ *http.Request, cursor string, w http.ResponseWriter, id json.RawMessage) {
			if cursor == "" {
				writeRPC(w, id, map[string]any{"tools": rawTools("a", 200), "nextCursor": "second"})
				return
			}
			writeRPC(w, id, map[string]any{"tools": rawTools("b", 57)})
		}, 502},
		{"16 pages", paged(16), 200},
		{"17 pages", paged(17), 502},
		{"repeated cursor", func(_ *http.Request, _ string, w http.ResponseWriter, id json.RawMessage) {
			writeRPC(w, id, map[string]any{"tools": []any{rawTool(fmt.Sprintf("loop%d", loops.Add(1)))}, "nextCursor": "same"})
		}, 502},
		{"over 4 MiB of definitions", one(big(2200<<10), big(2200<<10)), 502},
		{"just under 4 MiB", one(big(3900 << 10)), 200},
		{"null entries", one(nil, rawTool("ok")), 200},
		{"no input schema", one(rawTool("ok"), map[string]any{"name": "broken"}), 502},
		{"null input schema", one(rawTool("ok"), map[string]any{"name": "broken", "inputSchema": nil}), 502},
		{"string input schema", one(rawTool("ok"), map[string]any{"name": "broken", "inputSchema": map[string]any{"type": "string"}}), 502},
		{"untyped input schema", one(rawTool("ok"), map[string]any{"name": "broken", "inputSchema": map[string]any{}}), 502},
		{"name the registry cannot expose", one(rawTool("files.read"), rawTool("ok")), 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := newRawUpstream(t, c.list)
			p := newInspectProbe(t, u.server.URL+"/mcp")
			before := p.saved()
			id := p.window()
			w := p.inspect(id)
			after := p.saved()
			src := p.source(id)
			if w.Code != c.want {
				t.Fatalf("status %d, want %d: %s", w.Code, c.want, w.Body.String())
			}
			if c.want == 502 && (len(after) != len(before) || src != "setup_failed") {
				t.Fatalf("failed run changed the saved tools or kept its window: saved %v source %q", after, src)
			}
			if c.want == 200 && src != "setup_completed" {
				t.Fatalf("source %q", src)
			}
			if c.name == "name the registry cannot expose" {
				var result struct {
					ToolCount int      `json:"tool_count"`
					Tools     []string `json:"tools"`
					Skipped   []string `json:"skipped"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				exposed := listed(t, p.g.client(t, p.f.keys["agent"]))
				if result.ToolCount != 1 || !slices.Equal(result.Tools, []string{"ok"}) || !slices.Equal(result.Skipped, []string{"files.read"}) || !exposed["remote__ok"] || exposed["remote__files.read"] {
					t.Fatalf("route %+v, agent sees %v", result, exposed)
				}
			}
			if u.calls.Load() != 0 {
				t.Fatal("a tool was called")
			}
		})
	}
}

// TestConnectAndInspectClosedTab: a request cancelled during the list still
// ends the window with setup_failed, since reducing access is never lost to a
// closed tab.
func TestConnectAndInspectClosedTab(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	u := newRawUpstream(t, func(r *http.Request, _ string, w http.ResponseWriter, id json.RawMessage) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		writeRPC(w, id, map[string]any{"tools": []any{rawTool("late")}})
	})
	t.Cleanup(func() { close(release) })
	p := newInspectProbe(t, u.server.URL+"/mcp")
	id := p.window()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- p.discoverWith(ctx, id) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("tools/list never reached the upstream")
	}
	cancel()
	select {
	case code := <-done:
		if code != http.StatusBadGateway {
			t.Fatalf("cancelled discover answered %d", code)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("discover did not return after the tab closed")
	}
	if p.state(id) == "active" || p.source(id) != "setup_failed" {
		t.Fatalf("a closed tab kept the window: state %q source %q", p.state(id), p.source(id))
	}
}

// TestConnectAndInspectStoppedDuringRun: Stop during the list ends the run as a
// stopped window (409), not as an unreachable connector, and saves nothing.
func TestConnectAndInspectStoppedDuringRun(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	u := newRawUpstream(t, func(r *http.Request, _ string, w http.ResponseWriter, id json.RawMessage) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		writeRPC(w, id, map[string]any{"tools": []any{rawTool("late")}})
	})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	p := newInspectProbe(t, u.server.URL+"/mcp")
	before := len(p.saved())
	id := p.window()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- p.inspect(id) }()
	<-entered
	p.f.expect(req{method: "DELETE", path: "/api/leases/" + id, user: "alice"}, 204, nil)
	once.Do(func() { close(release) })
	w := <-done
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"stale"`) || p.state(id) == "active" || len(p.saved()) != before {
		t.Fatalf("stopped during the run: %d %s; window %q, saved %v", w.Code, w.Body.String(), p.state(id), p.saved())
	}
}

// TestConnectAndInspectKeepsToolWindows: saving a discovery does not end tool
// windows; a changed definition makes the old window stale for that tool, and
// the call is refused without reaching the upstream.
func TestConnectAndInspectKeepsToolWindows(t *testing.T) {
	upstream := newHeaderUpstream(t)
	f := newOwnerFixture(t, upstream.server.URL+"/mcp")
	f.destination = &secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: f.entry.URL, HeaderNames: []string{"authorization"}, Network: "private", PrivatePrefixes: []string{"127.0.0.1/32"}, AllowLoopbackHTTP: true}
	g := f.guardedGateway()
	agent := g.client(t, f.keys["agent"])
	_, record := f.provision("none")
	request := f.requestAccess("agent", record.CredentialID)
	var window leaseView
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, &window)
	if text, failed := callText(t, agent, "remote__search"); failed {
		t.Fatalf("call before inspect: %q", text)
	}
	p := &inspectProbe{f: f, g: g, credentialID: record.CredentialID}
	upstream.mcp.AddTool(&mcp.Tool{Name: "deploy", Description: "Synthetic deploy", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deployed"}}}, nil
	})
	id := p.window()
	if w := p.inspect(id); w.Code != http.StatusOK {
		t.Fatalf("inspect: %d %s", w.Code, w.Body.String())
	}
	if text, failed := callText(t, agent, "remote__search"); failed || p.state(window.LeaseID) != "active" {
		t.Fatalf("an unchanged tool stopped working after an inspect: %q, window %q", text, p.state(window.LeaseID))
	}
	upstream.mcp.AddTool(&mcp.Tool{Name: "search", Description: "Synthetic search, now also deletes", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		upstream.calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "changed"}}}, nil
	})
	before := upstream.calls.Load()
	id = p.window()
	if w := p.inspect(id); w.Code != http.StatusOK {
		t.Fatalf("inspect: %d %s", w.Code, w.Body.String())
	}
	if text, failed := callText(t, agent, "remote__search"); !failed || !strings.HasPrefix(text, "MCPWARDEN_LEASE_REQUIRED") || upstream.calls.Load() != before {
		t.Fatalf("a changed definition ran under the old window: %q", text)
	}
}

// TestConnectAndInspectSaveRefused: a window stopped, or execution locked,
// after the list but before the save refuses the save in its transaction (409)
// and leaves the saved tools unchanged.
func TestConnectAndInspectSaveRefused(t *testing.T) {
	for _, how := range []string{"stopped", "execution locked"} {
		t.Run(how, func(t *testing.T) {
			u := newRawUpstream(t, func(_ *http.Request, _ string, w http.ResponseWriter, id json.RawMessage) {
				writeRPC(w, id, map[string]any{"tools": []any{rawTool("fresh")}})
			})
			p := newInspectProbe(t, u.server.URL+"/mcp")
			id := p.window()
			save := p.f.api.saveDiscovery
			p.f.api.saveDiscovery = func(owner, name, connectorID, leaseID string, tools []*mcp.Tool) error {
				if how == "stopped" {
					p.f.expect(req{method: "DELETE", path: "/api/leases/" + leaseID, user: "alice"}, 204, nil)
				} else {
					p.f.expect(req{method: "POST", path: "/api/vault/lock-execution", user: "alice", body: "{}"}, 204, nil)
				}
				return save(owner, name, connectorID, leaseID, tools)
			}
			before := p.saved()
			if w := p.inspect(id); w.Code != http.StatusConflict {
				t.Fatalf("refused save answered %d, want 409: %s", w.Code, w.Body.String())
			}
			if after := p.saved(); !slices.Equal(after, before) {
				t.Fatalf("a refused save changed the tools: %v", after)
			}
		})
	}
}

// TestUnregistrableToolIsSkipped: a no-auth connector whose upstream lists a
// tool the SDK server would refuse to register. The manager publishes it from
// its own goroutine, where a panic would stop the gateway; the runtime skips
// that tool and exposes the rest.
func TestUnregistrableToolIsSkipped(t *testing.T) {
	u := newRawUpstream(t, func(_ *http.Request, _ string, w http.ResponseWriter, id json.RawMessage) {
		writeRPC(w, id, map[string]any{"tools": []any{map[string]any{"name": "broken"}, rawTool("ok")}})
	})
	f := newOwnerFixture(t, "https://example.com/mcp")
	g := f.guardedGateway()
	if err := g.rs.add(catalog.Entry{Owner: f.owners["alice"], Name: "plain", URL: u.server.URL + "/mcp", AuthType: "none", CallTimeout: "30s"}); err != nil {
		t.Fatal(err)
	}
	agent := g.client(t, f.keys["agent"])
	deadline := time.Now().Add(10 * time.Second)
	for !listed(t, agent)["plain__ok"] {
		if time.Now().After(deadline) {
			t.Fatal("the connector's valid tool was never published")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if listed(t, agent)["plain__broken"] {
		t.Fatal("a tool without an input schema was published")
	}
}

// TestSetupPhaseForwardsOnlyListing posts through the setup material's
// credential transport directly: a tool call, an unknown method and a JSON-RPC
// response are refused before they reach the upstream, and the listing itself
// still works.
func TestSetupPhaseForwardsOnlyListing(t *testing.T) {
	u := newRawUpstream(t, func(_ *http.Request, _ string, w http.ResponseWriter, id json.RawMessage) {
		writeRPC(w, id, map[string]any{"tools": []any{rawTool("ok")}})
	})
	p := newInspectProbe(t, u.server.URL+"/mcp")
	refused := map[string]error{}
	p.f.api.discoverTools = func(ctx context.Context, material lease.Material) ([]*mcp.Tool, error) {
		handle := material.(*secret.Handle)
		for name, body := range map[string]string{
			"tools/call": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ok","arguments":{}}}`,
			"unknown":    `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}`,
			"response":   `{"jsonrpc":"2.0","id":"srv-1","result":{}}`,
		} {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, handle.Endpoint(), strings.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			res, err := handle.Client("").Do(req)
			if err == nil {
				res.Body.Close()
			}
			refused[name] = err
		}
		return upstream.DiscoverLeased(ctx, material)
	}
	id := p.window()
	if w := p.inspect(id); w.Code != http.StatusOK {
		t.Fatalf("inspect: %d %s", w.Code, w.Body.String())
	}
	for name, err := range refused {
		if !errors.Is(err, lease.ErrDenied) {
			t.Fatalf("%s through the setup phase: %v", name, err)
		}
	}
	if len(refused) != 3 || u.calls.Load() != 0 {
		t.Fatal("a tool call reached the upstream")
	}
	for _, method := range u.seen() {
		if !slices.Contains([]string{"server/discover", "initialize", "notifications/initialized", "tools/list"}, method) {
			t.Fatalf("the upstream saw %q", method)
		}
	}
}
