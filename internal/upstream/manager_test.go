package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/config"
)

func TestStdioHelperProcess(t *testing.T) {
	if os.Getenv("MCPWARDEN_TEST_CHILD") != "1" {
		return
	}
	_ = os.WriteFile(os.Getenv("MCPWARDEN_TEST_PIDFILE"), []byte(strconv.Itoa(os.Getpid())), 0600)
	if f := os.Getenv("MCPWARDEN_TEST_ENVFILE"); f != "" {
		_ = os.WriteFile(f, []byte(strings.Join(os.Environ(), "\n")), 0600)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "helper", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(req.Params.Arguments)}}}, nil
	})
	_ = server.Run(context.Background(), &mcp.StdioTransport{})
	os.Exit(0)
}
func TestStdioChildTerminates(t *testing.T) {
	pidFile := t.TempDir() + "/pid"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New([]config.Upstream{{Name: "child", Transport: "stdio", Command: os.Args[0], Args: []string{"-test.run=TestStdioHelperProcess"}, Env: map[string]string{"MCPWARDEN_TEST_CHILD": "1", "MCPWARDEN_TEST_PIDFILE": pidFile}, Timeout: time.Second}}, logger, func(string, []*mcp.Tool, bool) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for !m.Ready() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !m.Ready() {
		m.Close()
		t.Fatal("child did not become ready")
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		m.Close()
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(b))
	if err != nil {
		m.Close()
		t.Fatal(err)
	}
	m.Close()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		err = syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child process %d remained after shutdown", pid)
}

func TestStdioChildEnvironment(t *testing.T) {
	t.Setenv("MCPWARDEN_TEST_SECRET", "must-not-leak")
	t.Setenv("LC_ALL", "C")
	t.Setenv("TZ", "UTC")
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New([]config.Upstream{{Name: "child", Transport: "stdio", Command: os.Args[0], Args: []string{"-test.run=TestStdioHelperProcess"}, Env: map[string]string{"MCPWARDEN_TEST_CHILD": "1", "MCPWARDEN_TEST_PIDFILE": dir + "/pid", "MCPWARDEN_TEST_ENVFILE": dir + "/env", "TZ": "Asia/Jakarta"}, Timeout: time.Second}}, logger, func(string, []*mcp.Tool, bool) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !m.Ready() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !m.Ready() {
		t.Fatal("child did not become ready")
	}
	b, err := os.ReadFile(dir + "/env")
	if err != nil {
		t.Fatal(err)
	}
	env := map[string][]string{}
	for _, kv := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = append(env[k], v)
	}
	if _, ok := env["MCPWARDEN_TEST_SECRET"]; ok {
		t.Fatal("stdio child inherited an unlisted gateway variable")
	}
	for k, want := range map[string]string{"PATH": os.Getenv("PATH"), "LC_ALL": "C", "TZ": "Asia/Jakarta", "MCPWARDEN_TEST_CHILD": "1"} {
		if got := env[k]; len(got) != 1 || got[0] != want {
			t.Fatalf("%s = %q, want exactly %q", k, got, want)
		}
	}
}
func TestHTTPRetryAfterStartupFailure(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "mock", Version: "1"}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}})
	server.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	m := New([]config.Upstream{{Name: "remote", Transport: "http", URL: "http://" + address, Timeout: time.Second}}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, []*mcp.Tool, bool) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.States()[0].Error != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m.Ready() || m.States()[0].Error == "" {
		t.Fatal("expected initial connection failure")
	}
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)}
	defer httpServer.Close()
	go func() { _ = httpServer.Serve(listener) }()
	deadline = time.Now().Add(5 * time.Second)
	for !m.Ready() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !m.Ready() {
		t.Fatalf("did not recover: %+v", m.States())
	}
}

func TestHTTPDisconnectAndReconnect(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "mock", Version: "1"}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}})
	server.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	httpServer := &http.Server{Handler: handler}
	go func() { _ = httpServer.Serve(listener) }()
	m := New([]config.Upstream{{Name: "remote", Transport: "http", URL: "http://" + address, Timeout: time.Second}}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, []*mcp.Tool, bool) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Close()
	waitFor(t, 5*time.Second, m.Ready)
	_ = httpServer.Close()
	waitFor(t, 5*time.Second, func() bool { return !m.Ready() })
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &http.Server{Handler: handler}
	defer restarted.Close()
	go func() { _ = restarted.Serve(listener) }()
	waitFor(t, 10*time.Second, m.Ready)
}
func waitFor(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestRefreshImmediatelyAfterEnable(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "slow", Version: "1"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			time.Sleep(40 * time.Millisecond)
		}
		handler.ServeHTTP(w, r)
	}))
	defer remote.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m := New([]config.Upstream{{Name: "remote", Transport: "http", URL: remote.URL, Disabled: true, Timeout: time.Second}}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, []*mcp.Tool, bool) {})
	m.Start(ctx)
	defer m.Close()
	for i := 0; i < 3; i++ {
		if err := m.SetEnabled("remote", true); err != nil {
			t.Fatal(err)
		}
		if err := m.Refresh(ctx, "remote"); err != nil {
			t.Fatalf("immediate refresh: %v", err)
		}
		if err := m.SetEnabled("remote", false); err != nil {
			t.Fatal(err)
		}
		if err := m.Refresh(ctx, "remote"); err == nil {
			t.Fatal("disabled refresh accepted")
		}
	}
}

// fakeToolServer serves echo tools over Streamable HTTP but answers
// tools/call for any name in raw with that literal result, as JSON or SSE.
func fakeToolServer(t *testing.T, sse bool, raw map[string]string) *httptest.Server {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	names := []string{"echo"}
	for name := range raw {
		names = append(names, name)
	}
	for _, name := range names {
		server.AddTool(&mcp.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
		})
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			_ = json.Unmarshal(body, &req)
			if result, ok := raw[req.Params.Name]; ok && req.Method == "tools/call" {
				msg := `{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + result + `}`
				if sse {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "event: message\r\ndata: "+msg+"\r\n\r\n")
				} else {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, msg)
				}
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(remote.Close)
	return remote
}

func startRemote(t *testing.T, url string) (*Manager, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	m := New([]config.Upstream{{Name: "remote", Transport: "http", URL: url, Timeout: time.Second}}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, []*mcp.Tool, bool) {})
	m.Start(ctx)
	t.Cleanup(m.Close)
	waitFor(t, 5*time.Second, m.Ready)
	return m, ctx
}

func TestNonArrayToolContentIsWrapped(t *testing.T) {
	for _, sse := range []bool{false, true} {
		remote := fakeToolServer(t, sse, map[string]string{
			"authorize": `{"content":"User is already authorized."}`,
			"single":    `{"content":{"type":"text","text":"one"},"isError":true}`,
		})
		m, ctx := startRemote(t, remote.URL)
		for name, want := range map[string]string{"authorize": "User is already authorized.", "single": "one"} {
			result, err := m.Call(ctx, "remote", name, map[string]any{})
			if err != nil {
				t.Fatalf("sse=%v %s: %v", sse, name, err)
			}
			if len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != want {
				t.Fatalf("sse=%v %s: content %#v", sse, name, result.Content)
			}
			if result.IsError != (name == "single") {
				t.Fatalf("sse=%v %s: isError %v", sse, name, result.IsError)
			}
		}
		if result, err := m.Call(ctx, "remote", "echo", map[string]any{}); err != nil || result.Content[0].(*mcp.TextContent).Text != "ok" {
			t.Fatalf("sse=%v normal result changed: %v", sse, err)
		}
	}
}

func TestNormalizeToolResultLeavesOtherShapes(t *testing.T) {
	for _, msg := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"x"}]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":42}}`,
		`{"jsonrpc":"2.0","id":1,"result":{}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"boom"}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"content":"x"}}`,
		`not json`,
	} {
		if out, changed := normalizeToolResult([]byte(msg)); changed || string(out) != msg {
			t.Fatalf("rewrote %s to %s", msg, out)
		}
	}
	out, changed := normalizeToolResult([]byte(`{"jsonrpc":"2.0","id":"a","result":{"content":"hi \u003c","structuredContent":{"n":1.50}}}`))
	if !changed {
		t.Fatal("string content not rewritten")
	}
	var got struct {
		ID     string `json:"id"`
		Result struct {
			Content    []map[string]string `json:"content"`
			Structured json.RawMessage     `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &got); err != nil || got.ID != "a" || len(got.Result.Content) != 1 || got.Result.Content[0]["type"] != "text" || got.Result.Content[0]["text"] != "hi <" || string(got.Result.Structured) != `{"n":1.50}` {
		t.Fatalf("unexpected rewrite %s", out)
	}
}

// TestStdioNonArrayToolContentIsWrapped drives the stdio connection wrapper
// with a hand-written peer, because the SDK server cannot emit this shape.
func TestStdioNonArrayToolContentIsWrapped(t *testing.T) {
	clientR, serverW := io.Pipe()
	serverR, clientW := io.Pipe()
	go func() {
		dec := json.NewDecoder(serverR)
		for {
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if dec.Decode(&req) != nil {
				serverW.Close()
				return
			}
			var result string
			switch req.Method {
			case "initialize":
				result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"raw","version":"1"}}`
			case "tools/call":
				result = `{"content":"User is already authorized."}`
			case "ping":
				result = `{"content":"not a tool result"}`
			default:
				if len(req.ID) > 0 {
					_, _ = io.WriteString(serverW, `{"jsonrpc":"2.0","id":`+string(req.ID)+`,"error":{"code":-32601,"message":"method not found"}}`+"\n")
				}
				continue
			}
			_, _ = io.WriteString(serverW, `{"jsonrpc":"2.0","id":`+string(req.ID)+`,"result":`+result+"}\n")
		}
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, compatTransport{&mcp.IOTransport{Reader: clientR, Writer: clientW}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "authorize", Arguments: map[string]any{}})
	if err != nil || len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != "User is already authorized." {
		t.Fatalf("call: %v %#v", err, result)
	}
	if err := session.Ping(ctx, nil); err != nil {
		t.Fatalf("non tools/call response affected: %v", err)
	}
}

func TestMalformedToolResponseDoesNotDisconnect(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "malformed", Version: "1"}, nil)
	for _, name := range []string{"bad", "echo"} {
		server.AddTool(&mcp.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
		})
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			var req struct {
				ID     any    `json:"id"`
				Method string `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			_ = json.Unmarshal(body, &req)
			if req.Method == "tools/call" && req.Params.Name == "bad" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"content": 42}})
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	defer remote.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m := New([]config.Upstream{{Name: "remote", Transport: "http", URL: remote.URL, Timeout: time.Second}}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, []*mcp.Tool, bool) {})
	m.Start(ctx)
	defer m.Close()
	waitFor(t, 5*time.Second, m.Ready)
	m.items["remote"].mu.RLock()
	session := m.items["remote"].session
	m.items["remote"].mu.RUnlock()
	if _, err := m.Call(ctx, "remote", "bad", map[string]any{}); err == nil {
		t.Fatal("malformed result accepted")
	}
	for i := 0; i < 5; i++ {
		time.Sleep(20 * time.Millisecond)
		result, err := m.Call(ctx, "remote", "echo", map[string]any{})
		if err != nil || result.IsError {
			t.Fatalf("healthy call after malformed result failed: %v", err)
		}
	}
	m.items["remote"].mu.RLock()
	same := m.items["remote"].session == session
	m.items["remote"].mu.RUnlock()
	if !same {
		t.Fatal("request decoding error replaced upstream session")
	}
}

// A guarded connector never dials its upstream, even when headers are set, and
// later enable/disable generations keep it guarded. An unguarded connector on
// the same upstream shows the server is reachable.
func TestGuardedConnectorNeverDials(t *testing.T) {
	var legacy, other atomicCounter
	s := mcp.NewServer(&mcp.Implementation{Name: "remote", Version: "1"}, nil)
	s.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer legacy" {
			legacy.add()
		} else {
			other.add()
		}
		h.ServeHTTP(w, r)
	}))
	defer remote.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	events := make(chan bool, 16)
	cfg := func(name string, guarded bool) config.Upstream {
		return config.Upstream{Name: name, Transport: "http", URL: remote.URL, Headers: map[string]string{"Authorization": "Bearer legacy"}, Timeout: time.Second, Guarded: guarded}
	}
	m := New([]config.Upstream{cfg("locked", true), cfg("open", false)}, logger, func(name string, _ []*mcp.Tool, healthy bool) {
		if name == "open" {
			events <- healthy
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Close()
	if !<-events {
		t.Fatal("unguarded connector did not connect")
	}
	if err := m.Refresh(ctx, "locked"); !errors.Is(err, ErrGuarded) {
		t.Fatalf("refresh of a guarded connector: %v", err)
	}
	if _, err := m.Call(ctx, "locked", "echo", nil); !errors.Is(err, ErrGuarded) {
		t.Fatalf("call through a guarded connector: %v", err)
	}
	before := legacy.get()
	for _, enabled := range []bool{false, true} {
		if err := m.SetEnabled("locked", enabled); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if err := m.Refresh(ctx, "locked"); !errors.Is(err, ErrGuarded) {
		t.Fatalf("refresh after enable: %v", err)
	}
	for _, st := range m.States() {
		if st.Name == "locked" && (st.Custody != "vault" || st.Healthy) {
			t.Fatalf("guarded state: %+v", st)
		}
	}
	if legacy.get() != before || other.get() != 0 {
		t.Fatal("a guarded connector reached the upstream")
	}
	if !m.Ready() {
		t.Fatal("enabled vault connectors are serviceable")
	}
}

type atomicCounter struct {
	mu sync.Mutex
	n  int
}

func (c *atomicCounter) add() { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *atomicCounter) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
