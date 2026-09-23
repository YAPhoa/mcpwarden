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
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"content": "User is already authorized."}})
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
