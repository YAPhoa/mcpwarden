package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/approval"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/testutil"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

func TestGatewayIntegration(t *testing.T) {
	a := testutil.NewMock(200 * time.Millisecond)
	defer a.Close()
	b := testutil.NewMock(200 * time.Millisecond)
	defer b.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol, err := policy.New(config.Policy{Default: "allow", Rules: []config.Rule{{Match: "a__fail", Action: "deny"}}})
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	p := New(registry.New(), pol, approval.None{}, auditLog, logger)
	p.Owner = "timing-test"
	m := upstream.New([]config.Upstream{{Name: "a", Transport: "http", URL: a.HTTP.URL, Timeout: 50 * time.Millisecond}, {Name: "b", Transport: "http", URL: b.HTTP.URL, Timeout: time.Second}}, logger, p.Changed)
	p.Manager = m
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Close()
	endpoint := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return p.Server }, nil))
	defer endpoint.Close()
	event := make(chan struct{}, 8)
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ClientOptions{ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
		select {
		case event <- struct{}{}:
		default:
		}
	}})
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	await(t, 5*time.Second, func() bool { return len(p.Registry.Names()) == 6 })
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 5 {
		t.Fatalf("got %d visible tools, want 5", len(list.Tools))
	}
	names := map[string]bool{}
	for _, tool := range list.Tools {
		names[tool.Name] = true
	}
	if !names["a__echo"] || !names["b__echo"] || names["a__fail"] {
		t.Fatal(names)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "b__echo", Arguments: map[string]any{"message": "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "hello") {
		t.Fatal(res)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "a__fail", Arguments: map[string]any{}})
	if err != nil || !res.IsError {
		t.Fatalf("denied: %v, %v", res, err)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "b__fail", Arguments: map[string]any{}})
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "intentional") {
		t.Fatalf("tool error: %v, %v", res, err)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "a__slow", Arguments: map[string]any{}})
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "timed out") {
		t.Fatalf("timeout: %v, %v", res, err)
	}
	rows, _, err := auditLog.History("timing-test", "", 1, 25)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if row.SchemaVersion != 2 || row.InvocationID == "" || row.EventID == "" || row.UpstreamID == "" || row.CompletedAt.Before(row.TS) {
			t.Fatalf("incomplete audit event: %+v", row)
		}
		timing := row.Timing
		if timing == nil || timing.HandlerUS < timing.UpstreamUS || timing.HandlerUS != timing.GatewayUS+timing.UpstreamUS {
			t.Fatalf("invalid timing: %+v", timing)
		}
		if row.Status == "denied" && (timing.Forwarded || timing.UpstreamUS != 0) {
			t.Fatal("denied call counted as upstream traffic")
		}
		if row.Status == "timeout" && (!timing.Forwarded || timing.UpstreamUS < 40000) {
			t.Fatal("upstream timeout not measured")
		}
		seen[row.Status] = true
	}
	for _, status := range []string{"ok", "denied", "tool_error", "timeout"} {
		if !seen[status] {
			t.Fatalf("missing timing for %s", status)
		}
	}
	select {
	case <-a.Cancelled:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive cancellation")
	}
	callCtx, cancelCall := context.WithCancel(ctx)
	finished := make(chan struct{})
	go func() {
		_, _ = cs.CallTool(callCtx, &mcp.CallToolParams{Name: "b__slow", Arguments: map[string]any{}})
		close(finished)
	}()
	select {
	case <-b.Started:
	case <-time.After(time.Second):
		t.Fatal("slow call did not start")
	}
	cancelCall()
	select {
	case <-b.Cancelled:
	case <-time.After(time.Second):
		t.Fatal("client cancellation did not reach upstream")
	}
	<-finished
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "missing__tool"})
	if err == nil {
		t.Fatal("unknown tool did not return protocol error")
	}
	for {
		select {
		case <-event:
			continue
		default:
			goto drained
		}
	}
drained:
	a.Add("extra", func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "extra"}}}, nil
	})
	await(t, 5*time.Second, func() bool { _, ok := p.Registry.Lookup("a__extra"); return ok })
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatal("missing downstream list_changed")
	}
	var all []*mcp.Tool
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, tool)
	}
	if len(all) != 6 {
		t.Fatalf("after update: got %d tools", len(all))
	}
}
func await(t *testing.T, timeout time.Duration, f func() bool) {
	t.Helper()
	until := time.Now().Add(timeout)
	for time.Now().Before(until) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}
