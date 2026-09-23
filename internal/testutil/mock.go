package testutil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Mock is an SDK-based upstream with dynamic tool registration.
type Mock struct {
	Server    *mcp.Server
	HTTP      *httptest.Server
	Cancelled chan struct{}
	Started   chan struct{}
	Slow      time.Duration
}

func NewMock(slow time.Duration) *Mock {
	m := &Mock{Server: mcp.NewServer(&mcp.Implementation{Name: "mock", Version: "1"}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}}), Cancelled: make(chan struct{}, 1), Started: make(chan struct{}, 1), Slow: slow}
	m.Add("echo", func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(req.Params.Arguments)}}}, nil
	})
	m.Add("slow", func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		select {
		case m.Started <- struct{}{}:
		default:
		}
		select {
		case <-time.After(m.Slow):
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, nil
		case <-ctx.Done():
			select {
			case m.Cancelled <- struct{}{}:
			default:
			}
			return nil, ctx.Err()
		}
	})
	m.Add("fail", func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "intentional tool failure"}}}, nil
	})
	m.HTTP = httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return m.Server }, nil))
	return m
}
func (m *Mock) Add(name string, handler mcp.ToolHandler) {
	m.Server.AddTool(&mcp.Tool{Name: name, Description: name + " mock tool", InputSchema: json.RawMessage(`{"type":"object"}`)}, handler)
}
func (m *Mock) Close() { m.HTTP.Close() }
