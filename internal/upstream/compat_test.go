package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func readSSE(t *testing.T, body string, limit int) (string, error) {
	t.Helper()
	out, err := io.ReadAll(newSSENormalizer(io.NopCloser(strings.NewReader(body)), limit))
	return string(out), err
}

func TestSSENormalizerPassesAndRepairsEvents(t *testing.T) {
	plain := ": keepalive\r\n\r\nevent: message\nid: 7\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n"
	if out, err := readSSE(t, plain, 4096); err != nil || out != plain {
		t.Fatalf("unchanged events altered: %q %v", out, err)
	}
	repaired, err := readSSE(t, "event: message\r\nid: 8\r\n: note\r\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{\"content\":\"hi\"}}\r\n\r\n", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(repaired, "event: message\r\nid: 8\r\n: note\r\ndata: ") || !strings.Contains(repaired, `"content":[{"text":"hi","type":"text"}]`) || !strings.HasSuffix(repaired, "\n\n") {
		t.Fatalf("unexpected repair %q", repaired)
	}
}

// Both cases keep the stream open so only the budget can end the read.
func TestSSENormalizerBoundsUnterminatedEvents(t *testing.T) {
	const limit = 4096
	for name, chunk := range map[string][]byte{
		"one long line":    bytes.Repeat([]byte("x"), 1024),
		"many short lines": []byte(": comment line\n"),
	} {
		t.Run(name, func(t *testing.T) {
			r, w := io.Pipe()
			defer w.Close()
			go func() {
				for {
					if _, err := w.Write(chunk); err != nil {
						return
					}
				}
			}()
			done := make(chan error, 1)
			go func() {
				_, err := io.ReadAll(newSSENormalizer(r, limit))
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, errSSEEventTooLarge) {
					t.Fatalf("got %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("oversized event was buffered without limit")
			}
			r.Close()
		})
	}
}

func TestHTTPOversizedSSEEventFailsCallPromptly(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "oversized", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "big", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	release := make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			if isToolCall(body) {
				// Comment lines with no event terminator, then hold the stream open.
				w.Header().Set("Content-Type", "text/event-stream")
				line := ": " + strings.Repeat("x", 1<<16) + "\n"
				for sent := 0; sent <= maxSSEEventBytes; sent += len(line) {
					if _, err := io.WriteString(w, line); err != nil {
						return
					}
				}
				w.(http.Flusher).Flush()
				select {
				case <-release:
				case <-r.Context().Done():
				}
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(remote.Close)
	t.Cleanup(func() { close(release) })
	m, ctx := startRemote(t, remote.URL)
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if _, err := m.Call(callCtx, "remote", "big", map[string]any{}); err == nil {
		t.Fatal("oversized event accepted")
	}
	if callCtx.Err() != nil {
		t.Fatal("oversized event waited for the call deadline")
	}
}

// capturingTransport exposes the wrapped connection so tests can inspect it.
type capturingTransport struct {
	compatTransport
	conn chan *compatConn
}

func (t capturingTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.compatTransport.Connect(ctx)
	if err == nil {
		t.conn <- conn.(*compatConn)
	}
	return conn, err
}

func TestStdioCancelledCallsAreRetired(t *testing.T) {
	clientR, serverW := io.Pipe()
	serverR, clientW := io.Pipe()
	cancelled := make(chan struct{}, 16)
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
			case "ping":
				result = `{}`
			case "notifications/cancelled":
				cancelled <- struct{}{}
				continue
			case "tools/call":
				continue // never answers
			default:
				if len(req.ID) > 0 {
					_, _ = io.WriteString(serverW, `{"jsonrpc":"2.0","id":`+string(req.ID)+`,"error":{"code":-32601,"message":"method not found"}}`+"\n")
				}
				continue
			}
			_, _ = io.WriteString(serverW, `{"jsonrpc":"2.0","id":`+string(req.ID)+`,"result":`+result+"}\n")
		}
	}()
	transport := capturingTransport{compatTransport{&mcp.IOTransport{Reader: clientR, Writer: clientW}}, make(chan *compatConn, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	conn := <-transport.conn
	const calls = 8
	for i := 0; i < calls; i++ {
		callCtx, stop := context.WithTimeout(ctx, 20*time.Millisecond)
		if _, err := session.CallTool(callCtx, &mcp.CallToolParams{Name: "slow", Arguments: map[string]any{}}); err == nil {
			t.Fatal("unanswered call succeeded")
		}
		stop()
	}
	for i := 0; i < calls; i++ {
		select {
		case <-cancelled:
		case <-ctx.Done():
			t.Fatal("cancellation notifications not sent")
		}
	}
	if err := session.Ping(ctx, nil); err != nil {
		t.Fatalf("session unusable after cancellations: %v", err)
	}
	remaining := 0
	conn.calls.Range(func(any, any) bool { remaining++; return true })
	if remaining != 0 {
		t.Fatalf("%d cancelled call IDs still tracked", remaining)
	}
}
