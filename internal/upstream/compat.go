package upstream

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"strconv"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

// Some upstreams (Kaggle's authorize tool) return tools/call results whose
// content is a bare string or a single content object instead of an array.
// The SDK rejects the whole result, so the caller loses a message that is
// otherwise intact. normalizeToolResult wraps those two shapes into the
// array form and leaves every other response byte-for-byte unchanged.
// Only responses to tools/call requests are inspected.

// normalizeToolResult rewrites result.content in a JSON-RPC response when it
// is a string or an object. It reports whether anything changed.
func normalizeToolResult(msg []byte) ([]byte, bool) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(msg, &envelope) != nil {
		return msg, false
	}
	rawResult, ok := envelope["result"]
	if !ok {
		return msg, false
	}
	result, ok := normalizeResultContent(rawResult)
	if !ok {
		return msg, false
	}
	envelope["result"] = result
	out, err := json.Marshal(envelope)
	if err != nil {
		return msg, false
	}
	return out, true
}

func normalizeResultContent(raw []byte) (json.RawMessage, bool) {
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil {
		return nil, false
	}
	content := bytes.TrimSpace(result["content"])
	if len(content) == 0 {
		return nil, false
	}
	var wrapped []byte
	switch content[0] {
	case '"':
		var text string
		if json.Unmarshal(content, &text) != nil {
			return nil, false
		}
		b, err := json.Marshal([]map[string]string{{"type": "text", "text": text}})
		if err != nil {
			return nil, false
		}
		wrapped = b
	case '{':
		wrapped = append(append([]byte{'['}, content...), ']')
	default:
		return nil, false
	}
	result["content"] = wrapped
	out, err := json.Marshal(result)
	if err != nil {
		return nil, false
	}
	return out, true
}

// compatRoundTripper applies normalizeToolResult to Streamable HTTP responses
// for tools/call requests, covering both JSON and SSE response bodies.
type compatRoundTripper struct {
	base http.RoundTripper
}

func (c compatRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.Body == nil {
		return c.base.RoundTrip(req)
	}
	// The SDK already holds each outgoing message in memory; buffering it here
	// lets the response handler know whether the request was tools/call.
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	resp, err := c.base.RoundTrip(clone)
	if err != nil || resp.Body == nil || !isToolCall(body) {
		return resp, err
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mediaType {
	case "application/json":
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		raw, _ = normalizeToolResult(raw)
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.Itoa(len(raw)))
	case "text/event-stream":
		resp.Body = newSSENormalizer(resp.Body)
	}
	return resp, nil
}

func isToolCall(body []byte) bool {
	var req struct {
		Method string `json:"method"`
	}
	return json.Unmarshal(body, &req) == nil && req.Method == "tools/call"
}

// sseNormalizer rewrites the data of each SSE event. Events that do not change
// are emitted with their original bytes.
type sseNormalizer struct {
	src *bufio.Reader
	rc  io.ReadCloser
	out bytes.Buffer
	err error
}

func newSSENormalizer(rc io.ReadCloser) io.ReadCloser {
	return &sseNormalizer{src: bufio.NewReader(rc), rc: rc}
}

func (s *sseNormalizer) Read(p []byte) (int, error) {
	for s.out.Len() == 0 && s.err == nil {
		s.err = s.nextEvent()
	}
	if s.out.Len() > 0 {
		return s.out.Read(p)
	}
	return 0, s.err
}

func (s *sseNormalizer) Close() error { return s.rc.Close() }

func (s *sseNormalizer) nextEvent() error {
	var raw, other bytes.Buffer
	var data [][]byte
	for {
		line, err := s.src.ReadBytes('\n')
		raw.Write(line)
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(line) > 0 && len(trimmed) > 0 {
			if v, ok := bytes.CutPrefix(trimmed, []byte("data:")); ok {
				data = append(data, bytes.TrimPrefix(v, []byte(" ")))
			} else {
				other.Write(line)
			}
		}
		if err != nil || (len(line) > 0 && len(trimmed) == 0) {
			if len(data) > 0 {
				if rewritten, changed := normalizeToolResult(bytes.Join(data, []byte("\n"))); changed {
					s.out.Write(other.Bytes())
					s.out.WriteString("data: ")
					s.out.Write(rewritten)
					s.out.WriteString("\n\n")
					return err
				}
			}
			s.out.Write(raw.Bytes())
			return err
		}
	}
}

// compatTransport wraps a stdio transport so its connection applies the same
// normalization to responses whose request was tools/call.
type compatTransport struct {
	mcp.Transport
}

func (t compatTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &compatConn{Connection: conn}, nil
}

type compatConn struct {
	mcp.Connection
	calls sync.Map // jsonrpc.ID -> struct{}
}

func (c *compatConn) Write(ctx context.Context, msg jsonrpc.Message) error {
	if req, ok := msg.(*jsonrpc.Request); ok && req.Method == "tools/call" && req.IsCall() {
		c.calls.Store(req.ID, struct{}{})
	}
	return c.Connection.Write(ctx, msg)
}

func (c *compatConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := c.Connection.Read(ctx)
	if resp, ok := msg.(*jsonrpc.Response); ok && err == nil {
		if _, pending := c.calls.LoadAndDelete(resp.ID); pending && resp.Result != nil {
			if result, changed := normalizeResultContent(resp.Result); changed {
				resp.Result = result
			}
		}
	}
	return msg, err
}
