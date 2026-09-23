package secret

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// RecordSource returns an owner-scoped, immutable current ciphertext snapshot.
// It must be a bounded local cache updated through the lease owner coordinator,
// never a database/network call made from inside the activation transaction.
type RecordSource interface {
	Current(owner, credentialID string) (Record, bool)
}
type Record struct {
	Envelope    []byte
	Destination Destination
}
type Activator struct{ Records RecordSource }

type privateHeader struct {
	name  string
	value []byte
}
type Handle struct {
	mu          sync.RWMutex
	closed      bool
	destination destination
	headers     []privateHeader
}

func (*Handle) String() string               { return "[activated credential]" }
func (*Handle) GoString() string             { return "[activated credential]" }
func (*Handle) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func (a Activator) Stage(ctx context.Context, owner string, credential lease.Credential, key []byte) (lease.Material, error) {
	defer clear(key)
	if ctx.Err() != nil || a.Records == nil {
		return nil, lease.ErrKey
	}
	r, ok := a.Records.Current(owner, credential.ID)
	if !ok {
		return nil, lease.ErrKey
	}
	d, err := r.Destination.validate()
	if err != nil {
		return nil, lease.ErrKey
	}
	digest, err := d.profile.Digest()
	if err != nil || digest != credential.DestinationDigest {
		return nil, lease.ErrKey
	}
	header := Header{Format: Format, Algorithm: Algorithm, Purpose: "upstream-credential", OwnerID: owner,
		ConnectorID: credential.ConnectorID, CredentialID: credential.ID, Epoch: credential.Epoch, Revision: credential.Revision, DestinationDigest: digest}
	plain, err := open(r.Envelope, header, key)
	if err != nil {
		return nil, lease.ErrKey
	}
	defer clear(plain)
	headers, err := parseBundle(plain, d.profile.HeaderNames)
	if err != nil {
		return nil, lease.ErrKey
	}
	h := &Handle{destination: d, headers: headers}
	if ctx.Err() != nil {
		h.Destroy()
		return nil, lease.ErrKey
	}
	return h, nil
}

func parseBundle(raw []byte, names []string) ([]privateHeader, error) {
	if json.Validate(raw, MaxBundleBytes, 5) != nil {
		return nil, ErrInvalid
	}
	var bundle struct {
		Kind    string `json:"kind"`
		Headers []struct {
			Name  string  `json:"name"`
			Value *string `json:"value"`
		} `json:"headers"`
	}
	if json.UnmarshalStrict(raw, &bundle) != nil || bundle.Kind != "header_bundle" || len(bundle.Headers) != len(names) || len(bundle.Headers) == 0 {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	var headers []privateHeader
	valid := false
	defer func() {
		if !valid {
			for _, h := range headers {
				clear(h.value)
			}
		}
	}()
	for _, h := range bundle.Headers {
		name := strings.ToLower(h.Name)
		if !credentialHeader(name) || !slices.Contains(names, name) || seen[name] || h.Value == nil || !utf8.ValidString(*h.Value) {
			return nil, ErrInvalid
		}
		// RFC field values cannot contain CR/LF, NUL, DEL or other controls.
		// Empty/space-padded values are rejected rather than silently normalized.
		value := *h.Value
		if value == "" || len(value) > 16<<10 || strings.TrimSpace(value) != value {
			return nil, ErrInvalid
		}
		for _, c := range []byte(value) {
			if c < 32 || c == 127 {
				return nil, ErrInvalid
			}
		}
		seen[name] = true
		headers = append(headers, privateHeader{name: http.CanonicalHeaderKey(name), value: []byte(value)})
	}
	valid = true
	return headers, nil
}

// Destroy clears owned byte buffers. Go/HTTP may retain temporary string or
// cipher-library copies; this is best-effort memory hygiene, not guaranteed
// instantaneous zeroization. No durable server unwrap key is created here.
func (h *Handle) Destroy() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for _, header := range h.headers {
		clear(header.value)
	}
	h.headers = nil
}

func (h *Handle) Endpoint() string { return h.destination.profile.Endpoint }

// Client creates a dedicated, constrained MCP transport. It is useless without
// the original live Prepare/Admission context. Header values are never returned.
// The trusted dispatcher pins the original upstream tool name for this call.
func (h *Handle) Client(tool string) *http.Client {
	return &http.Client{Transport: &credentialTransport{handle: h, tool: tool, base: h.destination.transport(func(ctx context.Context) error { _, err := lease.CheckUse(ctx, h); return err })},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type credentialTransport struct {
	handle *Handle
	tool   string
	base   http.RoundTripper
}

func (t *credentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h := t.handle
	phase, err := lease.CheckUse(req.Context(), h)
	if err != nil {
		return nil, lease.ErrDenied
	}
	if req.Method != http.MethodPost || req.URL == nil || req.URL.String() != h.Endpoint() || req.Host != "" && req.Host != req.URL.Host || req.RequestURI != "" || req.Body == nil {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, lease.MaxArgumentBytes+(64<<10)+1))
	_ = req.Body.Close()
	if err != nil || json.Validate(raw, lease.MaxArgumentBytes+(64<<10), 70) != nil {
		return nil, ErrInvalid
	}
	var rpc struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal(raw, &rpc) != nil {
		return nil, ErrInvalid
	}
	if phase == "prepare" {
		switch rpc.Method {
		case "server/discover", "initialize", "notifications/initialized", "tools/list":
		default:
			return nil, lease.ErrDenied
		}
	} else if phase == "call" {
		if rpc.Method != "tools/call" {
			return nil, lease.ErrDenied
		}
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal(rpc.Params, &params) != nil || params.Name != t.tool || lease.ClaimCall(req.Context(), h, params.Arguments) != nil {
			return nil, lease.ErrDenied
		}
	} else {
		return nil, lease.ErrDenied
	}
	copyReq := req.Clone(req.Context())
	if copyReq.Header == nil {
		copyReq.Header = make(http.Header)
	}
	copyReq.Body = io.NopCloser(bytes.NewReader(raw))
	copyReq.GetBody = nil // No net/http replay, even if a future caller adds retry metadata.
	copyReq.Header.Del("Idempotency-Key")
	copyReq.Header.Del("X-Idempotency-Key")
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return nil, lease.ErrStale
	}
	var injected []string
	for _, header := range h.headers {
		copyReq.Header.Set(header.name, string(header.value))
		injected = append(injected, header.name)
	}
	h.mu.RUnlock()
	scrub := func() {
		for _, name := range injected {
			copyReq.Header.Del(name)
		}
	}
	if _, err := lease.CheckUse(req.Context(), h); err != nil {
		scrub()
		return nil, lease.ErrStale
	}
	response, err := t.base.RoundTrip(copyReq)
	if err != nil {
		scrub()
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if errors.Is(req.Context().Err(), context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(req.Context().Err(), context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, ErrInvalid // Never forward transport/provider error text.
	}
	if response == nil || response.Body == nil {
		scrub()
		return nil, ErrInvalid
	}
	response.Request = req // Do not expose the private clone through Response.Request.
	response.Body = &scrubbingBody{ReadCloser: response.Body, scrub: scrub}
	return response, nil
}

type scrubbingBody struct {
	io.ReadCloser
	once  sync.Once
	scrub func()
}

func (b *scrubbingBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.scrub); return err }
