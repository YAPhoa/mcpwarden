package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/config"
)

type State struct {
	Enabled   bool   `json:"enabled"`
	Name      string `json:"name"`
	Transport string `json:"transport"`
	Healthy   bool   `json:"healthy"`
	Error     string `json:"error,omitempty"`
	ToolCount int    `json:"tool_count"`
	// Custody is "vault" for a guarded connector. It has no background
	// session; each admitted call opens its own under an access window.
	Custody string `json:"custody,omitempty"`
}

// ErrGuarded reports an operation that would need a connector's credential
// outside an access window. Discovery for such connectors needs the owner
// setup flow (roadmap step 5); background refresh never runs for them.
var ErrGuarded = errors.New("connector credentials are in vault custody; the gateway cannot refresh it without an access window")

type connection struct {
	initialDone chan struct{}
	cfg         config.Upstream
	cancel      context.CancelFunc
	mu          sync.RWMutex
	session     *mcp.ClientSession
	state       State
	refreshMu   sync.Mutex
}
type Manager struct {
	mu       sync.RWMutex
	items    map[string]*connection
	ctx      context.Context
	logger   *slog.Logger
	onChange func(string, []*mcp.Tool, bool)
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func New(cfg []config.Upstream, logger *slog.Logger, onChange func(string, []*mcp.Tool, bool)) *Manager {
	m := &Manager{items: map[string]*connection{}, logger: logger, onChange: onChange}
	for _, u := range cfg {
		m.items[u.Name] = newConnection(u)
	}
	return m
}

// newConnection drops any headers from a guarded connector, so the manager
// holds nothing that could reach it.
func newConnection(u config.Upstream) *connection {
	c := &connection{initialDone: make(chan struct{}), cfg: u, state: State{Name: u.Name, Transport: u.Transport, Enabled: !u.Disabled}}
	if u.Guarded {
		c.cfg.Headers = nil
		c.state.Custody = "vault"
		close(c.initialDone)
	}
	return c
}

// runs reports whether the connection loop may start.
func (c *connection) runs() bool { return !c.cfg.Disabled && !c.cfg.Guarded }
func (m *Manager) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	m.ctx = ctx
	m.cancel = cancel
	for _, c := range m.items {
		if !c.runs() {
			continue
		}
		m.wg.Add(1)
		childCtx, childCancel := context.WithCancel(ctx)
		c.cancel = childCancel
		go func(c *connection) { defer m.wg.Done(); m.run(childCtx, c) }(c)
	}
	m.mu.Unlock()
}

// Add starts a new upstream without disrupting active downstream sessions.
func (m *Manager) Add(u config.Upstream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil || m.ctx.Err() != nil {
		return fmt.Errorf("upstream manager is stopped")
	}
	if _, exists := m.items[u.Name]; exists {
		return fmt.Errorf("upstream %s already exists", u.Name)
	}
	ctx, cancel := context.WithCancel(m.ctx)
	c := newConnection(u)
	c.cancel = cancel
	m.items[u.Name] = c
	if !c.runs() {
		cancel()
		return nil
	}
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.run(ctx, c) }()
	return nil
}

// Remove stops an upstream and removes it from the manager. The caller must
// remove its tools from the registry once this returns.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	c := m.items[name]
	if c == nil {
		m.mu.Unlock()
		return fmt.Errorf("upstream %s does not exist", name)
	}
	delete(m.items, name)
	m.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.RLock()
	s := c.session
	c.mu.RUnlock()
	if s != nil {
		_ = s.Close()
	}
	return nil
}
func (m *Manager) run(ctx context.Context, c *connection) {
	var initial sync.Once
	done := func() { initial.Do(func() { close(c.initialDone) }) }
	defer done()
	backoff := time.Second
	for ctx.Err() == nil {
		session, err := m.connect(ctx, c)
		if err == nil {
			c.mu.Lock()
			c.session = session
			c.state.Healthy = true
			c.state.Error = ""
			c.mu.Unlock()
			err = m.refresh(ctx, c, session)
			done()
			if err == nil {
				backoff = time.Second
				err = session.Wait()
			}
			c.mu.Lock()
			if c.session == session {
				c.session = nil
			}
			c.state.Healthy = false
			c.state.ToolCount = 0
			if err != nil {
				c.state.Error = err.Error()
			}
			c.mu.Unlock()
			m.emit(c, nil, false)
			_ = session.Close()
		}
		done()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.logger.Warn("upstream unavailable", "upstream", c.cfg.Name, "error", err)
			c.mu.Lock()
			c.state.Error = err.Error()
			c.mu.Unlock()
		}
		jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
		select {
		case <-time.After(backoff + jitter):
		case <-ctx.Done():
			return
		}
		backoff *= 2
		if backoff > time.Minute {
			backoff = time.Minute
		}
	}
}
func (m *Manager) connect(ctx context.Context, c *connection) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "mcpwarden", Version: "0.1.0"}, &mcp.ClientOptions{
		ToolListChangedHandler: func(_ context.Context, _ *mcp.ToolListChangedRequest) {
			c.mu.RLock()
			s := c.session
			c.mu.RUnlock()
			if s != nil {
				go func() {
					if err := m.refresh(ctx, c, s); err != nil {
						m.logger.Warn("refresh tools failed", "upstream", c.cfg.Name, "error", err)
						_ = s.Close()
					}
				}()
			}
		},
	})
	var transport mcp.Transport
	if c.cfg.Transport == "stdio" {
		cmd := exec.Command(c.cfg.Command, c.cfg.Args...)
		cmd.Env = stdioEnv(c.cfg.Env)
		cmd.Stderr = os.Stderr
		transport = compatTransport{&mcp.CommandTransport{Command: cmd, TerminateDuration: 5 * time.Second}}
	} else {
		base := http.DefaultTransport.(*http.Transport).Clone()
		transport = &mcp.StreamableClientTransport{Endpoint: c.cfg.URL, HTTPClient: &http.Client{Transport: compatRoundTripper{headerTransport{base, c.cfg.Headers}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, MaxRetries: -1, MaxEventSize: maxSSEEventBytes}
	}
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	s, err := client.Connect(connectCtx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: connect: %w", c.cfg.Name, err)
	}
	return s, nil
}

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copyReq := req.Clone(req.Context())
	for k, v := range h.headers {
		copyReq.Header.Set(k, v)
	}
	return h.base.RoundTrip(copyReq)
}
func (m *Manager) refresh(ctx context.Context, c *connection, s *mcp.ClientSession) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	listCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var tools []*mcp.Tool
	seen := map[string]bool{}
	cursor := ""
	for {
		res, err := s.ListTools(listCtx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return fmt.Errorf("upstream %s: list tools: %w", c.cfg.Name, err)
		}
		tools = append(tools, res.Tools...)
		if res.NextCursor == "" {
			break
		}
		if seen[res.NextCursor] {
			return fmt.Errorf("upstream %s: repeated tools cursor", c.cfg.Name)
		}
		seen[res.NextCursor] = true
		cursor = res.NextCursor
	}
	c.mu.RLock()
	current := c.session == s
	c.mu.RUnlock()
	if current {
		c.mu.Lock()
		c.state.ToolCount = len(tools)
		c.mu.Unlock()
		m.emit(c, tools, true)
	}
	return nil
}
func (m *Manager) emit(c *connection, tools []*mcp.Tool, healthy bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.items[c.cfg.Name] == c {
		m.onChange(c.cfg.Name, tools, healthy)
	}
}
func (m *Manager) Call(ctx context.Context, upstream string, name string, args any) (*mcp.CallToolResult, error) {
	m.mu.RLock()
	c := m.items[upstream]
	m.mu.RUnlock()
	if c == nil {
		return nil, fmt.Errorf("upstream %s unavailable", upstream)
	}
	if c.cfg.Guarded {
		return nil, ErrGuarded
	}
	c.mu.RLock()
	s := c.session
	c.mu.RUnlock()
	if s == nil {
		return nil, fmt.Errorf("upstream %s unavailable", upstream)
	}
	// Request-level protocol and decoding errors do not imply a broken transport.
	// The connection loop observes session.Wait and reconnects on transport failure.
	return s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
}
func (m *Manager) Refresh(ctx context.Context, name string) error {
	m.mu.RLock()
	c := m.items[name]
	m.mu.RUnlock()
	if c == nil {
		return fmt.Errorf("upstream %s does not exist", name)
	}
	if c.cfg.Disabled {
		return fmt.Errorf("upstream %s disabled", name)
	}
	if c.cfg.Guarded {
		return ErrGuarded
	}
	// Enabling starts a new connection asynchronously. Wait for its first
	// discovery attempt instead of treating the startup window as unavailable.
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case <-c.initialDone:
	case <-waitCtx.Done():
		return waitCtx.Err()
	}
	m.mu.RLock()
	current := m.items[name] == c
	m.mu.RUnlock()
	if !current {
		return fmt.Errorf("upstream %s changed during refresh", name)
	}
	c.mu.RLock()
	s := c.session
	c.mu.RUnlock()
	if s == nil {
		return fmt.Errorf("upstream %s unavailable", name)
	}
	return m.refresh(ctx, c, s)
}
func (m *Manager) Timeout(upstream string) time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if c := m.items[upstream]; c != nil {
		return c.cfg.Timeout
	}
	return 30 * time.Second
}
func (m *Manager) States() []State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]State, 0, len(m.items))
	for _, c := range m.items {
		c.mu.RLock()
		out = append(out, c.state)
		c.mu.RUnlock()
	}
	return out
}

// Ready reports a connected upstream or an enabled vault connector, which
// serves calls through access windows without a background session.
func (m *Manager) Ready() bool {
	for _, s := range m.States() {
		if s.Healthy || s.Custody == "vault" && s.Enabled {
			return true
		}
	}
	return false
}
func (m *Manager) Close() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.ctx = nil
	sessions := make([]*mcp.ClientSession, 0, len(m.items))
	for _, c := range m.items {
		c.mu.RLock()
		s := c.session
		c.mu.RUnlock()
		if s != nil {
			sessions = append(sessions, s)
		}
	}
	m.mu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
	m.wg.Wait()
}

// SetEnabled replaces the connection generation so old callbacks cannot restore
// a disabled provider. Cached registry tools are retained by the callback.
func (m *Manager) SetEnabled(name string, enabled bool) error {
	m.mu.Lock()
	old := m.items[name]
	if old == nil || m.ctx == nil || m.ctx.Err() != nil {
		m.mu.Unlock()
		return fmt.Errorf("provider unavailable")
	}
	if !old.cfg.Disabled == enabled {
		m.mu.Unlock()
		return nil
	}
	cfg := old.cfg
	cfg.Disabled = !enabled
	c := newConnection(cfg)
	m.items[name] = c
	// Holding the manager lock excludes both old and new discovery callbacks.
	m.onChange(name, nil, false)
	if c.runs() {
		ctx, cancel := context.WithCancel(m.ctx)
		c.cancel = cancel
		m.wg.Add(1)
		go func() { defer m.wg.Done(); m.run(ctx, c) }()
	}
	m.mu.Unlock()
	if old.cancel != nil {
		old.cancel()
	}
	old.mu.RLock()
	session := old.session
	old.mu.RUnlock()
	if session != nil {
		_ = session.Close()
	}
	return nil
}

// stdioInherited lists the only gateway environment variables a stdio upstream
// inherits, plus LC_* locale settings. The gateway environment holds the catalog
// key, operator token and OAuth client secret, so anything else a command needs
// must be passed explicitly through the upstream's env map.
var stdioInherited = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TZ", "TERM", "TMPDIR",
	// Windows process basics.
	"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
}

func stdioEnv(explicit map[string]string) []string {
	env := make([]string, 0, len(stdioInherited)+len(explicit))
	for _, k := range stdioInherited {
		if _, set := explicit[k]; set {
			continue
		}
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "LC_") {
			if _, set := explicit[k]; !set {
				env = append(env, kv)
			}
		}
	}
	for k, v := range explicit {
		env = append(env, k+"="+v)
	}
	return env
}
