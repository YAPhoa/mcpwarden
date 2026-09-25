package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/approval"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

type Proxy struct {
	Owner       string
	Server      *mcp.Server
	AdminServer *mcp.Server
	Registry    *registry.Registry
	Manager     *upstream.Manager
	Policy      *policy.Policy
	Visible     func(string) bool
	Approver    approval.Approver
	Audit       audit.Appender
	Logger      *slog.Logger
	Security    *LeasedExecution
	syncMu      sync.Mutex
	registered  []string
}

func New(reg *registry.Registry, pol *policy.Policy, approver approval.Approver, log audit.Appender, logger *slog.Logger) *Proxy {
	p := &Proxy{Registry: reg, Policy: pol, Approver: approver, Audit: log, Logger: logger}
	p.Server = mcp.NewServer(&mcp.Implementation{Name: "mcpwarden", Version: "0.1.0"}, &mcp.ServerOptions{Logger: logger, Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}})
	p.AdminServer = mcp.NewServer(&mcp.Implementation{Name: "mcpwarden-admin", Version: "0.1.0"}, &mcp.ServerOptions{Logger: logger, Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}})
	filter := func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if method != "tools/list" || err != nil {
				return res, err
			}
			list, ok := res.(*mcp.ListToolsResult)
			if !ok {
				return res, nil
			}
			filtered := make([]*mcp.Tool, 0, len(list.Tools))
			for _, t := range list.Tools {
				if strings.HasPrefix(t.Name, "warden_") && !strings.Contains(t.Name, "__") {
					filtered = append(filtered, t)
					continue
				}
				if entry, ok := p.Registry.Lookup(t.Name); ok && (entry.Healthy || p.leaseListed(entry)) && p.Policy.Allow(t.Name) && p.isVisible(t.Name) {
					filtered = append(filtered, t)
				}
			}
			copyList := *list
			copyList.Tools = filtered
			return &copyList, nil
		}
	}
	p.Server.AddReceivingMiddleware(filter)
	p.AdminServer.AddReceivingMiddleware(filter)
	return p
}
func (p *Proxy) isVisible(name string) bool {
	return p.Visible == nil || p.Visible(name)
}

// VisibilityChanged re-registers one existing tool so the SDK sends its
// tools/list_changed notification to downstream sessions.
func (p *Proxy) VisibilityChanged(provider string) {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()
	for _, name := range p.registered {
		entry, ok := p.Registry.Lookup(name)
		if !ok || entry.Upstream != provider {
			continue
		}
		for _, server := range []*mcp.Server{p.Server, p.AdminServer} {
			server.AddTool(entry.Tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return p.call(ctx, req, entry.Tool.Name)
			})
		}
		return
	}
}
func (p *Proxy) Changed(upstreamName string, tools []*mcp.Tool, healthy bool) {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()
	skipped := p.Registry.Replace(upstreamName, tools, healthy)
	for _, name := range skipped {
		p.Logger.Warn("invalid exposed tool name skipped", "upstream", upstreamName, "tool", name)
	}
	previous := map[string]bool{}
	for _, name := range p.registered {
		previous[name] = true
	}
	all := p.Registry.All()
	for name := range previous {
		if _, ok := all[name]; !ok {
			p.Server.RemoveTools(name)
			p.AdminServer.RemoveTools(name)
			delete(previous, name)
		}
	}
	for name, e := range all {
		if previous[name] && e.Upstream != upstreamName {
			continue
		}
		entry := e
		for _, server := range []*mcp.Server{p.Server, p.AdminServer} {
			server.AddTool(entry.Tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return p.call(ctx, req, entry.Tool.Name)
			})
		}
		previous[name] = true
	}
	p.registered = p.registered[:0]
	for name := range previous {
		p.registered = append(p.registered, name)
	}
	sort.Strings(p.registered)
}
func (p *Proxy) Removed(upstreamName string) {
	p.syncMu.Lock()
	defer p.syncMu.Unlock()
	var names []string
	for _, name := range p.registered {
		if entry, ok := p.Registry.Lookup(name); ok && entry.Upstream == upstreamName {
			names = append(names, name)
		}
	}
	p.Registry.Delete(upstreamName)
	for _, name := range names {
		p.Server.RemoveTools(name)
		p.AdminServer.RemoveTools(name)
	}
	p.registered = p.Registry.Names()
}

func errorResult(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}
func (p *Proxy) call(ctx context.Context, req *mcp.CallToolRequest, name string) (*mcp.CallToolResult, error) {
	start := time.Now()
	entry, ok := p.Registry.Lookup(name)
	if !ok {
		return errorResult("tool unavailable"), nil
	}
	if credentialID, required := p.leaseBinding(entry); required {
		return p.callLeased(ctx, req, entry, credentialID)
	}
	hash := audit.HashArgs(req.Params.Arguments)
	timing := &audit.Timing{}
	record := audit.NewInvocation(ctx, p.Owner)
	var admissionTime time.Duration
	admitted := false
	record.Timing, record.Owner, record.ToolID = timing, p.Owner, entry.ID
	record.TS, record.Tool = start.UTC(), name
	if req.Session != nil {
		record.Session = req.Session.ID()
	}
	record.Upstream, record.UpstreamID = entry.Upstream, entry.UpstreamID
	record.ArgsSHA256, record.Decision, record.Status = hash, "allow", "ok"
	defer func() {
		if admitted && record.EventType != audit.DispatchCompleted {
			return // A panic/interruption after admission leaves an unknown outcome.
		}
		record.CompletedAt = time.Now().UTC()
		record.OccurredAt = record.CompletedAt
		if record.EventType == audit.DispatchDenied {
			record.Decision = "deny"
		}
		timing.AdmissionUS = admissionTime.Microseconds()
		timing.HandlerUS = (time.Since(start) - admissionTime).Microseconds()
		timing.GatewayUS = timing.HandlerUS - timing.UpstreamUS
		record.DurationMS = timing.HandlerUS / 1000
		if err := p.Audit.Write(record); err != nil {
			p.Logger.Error("audit write failed", "event_id", record.EventID, "event_type", record.EventType)
		}
	}()
	if actor, ok := identity.ActorFrom(ctx); ok && actor.Owner != p.Owner {
		record.Status = "denied"
		return errorResult("workspace access denied"), nil
	}
	if !p.Policy.Allow(name) {
		record.Decision = "deny"
		record.Status = "denied"
		return errorResult("tool denied by policy"), nil
	}
	if !p.isVisible(name) {
		record.Decision = "deny"
		record.Status = "denied"
		return errorResult("tool hidden by visibility settings"), nil
	}
	approved, err := p.Approver.Approve(ctx, approval.Request{Tool: name, Upstream: entry.Upstream, ArgsHash: hash})
	if err != nil || !approved {
		record.Decision = "deny"
		record.Status = "denied"
		return errorResult("tool denied by approval"), nil
	}
	if !entry.Healthy {
		record.Status = "unavailable"
		return errorResult("upstream " + entry.Upstream + " unavailable"), nil
	}
	timeout := p.Manager.Timeout(entry.Upstream)
	admissionStart := time.Now()
	err = p.Audit.Write(record.Admission())
	admissionTime = time.Since(admissionStart)
	if err != nil {
		record.Status = "audit_error"
		p.Logger.Error("dispatch admission audit failed", "invocation_id", record.InvocationID)
		return errorResult("MCPWARDEN_AUDIT_UNAVAILABLE: No upstream action was executed. Durable audit storage is unavailable."), nil
	}
	admitted = true
	// The connector may have converted to vault custody after the routing check
	// above. Re-check after the durable admission so a call admitted once the
	// binding is published never reaches the legacy session.
	if _, required := p.leaseBinding(entry); required {
		record.EventType, record.Status = audit.DispatchCompleted, "denied"
		record.Decision = "deny"
		return leaseError(lease.ErrRequired), nil
	}
	// The upstream's timeout starts after the durable admission write, so a
	// slow fsync does not shorten the time the upstream gets.
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	upstreamStart := time.Now()
	timing.Forwarded = true
	res, err := p.Manager.Call(callCtx, entry.Upstream, entry.Original, json.RawMessage(req.Params.Arguments))
	record.EventType = audit.DispatchCompleted
	timing.UpstreamUS = time.Since(upstreamStart).Microseconds()
	if errors.Is(err, upstream.ErrGuarded) {
		// Conversion replaced the legacy connection before dispatch.
		timing.Forwarded = false
		record.Decision, record.Status = "deny", "denied"
		return leaseError(lease.ErrRequired), nil
	}
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			record.Status = "timeout"
			return errorResult("upstream " + entry.Upstream + " timed out after " + timeout.String()), nil
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			record.Status = "protocol_error"
			return errorResult("call cancelled"), nil
		}
		record.Status = "protocol_error"
		return errorResult("upstream " + entry.Upstream + ": " + err.Error()), nil
	}
	record.ResponseItems = len(res.Content)
	record.Structured = res.StructuredContent != nil
	if res.IsError {
		record.Status = "tool_error"
	}
	return res, nil
}

type ToolItem struct {
	ID          string    `json:"id"`
	UpstreamID  string    `json:"upstream_id"`
	DisplayName string    `json:"display_name"`
	Name        string    `json:"name"`
	Upstream    string    `json:"upstream"`
	Description string    `json:"description"`
	Healthy     bool      `json:"healthy"`
	Allowed     bool      `json:"allowed"`
	Visible     bool      `json:"visible"`
	Custody     string    `json:"custody,omitempty"`
	Tool        *mcp.Tool `json:"tool"`
}

func (p *Proxy) ToolItems(provider, search string) []ToolItem {
	all := p.Registry.All()
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ToolItem, 0, len(names))
	search = strings.ToLower(strings.TrimSpace(search))
	for _, name := range names {
		e := all[name]
		if provider != "" && e.Upstream != provider {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(name+" "+e.Tool.Description), search) {
			continue
		}
		item := ToolItem{ID: e.ID, UpstreamID: e.UpstreamID, DisplayName: e.Original, Name: name, Upstream: e.Upstream, Description: e.Tool.Description, Healthy: e.Healthy, Allowed: p.Policy.Allow(name), Visible: p.isVisible(name), Tool: e.Tool}
		if p.requiresLease(e) {
			item.Custody = "vault"
		}
		out = append(out, item)
	}
	return out
}

func (p *Proxy) ToolsJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p.ToolItems(r.URL.Query().Get("provider"), r.URL.Query().Get("search")))
}
