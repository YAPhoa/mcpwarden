package proxy

import (
	"context"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

// LeasedExecution is installed before serving requests. Credential reads only
// current owner-scoped custody metadata, including tombstones: a required binding
// MUST NOT disappear into legacy fallback when a credential is locked/deleted.
// Its security mutations use Service.Change. Complete appends to the same durable
// store as lease admissions. Available, when set, hides a bound connector's
// cached tools from tools/list while it is disabled. History, when set,
// receives a best-effort copy of each admission and completion for the owner's
// call history; the durable record is the one Complete and admission wrote.
type LeasedExecution struct {
	Service    *lease.Service
	Credential func(owner, connectorID string) (credentialID string, required bool)
	Complete   func(context.Context, audit.Record) error
	Available  func(owner, provider string) bool
	History    audit.Appender
	Timeout    func(registry.Entry) time.Duration
}

func (p *Proxy) leaseBinding(e registry.Entry) (string, bool) {
	if p.Security == nil {
		return "", false
	}
	// A misconfigured security adapter fails closed for every provider.
	if p.Security.Credential == nil {
		return "", true
	}
	return p.Security.Credential(p.Owner, e.UpstreamID)
}
func (p *Proxy) requiresLease(e registry.Entry) bool {
	_, required := p.leaseBinding(e)
	return required
}

// leaseListed keeps a bound connector's cached tools listed while its
// credential is locked, unless the connector is disabled.
func (p *Proxy) leaseListed(e registry.Entry) bool {
	return p.requiresLease(e) && (p.Security.Available == nil || p.Security.Available(p.Owner, e.Upstream))
}

func (p *Proxy) mirror(r audit.Record) {
	if p.Security.History == nil {
		return
	}
	if err := p.Security.History.Write(r); err != nil {
		p.Logger.Error("call history copy failed", "event_id", r.EventID, "event_type", r.EventType)
	}
}

// maxLeasedTimeout bounds one admitted call. A connector's own longer call
// timeout is clamped to it; an unset one falls back to 30 seconds.
const maxLeasedTimeout = 5 * time.Minute

func (p *Proxy) leasedTimeout(entry registry.Entry) time.Duration {
	var timeout time.Duration
	if p.Security.Timeout != nil {
		timeout = p.Security.Timeout(entry)
	}
	if timeout <= 0 {
		return 30 * time.Second
	}
	return min(timeout, maxLeasedTimeout)
}

func leaseError(err error) *mcp.CallToolResult {
	switch {
	case errors.Is(err, lease.ErrRequired), errors.Is(err, lease.ErrStale), errors.Is(err, lease.ErrLocked):
		return errorResult("MCPWARDEN_LEASE_REQUIRED: No tool action was executed. An active access window for this caller and tool is required. Resume the request after owner activation.")
	case errors.Is(err, lease.ErrStorage):
		return errorResult("MCPWARDEN_AUDIT_UNAVAILABLE: No tool action was executed. Durable security storage is unavailable.")
	case errors.Is(err, lease.ErrBusy):
		return errorResult("MCPWARDEN_BUSY: No tool action was executed. The caller concurrency limit was reached.")
	default:
		return errorResult("MCPWARDEN_ACCESS_DENIED: No tool action was executed. Credential access or authorized connection setup failed.")
	}
}

func (p *Proxy) callLeased(ctx context.Context, req *mcp.CallToolRequest, entry registry.Entry, credentialID string) (*mcp.CallToolResult, error) {
	started := time.Now()
	r := audit.NewInvocation(ctx, p.Owner)
	r.ToolID, r.Tool, r.UpstreamID, r.Upstream = entry.ID, entry.Tool.Name, entry.UpstreamID, entry.Upstream
	r.ArgsSHA256, r.Decision, r.Status = audit.HashArgs(req.Params.Arguments), "deny", "denied"
	if req.Session != nil {
		r.Session = req.Session.ID()
	}
	timing := &audit.Timing{}
	admitted := false
	var admission audit.Record
	defer func() {
		if admitted && r.EventType != audit.DispatchCompleted {
			p.mirror(admission)
			return
		} // Panic leaves unknown outcome.
		r.CompletedAt = time.Now().UTC()
		r.OccurredAt = r.CompletedAt
		timing.HandlerUS = time.Since(started).Microseconds() - timing.AdmissionUS
		timing.GatewayUS = timing.HandlerUS - timing.UpstreamUS
		r.Timing, r.DurationMS = timing, timing.HandlerUS/1000
		var err error
		if admitted {
			completionCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = p.Security.Complete(completionCtx, r)
			// The best-effort history copies run after dispatch, outside the
			// call timeout, so they never delay or prevent an admitted call.
			p.mirror(admission)
			p.mirror(r)
		} else {
			err = p.Audit.Write(r)
		}
		if err != nil {
			p.Logger.Error("audit write failed", "event_id", r.EventID, "event_type", r.EventType)
		}
	}()
	actor, ok := identity.ActorFrom(ctx)
	if !ok || actor.Owner != p.Owner || !p.Policy.Allow(entry.Tool.Name) || !p.isVisible(entry.Tool.Name) {
		return leaseError(lease.ErrDenied), nil
	}
	if p.Security.Service == nil || p.Security.Complete == nil || credentialID == "" {
		return leaseError(lease.ErrLocked), nil
	}
	callCtx, cancel := context.WithTimeout(ctx, p.leasedTimeout(entry))
	defer cancel()
	prepared, err := upstream.PrepareLeased(callCtx, p.Security.Service, credentialID, entry, req.Params.Arguments)
	if err != nil {
		return leaseError(err), nil
	}
	defer prepared.Close()
	admissionStart := time.Now()
	permit, err := prepared.Admit(callCtx, r)
	timing.AdmissionUS = time.Since(admissionStart).Microseconds()
	if err != nil {
		return leaseError(err), nil
	}
	admitted = true
	r = permit.Record // Preserve the exact durable actor/credential/revision snapshot.
	admission = r
	r.EventID = identity.New()
	var result *mcp.CallToolResult
	err = permit.RunWithMaterial(func(ctx context.Context, material lease.Material) error {
		forwarded := time.Now()
		timing.Forwarded = true
		var err error
		result, err = prepared.Call(ctx, material)
		timing.UpstreamUS = time.Since(forwarded).Microseconds()
		return err
	})
	r.EventType, r.Decision, r.Status = audit.DispatchCompleted, "allow", "ok"
	if err != nil {
		r.Status = "protocol_error"
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			r.Status = "timeout"
		}
		// Admission may already have reached the provider. Never claim safe retry
		// or expose provider/SDK errors, which may contain private response data.
		return errorResult("MCPWARDEN_UPSTREAM_ERROR: The admitted call did not return a usable response. It was not retried; the upstream outcome may be unknown."), nil
	}
	if result == nil {
		r.Status = "protocol_error"
		return errorResult("MCPWARDEN_UPSTREAM_ERROR: No usable upstream response."), nil
	}
	r.ResponseItems, r.Structured = len(result.Content), result.StructuredContent != nil
	if result.IsError {
		r.Status = "tool_error"
	}
	return result, nil
}
