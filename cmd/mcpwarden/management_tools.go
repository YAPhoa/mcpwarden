package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/proxy"
)

type toolResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *toolResponse) Header() http.Header    { return w.header }
func (w *toolResponse) WriteHeader(status int) { w.status = status }
func (w *toolResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(b)
}

func (rs *runtimes) registerGatewayTools(owner string, p *proxy.Proxy) {
	providerSchema := json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string","description":"Provider name from the connector page or upstream tool prefix"}},"required":["provider"],"additionalProperties":false}`)
	add := func(name, description string, schema json.RawMessage, admin bool, method string, path func(map[string]json.RawMessage) string, handler http.HandlerFunc) {
		tool := &mcp.Tool{Name: name, Description: description, InputSchema: schema}
		call := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			record := audit.NewInvocation(ctx, owner)
			record.Owner, record.ToolID, record.Tool = owner, name, name
			record.Decision, record.Status = "allow", "ok"
			if req.Session != nil {
				record.Session = req.Session.ID()
			}
			record.ArgsSHA256 = audit.HashArgs(req.Params.Arguments)
			var admissionTime time.Duration
			admitted := false
			defer func() {
				if admitted && record.EventType != audit.DispatchCompleted {
					return // Preserve the admission as unknown if the handler panics.
				}
				record.CompletedAt = time.Now().UTC()
				record.OccurredAt = record.CompletedAt
				if record.EventType == audit.DispatchDenied {
					record.Decision = "deny"
				}
				record.DurationMS = (time.Since(record.TS) - admissionTime).Milliseconds()
				if err := rs.audit.Write(record); err != nil {
					rs.logger.Error("audit write failed", "event_id", record.EventID, "event_type", record.EventType)
				}
			}()
			if credential, ok := accessFrom(ctx); ok && (credential.Owner != owner || admin && credential.Role != "admin") {
				record.Decision = "deny"
				record.Status = "denied"
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "management access required"}}}, nil
			}
			args := map[string]json.RawMessage{}
			_ = json.Unmarshal(req.Params.Arguments, &args)
			endpoint := path(args)
			request, _ := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(req.Params.Arguments))
			if _, ok := accessFrom(ctx); !ok {
				request = request.WithContext(context.WithValue(ctx, accountContextKey{}, accountIdentity{Owner: owner}))
			}
			admissionStart := time.Now()
			err := rs.audit.Write(record.Admission())
			admissionTime = time.Since(admissionStart)
			if err != nil {
				record.Status = "audit_error"
				rs.logger.Error("dispatch admission audit failed", "invocation_id", record.InvocationID)
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "MCPWARDEN_AUDIT_UNAVAILABLE: No provider action was executed. Durable audit storage is unavailable."}}}, nil
			}
			admitted = true
			response := &toolResponse{header: http.Header{}}
			handler(response, request)
			record.EventType = audit.DispatchCompleted
			failed := response.status >= 400
			text := strings.TrimSpace(response.body.String())
			if text == "" {
				text = "Done"
			}
			if failed {
				record.Status = "tool_error"
				text = "Provider action failed. Check the provider name, availability, and management settings."
			}
			record.ResponseItems = 1
			return &mcp.CallToolResult{IsError: failed, Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil
		}
		p.AdminServer.AddTool(tool, call)
		if !admin {
			p.Server.AddTool(tool, call)
		}
	}
	provider := func(args map[string]json.RawMessage) string {
		var name string
		_ = json.Unmarshal(args["provider"], &name)
		return url.PathEscape(name)
	}
	add("warden_refresh_provider", "Refresh one provider's tool discovery. Does not invoke its tools or enable a disabled provider.", providerSchema, false, "POST", func(a map[string]json.RawMessage) string { return "/api/discovery/" + provider(a) + "/refresh" }, rs.discovery)
	add("warden_list_providers", "List providers in your workspace, their UUIDs, status and visibility settings.", json.RawMessage(`{"type":"object","additionalProperties":false}`), true, "GET", func(map[string]json.RawMessage) string { return "/api/providers" }, rs.providers)
	add("warden_add_provider", "Add a personal remote MCP provider. For bearer, api_key and headers, list header names only; the owner stores the values in the vault at /vault.", json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"},"url":{"type":"string"},"call_timeout":{"type":"string"},"header_names":{"type":"array","items":{"type":"string"},"maxItems":32},"auth_type":{"type":"string","enum":["none","bearer","api_key","headers"]}},"required":["name","url"],"additionalProperties":false}`), true, "POST", func(map[string]json.RawMessage) string { return "/api/connections" }, rs.connections)
	add("warden_remove_provider", "Remove a personal provider and its saved credentials and discovered tools.", providerSchema, true, "DELETE", func(a map[string]json.RawMessage) string { return "/api/connections/" + provider(a) }, rs.connection)
	add("warden_set_provider_enabled", "Enable or disable a provider while preserving its credentials and tool choices.", json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"enabled":{"type":"boolean"}},"required":["provider","enabled"],"additionalProperties":false}`), true, "PUT", func(a map[string]json.RawMessage) string { return "/api/providers/" + provider(a) + "/enabled" }, rs.providerTools)
	add("warden_set_tool_visibility", "Select which upstream tools clients can discover. Enabled names use the full MCP wire name.", json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"mode":{"type":"string","enum":["all","selected"]},"enabled":{"type":"array","items":{"type":"string"}}},"required":["provider","mode","enabled"],"additionalProperties":false}`), true, "PUT", func(a map[string]json.RawMessage) string { return "/api/providers/" + provider(a) + "/visibility" }, rs.providerTools)
}
