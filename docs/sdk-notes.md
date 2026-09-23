# SDK notes

Verified against `github.com/modelcontextprotocol/go-sdk` v1.8.0 module source:

- `mcp.NewStreamableHTTPHandler` in `mcp/streamable.go` serves stateful HTTP sessions by default.
- `mcp.CommandTransport` in `mcp/cmd.go` starts and terminates stdio children.
- `mcp.ClientOptions.ToolListChangedHandler`, `ClientSession.ListTools`, and `ClientSession.CallTool` are in `mcp/client.go`.
- `mcp.Server.AddTool`, `RemoveTools`, `AddReceivingMiddleware`, and `Sessions` are in `mcp/server.go`.
- `CallToolRequest.Params.Arguments` is `json.RawMessage`; `Tool.InputSchema` and `OutputSchema` accept JSON-marshalable values.
- `auth.RequireBearerToken` and `auth.ProtectedResourceMetadataHandler` are in `auth/auth.go`; the former accepts a caller-supplied token verifier and emits the OAuth resource-metadata challenge.
- `auth.TokenInfoFromContext` exposes the validated OAuth subject to the HTTP handler, and the Streamable HTTP handler carries it through session requests. `mcp.NewStreamableHTTPHandler` can select a per-user server with its request callback. The personal-upstream integration test confirms separate tool inventories.
- The SDK has no exported standalone tool-list-change notification method in v1.8.0. `Server.AddTool` calls `changeAndNotify` even when replacing a tool with the same name, so a visibility change re-registers one provider tool to notify downstream sessions. The integration test confirms the notification and filtered list.

No raw JSON-RPC workaround is used.
