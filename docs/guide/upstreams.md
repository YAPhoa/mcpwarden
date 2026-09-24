# Upstreams

An upstream is an MCP server that mcpwarden connects to and re-exposes. Upstreams come from two places: shared entries in `config.yaml`, and personal connections that each user adds in the panel.

## Add an upstream

Use **Add upstream** in the panel to register a remote Streamable HTTP URL, timeout, and request headers. Authentication options:

- **Bearer token**
- **API key header**
- **Custom headers**
- **No authentication**
- **OAuth** (see [below](#upstream-oauth))

The panel hides saved header values. Remote URLs must use HTTPS, except loopback HTTP for local testing. Upstream credentials are independent of gateway sign-in and downstream client tokens. Authentication is configured when adding a connection; editing saved credentials is not yet supported.

The default server image works with HTTP upstreams. For stdio commands in the container, install those commands in a custom image and make their files available there.

## Tool names and identity

Tool labels show the original name (for example `get_notebook_info`), with the connector alongside it. MCP names such as `kaggle-mcp__get_notebook_info` remain unchanged for clients, policies, and saved visibility rules.

- Internal tool keys are stable UUIDs. Existing encrypted connections receive persistent UUIDs automatically on first load.
- Tool IDs derive from the connector UUID and original tool name; renaming an upstream tool creates a different identity.
- Config-only connector UUIDs derive from the owner and configured connector name.

The panel shows cached tool schemas and annotations even when an upstream is offline; offline tools are not advertised to MCP clients.

## Enable and disable connectors

Use **Disable connector** or **Enable connector** at the top of a connector page to pause or resume the connection.

- Disabling stops its upstream session, removes its tools from MCP discovery, and blocks new calls.
- Credentials, cached tool metadata, and individual tool selections remain saved.
- The setting applies to your workspace, including your instance of a shared YAML connector.
- It requires encrypted managed storage.
- Disabling is not a rollback of tool calls already in progress.

Upstreams shows enabled/disabled/total provider counts and per-provider tool counts.

## Choose which tools are exposed

**Enable all tools** and **Disable all tools** apply to the entire selected upstream, independent of search and pagination. Enable all also includes tools discovered later; policy rules and provider availability still apply.

To expose only a few tools from a provider, open its connection details and choose **Selected tools only**, then use the connector tool switches to enable the desired tools. The first switch to that mode hides all its tools.

- Hidden tools remain in the admin panel for management, but they are absent from MCP `tools/list`; direct calls receive a tool error.
- Visibility choices are saved per user and provider.
- The YAML policy still applies after a tool is enabled.

## Upstream OAuth

For an OAuth-capable remote MCP server:

1. Add its MCP endpoint and select **OAuth · Connect account**.
2. Leave client fields blank for dynamic client registration, if the server supports it. Otherwise enter a registered client ID, its issuer URL, and an optional client secret. Register the callback URL shown in the form with that authorization server. Optional scopes narrow the requested permissions.
3. Save the connection, choose **Connect account**, and approve access in the new window. Close that window and reload inventory. Use **Reconnect account** if access is revoked or additional consent is needed.

How it works:

- The gateway uses the SDK's OAuth metadata discovery, authorization-code flow with PKCE, and refresh tokens.
- Grants and rotated refresh tokens are encrypted per account and restored after restart.
- Browser callbacks are one-time, expire after five minutes, and require a separate HttpOnly browser binding.
- For hosted panels, configure their HTTPS origin in `allowed_origins`; the callback must be served through the same panel origin.
- Authorization callbacks are excluded from the bundled nginx access log. Any external reverse proxy should also avoid logging callback query strings.

This authenticates MCP upstreams only. A Google Drive integration still needs a Drive MCP server; a raw Google Drive API URL is not an MCP endpoint. Provider-specific OAuth extensions and built-in Google API adapters are not included.

## Search

The panel searches loaded tool metadata, and the API supports provider-specific search. Meilisearch remains an optional future integration if inventories grow enough to need a separate index.
