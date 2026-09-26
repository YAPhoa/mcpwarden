# Upstreams

An upstream is an MCP server that mcpwarden connects to and re-exposes. Upstreams come from two places: shared entries in `config.yaml`, and personal connections that each user adds in the panel.

## Add an upstream

Use **Add upstream** in the panel to register a remote Streamable HTTP URL, timeout, and authentication method:

- **No authentication**
- **Bearer token** (sends `Authorization`)
- **API key header** (one header name, such as `X-API-Key`)
- **Custom headers** (1 to 32 header names, unique ignoring case)

The connection stores header names only, never values. For any method other than no authentication, save the credential in **Vault & windows** (`/vault`): it is encrypted in the browser, and the gateway never holds it. Such connectors are in vault custody from creation:

- The gateway never dials them in the background, and **Refresh** is off (the API returns 409).
- Every tool call needs an access window that you start; without one the call fails with `MCPWARDEN_LEASE_REQUIRED`.
- Tool discovery for them arrives with setup discovery (roadmap step 5). Until then a new credentialed connector has no tools and cannot be used.

Credentialed methods need the owner vault (`owner_security`). Without it, the panel disables them and the API accepts only no authentication. Upstream OAuth is not available; it returns under the vault in roadmap step 6.

Remote URLs must use HTTPS, except loopback HTTP for local testing. Upstream credentials are independent of gateway sign-in and downstream client tokens. Changing a connection's authentication method or header names is not yet supported; remove the connection and add it again.

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

## Search

The panel searches loaded tool metadata, and the API supports provider-specific search. Meilisearch remains an optional future integration if inventories grow enough to need a separate index.
