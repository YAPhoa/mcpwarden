# mcpwarden

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="ui/static/brand/monogram-dark.svg">
  <img src="ui/static/brand/monogram-light.svg" alt="MCPWarden monogram" width="160" height="90">
</picture>

A self-hosted MCP gateway with a headless Go server and a separate admin panel. Connect one MCP client to mcpwarden; it aggregates tools from stdio and Streamable HTTP upstreams under names like `fs__read_file`.

## Features

- Streamable HTTP at `/mcp`, or one-client `--stdio` mode
- Concurrent upstream connection, retry, namespaced tool routing, and dynamic tool refresh
- Per-tool allow/deny policy, an approval interface, and JSONL call audit
- Personal remote MCP connections with private headers, saved tool discovery, provider search, and per-user tool visibility
- Optional OAuth protection for remote MCP clients, operator bearer auth in local mode, Origin checks, `/healthz`, and `/readyz`
- Encrypted local storage by default, with backend-neutral catalog and audit boundaries; no external database is required

Security spec v1.1 includes integrated public caller-key IDs and durable dispatch
audit, plus a tested lease engine, PostgreSQL encrypted storage, browser
[vault primitives](docs/security/vault-storage.md), and opt-in
[encrypted MCP dispatch adapter](docs/security/encrypted-runtime.md). Owner vault
screens and live lease enforcement remain under development; current credential
storage remains server managed. See the
[review and implementation roadmap](docs/security/implementation.md).

## Run with Compose

Compose starts two services: the headless gateway on `127.0.0.1:8787` and the admin UI on `127.0.0.1:8788`. The UI proxies its API requests to the gateway over the Compose network.

```sh
cp examples/compose-config.yaml config.yaml
umask 077
printf 'MCPWARDEN_TOKEN=%s\nMCPWARDEN_CREDENTIAL_KEY=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -base64 32)" > .env
docker compose up --build
```

Open `http://127.0.0.1:8788/` for the admin panel, and configure MCP clients with `http://127.0.0.1:8787/mcp` plus the bearer token. The initial Compose config has no upstreams. Use **Add upstream** in the panel to register a remote Streamable HTTP URL, timeout, and request headers. Choose **Bearer token** for a bearer credential, **API key header**, **Custom headers**, **No authentication**, or **OAuth**. The panel hides saved header values. Keep the credential key in `.env` stable across restarts; losing it makes saved connections unreadable. The default server image works with HTTP upstreams. For stdio commands in the container, install those commands in a custom image and make their files available there.

### Panel accounts

The Compose example enables basic username/password registration. Open the panel, choose **Create an account**, and use a passphrase of at least 15 characters. Each account has its own remote connections, private headers, and tool visibility. The sidebar shows the current account. The dashboard is the landing page, with workspace totals and links to connectors. Opening an upstream shows its searchable, paginated tool list and manual enable switches. Filter by **Discoverable** or **Not discoverable**; expand **Connection settings** for endpoints, credentials, refresh and removal. The top breadcrumb links back to Upstreams. The separate tool directory searches across connections. **Refresh all** on Upstreams fetches fresh tool metadata for every enabled connector and reports individual failures. The bottom-left **Account & appearance** menu contains theme selection, sign out, and local-account password changes. Changing a password requires the current password and revokes other browser sessions; API keys remain active. MCP connection instructions live under **Access**. Browser Back/Forward and direct links work.

Enable accounts on an existing local-mode deployment with:

```yaml
accounts:
  allow_registration: true
```

This requires `managed_upstreams`. Set `allow_registration: false` after the intended users register if signup should be closed. Accounts cannot be combined with external OAuth mode. Account registration grants a personal workspace, not global administrator privileges. Shared config upstreams remain available to every account, so use config entries only for intentionally shared services. Basic accounts do not yet include password reset, email verification, account deletion, or account administration.

The existing encrypted catalog stores salted PBKDF2-SHA256 password hashes (600,000 iterations). Browser sessions use HttpOnly, SameSite=Strict cookies, expire after 12 hours, and persist across gateway restarts. Cookies require HTTPS outside loopback; serve the public panel over HTTPS. JSON requests with a custom header and origin checks protect session mutations. Authentication requests have a shared limit of 30/minute and at most two password computations at a time.

Use **Access** after sign-in to create a named, expiring API key for `/mcp`. Choose **Client** for enabled upstream tools and per-provider refresh, or **Admin** for those tools plus provider listing, addition, removal, enable/disable, and tool visibility management. Client keys cannot use the management API; they may use the per-provider refresh endpoint. Keys are shown once and only their hashes are stored. Existing single client tokens migrate to client-only keys. Browser session cookies are not accepted for MCP connections. The shared operator token remains usable through **Use an access token**; existing operator connections stay in that separate shared workspace.

The **Access** page lists named API keys, browser sessions, observed OAuth tokens, and active MCP connections. It supports rename and revocation, shows device/client names and creation/last-use/expiry times, and keeps ended/revoked history. Server-enforced limits per workspace are **10 active API keys**, **10 active browser/OAuth sessions combined**, and **10 concurrent MCP connections across all credentials**. Revocation and expiry free capacity. New keys expire after 1–365 days. MCP sessions expire with their credential and have a 30-minute idle timeout; process restart ends old MCP connections. Revoking a key closes its MCP connections; revoking an MCP connection leaves its key usable. Session IDs are bound to the exact credential and role, not just the account.

New named keys use `mcpw_<public ID>_<secret>`. Access pages display a short public-ID suffix, lengthened on collisions, and the full public ID in details. Existing `mw_` keys retain their tokens and verifier hashes and receive independent public IDs on catalog load. Call history keeps the exact authenticated access ID and label snapshot across renames and reconnects; `GET /api/history?actor_access_id=...` filters that owner's calls for one access record. Public handles do not grant authentication or approval authority.

OAuth revocation blocks that observed access token locally at this gateway; it does not revoke the identity provider's grant or future tokens. The configured operator bootstrap token is managed in configuration and is outside the minted-key list and limit. Encrypted lifecycle records retain creation, update, last-use, end/revocation and deletion times where applicable; provider deletion retains a credential-free UUID tombstone.

Each registered upstream belongs to one gateway user. Operator-token access has one shared user named `local`; registered accounts use separate internal identities. With OAuth mode, the validated access-token `sub` identifies the user for both `/mcp` and `/api`; each user can register a separate endpoint and headers, even under the same upstream name. Static YAML upstreams remain available to every user. By default, the gateway stores personal connections and the last successful tool discovery in an AES-GCM encrypted file under `/data`. Managed state and audit history now sit behind separate backend interfaces so a database adapter can be added without changing runtime or authentication logic; a PostgreSQL driver and schema are not bundled. See [the catalog storage contract](docs/catalog-storage.md) and [the history storage contract](docs/history-storage.md).

To expose only a few tools from a provider, open its connection details and choose **Selected tools only**, then use the connector tool switches to enable the desired tools. The first switch to that mode hides all its tools. Hidden tools remain in the admin panel for management, but they are absent from MCP `tools/list`; direct calls receive a tool error. Visibility choices are saved per user and provider. The YAML policy still applies after a tool is enabled.

## Upstream identity, availability, and authentication

Tool labels show the original name (for example `get_notebook_info`), with the connector alongside it. Internal tool keys are stable UUIDs; MCP names such as `kaggle-mcp__get_notebook_info` remain unchanged for clients, policies, and saved visibility rules. Existing encrypted connections receive persistent UUIDs automatically on first load. Tool IDs derive from the connector UUID and original tool name; renaming an upstream tool creates a different identity. Config-only connector UUIDs derive from the owner and configured connector name.

Use **Disable connector** or **Enable connector** at the top of a connector page to pause or resume the connection. Disabling stops its upstream session, removes its tools from MCP discovery, and blocks new calls. Credentials, cached tool metadata, and individual tool selections remain saved. The setting applies to your workspace, including your instance of a shared YAML connector. It requires encrypted managed storage. Upstreams shows enabled/disabled/total provider counts and per-provider tool counts. **Enable all tools** and **Disable all tools** apply to the entire selected upstream, independent of search and pagination. Enable all also includes tools discovered later; policy rules and provider availability still apply. Disabling is not a rollback of tool calls already in progress.

For an OAuth-capable remote MCP server:

1. Add its MCP endpoint and select **OAuth · Connect account**.
2. Leave client fields blank for dynamic client registration, if the server supports it. Otherwise enter a registered client ID, its issuer URL, and an optional client secret. Register the callback URL shown in the form with that authorization server. Optional scopes narrow the requested permissions.
3. Save the connection, choose **Connect account**, and approve access in the new window. Close that window and reload inventory. Use **Reconnect account** if access is revoked or additional consent is needed.

The gateway uses the SDK's OAuth metadata discovery, authorization-code flow with PKCE, and refresh tokens. Grants and rotated refresh tokens are encrypted per account and restored after restart. Browser callbacks are one-time, expire after five minutes, and require a separate HttpOnly browser binding. For hosted panels, configure their HTTPS origin in `allowed_origins`; the callback must be served through the same panel origin. Authorization callbacks are excluded from the bundled nginx access log. Any external reverse proxy should also avoid logging callback query strings.

This authenticates MCP upstreams. A Google Drive integration still needs a Drive MCP server; a raw Google Drive API URL is not an MCP endpoint. Provider-specific OAuth extensions and built-in Google API adapters are not included. Upstream credentials are independent of gateway sign-in and downstream client tokens. Authentication is configured when adding a connection; editing saved credentials is not yet supported.

## Connect from ChatGPT with OAuth

ChatGPT connects to remote MCP servers and can use OAuth 2.1. Configure an external identity provider with authorization-code + PKCE, its discovery document, a ChatGPT-compatible OAuth client, and token introspection. Copy [the OAuth example](examples/oauth-config.yaml) to `config.yaml`, set its public HTTPS `resource` and provider URLs, then set `MCPWARDEN_INTROSPECTION_CLIENT_ID` and `MCPWARDEN_INTROSPECTION_CLIENT_SECRET` in the Compose environment. The provider must issue access tokens whose audience matches `oauth.resource`, with an expiration and the configured scopes. mcpwarden validates those values on each `/mcp` request and publishes `/.well-known/oauth-protected-resource` for discovery.

In OAuth mode, the admin API requires an access token for the same user with the `mcp:manage` scope. The MCP view also uses that scope to select admin tools; tokens with client scopes receive only client tools. The panel currently accepts that token in its access-token dialog; an interactive browser login flow is not yet included. The local operator token does not grant access to `/mcp` or `/api` in OAuth mode. Use a public HTTPS endpoint or [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) for ChatGPT; the default loopback Compose binding is only for local clients. OpenAI's [MCP authentication guide](https://developers.openai.com/plugins/build/auth) describes provider discovery, PKCE, callback, audience, and refresh-token requirements. A live ChatGPT connection needs an identity provider and ChatGPT app setup, so the repository tests use a mock provider.

## Run the server locally

Requires Go 1.27 or newer. Copy and edit [the example config](examples/config.yaml); replace the sample upstreams with servers available on your machine. `${VAR}` placeholders must be set in the process environment. Stdio upstreams inherit only basic process variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `TERM`, `TMPDIR` and the Windows equivalents); pass anything else a command needs through its `env` map, for example `HTTPS_PROXY: ${HTTPS_PROXY}`. The sample `npx` upstream requires Node.js at runtime; the gateway and its tests do not.

```sh
go build -o mcpwarden ./cmd/mcpwarden
cp examples/config.yaml config.yaml
./mcpwarden --config config.yaml
```

The local binary runs only the server. Connect an MCP client to `http://127.0.0.1:8787/mcp`. Run `scripts/smoke.sh` against a running gateway; set `SMOKE_TOOL` and `SMOKE_ARGS` when the first listed tool requires arguments.

For a local Claude Desktop stdio connection, use an absolute binary and config path in `claude_desktop_config.json`:

```json
{"mcpServers":{"mcpwarden":{"command":"/absolute/path/to/mcpwarden","args":["--stdio","--config","/absolute/path/to/config.yaml"]}}}
```

For Claude Code, register the same local stdio command:

```sh
claude mcp add mcpwarden -- /absolute/path/to/mcpwarden --stdio --config /absolute/path/to/config.yaml
```

The panel searches loaded tool metadata, and the API supports provider-specific search. Meilisearch remains an optional future integration if inventories grow enough to need a separate index.

## Configuration and operations

`listen` defaults to `127.0.0.1:8787`. A non-loopback bind requires `downstream_auth.bearer_token_env`. Without OAuth mode, that bearer token protects the shared operator workspace at `/mcp` and `/api`. When `accounts` is enabled, registered users can also authenticate with personal MCP tokens or panel sessions. Set `allowed_origins` for non-loopback browser origins; requests with no Origin and loopback origins are accepted. Upstream HTTP headers are configured independently and never inherit a downstream token. Panel registration requires `managed_upstreams.path` and `managed_upstreams.key_env` in YAML; the key must be base64-encoded 32 bytes. Remote URLs must use HTTPS, except loopback HTTP for local testing.

`/healthz` reports process liveness. `/readyz` reports ready when at least one active upstream is healthy; its public body shows only static or local upstream status, so personal provider names are not disclosed. The authenticated API provides:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/auth/options` | Public sign-in mode and registration availability. |
| `POST /api/auth/register`, `/api/auth/login`, `/api/auth/logout` | Basic local account registration and browser sessions. |
| `POST /api/auth/client-token` | Legacy compatibility: replace the legacy client-only key from a browser session. |
| `GET/POST /api/access` | List access records or mint a named admin/client API key (admin only). |
| `PATCH/DELETE /api/access/{id}` | Rename or revoke an owned key/session (admin only). |
| `GET /api/status` | Readiness and validated workspace identity (no credentials). |
| `GET /api/providers` | List the current user's providers, health, discovered tool count, and last discovery time. |
| `GET /api/providers/{name}/tools?search=term` | List and search one provider's discovered tools. |
| `GET` / `PUT /api/providers/{name}/visibility` | Read or set `{"mode":"all"}` or `{"mode":"selected","enabled":["name__tool"]}`. |
| `GET /api/tools?provider=name&search=term` | Search across the current user's cached or live tools. |
| `POST /api/discovery/{name}/refresh` | Request a fresh upstream `tools/list`. |
| `GET /api/connections` | List personal upstreams with header names, never values. |
| `POST /api/connections` / `DELETE /api/connections/{name}` | Add or remove a personal remote MCP endpoint. |

The panel shows cached tool schemas and annotations even when an upstream is offline; offline tools are not advertised to MCP clients. Audit records contain workspace owner, stable tool ID, tool name, upstream, decision, status, duration, response item count, structured-response presence, session ID, and a SHA-256 hash of canonical JSON arguments. Raw arguments and results are never written to the audit file.

Run checks with `go build ./... && go vet ./... && go test -race ./...`. The integration tests use local SDK mock servers and a helper process; they need permission to bind loopback ports, but no external network. The optional Go/WebCrypto interoperability test uses Node.js and explicitly skips when Node is unavailable.

The optional PostgreSQL tests use a separate local fixture on port 55432. See
[lease storage and migration](docs/security/lease-storage.md) for setup and the
metadata migration command. PostgreSQL is not yet a selectable gateway catalog
backend. Sonic handles catalog snapshot encoding and new security/storage JSON;
legacy audit argument hashing retains its original serializer.

See [decisions](docs/decisions.md), [SDK notes](docs/sdk-notes.md), and [progress](docs/progress.md).


## Tool call history

The **History** page lists your workspace's recorded calls with tool, local time, outcome, duration, and response metadata. Calls are grouped by upstream service on each page. Filter by a From/Until date and hour/minute range (Until is exclusive), status, or upstream service; an optional tool filter narrows the selected service. pages contain 25 calls, newest recorded first. Each tool's detail dialog also has a scoped **History** tab. The authenticated management API is `GET /api/history?upstream=...&tool_id=...&status=...&from=...&to=...&page=...`; timestamps use RFC3339. It never accepts a user/owner parameter and excludes session IDs and argument hashes from its response. Client credentials cannot read history.

Tool dispatch requires a file-backed `audit.path` (the Compose default); stdout (`-`) is rejected at startup. Admission is synced before any upstream or gateway-management MCP action. Failed admission blocks execution. Completion is appended separately; failure to record completion preserves the actual result and never retries the action. History shows unmatched admissions as **Outcome unknown**, which may include work still running. It is not evidence of failure or safe retry. SDK validation failures before handler dispatch are not call records. Old ownerless records remain excluded; payloads, result bodies, raw errors and verifiers are not retained in history.

Call records are append-only. Stored tool UUIDs and name snapshots preserve history when a tool or connector is removed; connector deletion does not cascade into call history. Reserved management tools use their stable gateway names as IDs. Reads scan JSONL with bounded page selection (up to page 1000) plus state for unpaired admission/completion events. Use time filters for older records. For high-volume use, an indexed store and explicit retention policy remain necessary.

## Development checks

GitHub Actions checks build/vet/race behavior with PostgreSQL, UI crypto and three
browser engines, dependency vulnerabilities, secrets, workflow syntax and both
container images. See [CI setup and local commands](docs/ci.md). The
[remaining implementation tasks](docs/pending-tasks.md) describe the work needed
before client-release custody can be enabled.
