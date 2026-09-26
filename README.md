# mcpwarden

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="ui/static/brand/monogram-dark.svg">
  <img src="ui/static/brand/monogram-light.svg" alt="MCPWarden monogram" width="160" height="90">
</picture>

A self-hosted MCP gateway. Point one MCP client at mcpwarden and it serves the tools of all your upstream MCP servers, stdio or Streamable HTTP, under namespaced names like `fs__read_file`.

It ships as two parts: a headless Go server, and a separate admin panel for managing connections, tools, and access.

## Features

- **One endpoint for many servers.** Streamable HTTP at `/mcp`, or one-client `--stdio` mode. Upstreams connect concurrently with retry, namespaced routing, and dynamic tool refresh.
- **Control over tools.** Per-tool allow/deny policy, per-user tool visibility, an approval interface, and a JSONL call audit.
- **Personal connections.** Each user adds their own remote MCP servers, with saved tool discovery and provider search. Credentials for them live only in the owner vault and are used inside access windows the owner starts.
- **Access control.** Panel accounts with named, revocable API keys; operator bearer auth in local mode; or optional OAuth for remote clients such as ChatGPT. Origin checks, `/healthz`, and `/readyz`.
- **Nothing extra to run.** Encrypted local storage by default, behind backend-neutral catalog and audit interfaces; no external database is required. Connectors with credentials need the owner vault (`owner_security`), which uses PostgreSQL until the SQLite store lands.

## Quick start with Docker Compose

```sh
cp examples/compose-config.yaml config.yaml
umask 077
printf 'MCPWARDEN_TOKEN=%s\nMCPWARDEN_CREDENTIAL_KEY=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -base64 32)" > .env
docker compose up --build
```

This starts two services:

| Service | Address | Use |
| --- | --- | --- |
| Gateway | `http://127.0.0.1:8787/mcp` | Point MCP clients here, with the bearer token from `.env`. |
| Admin panel | `http://127.0.0.1:8788/` | Create an account, add upstreams, and mint API keys. |

The panel proxies its API requests to the gateway over the Compose network. The initial config has no upstreams: choose **Create an account** (passphrase of 15+ characters), then **Add upstream**.

> [!IMPORTANT]
> Keep `MCPWARDEN_CREDENTIAL_KEY` in `.env` stable across restarts. Losing it makes saved connections unreadable.

The default server image works with HTTP upstreams. To run stdio commands inside the container, install them in a custom image.

## Run the binary locally

Requires Go 1.27 or newer. Replace the sample upstreams in the config with servers available on your machine.

```sh
go build -o mcpwarden ./cmd/mcpwarden
cp examples/config.yaml config.yaml
./mcpwarden --config config.yaml
```

The local binary runs only the server; connect an MCP client to `http://127.0.0.1:8787/mcp`. Stdio upstreams get a minimal environment, so pass extra variables through each upstream's `env` map (see [configuration](docs/guide/configuration.md#stdio-upstreams)).

To use it as a stdio server from Claude Desktop, add this to `claude_desktop_config.json` with absolute paths:

```json
{"mcpServers":{"mcpwarden":{"command":"/absolute/path/to/mcpwarden","args":["--stdio","--config","/absolute/path/to/config.yaml"]}}}
```

Or from Claude Code:

```sh
claude mcp add mcpwarden -- /absolute/path/to/mcpwarden --stdio --config /absolute/path/to/config.yaml
```

## Documentation

| Guide | Covers |
| --- | --- |
| [Accounts and access](docs/guide/accounts-and-access.md) | Registration, the panel, API keys and roles, sessions, limits, workspaces. |
| [Upstreams](docs/guide/upstreams.md) | Adding servers, upstream auth and the vault, enabling connectors and tools, tool identity. |
| [OAuth mode (ChatGPT)](docs/guide/oauth-mode.md) | Using an external identity provider so ChatGPT can connect. |
| [Configuration and operations](docs/guide/configuration.md) | `listen`, downstream auth, origins, managed storage, stdio env, health checks, audit. |
| [Tool call history](docs/guide/call-history.md) | The History page, its API, and how calls are recorded. |
| [Management API](docs/guide/api.md) | Every `/api` endpoint. |

Design and project records: [decisions](docs/decisions.md), [SDK notes](docs/sdk-notes.md), [progress](docs/progress.md), [catalog storage](docs/catalog-storage.md), and [history storage](docs/history-storage.md).

## Security roadmap

Security spec v1.1 includes integrated public caller-key IDs and durable dispatch audit, plus a tested lease engine, PostgreSQL encrypted storage, browser [vault primitives](docs/security/vault-storage.md), and an [encrypted MCP dispatch adapter](docs/security/encrypted-runtime.md). With `owner_security` set, personal connector credentials are held only in the owner vault and every call to a credentialed connector needs an access window. Setup discovery (step 5) and vault-backed upstream OAuth (step 6) are still to come, so new credentialed connectors have no tools yet.

See the [review and implementation roadmap](docs/security/implementation.md) and the [remaining implementation tasks](docs/pending-tasks.md), which describe the work still needed.

## Development

```sh
go build ./... && go vet ./... && go test -race ./...
```

- Integration tests use local SDK mock servers and a helper process. They need permission to bind loopback ports, but no external network.
- The optional Go/WebCrypto interoperability test uses Node.js and skips when Node is unavailable.
- The optional PostgreSQL tests use a separate local fixture on port 55432. See [lease storage and migration](docs/security/lease-storage.md) for setup and the metadata migration command. PostgreSQL is not yet a selectable gateway catalog backend.
- Sonic handles catalog snapshot encoding and new security/storage JSON; legacy audit argument hashing retains its original serializer.

GitHub Actions checks build/vet/race behavior with PostgreSQL, UI crypto and three browser engines, dependency vulnerabilities, secrets, workflow syntax and both container images. See [CI setup and local commands](docs/ci.md).
