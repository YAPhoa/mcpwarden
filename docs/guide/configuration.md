# Configuration and operations

Start from [the example config](../../examples/config.yaml) for a local binary (listening on `127.0.0.1:8787`) or [the Compose config](../../examples/compose-config.yaml) for Docker (listening on `0.0.0.0:8787` inside the container, published on 127.0.0.1 only). `${VAR}` placeholders must be set in the process environment.

## Listening and downstream auth

- `listen` defaults to `127.0.0.1:8787`. A non-loopback bind requires `downstream_auth.bearer_token_env`.
- Without [OAuth mode](oauth-mode.md), that bearer token protects the shared operator workspace at `/mcp` and `/api`.
- When `accounts` is enabled, registered users can also authenticate with personal MCP tokens or panel sessions. See [Accounts and access](accounts-and-access.md).
- Set `allowed_origins` for non-loopback browser origins; requests with no Origin and loopback origins are accepted.
- Upstream HTTP headers are configured independently and never inherit a downstream token.

## Storage

The catalog, tool-call history and the owner vault live in one database, set by the `storage` section: a SQLite file (the default, `/data/mcpwarden.db` in Compose) or PostgreSQL. `storage.key_env` names the catalog key, base64-encoded 32 bytes. The gateway refuses to start if the database is unavailable and stops if it is lost; it never falls back. See [storage](../storage.md) for both drivers, backups and the threat model.

In Compose, the key comes from `MCPWARDEN_CREDENTIAL_KEY` in `.env`. Keep it stable across restarts; losing it makes saved connections unreadable.

The keys `audit`, `managed_upstreams` and `owner_security.database_url_env` were removed and are refused at startup, with their replacement in the message. A database created by a development build before the schema reset is refused too; start with a new one.

## Config and personal upstreams

Upstreams in YAML are served to every account and OAuth subject, with the operator's credentials. On a personal gateway, set `accounts.allow_registration: false` once your own account exists, before adding a credentialed config upstream.

Personal connectors are added in the panel. Remote URLs must use HTTPS, except loopback HTTP for local testing. They store header names only; their credentials live in the owner vault, which needs `owner_security` in accounts mode. Without it, only connectors without authentication can be added.

## HTTPS for the panel

The owner vault routes refuse plain HTTP. In Compose, start with the HTTPS override:

```sh
mkdir -p tls && mkcert -cert-file tls/cert.pem -key-file tls/key.pem localhost 127.0.0.1
docker compose -f compose.yaml -f compose.tls.yaml up -d
```

The panel is then at `https://localhost:8443/`, published on 127.0.0.1 like the other ports. `MCPWARDEN_TLS_DIR` selects another certificate directory. The override gives the Compose network the fixed subnet `172.30.87.0/24` and pins the ui container at `172.30.87.2`, the address `owner_security.trusted_proxies` names in the Compose config; if that subnet is taken on your host, change both. nginx overwrites `X-Forwarded-Proto` with its own scheme, so the gateway accepts owner routes only through the HTTPS server. Without the override the panel works over HTTP, but the vault stays closed.

A gateway run directly on the host can use a TLS reverse proxy listed in `trusted_proxies`, or `allow_insecure_loopback: true` for development on loopback.

## Stdio upstreams

Stdio upstreams inherit only basic process variables: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `TERM`, `TMPDIR` and the Windows equivalents. Pass anything else a command needs through its `env` map, for example `HTTPS_PROXY: ${HTTPS_PROXY}`.

The sample `npx` upstream requires Node.js at runtime; the gateway and its tests do not.

## Health checks

- `/healthz` reports process liveness.
- `/readyz` reports ready when at least one active upstream is healthy. Its public body shows only static or local upstream status, so personal provider names are not disclosed.

## Stdio clients

`--stdio` serves one MCP client over stdin and stdout. It needs SQLite storage and cannot share the database with a running gateway: give the gateway and the stdio clients separate `storage.path` values, or connect the clients over HTTP. Several stdio clients with the same config can share one database. They serve config upstreams and owner `local`'s connectors without authentication, and record their calls for owner `local`. See [stdio clients](../storage.md#stdio-clients).

## Call history

History records contain workspace owner, stable tool ID, tool name, upstream, decision, status, duration, response item count, structured-response presence, caller, and a SHA-256 hash of canonical JSON arguments. Raw arguments and results are never stored. Each call's admission is committed before dispatch. See [Tool call history](call-history.md).

## Smoke test

Run `scripts/smoke.sh` against a running gateway; set `SMOKE_TOOL` and `SMOKE_ARGS` when the first listed tool requires arguments.
