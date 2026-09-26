# Configuration and operations

Start from [the example config](../../examples/config.yaml) for a local binary or [the Compose config](../../examples/compose-config.yaml) for Docker. `${VAR}` placeholders must be set in the process environment.

## Listening and downstream auth

- `listen` defaults to `127.0.0.1:8787`. A non-loopback bind requires `downstream_auth.bearer_token_env`.
- Without [OAuth mode](oauth-mode.md), that bearer token protects the shared operator workspace at `/mcp` and `/api`.
- When `accounts` is enabled, registered users can also authenticate with personal MCP tokens or panel sessions. See [Accounts and access](accounts-and-access.md).
- Set `allowed_origins` for non-loopback browser origins; requests with no Origin and loopback origins are accepted.
- Upstream HTTP headers are configured independently and never inherit a downstream token.

## Managed upstreams

Panel registration requires `managed_upstreams.path` and `managed_upstreams.key_env` in YAML; the key must be base64-encoded 32 bytes. Remote URLs must use HTTPS, except loopback HTTP for local testing.

Personal connectors store header names only. Their credentials live in the owner vault, which needs `owner_security` in accounts mode; without it, only connectors without authentication can be added. `owner_security.custody_mode` no longer exists, and a config that still sets it fails to load. A catalog written by an older build (with stored header values or upstream OAuth settings) is refused with "created by an older build; start with a new catalog"; there is no conversion.

In Compose, the key comes from `MCPWARDEN_CREDENTIAL_KEY` in `.env`. Keep it stable across restarts; losing it makes saved connections unreadable.

## Stdio upstreams

Stdio upstreams inherit only basic process variables: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `TERM`, `TMPDIR` and the Windows equivalents. Pass anything else a command needs through its `env` map, for example `HTTPS_PROXY: ${HTTPS_PROXY}`.

The sample `npx` upstream requires Node.js at runtime; the gateway and its tests do not.

## Health checks

- `/healthz` reports process liveness.
- `/readyz` reports ready when at least one active upstream is healthy. Its public body shows only static or local upstream status, so personal provider names are not disclosed.

## Audit log

Audit records contain workspace owner, stable tool ID, tool name, upstream, decision, status, duration, response item count, structured-response presence, session ID, and a SHA-256 hash of canonical JSON arguments. Raw arguments and results are never written to the audit file.

Tool dispatch requires a file-backed `audit.path` (the Compose default); stdout (`-`) is rejected at startup. See [Tool call history](call-history.md) for how records are written and read.

## Smoke test

Run `scripts/smoke.sh` against a running gateway; set `SMOKE_TOOL` and `SMOKE_ARGS` when the first listed tool requires arguments.
