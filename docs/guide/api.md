# Management API

The admin panel talks to the gateway through this authenticated HTTP API. Responses are scoped to the validated user and never include stored header values or other credentials.

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
| `GET /api/history?...` | Owner-scoped tool call history. See [Tool call history](call-history.md#api). |

Client API keys cannot use the management API except the per-provider refresh endpoint, and cannot read history. See [Accounts and access](accounts-and-access.md#api-keys).

`/healthz` and `/readyz` are unauthenticated; see [Configuration and operations](configuration.md#health-checks).
