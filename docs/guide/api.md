# Management API

The admin panel talks to the gateway through this authenticated HTTP API. Responses are scoped to the validated user and never include stored header values or other credentials.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/auth/options` | Public sign-in mode and registration availability. |
| `POST /api/auth/register`, `/api/auth/login`, `/api/auth/logout` | Basic local account registration and browser sessions. |
| `POST /api/auth/client-token` | Legacy compatibility: replace the legacy client-only key from a browser session. |
| `GET/POST /api/access` | List access records or mint a named admin/client API key (admin only). |
| `PATCH/DELETE /api/access/{id}` | Rename or revoke an owned key/session (admin only). |
| `GET /api/status` | Readiness and validated workspace identity (no credentials). The session includes `vault: true` when this workspace can hold credentialed connectors: `owner_security` is on and the caller is signed in to a local account. |
| `GET /api/providers` | List the current user's providers, health, discovered tool count, and last discovery time. |
| `GET /api/providers/{name}/tools?search=term` | List and search one provider's discovered tools. |
| `GET` / `PUT /api/providers/{name}/visibility` | Read or set `{"mode":"all"}` or `{"mode":"selected","enabled":["name__tool"]}`. |
| `GET /api/tools?provider=name&search=term` | Search across the current user's cached or live tools. |
| `POST /api/discovery/{name}/refresh` | Request a fresh upstream `tools/list`. Returns 409 for a connector in vault custody. |
| `GET /api/connections` | List personal upstreams with header names, never values. Credentialed connectors carry `custody: "vault"`. |
| `POST /api/connections` / `DELETE /api/connections/{name}` | Add or remove a personal remote MCP endpoint. |
| `GET /api/history?...` | Owner-scoped tool call history. See [Tool call history](call-history.md#api). |

`POST /api/connections` takes `name`, `url`, `call_timeout`, `auth_type` (`none`, `bearer`, `api_key` or `headers`) and `header_names`: none for `none`, exactly `Authorization` for `bearer`, one name for `api_key`, and 1 to 32 unique names for `headers`. Header values are never accepted: a request with `headers` gets a 400 pointing to the vault (`/vault`), where the owner saves the credential. `auth_type: oauth` and an `oauth` object are refused until vault-backed upstream OAuth (roadmap step 6). Credentialed types need `owner_security` and a local-account owner; other workspaces (the operator's `local` workspace, OAuth subjects) and gateways without the vault accept only `none`. Their `url` must be one the vault destination accepts, compared as sent: HTTPS with a lowercase host name or public IP, an explicit path such as `/mcp`, no dot segments or encoded slashes, and no leading-zero port; or HTTP on `localhost`, `127.x.x.x` or `[::1]`. The admin MCP tool `warden_add_provider` takes the same `header_names` array. See [Upstreams](upstreams.md#add-an-upstream).

Client API keys cannot use the management API except the per-provider refresh endpoint, and cannot read history. See [Accounts and access](accounts-and-access.md#api-keys).

`/healthz` and `/readyz` are unauthenticated; see [Configuration and operations](configuration.md#health-checks).
