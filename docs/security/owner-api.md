# Owner security API

Roadmap step 1. The routes below are registered only when `owner_security` is set
in accounts mode. They run the lease engine, encrypted vault records and custody
index against PostgreSQL schema v3. Tool execution still uses file custody and does
not consult leases until guarded startup (step 4), so this API can be enabled and
exercised without changing how existing providers are called.

```yaml
owner_security:
  database_url_env: MCPWARDEN_SECURITY_DATABASE_URL  # runtime role DSN, never inline
```

Startup opens the executor session, starts a new boot (old windows are suspended),
loads every credential head and approval policy in one read-only snapshot, and
validates them before any route is served. A failure stops startup.

## Routes

| Route | Methods | Who |
|---|---|---|
| `/api/security/csrf` | GET | Owner browser |
| `/api/security/approval-policy` | GET, PUT | Owner browser; PUT needs the current password and `expected_revision` |
| `/api/security/events` | GET `?limit=1..200` | Owner browser |
| `/api/vault/state` | GET | Owner browser |
| `/api/vault/setup` | POST | Owner browser; current password; once per owner |
| `/api/vault/wrappers` | GET, PUT | Owner browser; PUT needs the current password and `expected_wrapper_revision` |
| `/api/vault/lock-execution` | POST | Owner browser |
| `/api/vault/credentials` | GET | Owner browser or API key (selectable tools only) |
| `/api/vault/credentials/{id}` | PUT, DELETE | Owner browser; epoch/revision CAS |
| `/api/access-requests`, `/{id}` | GET, POST | API key (its own requests) or owner browser (all) |
| `/api/approvals/{id}/begin`, `/deny`, `/activate` | POST | Owner browser only |
| `/api/leases`, `/{id}` | GET, DELETE | API key (its own windows) or owner browser |

Owner-only fields on a request (`gateway_boot_id`, `scope_digest`,
`request_digest`, `challenge`) are never returned to the requesting key.

## Enforcement

- **Interactive browser only.** Owner routes reject any request with an
  `Authorization` header (403), even if a valid session cookie is also sent, and
  audit the first attempts per key as `owner_route.rejected` / `api_key`. They then
  require a session cookie whose access record is an active `browser` record.
  API keys, admin keys and MCP sessions can never confirm or activate, in mode
  `none` or `confirm`.
- **CSRF and Origin.** Unsafe methods need an `Origin` in the configured
  allowlist, served over HTTPS (plain HTTP only for loopback development);
  `Sec-Fetch-Site`, when sent, must be `same-origin`; `X-CSRF-Token` must equal
  an HMAC of the session secret under a per-process key; bodies must be
  `application/json`. Every response is `no-store`.
- **Fresh authentication.** Approval-policy changes, vault setup and wrapper
  changes verify the current account password under the shared sign-in budget.
- **Activation.** Needs an `Idempotency-Key` UUID and echoes the owner-only
  boot ID, challenge, request digest and credential epoch before the key is
  released. An identical retry returns the same window; a new operation on a
  used request is refused. Rejections are audited as `activation.rejected`
  with reason `key`, `stale`, `denied` or `not_found`.
- **Limits.** Per-route body caps (256 KiB access requests, 128 KiB credential
  records, 16 KiB vault roots, 4 KiB everything else), strict JSON (duplicate or
  unknown keys fail), fixed windows of 120 requests/min per owner, 60/min per API
  key and 20 activations/min per owner.
- **Atomic changes.** Policy, root and credential writes run in `ChangeAtomic`:
  the record, its audit event, stale pending requests and revoked windows commit
  together, and caches publish only after commit.
- **Revocation.** Revoking an API key ends its windows through the coordinator
  first. If storage is lost, the key is still revoked in the catalog; the executor
  is already locked and restarts with every old window suspended. Signing out or
  revoking a browser session does not end approved windows (L09).
- **Fail closed.** A lost executor session returns 423/503 on every lease and
  vault route and publishes nothing.

Until the PostgreSQL catalog lands (step 3), tool-policy and connector-security
revisions are fixed at `1`; admission and activation still recheck live tool
visibility, policy and definition digests. Credentials bind to header-bundle
HTTP connectors whose URL and header names match exactly; private networks are
limited to loopback HTTP development until step 8.

## Tests

`cmd/mcpwarden/security_test.go` drives the real mux against a scratch PostgreSQL
database (`internal/lease/postgres/pgtest`) with real AES-GCM envelopes:
browser-only activation and CSRF/Origin rejections, replay and owner isolation,
`confirm` mode and policy changes, credential lifecycle across restart, concurrent
CAS writes and activations, key revocation, executor loss and request limits.
See the [acceptance matrix](acceptance-matrix.md) for per-case status.
