# Owner security API

Roadmap step 1. The routes below are registered only when `owner_security` is set
in accounts mode with a [`storage`](../storage.md) database. They run the lease
engine, encrypted vault records and custody index against that database
(PostgreSQL or SQLite). With `owner_security` set, every personal
connector with credentials runs only through access windows; see
[startup integration](encrypted-runtime.md#startup-integration). Without it, only
connectors without authentication can be created.

```yaml
storage:
  driver: sqlite                  # or postgres with database_url_env
  path: /data/mcpwarden.db
  key_env: MCPWARDEN_CREDENTIAL_KEY
owner_security:
  trusted_proxies: []             # explicit immediate proxy CIDRs
  allow_insecure_loopback: false  # direct local development only
```

`owner_security.database_url_env` was replaced by `storage.database_url_env` and
is refused.

Startup opens the executor session, starts a new boot (old windows are suspended),
loads every credential head and approval policy in one read-only snapshot, and
validates them before any route is served. A failure stops startup.

Production requires HTTPS. The API accepts direct TLS, or exactly one
`X-Forwarded-Proto: https` value from an immediate peer listed in
`trusted_proxies`. Use the actual proxy address as seen by the gateway, with a
narrow CIDR (for example `192.0.2.8/32`); hostnames and catch-all networks are
rejected. The trusted proxy must overwrite the header from verified transport
state, never preserve client input. Protect the proxy-to-gateway connection and
prevent clients from bypassing that proxy. Forwarding headers from all other
peers are ignored as evidence of TLS.

The bundled UI nginx service is an HTTP proxy, not a TLS terminator. Enabling this
API requires an explicitly configured HTTPS ingress and a protected proxy chain;
do not simply trust the UI container while allowing it to forward arbitrary
client headers. Direct development HTTP requires `allow_insecure_loopback: true`,
both a loopback socket peer and loopback Host, and no forwarding headers. This
exception does not apply to container-network or proxied requests, even with a
loopback Origin. The default Compose deployment leaves `owner_security` unset.

## Routes

| Route | Methods | Who |
|---|---|---|
| `/api/security/csrf` | GET | Owner browser |
| `/api/security/approval-policy` | GET, PUT | Owner browser; PUT needs the current password and `expected_revision` |
| `/api/security/events` | GET `?limit=1..200` | Owner browser |
| `/api/vault/state` | GET | Owner browser |
| `/api/vault/setup` | POST | Owner browser; current password; once per owner |
| `/api/vault/wrappers` | GET, PUT | Owner browser. GET includes each live credential's current `envelope` so the browser can authenticate it before releasing a key. PUT needs the current password and `expected_wrapper_revision` |
| `/api/vault/lock-execution` | POST | Owner browser |
| `/api/vault/credentials` | GET | Owner browser or API key (selectable tools only) |
| `/api/vault/credentials/{id}` | PUT, DELETE | Owner browser; epoch/revision CAS |
| `/api/access-requests`, `/{id}` | GET, POST | API key (its own requests) or owner browser (all). `"purpose": "setup_discovery"` is owner browser only |
| `/api/approvals/{id}/begin`, `/deny`, `/activate` | POST | Owner browser only |
| `/api/leases`, `/{id}` | GET `[?include=ended]`, DELETE | API key (its own windows) or owner browser. `include=ended` adds windows that ended in the last 24 hours (at most 50, newest first, with `ended_at`) |
| `/api/leases/{id}/discover` | POST | Owner browser that requested and started the setup window; runs Connect and inspect once |

Requests and windows carry `purpose`: `tool_use`, or `setup_discovery` for
Connect and inspect. A setup request names no tools and no `max_calls`, lasts
at most 300 seconds, and its requester is the calling browser session. The
discover route answers `{provider, tool_count, tools}` with the tool names,
409 `stale` when the window ended, was already run or changed, and 502
`discovery_failed` when the upstream failed or returned an invalid list; the
window ends either way. See
[Connect and inspect](encrypted-runtime.md#connect-and-inspect-setup-discovery).

Owner-only fields on a request (`gateway_boot_id`, `scope_digest`,
`request_digest`, `challenge`) are never returned to the requesting key.

## Enforcement

- **Verified transport.** All routes reject insecure requests before reading
  credentials or bodies. An HTTPS Origin, URL or untrusted forwarding header
  does not prove that the connection is encrypted.
- **Interactive browser only.** Owner routes reject any request with an
  `Authorization` header (403), even if a valid session cookie is also sent, and
  audit the first attempts per key as `owner_route.rejected` / `api_key`. They then
  require a session cookie whose access record is an active `browser` record.
  API keys, admin keys and MCP sessions can never confirm or activate, in mode
  `none` or `confirm`.
- **CSRF and Origin.** Unsafe methods need an `Origin` in the configured
  allowlist with an HTTPS scheme (HTTP loopback origins are accepted only when
  the independent transport check also passes);
  `Sec-Fetch-Site`, when sent, must be `same-origin`; `X-CSRF-Token` must equal
  an HMAC of the session secret under a per-process key; bodies must be
  `application/json`. Every response is `no-store`.
- **Fresh authentication.** Approval-policy changes, vault setup and wrapper
  changes verify the current account password under the shared sign-in budget.
  The checked password verifier must still match under the owner gate after any
  database wait; a concurrent password change invalidates that proof.
- **Activation.** Needs an `Idempotency-Key` UUID and echoes the owner-only
  boot ID, challenge, request digest and credential epoch before the key is
  released. An identical retry returns the same window; a new operation on a
  used request is refused. Rejections are audited as `activation.rejected`
  with reason `key`, `stale`, `denied` or `not_found`.
- **Limits.** Per-route body caps (256 KiB access requests, 128 KiB credential
  records, 16 KiB vault roots, 4 KiB everything else), strict JSON (duplicate or
  unknown keys fail), fixed windows of 120 requests/min per owner, 60/min per API
  key and 20 activations/min per owner.
- **Atomic changes.** Policy, root and credential writes run in `ChangeOwnerAtomic`:
  the record, its audit event, stale pending requests and revoked windows commit
  together, and caches publish only after commit. Browser authority is rechecked
  after acquiring the database owner lock and after writes, so session revocation
  or expiry during body upload, hashing or lock waits cannot reuse stale HTTP
  authorization. Logout, session replacement, explicit session revocation and
  password changes share the owner gate through commit and cache publication.
- **Revocation.** Revoking an API key ends its windows through the coordinator
  first. If storage is lost, the key is still revoked in the catalog; the executor
  is already locked and restarts with every old window suspended. Signing out or
  revoking a browser session does not end approved windows (L09), and still works
  when PostgreSQL is unavailable.
- **Fail closed.** A lost executor session prevents mutations and lease operations
  with 423/503 and publishes nothing. Cached metadata reads do not grant authority.

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
`security_transport_test.go` rejects forged HTTPS headers before reading a CEK
and covers the trusted-proxy and direct-loopback boundaries.
`security_authorization_test.go` covers session revocation during uploads,
replacement, password changes and expiry while queued on the database owner
lock. Lease tests verify rollback on expiry during writes and serialization of
revocation through commit and publication.
See the [acceptance matrix](acceptance-matrix.md) for per-case status.
