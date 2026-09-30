# Decisions

## 2026-09-22 — Lease coordinator, PostgreSQL metadata and Sonic

The user authorized PostgreSQL testing/migration design and selected Sonic after
considering JSON v2. Pin Sonic v1.15.4 behind `internal/jsoncodec`, retaining strict
validation on authorization inputs and byte-compatible catalog snapshot encoding.
Keep the historical audit argument hash on its existing serializer. Use the pinned
RFC 8785 implementation for approval hashes, after duplicate/Unicode/number
validation. No experimental Go flags or MCP SDK dependency changes are required.

Implement leases as a separate owner-coordinated state machine. All permissions
for a call must come from one finite, caller/epoch/boot-bound lease. Owner `none`
activation still requires an interactive browser identity and key release;
`confirm` adds a separate bounded decision. Neither admin nor client MCP keys can
self-confirm/activate. Material remains opaque and temporary; concrete credential
decryption and the browser lifecycle are not implemented in this slice. Fixed
deadlines survive retries unchanged; a database row never recreates activation.

Use pgx v5.11.0 and a reviewed component schema instead of promoting the candidate
spec SQL to a production catalog migration. One dedicated session holds executor
ownership and serializes short transactions. Sample the database clock after
owner locking, commit budget plus audit atomically, publish material only after
commit, and stop execution on lock loss or ambiguous commit. Separate runtime and
migration roles; grant no runtime audit mutations or DDL. Restore suspends prior
leases. No automatic database or tool retry is added.

The existing gateway remains on file custody/JSONL until the owner API, encrypted
credential handles and all security mutations use this coordinator. The generic
MCP SDK continues to own the wire protocol; this change introduces no custom
JSON-RPC transport and no enabled client-release configuration. See the
[storage/migration contract and validation boundaries](security/lease-storage.md).

## 2026-09-22 — Security v1.1 baseline, caller IDs and durable admission

Adopt the supplied timed, multi-call client-release specification as a staged
roadmap, starting with exact caller attribution and admission durability. The
gateway remains trusted with a released credential during execution; vault roots
and recovery keys must stay client-side in the eventual mode. Initial interactive
activation will use local-account owner sessions, separately from ordinary MCP
admin keys. `none` must never mean self-activation, permanent decryption or traffic
renewal. Push/TOTP remain optional and unselected. See the
[review and milestone boundaries](security/implementation.md).

New named keys carry independent random public IDs and 32-byte secrets, strictly
parsed, retaining SHA-256 over the entire issued token. Legacy verifiers and token
formats are preserved; display IDs are backfilled independently and persisted.
Audit uses the authenticated record, never a secret suffix or claimed client name.
Storeless legacy verifier-derived binding IDs do not enter audit actor metadata.

Inspected pinned SDK v1.8.0 `mcp/streamable.go`, `mcp/requests.go`,
`mcp/protocol.go` and connection context handling. Stateful handlers retain their
initial context while HTTP verifies credential/role binding; re-read that exact
access record in receiving middleware for current lifecycle and label snapshots.
No custom JSON-RPC encoding is introduced. Admission failures use SDK tool errors
with plain text and no fabricated `structuredContent` or automatic retry.

Use schema-v2 append-only admitted/completed/denied events and stable invocation
IDs. `audit.Appender.Write` now requires durable success for admitted events. Both
MCP views and gateway-management tools sync admission before invoking the action.
Reject stdout as configured dispatch audit storage. Completion errors preserve
actual tool results. History joins by owner/invocation and shows unknown completion
without inventing success, failure, or retry safety. V0/v1 history stays unchanged;
the argument-hash algorithm and existing handler timing semantics are preserved,
with admission persistence measured separately. This is not the future atomic
lease/counter/revocation gate. See [history storage](history-storage.md).

## 2026-09-22 — Portable immutable history events

Keep JSONL behind append/query interfaces and version completed-call records with
event ID, completion time and stable upstream ID. Order history by completion time
then event ID, replacing reverse physical log order. Preserve call-start date filters
and owner isolation. Legacy rows are normalized only in memory. Sync file writes,
reject malformed history and incomplete tails, and surface management audit failures
in logs without retrying MCP calls or changing already executed outcomes. No SDK calls
change. See [history storage contract](history-storage.md) for migration, deduplication,
single-writer and durability limits.

## SDK and protocol

- Pin the official Go MCP SDK to v1.8.0. Its stateful Streamable HTTP handler negotiates the legacy session protocol when needed, including the `initialize` and `Mcp-Session-Id` flow used by the smoke script. This preserves compatibility with existing clients. The SDK also handles newer protocol negotiation where the transport supports it.
- Register all valid upstream tools with the SDK and filter denied or unhealthy tools in SDK `tools/list` middleware. The SDK's ordinary tool handler then returns a visible tool error for direct calls to denied or unhealthy names. SDK `AddTool`/`RemoveTools` sends downstream list change notifications.
- Keep cached tool definitions while an upstream is unhealthy. Their list visibility changes immediately, and direct calls report that the upstream is unavailable. On refresh, removed tools are unregistered.
- Use the SDK's `CommandTransport` for stdio child cleanup. Its source closes stdin, waits, then sends SIGTERM and SIGKILL if needed.

## UI and search

- The Go gateway is headless. The separate `ui/` component runs in its own Nginx container with Compose. Nginx serves the admin panel and proxies `/api/` to the server over the Compose network. The browser stores its access token only in session storage.
- Panel-managed remote MCP connections are separate per user. In local mode the operator token selects the single `local` user. In OAuth mode the validated `sub` selects a user-specific MCP server, upstream sessions, headers, tool registry, and cached discovery. Static YAML upstreams are included in each user's registry.
- Personal connection definitions, header values, and last successful tool discovery are saved in one AES-GCM encrypted file. A base64 32-byte environment key is required; the file is written atomically with mode 0600. Header values are never returned by the admin API.
- Visibility is stored per user and provider. Providers default to showing all policy-allowed healthy tools. In selected mode, only explicitly enabled namespaced tools appear in MCP `tools/list`; direct calls to other tools return an audited tool error. The admin inventory continues to show hidden tools so they can be enabled again. Updating visibility re-registers one provider tool through the SDK to trigger its standard downstream list-change notification.
- The API supports provider listing and provider-specific tool listing and search; the panel also filters loaded metadata locally. Meilisearch would add an external service and indexing lifecycle, so it is left as a future option if inventories grow. No MCP search meta-tool is exposed.

## OAuth for ChatGPT

- At the user's request, `/mcp` can act as an OAuth protected resource. An external OAuth 2.1 provider performs authorization-code + PKCE, client registration, and refresh-token issuance. mcpwarden publishes protected-resource metadata and validates each bearer token through the provider's introspection endpoint, checking activity, expiration, audience, optional issuer, and scopes.
- The gateway does not mint OAuth tokens or host login pages. In OAuth mode, `/mcp` requires `mcp:tools` and `/api` requires `mcp:manage`; both use the same validated subject so personal connections match across clients. The panel currently accepts an access token supplied by the user. In local mode, one operator bearer token protects both endpoints.
- The resource identifier and authorization-server issuer are explicit config values so they can match the HTTPS URLs exposed to ChatGPT through a public endpoint or a Secure MCP Tunnel.


## Basic local panel accounts (2026-09-21)

The user explicitly expanded the UI scope to basic account registration. Local accounts are optional (`accounts.allow_registration`), require encrypted managed storage, and are mutually exclusive with external OAuth mode. They use opaque internal owner IDs, so existing per-owner runtime, discovery, registration and visibility isolation also apply to these accounts. No new database or OAuth authorization server was introduced. The static operator token continues to select the existing `local` workspace.

Passwords use the Go standard library PBKDF2-HMAC-SHA256 implementation, 600,000 iterations, independent random 16-byte salts, and constant-time comparison. This keeps dependencies unchanged while following the PBKDF2 work factor in the [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). Browser sessions use random opaque values (only hashes retained in server memory), 12-hour expiry, HttpOnly/SameSite=Strict cookies and Secure outside loopback. State-changing browser requests require a custom header and JSON; the server does not permit cross-origin CORS reads, and retains origin checks, following [OWASP's custom-header CSRF pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#employing-custom-request-headers-for-ajaxapi).

Personal MCP client tokens use random opaque bearer credentials, stored only as hashes and explicitly replaced by the user. They select the same owner as the panel account. Session cookies are intentionally not accepted at `/mcp`. These local bearer credentials do not implement an OAuth flow; external OAuth mode continues to use the external provider and management scope.

Registration creates personal accounts, not global administrators. Existing config upstreams remain shared across users; that must be intentional in the gateway configuration. Password reset, account deletion, email delivery, user administration, and federation between local/OAuth identities remain outside this basic flow.


## Stable tool identity and upstream authentication — 2026-09-21

The user requested original UI tool names, UUID internal keys, unchanged MCP names, a provider switch, and different upstream authentication methods. Managed connector IDs are persisted UUIDv4 values, migrated atomically inside the existing encrypted catalog. Tool registry keys are UUIDv5 values derived from the connector UUID and exact original tool name, following [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-5). Static connector IDs are deterministic per owner/name. MCP name aliases continue to route calls and preserve policy/visibility compatibility. No database or tool rename API was added.

Provider availability is persisted separately from tool selections within the owner/provider settings. The manager replaces connection generations when disabling/enabling, preventing late discovery callbacks from reviving disabled tools. The registry retains cached tool metadata while marking it unavailable, so list filtering and direct-call checks continue to enforce availability.

Upstream OAuth uses the pinned Go SDK v1.8.0 `auth.AuthorizationCodeHandler`, inspected in local module source, with preregistered issuer-bound clients or dynamic registration. The existing pinned `golang.org/x/oauth2` module is now a direct dependency for token-source persistence; no new module was downloaded. The SDK handles resource/issuer validation, PKCE/state and code exchange. The application adds explicit browser initiation, a one-time HttpOnly/SameSite=Lax callback binding (without weakening the main Strict session cookie), five-minute expiry, per-owner encrypted grants, refresh-token rotation persistence, stale-grant write rejection and connection restart. Background connection attempts only report that sign-in is required. HTTP endpoints are limited to HTTPS or loopback HTTP for local upstreams; redirects are not followed with credentials. OAuth errors are sanitized rather than exposing token endpoint responses.

The same panel origin hosts `/api/upstream-oauth/callback`. Its Origin is checked at initiation, and callback state plus browser binding are checked before code exchange; callbacks do not need the cross-site Strict account session cookie. Bundled nginx does not access-log this route. External proxies must apply equivalent query-string redaction. Generic MCP OAuth does not implement a Google Drive API adapter. See [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) and [Google's separate API OAuth flow](https://developers.google.com/identity/protocols/oauth2/web-server).


## 2026-09-21 — Access roles and transport sessions

Use two SDK MCP servers per workspace: a client view with upstream tools plus `warden_refresh_provider`, and an admin view with the same tools plus `warden_list_providers`, `warden_add_provider`, `warden_remove_provider`, `warden_set_provider_enabled`, and `warden_set_tool_visibility`. Role selection occurs after credential validation. Management handlers retain owner isolation and reject client credentials; the refresh HTTP route permits clients.

SDK v1.8.0 Streamable HTTP uses authenticated UserID to bind sessions. Bind it to credential ID plus role, preserving actual workspace owner separately in context. Track initialized ServerSessions, enforce the workspace cap, close them on revocation/expiry, and mark records ended on transport completion or process restart. Recheck credentials under the session lock to cover initialization/revocation races.

Store hashed credentials and lifecycle metadata in the existing encrypted catalog. Browser sessions are persistent; OAuth access tokens are observed only after external validation and remain subject to that validation on every request. Revocation is gateway-local for the observed token. Limits are 10 active minted keys, 10 combined browser/OAuth sessions, and 10 concurrent MCP connections per owner. Static configuration operator credentials remain recovery credentials outside the minted-key list. Migrate legacy account MCP tokens to client-only records. No embedded OAuth authorization server is introduced.

## 2026-09-21 — Refresh during connector initialization

Each connector generation signals completion of its first connection/discovery attempt. Manual refresh waits for that signal with a bounded, cancellable timeout and checks the generation is still current. Disabled connectors still reject refresh. This closes the asynchronous enable-to-session-ready window without changing MCP tool visibility or permitting stale callbacks to restore disabled tools.


## 2026-09-21 — Call history without a new database

Add owner and tool identity to the existing JSONL audit records. History readers require the validated workspace owner and expose only safe response metadata. Tool filters derive from that owner's recorded identities, including removed connectors. From is inclusive and Until exclusive; records paginate in reverse log order. Older ownerless records are omitted. Retain stable UUIDs and name snapshots, avoiding cascade deletion; reserved management tool IDs are their stable names. The user discussed soft delete/foreign keys; append-only history provides retention now without adding a relational store. An indexed store and retention workflow should precede high-volume deployment.

Password changes use the existing hashing/rate controls, require the current password and a browser session, atomically replace the password hash, and revoke other browser sessions. Keep the current session and API keys. Runtime shutdown now closes downstream sessions and joins their persistent cleanup to avoid storage writes after shutdown.

## 2026-09-21 — Persistent proxy timings and request error isolation

Every upstream tool invocation through either MCP role records microsecond handler, upstream and gateway durations in its existing owner-scoped audit event, including failures and denials. Upstream duration surrounds Manager.Call (SDK work, transport and remote execution); gateway duration is the remaining handler time, including argument hashing, policy and approval. These are not end-to-end client latency: credential verification before dispatch, audit persistence, SDK response encoding and client delivery are excluded. Timing presence distinguishes new records from legacy history; forwarded=false distinguishes denied/unavailable calls from upstream attempts. Gateway management tools keep their existing duration records and are excluded from proxy breakdown summaries.

History aggregates all matching timed records while scanning the existing log, with constant-memory histograms, mean, maximum and p50/p95 upper bounds. Filters remain owner-scoped; API clients cannot obtain other users' metrics. Fixed powers-of-two microsecond buckets trade precision for bounded memory. The overflow bucket uses the observed maximum as a conservative bound. Per-record durations remain precise to microseconds. This adds no payload logging, remote exporter or database. At larger traffic volumes, index/rotate the audit store and export histograms to a metrics backend; repeated whole-log scans are not a high-volume metrics store.

Pinned Go SDK v1.8.0 returns request decoding errors through CallTool without necessarily terminating the transport. Do not close the shared session on every CallTool error: the existing session.Wait connection loop handles actual transport termination. A malformed content response must fail that call without invalidating concurrent/following calls. Do not rewrite arbitrary upstream responses or retry tools automatically (tools may have side effects).

## 2026-09-24 — Narrow repair of non-array tool content

Kaggle's `authorize` tool returns `tools/call` results whose `content` is a bare string. Pinned SDK v1.8.0 rejects the whole result, so the caller only sees a decoding error. The user chose a narrow repair over keeping the failure. The upstream manager now wraps two shapes before SDK decoding, and only in responses to `tools/call`: a string becomes one text block, and a single content object becomes a one-element array. Every other field, message and shape (numbers, null, missing content, errors, notifications) passes through unchanged, and other malformed content still fails its own call without dropping the session. Streamable HTTP applies this in the client round tripper for JSON and SSE bodies, because wrapping the SDK connection would hide the streamable connection's unexported session hooks. Stdio wraps the SDK connection and matches responses to outgoing `tools/call` request IDs; an ID is retired by its response, by the outgoing `notifications/cancelled` naming it (the SDK has already retired the call and the peer may never answer), or by a failed write. The SSE wrapper holds at most one event of `mcp.DefaultMaxEventSize`, counting every line, and the transport sets the same `MaxEventSize` explicitly because the pinned SDK's Streamable HTTP reader treats zero as uncapped. The opt-in leased adapter is not installed at startup and does not apply the repair. The general rule above stands: no other upstream rewriting and no automatic retries.

## 2026-09-22 — Backend-neutral managed-state boundary

The encrypted catalog was directly coupled to runtime, authentication, access management, and upstream OAuth through `*catalog.Store`. Introduce `catalog.Repository` as the managed-state boundary and make those consumers depend on it. Keep the existing encrypted file store as the default implementation and add a no-op close method for lifecycle parity with connection-pool-backed stores. The contract requires concurrency safety, owner isolation, defensive reads, durable atomic mutations, transactional uniqueness/limit/CAS behavior, stable identity and lifecycle preservation, and protection of all secret-bearing fields at rest. Audit history remains a separate existing `audit.Store` boundary. No PostgreSQL driver, schema, configuration, or migration is added; a future adapter can implement both contracts and be wired at startup without changing business/runtime code. See [catalog storage contract](catalog-storage.md).

## 2026-09-23 — Encrypted material and leased SDK execution

Keep real credential activation separate from coherent metadata reads. The
header-bundle activator authenticates the exact current owner/connector/credential/
epoch/revision/destination using the spec's AES-GCM/JCS envelope. It consumes only
a selected CEK, clears its input, retains only opaque header material, and creates
no permanent server unwrap key. No production encryption API ships before the
browser lifecycle and durable CAS/nonce/cross-writer usage controls are ready.

Use separate lease capabilities for connection maintenance and tool dispatch.
Maintenance must already match a complete tool-use scope and counts against
caller concurrency. Final admission rechecks the exact prepared activation and
commits before a tool call. Context values alone are insufficient: the transport
checks the original callback lifetime, live authority and clocks, including after
DNS resolution. Admission records the material's authenticated revision; revision
drift fails closed until a coordinated refresh/replacement implementation exists.

Preserve legacy `audit.HashArgs` bytes. Its float64 normalization can map distinct
large JSON integers to the same hash, so it is not used as a wire-dispatch
capability. An ephemeral number-preserving Sonic encoding binds the actual
arguments instead. This does not change RFC 8785 approval hashes or store raw
arguments.

Inspected the pinned SDK v1.8.0 `Client.Connect`, `ClientSession.CallTool`,
`StreamableClientTransport.Connect/Write/Close`, and `ensureLogger` in local module
source. Connect can negotiate `server/discover` or fall back to legacy initialize;
call contexts reach HTTP POSTs, while connection context detachment preserves
values and does not preserve our original lifetime. Negative `MaxRetries` disables
SSE reconnect; `DisableStandaloneSSE`, no keepalive/subscription callbacks, no
OAuth handler and one transport claim prevent autonomous credential use or replay.
An OAuth handler can itself retry a request after authorization, so it is excluded
from this first adapter until explicit refresh authority/CAS is implemented.

Start with a bounded session per call and verify the actual selected tool
definition under maintenance before admission. The optional proxy adapter bypasses
per-call approval and lists cached visible tools while locked. The SDK's DELETE
on closing an old session carries its expired maintenance context and is rejected
locally; local session resources still close. Session pooling, remote cleanup and
load qualification are explicit future work, not hidden background authority.
Both legacy `2025-11-25` and modern `2026-07-28` downstreams are tested through
both proxy views with actual encrypted headers and PostgreSQL durable admission.

The versioned destination profile binds exact endpoint, header names and network
policy. The dedicated transport uses checked IP dialing, rejects mixed unsafe DNS
answers, disables proxies/redirects/replay, and permits HTTP only for explicit
loopback development profiles. Primary IP policy references and the exact release
boundary are recorded in [encrypted runtime](security/encrypted-runtime.md).
Application startup remains on legacy custody until browser setup/recovery,
encrypted persistence, owner APIs, catalog migration and coordinated mutation
paths are complete. This adapter is not a new accepted configuration switch.

## 2026-09-23 — Browser wrapping and atomic ciphertext storage

Keep vault roots and passphrase/recovery derivation in a dedicated browser worker.
Use the spec's exact AES-256-GCM/HKDF formats and fixed Argon2id profile. Vendor
hash-wasm 4.12.0 with license, npm integrity and file hashes; independent ASCII and
Unicode vectors verify its output. Its public API cannot wipe every WASM buffer,
so each derivation gets a one-use child worker, terminated on completion/error.
This does not claim guaranteed physical memory erasure or a completed dependency
audit. Main-panel integration and broader device qualification remain pending.

Add schema v2 without editing the deployed v1 SQL/checksum. Keep immutable encrypted
versions, current pointers, tombstones and database-enforced nonce/write limits.
Migrate only an exact pinned ledger prefix; unknown or incomplete runtime schemas
fail closed. Place ciphertext mutations and lease revocation in `ChangeAtomic`'s
owner transaction, then publish owned cache buffers and catalog authority after
commit. Publication failure or uncertain commit locks access; no callback retries.
The real MCP test now activates ciphertext read from PostgreSQL. No SDK call
semantics, legacy argument hash, gateway configuration or production custody mode
change. See [vault storage](security/vault-storage.md) for contracts and gates.

## 2026-09-23 — Downstream discovery readiness in integration tests

`Proxy.Changed` replaces the internal registry before registering individual tools
in the SDK servers. Verified the pinned Go SDK v1.8.0 `mcp/server.go`: `AddTool`
validates and publishes one tool through `changeAndNotify`; there is no atomic
batch publication implied by the registry count. Concurrent discovery can
therefore expose an intermediate downstream inventory during startup or refresh.

The gateway integration test now waits for the client-visible `tools/list`
inventory after internal discovery, and likewise for the iterator after a dynamic
tool addition. This corrects the readiness signal behind an intermittent hosted
race-test failure without adding sleeps, skipping assertions or changing runtime
behavior. Policy, call, timing, cancellation and list-change notification checks
remain in place.

## 2026-09-23 — Stdio upstream environment allowlist

Stdio upstreams previously inherited the whole gateway environment, which holds
the catalog key, operator bearer token and OAuth introspection credentials. Any
configured stdio command could read the key that decrypts every user's saved
connections. The child now receives only a fixed set of basic process variables
(`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LANGUAGE`, `LC_*`, `TZ`,
`TERM`, `TMPDIR` and Windows process basics) plus its explicit `env` map, which
wins over inherited values. Proxy settings and runtime-specific variables such as
`NODE_OPTIONS` are not inherited; operators pass them with `${VAR}` placeholders.
Process isolation beyond the environment remains in the pending hardening work.

## 2026-09-23 — Owner security API storage and request protection

Keep accounts, browser sessions and API keys in the file catalog for step 1; the
owner API is opt-in (`owner_security`, accounts mode only) and adds only
per-owner approval policies and new audit event types to PostgreSQL (schema v3).
Moving identity and catalog records is step 3. API-key revocation calls the lease
coordinator first so it ends the key's windows, and falls back to a direct catalog
revocation when storage is lost or execution is locked, so a database outage
never blocks revoking a key. Browser sign-out does not end windows.

Owner routes accept only an active browser session and refuse any request that
carries an `Authorization` header, so no MCP key can confirm or activate even in
mode `none`. CSRF tokens are an HMAC of the session secret under a per-process
key (no server-side token store; a restart invalidates them), combined with an
exact Origin allowlist, HTTPS outside loopback development, same-origin fetch
metadata and JSON-only bodies. Policy, vault setup and wrapper changes re-verify
the account password under the existing sign-in budget. Rate limits are
in-memory fixed windows, which is adequate for one executor process.

The default approval mode for owners without a stored policy is `confirm`.
Tool-policy and connector-security revisions are fixed at `1` until the
PostgreSQL catalog tracks them; admission and activation still recheck live
visibility, policy and definition digests. See
[owner API](security/owner-api.md).

## 2026-09-23 — Owner API transport and concurrent authorization

An HTTPS Origin authenticates neither the incoming transport nor a proxy hop.
Check direct TLS or an explicitly trusted immediate proxy before authentication
and body parsing on every security route. Trusted CIDRs are opt-in; only a single
`X-Forwarded-Proto: https` assertion is accepted, and the proxy must overwrite
client-supplied values. Plain HTTP development is a separate opt-in restricted
to direct loopback peers and hosts without forwarding headers. The existing HTTP
Compose UI does not establish this trust by itself.

Initial cookie validation cannot authorize a mutation after a slow upload or
database wait. `ChangeOwnerAtomic` rechecks the interactive browser inside the
owner transaction after acquiring the durable owner lock, then checks expiry
again after writes. `ChangeSessions` serializes logout, login replacement,
explicit session revocation and password changes with that transaction and its
cache publication. It requires no database operation and does not revoke agent
windows, preserving the browser-lock/execution-lock distinction. Expensive
password hashing stays outside the gate; its exact verifier is checked again
under the gate before root or policy changes. The trusted `ChangeAtomic` entry
point remains available to non-HTTP integrations.

## 2026-09-24 — Owner vault and access-window console

Build the console as a separate static module beside `app.js`, joined only by
`mcpwarden:identity` and `mcpwarden:route` events and a small
`MCPWardenWorkspace` object. It reuses `VaultClient` and the pinned worker
unchanged, apart from an `active` flag that reports whether a worker exists.
Owner requests never carry an Authorization header. They refresh the CSRF token
once on `csrf_required`, which the gateway checks before running the handler.
Every lock bumps a generation counter, and responses from an older generation
are dropped. Each operation captures the generation and its vault worker before
its first await and publishes results only after checking it. Locking restores
every operation's submit control, so a cancelled operation never leaves one
disabled. Unlock, renewal and credential entry also run as an operation that
their Cancel control ends: closing the dialog in any way, or cancelling the
unlock form, stops the flow before key release, approval or upload. After an
activation or upload is sent, cancellation no longer discards its outcome. A
cancelled credential save reports that outcome on the page and leaves the dialog
alone, because it may already hold a newer form. Only the operation that still
owns the dialog closes it, clears it or shows field errors. A refresh clears only
the page error it set itself, so an action's error survives the reload it
triggers.

Browser lock is separate from windows. Sign-out, account changes, leaving
`/vault`, page hide and 10 minutes without input terminate the worker, clear
sensitive inputs and drop late responses. None of them ends an agent window;
"Stop access" and "Lock all execution" do. Leaving `/vault` for another console
page counts as navigating away, so owners unlock again when they come back.

The recovery key is shown once as Crockford base32 with a SHA-256 checksum. It is
accepted with or without hyphens, in any case, and with I/L/O read as 1/1/0.
Setup uploads the root only after the typed key opens the recovery wrapper in a
separate worker. A wrong account password leaves no vault on the server.

Credential entry covers existing personal HTTP connectors with header
authentication (bearer, API key or custom headers) at HTTPS or loopback HTTP
endpoints. The destination profile is computed in the browser with the gateway's
JCS digest; shared Go and JavaScript vectors pin it. Replacing a credential is an
epoch rotation under the same credential ID with a new key. The gateway's legacy
header copy is left untouched and still serves ordinary calls.

Activation sends only the selected credential key, bound to the server's boot
ID, request digest and challenge, with a fresh Idempotency-Key. When the outcome
is uncertain (network failure or 5xx), the console keeps that key in page memory
and offers "Check status" and "Retry the same activation". It never creates a new
request automatically. Renewal creates a new owner request with the same caller,
credential, tools, constraints and call limit, then goes through the same
explicit start. The gateway binds that request to the current tool definitions
and credential version, so the console compares the returned scope with the one
the dialog showed. If anything the owner reviews differs (caller, credential
version, definition digests, constraints, duration or call limit), it shows the
new request and releases no key until the owner allows it again. It defaults to 15 minutes, with 5, 30 and 60 as options.

Two small additive API changes support the page. GET `/api/vault/wrappers` now
returns each live credential's current envelope, which the worker must
authenticate before releasing a key; the server still cannot decrypt it, and the
key-facing credential list is unchanged. GET `/api/leases?include=ended` adds
windows that ended in the last 24 hours, capped at 50 and newest first, with an
`ended_at` time. Key callers still see only their own. Countdowns correct for
clock skew over 2 seconds using the gateway's `Date` header, and a window's end
time is never computed in the browser.

## 2026-09-25 — PostgreSQL catalog, verified migration and reconciling rollback

The user approved roadmap step 3 with three conditions: a tested rollback that
never revives revoked authority and keeps new history (spec §20.5), the full
step 3 coordination (owner gate, atomic change plus audit, publication after
commit), and import verification from a consistent protected snapshot that goes
beyond counts and IDs. The live file backend stays unchanged and the default.

- **Custody.** Secret-bearing values are sealed with AES-GCM under keys derived
  by HKDF-SHA256 from the existing catalog key, with the row identity as
  associated data. Verifier lookup uses an HMAC digest. This relocates legacy
  server-managed custody; it is not client encryption. The user accepted keeping
  the server key for this step.
- **Coordination.** `lease.Service.Catalog` runs each catalog mutation inside
  one owner transaction under the owner gate, with the security event. API-key
  revocation and client-token replacement also end the owner's windows, as the
  file mode's guard does. Connector deletion ends them too, which the file mode
  does not, because the deleted connector's credential must not stay usable.
  It runs even for
  a blocked owner, so revocations never wait for a restart. The repository takes
  its view lock inside the transaction and releases it when it publishes after
  commit. The file backend's guards stay unset in this mode: calling back into
  the service under the owner gate would deadlock.
- **Failure.** An uncertain commit or a lost executor session marks the
  repository failed. Authentication then fails, mutations return unavailable,
  and the process exits. There is no fallback to the file.
- **History.** One row per record holds the exact JSONL bytes plus indexed
  columns, so query results match the JSONL reader. Latency means come from
  stored sums and can differ in the last float digits.
- **Import.** Import runs under the executor advisory lock and an exclusive
  `flock` on `<catalog>.lock`. The file gateway now holds that lock shared for
  its lifetime, its only behavior change. It reads a hash-pinned 0700 snapshot
  copy. Verification decodes every row and compares the canonical catalog and
  every history byte with the snapshot, both after import and again at cutover.
  History checkpoints persist the SHA-256 state so a resumed import still
  proves the whole file.
- **Rollback.** Rollback exports PostgreSQL's current state and does not
  restore the pre-cutover file. It suspends windows first, drops OAuth grants
  whose revision changed after cutover (the user required reauthorization), ends
  MCP sessions and appends new history to the pinned bytes. Marker files plus a
  database state check stop an older catalog file from starting, and a finished
  rollback stamps the exported file with its ID.
- **Tools.** The image ships `mcpwarden-security-db` and `mcpwarden-catalog`, so
  the migration runs with the gateway's own volume and key.


## 2026-09-25 — Step 3 review: provider authority, marker ownership, history columns

- **Provider changes are connector security.** Disabling or enabling a
  provider, or changing which tools are visible, now commits with the end of
  that connector's pending requests and windows and a higher connector security
  revision. `lease.Service.Catalog` takes the ending from the mutation
  (`lease.Ending`), so a repeated setting ends nothing and other connectors keep
  their windows. The revision is sealed in the visibility row, starts at zero on
  import and is dropped by a rollback export. Tool policy still reports a fixed
  revision: it comes from the config file, and changing it needs a restart that
  ends every window. With the file catalog and owner security the handlers end
  all of the owner's windows first, as key revocation does.
- **Markers belong to one database.** Each migration step checks the marker
  before replacing it: it must be absent or carry the import and rollback IDs
  of the database the step runs against. A `rolled_back` marker is the one
  exception; a new import keeps it inside its own marker and abort restores it.
  Import records itself in the database before writing its marker, so an
  importing marker without state in its database is never the tool's own.
- **History verification reads what queries read.** Cutover compares every
  derived history column with what `audit.ParseLine` derives from the pinned
  line, not only the stored bytes.

## 2026-09-25 — Step 3 second review: rollback export identity, resumable abort

- **Import after a rollback needs the export.** A `rolled_back` marker admits
  only the file that rollback wrote, so import now compares the snapshot's
  rollback ID with the marker before it writes any row, on a fresh run and on
  resume. A refused import leaves the marker as it was.
- **Abort keeps its ownership until the marker is clean.** Schema v4 (not yet
  applied to any live database) gains the `aborting` state. Abort deletes the
  imported rows and records `aborting` in one commit, cleans up the marker, then
  deletes the state. A retry against the same database finishes the cleanup; a
  different database still refuses the marker. File gateways with owner
  security refuse to start while a state is `aborting`.

## 2026-09-25 — Step 4: guarded execution for HTTP header connectors

- **Explicit custody mode.** `owner_security.custody_mode` is `legacy_managed`
  (default, unchanged behavior) or `client_release`. There is no automatic
  upgrade; the spec's other modes are rejected at startup. `--stdio` refuses
  `client_release`, because stdio mode never opens the owner security executor.
- **A vault credential converts its connector.** In `client_release`, an HTTP
  header connector with a vault credential head is bound to it. The owner
  converts a connector by saving its credential in the vault console; no
  separate switch exists. Conversion takes effect when the custody index
  publishes after commit, and the legacy session then closes. A deleted vault
  credential leaves a tombstone that keeps the connector bound and locked; it
  never falls back to legacy execution. Replacing the connector gives it a new
  ID and legacy custody again. A head does not record the mode that wrote it, so
  credentials saved or removed under `legacy_managed` convert (or lock) their
  connectors on the first `client_release` start; the legacy remove dialog says
  so. Locking only client_release-era tombstones would need the mode stored
  with the deletion and was not built (review round 1, 2026-09-25).
- **Legacy calls re-check custody after admission.** Routing is decided before
  the durable legacy admission, and conversion publishes independently of it.
  The proxy therefore re-checks the binding after admission and before
  `Manager.Call`, and maps `upstream.ErrGuarded` to the same
  `MCPWARDEN_LEASE_REQUIRED` denial, recorded as not forwarded. A call whose
  re-check ran before the binding published is ordered before conversion; the
  credential save returns only after the legacy session is closed (review
  round 3, 2026-09-25). The denial keeps the admission's `allow` decision and
  records status `denied`, since audit accepts `deny` only on
  `tool.dispatch.denied` (round 4).
- **Startup loads custody before any runtime.** The file backend now opens the
  owner security executor and loads its caches before the first runtime is
  built, as the PostgreSQL backend already did. A converted connector is built
  guarded: the legacy manager keeps its state entry but never connects it and
  drops its server-held headers and OAuth handler from its copy. The new boot
  starts with no active material; cached tools stay listed and calls need a new
  owner-activated window.
- **Server-held headers are kept, unused.** The sealed catalog headers of a
  converted connector are not read for it while `client_release` is on.
  Switching back to `legacy_managed` is the rollback; it also returns
  tombstoned connectors to their server-held headers. Purging them is a separate
  step; Yohanes chose to keep them on 2026-09-25.
- **No legacy discovery for converted connectors.** Refresh returns 409
  (`upstream.ErrGuarded`); tool definitions come from the last legacy discovery
  in the catalog and every leased call verifies the selected definition. Owner
  setup discovery is step 5.
- **Call history.** The durable admission and completion stay in the lease
  store. The proxy also writes a best-effort copy of both to the owner's call
  history so guarded calls appear there with credential, lease and approval
  attribution. A failed copy is logged and never affects the call.
- **Status reporting.** Providers and tools report `custody: "vault"`. Such a
  connector is not `healthy` (it has no session), counts as ready while enabled,
  and its cached tools leave `tools/list` while it is disabled.

## 2026-09-26 — Vault-only custody for personal credentials

Yohanes decided on 2026-09-25 that there is no legacy deployment to preserve,
and approved the removal plan on 2026-09-26. This is PR 1 of that plan.

- **Header names, never values.** A personal connector stores only the header
  names its credential uses: `bearer` is exactly `Authorization`, `api_key`
  one name, `headers` 1 to 32 unique names, `none` none. The catalog checks
  names with the vault destination's own rule (`secret.CredentialHeader`), so
  every connector the catalog accepts can receive a credential.
- **Vault custody from creation.** A credentialed connector is guarded when it
  is created. The manager never dials it, refresh returns 409
  (`upstream.ErrGuarded`) and every call needs an owner-activated access
  window; with no credential, or after deletion, it stays locked. The
  post-admission re-check and `Manager.Guard` existed only for conversion and
  are gone; the proxy still maps `ErrGuarded` to `MCPWARDEN_LEASE_REQUIRED`.
- **Only vault-ready connectors.** The catalog also checks a credentialed
  connector's endpoint against the destination the console will send (public
  HTTPS, or the loopback profile for HTTP), through
  `secret.ConnectorDestination`. Only a local account may create one: owner
  routes need that account's browser session, so the shared operator
  workspace could never unlock it (review round 1, R1-N1 and R1-N2).
- **No custody switch.** `owner_security.custody_mode` is removed and a config
  that sets it fails to load. Guarded execution is installed whenever the
  owner vault runs. Without it only `none` connectors can be created.
- **Upstream OAuth waits for step 6.** The SDK `OAuthHandler` wiring, the
  callback route and the per-connector grant are removed; `auth_type: oauth`
  is refused until OAuth grants live in the vault.
- **No conversion.** Catalog data with stored header values, OAuth settings or
  a PostgreSQL `grant_id` is refused with "created by an older build; start
  with a new catalog". The rollback manifest's reauthorization list is always
  empty.
- **Browser flows.** Until setup discovery (step 5), the owner-flow gateway is
  built with the `flowtest` tag, which adds a route that stores a given tool
  list as a vault connector's cached discovery without dialing it. Release
  builds do not include it.

## 2026-09-26 — Store hardening: cancellation, heartbeat, bounded history

- The executor session runs statements on a store context detached from the
  caller (5 s for owner transactions and history writes, 30 s for the startup
  load and custody load). pgx closes a session whose statement context ends, so
  a client disconnect used to stop the gateway. The caller's context is checked
  before COMMIT instead: a caller that has gone gets its context error, nothing
  is committed and `Lost()` stays open. The error wraps `lease.ErrRolledBack`,
  so the catalog repository fails only that change, not the gateway, when its
  own 15 s context ends before COMMIT (found by an independent second review). Revoke, deny and lock execution detach
  from the request, so a closed tab never loses them.
- The heartbeat pings only when the executor gate is idle. A busy gate is
  bounded by the holder's store deadline, so contention is never read as loss.
- History pages run on a second, read-only session, one REPEATABLE READ
  transaction per page. Pages take turns: the wait has its own 15 s bound and
  each page's 5 s deadline starts once it runs, so queued pages do not share a
  budget. Only a session pgx has closed is dropped; one that died while idle is
  replaced once within the page, and a failed open is not retried within a
  second. A failed page never stops the executor. The statement timeout
  (4.5 s) sits under the page deadline, so the server ends a long statement and
  the session stays. Close cancels the running page and never queues.
- Each page reads at most the newest 25,000 matching events (the page limit),
  reports `total_capped`, and refuses pages beyond the window. Time ranges use
  history time in both readers.
- Deviation from the plan's index list, found by the scale test: with plain
  per-filter indexes over every event, pages at 1,000,000 calls took 520 to
  870 ms, because half the events are admissions of finished calls that each
  page walked and probed. The filter indexes are now partial on
  `event_type IS NULL OR event_type <> 'tool.dispatch.admitted'` (settled
  events), and open admissions come from `history_open`, merged in history
  order. The page rows, count and timing buckets come from one statement over a
  materialized window, read once. The same cases now take 11 to 181 ms. The
  planned `visible` anti-join is gone; `history_open` is the source of truth
  for which admissions are shown, and a test checks the backfill matches live
  writes.
- Open MCP session records are ended at startup, one owner transaction per
  owner with `access.ended` events, as the file store does when it opens.

## 2026-09-28 — SQLite store and the storage section (removal plan PR 3)

- Driver: `modernc.org/sqlite` v1.59.0, pure Go. The gateway image and CI
  build with `CGO_ENABLED=0` onto distroless static, which rules out cgo
  drivers. The stripped gateway grows from 18.6 MB to 22.7 MB. The store uses
  `database/sql`, so the driver can be swapped later. `ncruces/go-sqlite3`
  (WASM) was the alternative; the plan's decision D8 chose modernc.
- One contract suite (`internal/lease/storetest`) runs on both stores. It
  replaced the PostgreSQL-only copies of the lease, vault, cancellation,
  catalog, history and repository tests; PostgreSQL keeps only its privilege,
  advisory-lock and schema-drift tests. Running it found that the PostgreSQL
  history reader mapped `catalogdb.ErrHistoryWindow` to a storage error; it now
  returns it as the caller's error.
- SQLite cannot enforce PostgreSQL's grants, so `BEFORE DELETE` triggers refuse
  deletes on every table the runtime role cannot delete from, and the migration
  ledger also refuses updates. They catch bugs; the gateway owns the file, so
  they are not a boundary against a compromised gateway.
- A deferred foreign key that fails at COMMIT leaves a SQLite transaction open.
  The store rolls back on the connection after any failed COMMIT, then fails.
- The executor's single session is an exclusive lock file held for the process
  lifetime, with a 30 s wait at open and an inode check in the heartbeat.
  Network and FUSE filesystems are refused.
- The `storage` section replaces `managed_upstreams.backend: postgres` and
  `owner_security.database_url_env`, both refused with a pointer to
  `docs/storage.md`. With it, the executor runs in every HTTP mode, history is
  in the database and `audit.path` must be unset. `owner_security` now requires
  `storage`: the file catalog beside a PostgreSQL owner vault is gone, since
  there are no live users of it. `--stdio` with `storage` is refused until the
  stdio client arrives in PR 4.
- Under `storage.driver: postgres`, a database with no catalog state loads as a
  fresh catalog and any state other than `active` is refused (plan N9), so a
  database mid-import never serves.
- `custody.MaxEventPage` and `custody.MaxEndedLeases` moved to `custody`, so
  both stores and the owner API share one bound.
- The gateway's owner flows run on SQLite by default and on PostgreSQL under
  `TestOwnerFlowsOnPostgres`. The SQLite hold for the session-wait test is an
  owner transaction of the store itself: SQLite locks the whole database, so
  an external write lock would block the session lookup too.
- Review round 1 of PR 3: the heartbeat checks the database and lock inodes on
  every tick before it tries the gate, so a replaced file stops a busy store
  too; only the session ping waits for an idle gate. Under a tool filter the
  SQLite history query writes the other equality terms with a unary `+`: the
  planner has no statistics (the gateway never runs ANALYZE) and otherwise
  drove upstream plus tool from the upstream index, 644 ms at 1M calls.
- The request binding and approved-mode CHECKs are wrapped in `(…) IS TRUE` on
  both stores (PostgreSQL migration 006), because a CHECK that is NULL passes.
- A JSON identity field (envelope epoch and revision, wrapped key epoch and
  root version, wrapper root versions) written as `1e0` is accepted by
  PostgreSQL (jsonb normalizes it to 1) and refused by SQLite. Recorded rather than
  refused: jsonb cannot tell the spellings apart, and every writer uses strings.

## 2026-09-29 — Single database, schema reset and the stdio client (removal plan PR 4)

The removal plan's decisions D1 to D10 were approved on 2026-09-26. This PR
carries D2, D3, D5, D6, D7 and D9; D10 landed in PR 2 and D8 in PR 3.

- Storage is required (D2). Without a `storage` section the gateway uses
  SQLite at `/data/mcpwarden.db`. The encrypted catalog file, JSONL history,
  `pgcatalog` and `mcpwarden-catalog` with its import, cutover and rollback are
  removed. `audit`, `managed_upstreams` and `owner_security.database_url(_env)`
  are refused with their replacement. `audit.Encode` accepts schema-2
  invocation events only; `audit.HashArgs` bytes are unchanged and pinned by a
  test. `/api/auth/client-token`, the legacy client-token replacement, is gone.
- The catalog key stays (D3). It seals account records, verifier digests,
  discovery and connector metadata; it no longer protects upstream
  credentials, which live only in the vault.
- Config upstreams stay operator-held and are served to every account and
  OAuth subject (D5). The guide and the Compose config say to close
  registration once the owner's account exists.
- Both schemas are reset to one `001_baseline.sql` at version 1 (D6). The
  PostgreSQL baseline is the merge of 001 to 006 without catalog state, legacy
  tombstones, custody or grant columns, the history `source` columns and the
  `connector.oauth_saved` event type; a `pg_dump` of the new schema matched the
  old one after those drops except for the auto-named request CHECKs. History
  is schema version 2 only, with `event_type` and `invocation_id` NOT NULL. A
  ledger whose version 1 has the pre-reset checksum is refused with
  `ErrSchemaReset` ("create a new database"); nothing is converted.
- `--stdio` is a SQLite client (D9). It holds `<path>.lock` shared while it
  serves and exclusively only to create or migrate, following the plan's lock
  loop (§4.5): shared check, exclusive create or migrate, a non-atomic
  conversion done as unlock then shared lock, and a random 50 to 100 ms wait,
  for up to 10 s. The conversion is done in two explicit steps on both
  platforms, so a test hook can take the lock in the gap. It never runs the
  executor; `dbcatalog.NewSnapshot` loads owner `local`'s rows through
  `catalogdb.Client.LoadOwner`, drops accounts, access records and
  credentialed connectors, keeps discovery refreshes in memory and refuses
  every other change. History goes through `dbcatalog.NewHistoryWriter`, one
  `BEGIN IMMEDIATE` per event with a 5 s busy timeout after an inode check; a
  replaced file or an unknown commit outcome stops the client. Stdio calls
  carry actor type `stdio` through a receiving middleware. PostgreSQL is
  refused before connecting, so no stdio config holds the runtime role.
- HTTPS for the panel is an opt-in override (D7). nginx's locations moved to
  one shared `ui/locations.conf` that the HTTP server and the HTTPS server
  (`ui/nginx-tls.conf`, mounted by `compose.tls.yaml`) both include, so they
  cannot drift; the API location overwrites `X-Forwarded-Proto` with nginx's
  own `$scheme` and clears `Forwarded`. The override gives the default network
  `172.30.87.0/24`, allocates other containers from `172.30.87.128/25`, and
  pins ui at `172.30.87.2`, the only trusted proxy in the Compose config.
  Without the override the header says `http`, so owner routes stay refused.
  The container smoke test runs with the override and checks that owner routes
  refuse plain HTTP (direct, through nginx, and with a spoofed header) and
  accept HTTPS through nginx.
- Compose mounts a new `data` volume at `/data`. The old `audit_data` volume is
  no longer declared, so `down --volumes` cannot delete it; it stays on disk as
  the backup. The container smoke test checks that every shipped Compose file
  publishes ports on 127.0.0.1 only.
- The owner browser flows run on SQLite in all three engines and on
  PostgreSQL in Chromium (`OWNER_STORAGE=postgres`).

## 2026-09-29 — Connect and inspect (setup discovery, removal plan PR 5)

Yohanes asked for step 5 on 2026-09-29: the owner explicitly authorizes a short
discovery window, the gateway discovers and saves the connector's tools, and
discovery ends without permitting tool execution.

- **The window is the owner's own.** A `setup_discovery` scope names the
  owner's browser session as its requester. `lease.Service.current` accepts a
  browser requester only for that purpose and an API key only for `tool_use`,
  so no key can request, start or run one, and `oauth_setup` stays refused
  until step 6. Only the session that requested it may activate and run it. It
  names no tools and no call budget and lasts at most 300 seconds. The
  approval policy applies unchanged (`confirm` begins, then activates).
- **One run, then the window ends.** `Service.Setup` marks the window used
  under the owner gate before lending the material, so concurrent or repeated
  runs fail. The save and the end of the window commit together through
  `Service.CatalogSetup`, which rechecks the window (active, live, current,
  run, same connector) in the same transaction before the catalog mutation
  runs. The check reads the catalog through the authority, so it cannot run
  after the repository takes its view lock. A failed run or a refused save
  revokes the window. No new event type or lease state: the end is
  `lease.revoked` with source `setup_completed` or `setup_failed`, both added
  to the event source allowlist.
- **Discovery through the SDK.** `upstream.DiscoverLeased` uses one
  `StreamableClientTransport` with `MaxRetries: -1` and
  `DisableStandaloneSSE: true`, like `PrepareLeased`, over the vault handle's
  constrained client with no pinned tool. The credential transport's `setup`
  phase allows the same maintenance methods as `prepare` (`server/discover`,
  `initialize`, `notifications/initialized`, `tools/list`) and refuses
  `tools/call` before injecting headers. Paging stops at 16 pages; a repeated
  cursor, a duplicate or empty name, more than 256 tools or more than 4 MiB of
  definitions fails the whole run. The SDK's session DELETE at close is refused
  locally, as for leased calls.
- **Saving does not end tool windows.** A tool window binds each tool's
  definition digest, so a changed definition makes it stale and the owner
  reviews the new one; unchanged tools keep working.
- **Refresh stays off.** The runtime refresh route and
  `warden_refresh_provider` still return 409 for a vault connector; the message
  now points to Connect and inspect.
- **No seed route.** The `flowtest` build tag and `PUT /api/test/discovery/`
  are removed. The browser flows discover through Connect and inspect against
  the synthetic upstream, which accepts only the vault credentials, and make one
  real agent call inside a window.
- **Tools the SDK server cannot register are refused (review round 1).**
  `mcp.Server.AddTool` (go-sdk v1.8.0, `server.go`) panics on a tool whose
  input schema is missing, is not a JSON object or has a type other than
  `"object"`, or whose output schema does not encode; the SDK client does not
  check this when listing. `registry.CheckSchemas` makes the same checks.
  Discovery fails the whole run on such a tool (502, `setup_failed`, nothing
  saved), and `Registry.Replace` skips and reports it for every connector, so
  no listed or stored tool can panic a runtime or a manager goroutine.
- **Failures keep a category, not a cause.** `upstream.DiscoveryError` names
  the failed step (connect, list, pages, tools, size, name, schema, cursor),
  which the route logs without upstream text. A window that ended during the
  run answers 409 `stale`, and a catalog save that did not commit answers 503
  `not_saved`. The console asks for a 60-second window.
