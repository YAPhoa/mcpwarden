# mcpwarden: current-state and research handoff

Date: 2026-09-22 (Asia/Singapore)

Repository: `/home/yaphoa/Documents/mcpwarden`

This document is a self-contained handoff for an agent doing deeper architectural,
security, database, or client-side-encryption research. It describes what exists now,
what was deliberately excluded, and which decisions remain open. It contains no
credential values, tokens, private headers, or account identifiers.

## 1. Executive summary

mcpwarden is a self-hosted Model Context Protocol (MCP) gateway. A client connects to
one downstream MCP endpoint and receives a namespaced aggregate of tools supplied by
multiple upstream MCP servers. The project has two deliberately separate components:

- a headless Go gateway (`cmd/mcpwarden`), and
- a static browser administration UI (`ui/`) served by Nginx.

Compose runs these as separate `server` and `ui` services. The UI never embeds the Go
server and reads all status/tool data through the gateway's HTTP management API.

The current persistence implementation uses:

- one whole-file AES-256-GCM encrypted catalog for accounts, access records,
  personal connectors, credentials, OAuth grants, cached tool metadata, visibility,
  lifecycle timestamps, and connector tombstones; and
- a separate append-only plaintext JSONL audit/history file containing metadata and
  canonical argument hashes, but never raw tool arguments, results, credentials, or
  raw upstream errors.

There is no PostgreSQL implementation yet. The managed catalog and audit runtime now
sit behind `catalog.Repository` and `audit.Store` interfaces, respectively, so a
database adapter can be added without changing the main business/runtime layers.

The next requested direction is to investigate client-side/client-decrypted handling
for important data. That work has not been implemented and needs a threat model first:
the gateway must currently decrypt upstream credentials to call upstream services, so
not every secret can become opaque to the server without changing runtime behavior.

## 2. Repository and delivery state

- Module: `github.com/yaphoa/mcpwarden`
- Go language baseline: 1.27 (`go 1.27.0`)
- Container builder: Go 1.27.1
- MCP SDK: `github.com/modelcontextprotocol/go-sdk v1.8.0`
- Other direct dependencies: `golang.org/x/oauth2 v0.37.0`, `gopkg.in/yaml.v3 v3.0.1`
- UI: framework-free HTML/CSS/JavaScript behind Nginx
- UI asset version in `index.html`: `20260922-43`
- Compose bindings: gateway `127.0.0.1:8787`; UI `127.0.0.1:8788`
- The gateway image was most recently rebuilt and its internal `/healthz` returned
  `ok`.
- Latest validation completed successfully with Go 1.27.1:
  `go mod tidy -diff`, `go build ./...`, `go vet ./...`, and
  `go test -race ./...`.

Important repository-state warning: the current `main` branch has no commits and the
entire project appears as untracked files in `git status`. A research or implementation
agent should not assume Git can restore a baseline. Establish a safe baseline/commit
before invasive changes, with the owner's approval.

## 3. Main runtime architecture

```text
MCP client / browser
        |
        v
Go gateway (:8787)
  - downstream auth and sessions
  - per-owner runtime
  - client/admin MCP views
  - policy and visibility checks
  - tool registry and stable IDs
  - upstream connection manager
  - audit write/query boundary
        |
        +---- stdio MCP upstreams
        |
        +---- Streamable HTTP MCP upstreams
                  - no auth
                  - bearer/API-key/custom headers
                  - generic MCP OAuth

Browser (:8788) -> Nginx static UI -> proxies /api/ to gateway
```

Key packages:

- `cmd/mcpwarden`: process wiring, HTTP endpoints, account/session auth, access keys,
  management tools, per-user runtimes, and upstream OAuth HTTP callbacks.
- `internal/upstream`: concurrent upstream lifecycle, reconnect, refresh, availability,
  timeouts, and SDK transports.
- `internal/registry`: namespaced tool routing, stable tool/provider IDs, and inventory.
- `internal/proxy`: client/admin MCP servers, policy/visibility enforcement, calls, and
  audit creation.
- `internal/catalog`: encrypted managed state and the backend-neutral repository
  contract.
- `internal/audit`: append-only call history plus filtering and performance summaries.
- `internal/oauth`: downstream OAuth resource-server validation through external token
  introspection.
- `internal/upstreamauth`: upstream MCP OAuth authorization-code/PKCE flow and encrypted
  refresh-token persistence.
- `internal/policy`: static allow/deny rules.
- `internal/approval`: approval interface; only the `None` implementation exists.

Each validated owner receives a separate runtime, upstream session set, registry,
personal connections, cached discovery, and visibility state. Static YAML upstreams
are shared intentionally and instantiated in each owner's runtime.

## 4. MCP behavior

Supported downstream transports:

- Streamable HTTP at `/mcp`.
- One-client stdio mode using `--stdio`.

Supported upstream transports:

- stdio through the official Go MCP SDK command transport;
- Streamable HTTP; and
- remote HTTP with no auth, bearer auth, API-key/custom headers, or generic MCP OAuth.

Tools are exposed as namespaced names such as `provider__tool`. Personal connector IDs
are persisted UUIDv4 values. Tool IDs are stable UUIDv5 values derived from connector
ID and the exact upstream tool name. Static connector IDs are deterministic per owner
and configured name.

Hidden tools remain visible in the admin inventory but are excluded from downstream
`tools/list`; direct calls to hidden tools are denied and audited. Disabled providers
are disconnected and unavailable while cached metadata and user choices remain.

There are separate MCP views:

- client: enabled upstream tools plus per-provider refresh;
- admin: client view plus provider list/add/remove, provider enable/disable, and tool
  visibility management.

## 5. Authentication and account modes

The system supports mutually exclusive deployment modes:

1. Local operator bearer token
   - Selects the shared `local` workspace.
   - Configured through an environment variable named in YAML.

2. Local accounts
   - Optional registration controlled by `accounts.allow_registration`.
   - Accounts are personal workspaces, not global administrator roles.
   - Password minimum is 15 characters.
   - Passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations and independent
     16-byte salts.
   - Browser sessions use random opaque tokens, HttpOnly/SameSite=Strict cookies,
     12-hour expiry, and persistent hashed access records.
   - Password changes require the current password and revoke other browser sessions.

3. External OAuth resource-server mode
   - An external identity provider owns login and token issuance.
   - Gateway performs token introspection and validates active/expiry/audience,
     optional issuer, and scopes.
   - `mcp:tools` is the normal client scope; `mcp:manage` selects management access.
   - The validated token subject selects the personal workspace.
   - The panel accepts a supplied access token; it has no interactive downstream OAuth
     login flow.

Named API keys may be client or admin role, expire after 1-365 days, are displayed
once, and are stored only as SHA-256 hashes. Active limits are 10 API keys, 10 combined
browser/OAuth sessions, and 10 MCP connections per workspace.

## 6. Upstream OAuth

Generic upstream MCP OAuth uses the pinned SDK authorization-code handler with PKCE,
metadata discovery, optional dynamic client registration, preregistered clients, and
refresh tokens. Grants and rotated refresh tokens are stored in the encrypted catalog.
Authorization flows use one-time state and a separate HttpOnly/SameSite=Lax browser
binding, expire after five minutes, and return through the UI origin's
`/api/upstream-oauth/callback`.

Recent GitHub finding:

- Official remote endpoint: `https://api.githubcopilot.com/mcp/`.
- The endpoint correctly returns an OAuth protected-resource challenge.
- Its authorization server is `https://github.com/login/oauth`.
- GitHub does not advertise dynamic client registration.
- A blank client ID therefore fails before an authorization URL can be produced.
- For OAuth, a GitHub OAuth App must be registered first and its client ID, secret,
  issuer, and exact callback URL supplied when the connector is created.
- Alternatively, the official remote GitHub MCP server supports a GitHub PAT as a
  bearer token.
- Saved authentication settings cannot currently be edited; the connector must be
  deleted/recreated to change auth configuration.
- The UI currently turns this server-side HTTP 400 into a generic “connection could
  not start” message, so provider-specific/actionable error UX is a known improvement.

## 7. Current storage model

### 7.1 Encrypted managed catalog

Implementation: `internal/catalog/store.go`.

The catalog stores:

- local accounts, password hashes, and salts;
- access credential hashes, roles, expiry, device/name, and lifecycle timestamps;
- personal connector names, URLs, header values, timeouts, and auth type;
- upstream OAuth client ID/secret, scopes, authorization configuration, access token,
  refresh token, and grant identity;
- cached MCP tool definitions/schemas;
- provider availability and per-tool visibility;
- stable IDs and credential-free deletion tombstones.

Encryption/write behavior:

- The environment supplies a base64-encoded 32-byte key.
- Go creates AES with that key and wraps it with GCM (AES-256-GCM).
- Each whole-file save generates a fresh random GCM nonce.
- File format is `nonce || ciphertext-and-tag`.
- The entire catalog state is serialized as JSON and encrypted as one unit.
- The directory is created as mode `0700`; a temporary file is mode `0600`.
- The temporary file is written, synced, closed, then atomically renamed.
- GCM authentication causes startup to reject incorrect keys or modified ciphertext.
- The entire catalog is decrypted into process memory at startup and maintained in
  in-memory maps guarded by a read/write mutex.

Current limitations relevant to security/database research:

- one deployment-wide key protects every owner and every field;
- the key is supplied as a process/container environment secret;
- there is no envelope encryption, per-user/data key, KMS/HSM integration, key ID,
  key version, online rotation, or recovery workflow;
- the ciphertext has no explicit file-format/version header or authenticated metadata
  (GCM additional authenticated data is nil);
- all fields are encrypted together, so there is no selective disclosure/indexing;
- plaintext objects and secrets remain in Go memory while the process runs, with no
  explicit zeroization;
- each mutation rewrites the complete catalog, limiting scale;
- the implementation is single-process and not active-active;
- the temporary file itself is synced, but the parent directory is not explicitly
  fsynced after rename;
- losing the environment key makes the catalog unrecoverable;
- compromise of the running gateway or its key reveals the full catalog.

### 7.2 Backend abstraction

`catalog.Repository` is now the managed-state boundary. Runtime, local-account auth,
access management, upstream OAuth, and startup wiring depend on the interface, not the
file implementation. Its contract requires concurrency safety, owner isolation,
defensive copies, durable mutations, atomic uniqueness/limit/OAuth compare-and-swap
behavior, stable identity/lifecycle preservation, secret-at-rest protection, and
backend closing.

Repository reads intentionally do not return errors because visibility checks run in
synchronous MCP SDK callbacks. A remote database implementation must load a coherent
view before startup, serve reads from that view, commit mutations durably, and publish
new cached state only after commit. The current contract targets one active gateway
process. Active-active operation needs a separate cache invalidation/serialization
design.

No PostgreSQL driver, schema, migration command, database configuration, or import
tool exists yet.

### 7.3 Audit/history

Audit uses a separate `audit.Store` interface. The current JSONL writer is append-only,
syncs successful writes, supports owner-scoped query/filter/pagination, and computes
bounded-memory timing summaries while scanning.

Audit records include owner, stable tool/provider identity, name snapshots, decision,
status, duration/timing, response item count, structured-response presence, session
identity, and a SHA-256 hash of canonical JSON arguments. They exclude raw arguments,
tool results, credentials, and raw error messages. The management API further excludes
session IDs and argument hashes from responses.

The audit file is not encrypted by the catalog mechanism. It therefore contains
sensitive operational metadata even though it contains no payloads. Reads scan the
file; there is no retention/rotation workflow or indexed backend. A database adapter
must preserve append-only semantics, stable event IDs, owner boundaries, historical
name snapshots, ordering, deduplication behavior, and non-cascading history.

## 8. Admin API and browser UI

Principal endpoints:

- `/mcp`: downstream Streamable HTTP MCP.
- `/healthz`, `/readyz`: process and upstream readiness.
- `/api/auth/options`: public auth-mode discovery.
- `/api/auth/register|login|logout|password`: local account lifecycle.
- `/api/access` and `/api/access/{id}`: list, mint, rename, revoke keys/sessions.
- `/api/status`: current workspace/status.
- `/api/providers` and `/api/providers/{name}/tools`: provider inventory.
- `/api/providers/{name}/visibility`: all/selected tool visibility.
- `/api/tools`: cross-provider inventory/search.
- `/api/connections`: personal remote connector list/add/delete.
- `/api/discovery/{name}/refresh`: per-provider refresh.
- `/api/history`: owner-scoped call history and performance metadata.
- `/api/upstream-oauth/callback`: upstream OAuth completion.

The API never returns stored header values or OAuth client secrets/tokens. Connection
views expose header names and safe metadata only.

The UI is a static single-page app with History API routes, responsive layouts,
light/dark/system theme, timezone selection, custom accessible calendar controls,
provider/tool search, history filters, and access-key/session management. The UI keeps
manually supplied access tokens in `sessionStorage`; non-sensitive theme/timezone
preferences use guarded browser storage. Local account sessions use HttpOnly cookies.

## 9. Policy, approvals, and audit behavior

- Static policy supports default allow/deny plus ordered rules.
- Policy and user visibility both affect `tools/list` and direct calls.
- Direct denied/unavailable/tool/protocol/timeout outcomes are audited.
- The approval boundary exists but only `approval.None` is implemented.
- Push approvals are intentionally out of scope unless separately authorized.
- Tool calls are never retried automatically because tools may have side effects.
- Raw tool arguments/results and credential values must never be logged.

## 10. Client-side/client-decrypted next iteration

“Client decrypted” needs to be split by data class. A single end-to-end-encryption
answer does not fit the current gateway responsibilities.

### Data the gateway must currently use in plaintext

- upstream bearer/API-key/custom header values;
- upstream OAuth client secrets, access tokens, and refresh tokens;
- connector endpoint and tool metadata used for routing/discovery;
- session/access state used for authorization and revocation.

The gateway cannot make unattended upstream calls if these values are encrypted under
a key that exists only in a disconnected browser. Possible designs require a deliberate
availability tradeoff, such as unlocking a per-user key for the duration of a session,
running calls through a trusted local agent, or keeping operational credentials under
server/KMS-controlled envelope encryption rather than true client-only encryption.

### Data that should remain verifier-only, not decryptable

- local passwords: salted password verifier only;
- opaque API keys and session tokens: hashes only;
- one-time flow bindings: hashes/short-lived state where possible.

### Data that could be client-only encrypted

- future private notes, labels, descriptions, or user-authored metadata that the
  gateway does not need for routing, policy, search, or calls;
- exported backup bundles intended only for the user;
- possibly connector display metadata if server-side filtering/search is sacrificed.

### Candidate hybrid architecture for research

1. Give each account a random data-encryption key (DEK).
2. Encrypt individual secret fields with versioned AEAD records rather than encrypting
   an entire database/file as one blob.
3. Bind ciphertext using authenticated data containing schema version, owner ID,
   record ID, field name, and key version to prevent ciphertext swapping.
4. Wrap DEKs separately for one or more recovery/unlock methods:
   - server KMS/KEK for operational secrets the gateway must use;
   - client-held recovery key/passphrase/WebAuthn-derived mechanism for client-only
     material; and
   - optional migration/rotation wrappers during key changes.
5. Store algorithm, nonce, ciphertext/tag, AAD/schema version, and key version
   explicitly. Never use deterministic nonces with GCM.
6. Define key rotation, account recovery, device addition/removal, backup/restore,
   revoked-device behavior, and lost-key behavior before schema implementation.
7. Keep searchable/non-secret columns separate from encrypted secret blobs, while
   ensuring they do not leak more metadata than the threat model permits.

Critical threat-model caveat: browser-side decryption in JavaScript served by the same
gateway protects against database/backups disclosure and some passive operators, but
not against an actively compromised server. Such a server can deliver modified
JavaScript that exfiltrates the decrypted key/plaintext. Strong protection from the
server itself generally requires a separately trusted client, signed application,
extension, or independently verifiable static client—not merely Web Crypto in pages
served by that server.

Research should explicitly answer:

- Which adversary is in scope: stolen database, backup operator, host administrator,
  compromised gateway process, malicious deployment operator, XSS, or stolen client?
- Which data must remain available when no browser is connected?
- Is a locked workspace allowed to stop upstream connections?
- Is multi-device access required, and how are new devices authorized?
- What recovery behavior is acceptable if the client key/passphrase is lost?
- Is server-side tool/provider search required over encrypted metadata?
- Is active-active/multi-instance deployment required?
- Which KMS providers or self-hosted key systems must be supported?
- What migration and rollback guarantees are required for the existing encrypted file?
- Should plaintext audit metadata also be encrypted, selectively tokenized, or moved
  to a database with retention controls?

## 11. Known constraints and unfinished areas

- No PostgreSQL adapter, schema, migrations, or active-active consistency protocol.
- No client-side encryption or key-management implementation.
- No credential/auth-settings edit API; connector recreation is required.
- No embedded OAuth authorization server.
- No interactive browser login for downstream external-OAuth mode.
- No password reset, email verification, account deletion, or account administration.
- No push approval implementation.
- No MCP resources or prompts proxying.
- No database-backed/rotated audit retention.
- No built-in Google Drive API adapter; users need an MCP server.
- Generic provider OAuth only; provider-specific registration conveniences are absent.
- GitHub OAuth error is currently too generic when dynamic registration is unavailable.
- UI browser/screen-reader coverage is incomplete even though keyboard/responsive checks
  and synthetic controller tests exist.

## 12. Scope constraints that research must respect

Do not expand into the following without explicit user approval:

- embedded authorization server;
- push approvals;
- MCP resources or prompts;
- unrelated database-backed features;
- provider-specific adapters such as a native Google Drive API implementation.

Maintain these invariants:

- official `github.com/modelcontextprotocol/go-sdk` remains the MCP SDK;
- verify SDK API details against the pinned module source before changes;
- keep Go gateway and UI as separate services;
- keep `examples/config.yaml` synchronized with config code;
- never log raw arguments, results, credentials, OAuth tokens, or header values;
- audit stores only the canonical argument hash, never raw arguments;
- all personal state and admin responses remain owner-scoped;
- hidden tools remain in admin inventory but not downstream discovery/direct calls;
- connector deletion retains historical call records;
- dependencies require justification; the intended small dependency set is deliberate;
- before a milestone is complete, run build, vet, and race tests and record results in
  `docs/progress.md`;
- record SDK/MCP behavior decisions in `docs/decisions.md`.

## 13. Suggested research work products

A useful deep-research response should produce:

1. A precise threat model and data classification table.
2. A comparison of server-side envelope encryption, session-unlocked per-user keys,
   and true end-to-end/client-only encryption.
3. A PostgreSQL logical schema covering accounts, connectors, secret fields, OAuth
   grants, access records, visibility, discovery cache, tombstones, and audit events.
4. Transaction/isolation strategies for uniqueness, credential caps, password/session
   replacement, and OAuth grant compare-and-swap.
5. A versioned encrypted-field envelope and AAD specification.
6. Key hierarchy, KMS/self-hosted options, rotation, backup, recovery, and migration.
7. Browser/client cryptography and XSS/supply-chain analysis.
8. A phased migration plan from the current AES-GCM file and JSONL audit, including
   rollback and verification.
9. Test strategy: known-answer crypto tests, corruption/tamper tests, owner isolation,
   concurrency/race tests, migration fixtures, failure injection, and restore drills.
10. Explicit recommendations about which fields must remain server-decryptable and
    which can become truly client-only.

## 14. Primary project documents and source entry points

- `AGENTS.md`: authoritative scope and implementation constraints.
- `README.md`: operator/user behavior and APIs.
- `docs/decisions.md`: accepted architecture and protocol decisions.
- `docs/progress.md`: chronological implementation/validation history.
- `docs/catalog-storage.md`: managed-state backend contract.
- `docs/history-storage.md`: audit/history semantics and future DB constraints.
- `docs/sdk-notes.md`: pinned MCP SDK behavior.
- `docs/proxy-performance.md`: timing definitions.
- `internal/catalog/store.go`: current AES-GCM file persistence.
- `internal/catalog/repository.go`: alternative-backend boundary.
- `internal/catalog/access.go`: access credentials, limits, revocation, lifecycle.
- `internal/audit/audit.go`: JSONL audit backend and query behavior.
- `cmd/mcpwarden/main.go`: startup, modes, routing, endpoint registration.
- `cmd/mcpwarden/runtime.go`: per-user runtime and provider/tool APIs.
- `cmd/mcpwarden/accounts.go`: local accounts and sessions.
- `cmd/mcpwarden/access.go`: API keys and MCP connection records.
- `internal/upstreamauth/oauth.go`: upstream OAuth flow and token persistence.
- `internal/oauth/oauth.go`: downstream resource-server token validation.
- `ui/static/app.js`: browser controller and API integration.
- `compose.yaml`, `examples/*.yaml`: deployment/configuration examples.

## 15. Validation commands

```sh
go mod tidy -diff
go build ./...
go vet ./...
go test -race ./...
node --test ui/tests/app.test.cjs ui/tests/timezone.test.cjs
docker compose up -d --build
docker compose exec -T ui wget -qO- http://server:8787/healthz
```

Tests that use SDK mock HTTP servers need permission to bind loopback ports. Avoid
printing `.env`, Docker environment values, the encrypted catalog key, PATs, OAuth
secrets/tokens, or stored header values during diagnostics.
