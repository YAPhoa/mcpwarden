# Security spec v1.1 implementation review

Reviewed on 2026-09-22 against the actual repository and pinned Go MCP SDK v1.8.0.
The user's request establishes the staged roadmap. The caller/audit part of M1 is
integrated; subsequent slices add the lease core, PostgreSQL metadata adapter,
real encrypted-envelope activation, browser vault primitives, encrypted-record
persistence, and an opt-in proxy execution adapter tested through MCP with
PostgreSQL. Application startup, owner HTTP API and UI have not
installed this path. Client encryption is not enabled in the running gateway.

The [supplied specification](spec-v1.1/SECURITY-DESIGN.md) is retained byte-for-byte
along with its checklist, candidate schema, and public interoperability fixtures.
All 16 entries in its supplied SHA-256 manifest matched before and after copying.
The candidate SQL/configuration remain design references, not production migrations
or accepted gateway configuration. The external reference catalogue has not been
independently revalidated in this repository review.

## Accepted direction

- Authorize a fixed, multi-call working window per exact caller access record,
  credential epoch, finite tool/resource scope, and gateway boot. Proposed default
  is 15 minutes, capped at 60, with no idle expiry, default call budget, traffic
  renewal, or automatic tool replay.
- Keep the vault root and recovery material in the browser. Release only the
  selected credential key to the trusted executing gateway. The gateway can see
  that credential during execution; this is not secrecy from a compromised executor.
- Separate interactive owner activation from ordinary admin/client MCP authority.
  Initial client-release support targets local-account browser sessions plus named
  caller keys. Legacy operator, pasted OAuth management tokens, and stdio need
  deliberate support before they can enter that custody mode.
- Keep `none`, first-party `confirm`, and optional `step_up` distinct. `none` still
  needs explicit owner key release and a bounded lease. Push is delivery only.
  Push/TOTP are unselected optional modules and are not dependencies of this work.
- Use a separate fallible secret-resolution path and preserve coherent metadata
  reads, owner isolation, hidden tools, stable IDs, and append-only history.

## Review findings and implementation order

| Boundary | Verified baseline | Required next work |
|---|---|---|
| Caller identity | Exact access record and role already bind SDK sessions; live audit lacked caller identity. | Public IDs and audit snapshots implemented here; owner-coordinated admission/revocation remains. |
| Audit durability | One synced completion event after execution; failures only logged. | Admission and completion events implemented here; transactionally linking leases/budgets to audit remains. |
| Approval | `internal/approval.None` runs on every tool call. | Add immutable requests, finite scopes, timed leases, explicit activation and revocation. Do not adapt this per-call interface into repeated human prompts. |
| Custody | A deployment AES-GCM key decrypts the whole catalog into memory. | Browser root/CEK lifecycle, strict envelopes, recovery, field encryption, and restart-locked activation. Current custody remains legacy server managed. |
| Storage | Coherent catalog repository and independent JSONL audit interfaces. | Reviewed PostgreSQL adapter and migration preserving all legacy metadata/verifiers; candidate SQL lacks the full transition and current MCP connection lifecycle contract. |
| Upstreams | Startup/reconnect/discovery use stored headers or grants directly. | Setup/discovery leases, transport credential handles, epoch/revision binding, guarded refresh, and final-lease drain. |
| Network | URL and redirect checks exist. | Connection-time DNS/IP/SSRF enforcement, explicit private-network policy, and stdio environment/process isolation. |
| Owner UI | Basic accounts, access inventory, and history exist. | Vault setup/unlock/recovery, owner-only activation, inbox, countdowns, renewals, and execution lock. |

The owner security coordinator and immutable lease/request model are now in
`internal/lease`, with synthetic credentials and a tested PostgreSQL transaction
adapter. Admission and revocation share its gate, which is released before work
runs. Next connect the interactive owner API and scoped credential runtime. Do not
advertise client-release custody until M2's browser lifecycle, encrypted persistence,
recovery and restart tests pass. M3's push/TOTP work remains optional. M4/M5 cover
runtime hardening, migration, restore, and controlled rollout.

## Implemented in this slice

New named keys use `mcpw_<32 lowercase hex public-ID characters>_<43 base64url secret
characters>`. The public ID and 32-byte secret are independently random. The full
token remains SHA-256 verified with constant-time comparison. Both local-account
and operator/OAuth named-key authentication paths accept the format strictly.
Legacy `mw_` tokens, including the compatibility replacement endpoint, remain valid.
Existing API keys receive independent persisted public IDs without altering their
verifiers, IDs, roles, ownership, expiry, or lifecycle timestamps. Access names show
collision-aware public suffixes. Stored header values and token verifiers are not
exposed. Cross-owner `AccessByID` misses now return an empty value as well as false.

Live tool handlers write schema-v2 invocation events with the authenticated access
ID, public ID, immutable label snapshot, stable tool/provider IDs, and the existing
argument-hash bytes plus a hash-version marker. The middleware refreshes the exact
record for each SDK call so a renamed key gets a new snapshot while prior history
keeps its old name. Client-supplied arguments and `clientInfo` do not choose the
audit actor. Legacy operator/storeless OAuth verifier-derived session-binding IDs
are deliberately omitted from public audit identity; those modes only report their
actor type until an independent access-record identity exists.

Both upstream and gateway-management MCP tool handlers sync a separate admission
before dispatch. Admission failure returns a plain-text tool error with no upstream
or provider-management action. Completion failure preserves the actual result and
logs only safe event identifiers; it never retries the operation. Stdout/discard
sinks cannot authorize dispatch; startup configuration now requires a persistent
audit file. New audit-file directory entries are also synced.

History folds admission/completion pairs into one invocation and shows unpaired
admissions as **Outcome unknown** with no fabricated completion time, response,
or execution duration. Unknown includes calls still running, crashes before/after
network dispatch, and missing completion writes. It is not evidence of failure or
safe retry. Existing v0/v1 history bytes and completion ordering are preserved.
The API adds `actor_access_id` filtering and safe actor/event metadata. See the
[updated storage contract](../history-storage.md) for exact scan and timing limits.

## Coverage and remaining release gates

This is partial progress against A03/A09 and P02–P05/P07, not completion of those
acceptance families. Tests cover new/legacy key authentication, public-ID migration
and collisions, owner isolation, caller spoofing, key rename/reconnect attribution,
failures before admission and after execution, both MCP views, unknown outcomes,
out-of-order event import, original history preservation, and escaped UI labels.
Existing owner, visibility, cap, OAuth, and integration tests remain required.

The complete L/C/D/O suites remain release gates. The original caller/audit slice
did not add leases or a database; the following slice adds their tested core.
The existing SDK schema-validation failures before tool handlers remain outside
the invocation audit. Audit-health alerting beyond safe error logs is still open.

## Baseline and rollout

The repository had no tracked source baseline; all project files were untracked.
A 67-file source archive and hash manifest were created before editing at
`/tmp/mcpwarden-security-baseline-20260922T141536Z/`, with directory mode 0700 and
files mode 0600. This is a source backup, not a live data/key backup. Ignored runtime
data and deployment secrets were not copied or displayed. No Git commit was made.

The initial implementation did not restart Compose. Both services were subsequently
rebuilt and restarted at the user's request on 2026-09-22. A consistent protected
catalog/audit/configuration backup is stored at
`/tmp/mcpwarden-predeploy-20260922-security-1/`, with keys kept separately in
`/tmp/mcpwarden-predeploy-keys-20260922-security-1/`. The existing audit history was
verified byte-for-byte after deployment; gateway/UI/API smoke checks passed.

Before future deployments/migrations, take a consistent protected backup of
catalog, audit, configuration and keys, with keys handled separately.
Older binaries cannot read schema-v2 audit history; stop
execution before any rollback and preserve the new append-only log. Do not roll
back by discarding security events or silently weakening admission requirements.

Actual validation results are recorded in [progress](../progress.md).

## Lease core and PostgreSQL metadata slice — 2026-09-22

The user authorized PostgreSQL testing and selected Sonic. Added:

- Strict, bounded scopes with RFC 8785 hashes; explicit tool definition and
  destination pins; required, exact scalar equality and finite-set predicates;
  rejection of duplicate fields, malformed Unicode, unknown fields, unsafe
  integers and unsupported predicates. The original audit argument hash is intact.
- Immutable requests bound to owner, exact caller, credential epoch, scope,
  boot, nonce, expiry, approval mode, verification method and policy revision.
  Owner-only `none` activation and separate `confirm` decisions; no agent key can
  confirm or activate. A key length check is not credential authentication: the
  mandatory `Activator.Stage` implementation must authenticate the current
  encrypted record. This slice initially used synthetic test activators; the
  following slice adds the real header-bundle envelope activator.
- Fixed multi-call windows, caller-expiry caps, explicit renewal, replay-safe
  activation, request deduplication/caps, per-caller concurrency, optional atomic
  call budgets, earliest-expiry selection and no union of partial scopes. Wall
  and monotonic deadlines both apply; uncertain clocks suspend execution.
- Coordinated admission/revocation, cancellation and material destruction after
  in-flight work drains. Security mutation integration has an explicit `Change`
  hook; actual catalog mutation call sites still need to use the coordinator.
- A versioned, checksummed PostgreSQL schema and migration CLI. A dedicated
  session holds exclusive executor ownership; loss or ambiguous commit locks
  execution. Restart suspends old durable leases without recreating material.
  Owner row locking samples `clock_timestamp()` after waiting. Lease counters
  and admission audit commit together; immutable binding triggers, owner foreign
  keys and separate runtime privileges protect durable state.
- Sonic v1.15.4 for catalog snapshot encoding and new security/storage JSON. No
  experimental Go build flags. Compatibility fixtures preserve catalog bytes,
  identities and timestamps; performance and allocation measurements are in
  the storage note.

These are library-level L01/L04–L12, A01/A02/A04–A08, and P transaction checks,
not a claim that the entire acceptance families pass through live MCP. PostgreSQL
tests cover contention, late lock timestamps, immutable bindings, cross-owner
misses/foreign keys, role restrictions, rejected commits, **committed activation
with its response deliberately lost**, executor termination, and database snapshot
restore. The integration fixture contains synthetic records only.

Full catalog/history migration, browser VRK/CEK
setup/recovery, owner routes/CSRF, countdown UI, gated provider setup/discovery/
refresh and stdio hardening remain. The following slice adds strict credential
envelopes and connection-time network checks for its header-only adapter. M1/M2 are not complete.
See [storage contracts, test setup and the next migration design](lease-storage.md).

## Encrypted activation and guarded MCP dispatch — 2026-09-23

Added strict AES-GCM credential envelopes, expected-context JCS AAD, a real
header-bundle activator, opaque non-serializable material, destination-bound header
injection, connection-time DNS/IP checks and redirect refusal. No vault root or
permanent server unwrap route is introduced. Go/Node WebCrypto interoperability
covers the supplied vector and international owner identities.

The lease engine now lends separate bounded maintenance and dispatch capabilities.
Final admission rechecks the exact prepared activation; each HTTP request rechecks
authority and both clocks. Old material cannot be stamped with a new revision.
A number-preserving ephemeral argument binding prevents legacy audit-hash rounding
from authorizing altered wire arguments, without changing historical audit bytes.

The opt-in proxy adapter uses the pinned SDK to check the actual upstream tool
definition before durable admission, then permits one call with no per-call human
approval or automatic replay. Cached visible tools remain listed while locked.
Real PostgreSQL/SDK tests cover both supported transport eras, 25 calls under one
fixed window, reconnecting through both views, exact active caller isolation,
wrong CEKs, definition drift, redirects, lost results, completion failure,
revocation and admission commit failure. See [the execution contract and release
gates](encrypted-runtime.md).

This closes a substantial library/integration boundary, not the M2 release gate.
The deployed application still uses legacy custody. Browser root/CEK wrappers,
passphrase/recovery lifecycle, encrypted-record storage/CAS/nonce caps, complete
catalog/history migration, owner routes and UI, initial setup discovery, OAuth
refresh, and production wiring remain. No production redeployment occurred.

## Browser primitives and ciphertext persistence — 2026-09-23

Added browser worker primitives for setup, passphrase/recovery unlock, selected CEK
release, passphrase rewrapping and lock, using pinned local Argon2id assets and
strict spec-format wrappers. PostgreSQL schema v2 stores encrypted root wrappers,
credential epochs/revisions and tombstones, with expected-version writes, nonce
constraints, immutable history and conservative write caps. `ChangeAtomic` commits
ciphertext with lease revocation and publishes cache/authority only after commit.

Real-browser worker/CSP tests and independent Argon2 vectors complement Go/Node
round trips for all envelope layers. The actual MCP dispatch tests now read their
encrypted credentials through PostgreSQL. This is progress toward M2, not rollout:
owner HTTP routes/CSRF, vault screens and lifecycle hooks, full catalog/history
migration, startup installation, setup discovery, OAuth refresh and restore/load
qualification remain. See [vault storage](vault-storage.md) for exact coverage.

## Owner security API — 2026-09-23

Owner-scoped vault, credential, access-request, confirmation, activation,
revocation and execution-lock routes now run in the gateway when `owner_security`
is configured. Only an active local-account browser session can confirm or
activate; any request carrying an API key is refused and audited. Unsafe requests
need an allowlisted HTTPS Origin, a session-bound CSRF token and JSON bodies;
all routes separately require direct TLS or verified HTTPS from an explicitly
trusted immediate proxy. Direct loopback HTTP development is opt-in. Security
changes re-verify the account password. Policy and ciphertext changes
commit with their audit event, stale requests and revoked windows in one
transaction, rechecking session authority after database waits and writes.
Session revocation and password changes share the owner gate through commit.
PostgreSQL route tests cover isolation, replay, concurrent CAS writes
and activations, key/session revocation, queued session expiry, transport trust
and executor loss. Execution does not consult
leases yet (step 4). See [owner API](owner-api.md).
