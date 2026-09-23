# mcpwarden security design
## Client-encrypted credentials and time-bounded, multi-call MCP access

**Status:** Proposed implementation specification, not an implemented feature or security certification.  
**Version:** 1.1 — 22 September 2026. Provider-neutral, optional approval revision.  
**Audience:** Product owner, Go/backend implementer, browser-client implementer, security reviewer.  
**Baseline:** `mcpwarden-current-state-2026-09-22.md`, supplied by the project owner; included in `sources/`.  
**Primary decision:** Authorize a bounded working window, not each individual MCP call. Additional confirmation, push notifications, and OTP verification are independently configurable; no third-party approval provider is required.

> A user starts a working window for a particular MCP caller to use a particular upstream credential, for an explicitly bounded set of tools and resources, for a fixed duration. The configured policy may require an additional confirmation or second-factor verification, but neither push nor OTP is mandatory. The client releases only that credential's encryption key to the user's trusted gateway. The gateway handles multiple calls without further prompts, checking the lease on every dispatch. PostgreSQL stores encrypted credential records and authorization history, never the unwrapped runtime key.

This is **client-encrypted storage with temporary, authorized server-side execution**. It is not a claim that the executing gateway cannot see the selected credential while using it. HTTPS is mandatory for browser and remote MCP traffic. A separate private runner is not required for this first self-hosted implementation.

---

## Contents

1. [Decisions and scope](#1-decisions-and-scope)
2. [What exists today](#2-what-exists-today)
3. [Threat model and guarantees](#3-threat-model-and-guarantees)
4. [Architecture and terminology](#4-architecture-and-terminology)
5. [Lease semantics](#5-lease-semantics)
6. [Permission model](#6-permission-model)
7. [End-to-end approval and activation](#7-end-to-end-approval-and-activation)
8. [Key hierarchy and encrypted records](#8-key-hierarchy-and-encrypted-records)
9. [Runtime enforcement and concurrency](#9-runtime-enforcement-and-concurrency)
10. [MCP compatibility and errors](#10-mcp-compatibility-and-errors)
11. [Optional approval, notifications, and verification](#11-optional-approval-notifications-and-verification)
12. [PostgreSQL model and transaction boundaries](#12-postgresql-model-and-transaction-boundaries)
13. [HTTP management API](#13-http-management-api)
14. [OAuth, discovery, and background work](#14-oauth-discovery-and-background-work)
15. [Audit identity and key display handles](#15-audit-identity-and-key-display-handles)
16. [Browser, HTTPS, and deployment security](#16-browser-https-and-deployment-security)
17. [Lifecycle, recovery, and rotation](#17-lifecycle-recovery-and-rotation)
18. [UX specification](#18-ux-specification)
19. [Go integration plan](#19-go-integration-plan)
20. [Migration and rollback](#20-migration-and-rollback)
21. [Failure behavior](#21-failure-behavior)
22. [Acceptance tests](#22-acceptance-tests)
23. [Implementation milestones](#23-implementation-milestones)
24. [Decisions deliberately deferred](#24-decisions-deliberately-deferred)
25. [References and evidence map](#25-references-and-evidence-map)

## 1. Decisions and scope

### 1.1 Product decision

The normal operation is **Allow for 15 minutes**, with configurable choices such as 5, 15, 30, and 60 minutes. Those numbers are proposed product defaults, not requirements imposed by MCP, Vaultwarden, or an approval vendor.

During an active lease, an agent may perform many permitted tool calls, use results in subsequent calls, reconnect, and make concurrent requests within configured concurrency limits. It must not ask the user to approve each of those calls. A per-invocation authorization check is an inexpensive software check, not a new human interaction.

When confirmation is enabled, the approval concerns the **whole displayed scope for the whole displayed window**. With additional approval disabled, the owner starts that same bounded window during client key release, without an extra review or factor dialog. It does not purport to be advance review of unknown future arguments. Broad write access remains broad write access even when limited to fifteen minutes.

### 1.2 Normative decisions for this proposal

| Decision | Specification |
|---|---|
| Default authorization unit | One caller × one credential epoch × an explicit permission scope × a fixed working window. |
| Prompt frequency | If configured, on initial lease creation, explicit renewal, or scope expansion; never each permitted tool call. |
| Additional approval | Configurable: `none`, `confirm`, or `step_up`. Default proposal: `confirm`, with push and OTP off. |
| Notification delivery | In-app review works without push; browser/app push is optional delivery, not proof of approval. |
| Encryption custody | Vault root stays on the approving client; only a selected credential key is released. |
| Executor | The existing self-hosted Go gateway, trusted while it executes. |
| Storage | PostgreSQL is a proposed adapter and durable state store; no SQL-side plaintext encryption. |
| Runtime secrets | Memory-only; never persist an unwrapped credential key or a server-unlock wrapper for this mode. |
| Browser availability | Required for key release; not required after successful activation until expiry/revocation. |
| Restart behavior | Start locked; prior live leases are suspended, not automatically resumed. |
| Caller identity | A validated access record, never a display suffix, claimed client name, IP, or transport connection. |
| Activation identity | An interactive owner key-release flow in client-release mode, even with extra approval off. An agent's admin API key is not activation authority. |
| Retry behavior | No automatic replay of an upstream tool call after approval, timeout, or ambiguous failure. |
| First deployment topology | One active gateway process. PostgreSQL does not imply active-active support. |

### 1.3 Scope change relative to the handoff

The handoff excludes push approvals unless separately authorized. The subsequent product discussion explicitly requests their design, so this specification includes optional first-party app/browser approval and OTP **as proposed scope**, not a vendor requirement. The owner clarified that the earlier Duo emphasis was incidental. Implementation still needs an explicit project decision and corresponding updates to `AGENTS.md` and `docs/decisions.md`; this document does not modify the repository. [P0 §9, §12]

Keep the official Go MCP SDK; keep the gateway and static UI separate; preserve owner isolation, hidden-tool enforcement, stable identifiers, historical records, and the prohibition on logging raw arguments, results, headers, or tokens. Do not add an embedded authorization server, provider-native APIs, or resources/prompts proxying as part of this work. [P0 §12]

### 1.4 Revision 1.1: optional means optional

The core ships and operates without a push service, OTP enrollment, or an external approval integration. The encryption/custody mode is independent from the approval mode. Disabling extra approval must not disable authenticated caller checks, client-side key release, per-caller leases, fixed expiry, revocation, or audit. See §11 for the three modes, their state transitions, and implementation details. Existing references to an “approval request” name the shared authorization-binding record; `authorization_source` identifies whether there was actual confirmation, step-up verification, or only owner-initiated client activation.

### 1.5 How to read this document

**Baseline** statements describe the supplied handoff, not independently inspected source code. **Specification** statements are proposed mcpwarden behavior. **External reference** statements identify documented behavior in standards or adjacent products. An implementation must not treat examples, interface sketches, or the companion SQL as an already-reviewed production patch.

## 2. What exists today

The baseline describes a headless Go gateway and a separate Nginx-served browser UI. It aggregates remote HTTP and stdio MCP upstreams, isolates personal runtimes by owner, supports named client/admin access keys, and has separate catalog and audit interfaces. [P0 §1, §3–5]

The existing catalog uses a deployment-wide AES-256-GCM key, decrypts the entire catalog into process memory, and rewrites the whole encrypted file on mutation. API keys are stored as SHA-256 verifiers. The audit file contains operational metadata and canonical argument hashes, not raw payloads. [P0 §5, §7]

There is no PostgreSQL adapter, client encryption, credential-edit API, or push implementation. `internal/approval` has only the `None` implementation. Repository reads intentionally assume a coherent in-process snapshot and do not return errors. These details materially constrain the integration approach. [P0 §3, §7.2, §11]

The source lists Go 1.27 and `github.com/modelcontextprotocol/go-sdk v1.8.0`. This review does not verify those local modules. Before implementation, inspect the actual pinned SDK source and run the project's own validation commands. The published SDK compatibility table now includes the 2026-07-28 protocol; both that revision and the older 2025-11-25 session-based behavior need deliberate compatibility tests. [P0 §2, §12; R08]

### Relevant Vaultwarden distinction

Vaultwarden documents PostgreSQL support and HTTPS deployment for its Bitwarden-compatible web vault. Those are sound architectural precedents for storage and browser transport, not proof that PostgreSQL or HTTPS alone hides plaintext from an executing service. Bitwarden's documented client-side key handling is the relevant encryption precedent. mcpwarden differs because its gateway must actually exercise the upstream credential. [R01–R03]

## 3. Threat model and guarantees

### 3.1 Trusted components in v1

The approving browser/OS, the delivered UI code, the TLS termination path, the live gateway process, the integrity of its authorization database, and the selected upstream service are trusted for their respective tasks. PostgreSQL and backups are **not trusted with credential confidentiality merely because they store the data**: they receive ciphertext and wrapped keys.

Trusting database integrity is important. An attacker with arbitrary write access can tamper with ordinary access records, permissions, and revocations. The v1 design does not promise complete protection from a malicious live database. Authenticated ciphertext prevents certain substitutions; it does not authenticate every authorization row or prevent rollback of an entire valid historical database.

### 3.2 Threat coverage

| Adversary or failure | Intended protection | Limitation |
|---|---|---|
| Stolen database or backup, without unlock material | Cannot directly decrypt credential bundles or root wrappers. | Password-derived wrappers permit offline guessing; metadata remains visible. |
| Stolen named MCP client key, no matching lease | Cannot use a locked credential or create/activate a window for itself, including when extra approval is off. | Can request access within configured limits; may see authorized cached metadata. |
| Stolen client key during a matching active lease | Restricted by that lease's tools, resources, duration, and rate limits. | Can exercise all approved authority until stopped. A bearer key does not distinguish its thief from its legitimate holder. |
| Another account | Owner-scoped queries, composite foreign keys, and runtime checks prevent cross-owner access. | Requires correct application authorization; RLS is defense in depth. |
| Network observer | HTTPS protects browser/remote MCP traffic. | A trusted TLS terminator sees decrypted transport, including activation payloads. |
| Malicious upstream or prompt injection | Credential routing, input validation, explicit scopes, isolation, and downstream caller checks limit access. | A lease is not a semantic proof that an agent's task is safe. |
| Compromised gateway while a credential is active | No cryptographic guarantee against that gateway reading the released credential. | The gateway may retain it, issue calls, inspect payloads, or falsify local logs. |
| Malicious UI delivery or XSS | Deployment hardening reduces risk. | Script with access to an unlocked client can steal or use its secrets. |
| Revoked device with an earlier vault copy | Future server access can be denied. | Earlier keys/ciphertext cannot be recalled; rotate affected upstream secrets where necessary. |

The browser-code caveat is explicitly present in the supplied handoff. It is not solved by putting the UI and gateway in separate containers under the same compromised operator. [P0 §10]

### 3.3 Precise security claims

Acceptable wording:

> Credentials are encrypted in your client. Starting a timed access window releases only the selected credential to your trusted gateway, with optional confirmation or additional verification. The gateway never needs your vault root key. Access is scoped to the requesting client and checked on every call.

Do not claim “the server never sees credentials,” “push or OTP cryptographically erases keys at expiry,” “PostgreSQL administrators cannot influence execution,” or “revocation deletes secrets already copied elsewhere.”

### 3.4 Time is a policy boundary, not an expiring cipher

An AES key does not stop decrypting because a timestamp passes. Expiry removes permission in a cooperating gateway and triggers cleanup. Stronger externally enforceable expiry requires an upstream credential that expires or can be revoked by the upstream issuer. Even then, its authority and any resulting sessions or tokens must be understood separately.

For this product, the principal benefit is bounded exposure and explicit authorization, not an impossible promise that a previously authorized process cannot remember a secret.

## 4. Architecture and terminology

### 4.1 Components

```text
                     Owner starts access window
                         /              \
                 Browser vault       Optional verification
                 root key local       local/enrolled factor
                       |                     |
             selected credential key        |
                 HTTPS activation           |
                       v                     v
MCP client ------> Go gateway --------------------------------> Upstream MCP
(named access key)  authentication / owner boundary               service
                    lease service / dispatch gate
                    temporary credential activation
                    upstream OAuth / destination guard
                    audit writer
                         |
                         v
                    PostgreSQL
                    ciphertext + wrapped keys
                    access verifiers + immutable approvals
                    lease metadata + append-only audit

No vault root, recovery key, unwrapped credential key,
raw tool arguments, or raw tool results belong in PostgreSQL.
```

Approval, notification delivery, and factor verification are separate from the encryption path. The baseline uses the mcpwarden UI itself; optional browser/app push wakes a review flow, and optional OTP or another enrolled factor verifies it. No separate runner or external approval service is necessary for the baseline implementation.

### 4.2 Distinct objects

| Object | Meaning |
|---|---|
| Vault root key, `VRK` | Random 256-bit root held by an unlocked client. Wraps subordinate keys through a derived wrapping key. |
| Credential encryption key, `CEK` | Random 256-bit key for one upstream credential and one security epoch. |
| Upstream credential | API token, bearer value, header bundle, or OAuth grant material encrypted under a CEK. |
| Client access record | Server-side identity of the bearer credential authenticated on an MCP request. |
| Approval request | Immutable request describing a caller, credential, scope, duration, and execution boot. |
| Approval attempt | Optional verification interaction under the configured policy. No synthetic successful attempt is created when approval is off. |
| Notification subscription | Delivery destination for an enrolled browser/app; not an approval factor or vault-key recipient. |
| Authorization source | `client_activation`, `owner_confirmation`, or `step_up`; distinguishes what actually authorized the window. |
| Execution lease | Durable authorization for multiple calls during a fixed window. |
| Runtime activation | In-memory CEK/credential availability on one particular gateway boot. |
| Dispatch admission | A single internal authorization decision immediately before upstream execution; not a human prompt. |
| Credential epoch | Changes after manual replacement, key compromise, regrant with changed authority, or material destination change. |
| Credential revision | Changes for ordinary encrypted-record updates, including OAuth refresh within the same epoch. |

### 4.3 Authorization and decryption must both succeed

```text
can_dispatch = authenticated_caller
            AND owner_matches
            AND current_policy_allows
            AND tool_visible_and_provider_enabled
            AND matching_lease_is_active
            AND lease_scope_matches_this_call
            AND runtime_activation_exists_for_current_boot
            AND credential_epoch_and_destination_match
            AND deadlines_and_limits_allow
```

A key in memory does not grant permission to other callers. Conversely, an `active` database row does not provide decryption capability after a restart.

## 5. Lease semantics

### 5.1 Proposed defaults

| Parameter | Default | Rule |
|---|---:|---|
| Working window | 15 minutes | User selects before confirmation. |
| Maximum working window | 60 minutes | Server-enforced deployment cap; never trust the browser's requested duration. |
| Approval-request lifetime | 5 minutes | Ends stale requests; separate from the work window. |
| Activation after approval | Within 60 seconds | Also bounded by the approval request's expiry. |
| Idle expiry | Disabled | Normal pauses while the agent reasons must not create surprise prompts. |
| Maximum call count | Unset | Multiple calls are the default, not a one-use permit. |
| Per-caller concurrency | 4, initially | Configurable engineering default, not a measured optimum. |
| Prompt deduplication | One live equivalent request | Same caller, credential, epoch, scope, duration, and boot. |
| Expiry behavior | Stop new admissions; cancel pending dispatch work | In-flight completion handling is specified below. |
| Renewal | Explicit new window | Applies current approval policy; traffic never silently extends the window. |

Rate limits and concurrency limits remain independent of human approval. A fifteen-minute lease need not allow an unlimited burst.

### 5.2 When time starts

The working window starts at **successful activation**, not when the agent first requests permission or when a push is queued.

```text
activated_at = authoritative activation time
expires_at   = min(activated_at + approved_duration,
                   requesting_access_record.expires_at,
                   any explicitly approved absolute end)
```

A lease must activate before `activation_deadline`. If the browser spends too long unlocking, obtain a new authorization under the current mode; do not keep a decided request redeemable indefinitely. Prefer unlocking before starting a short-lived verification challenge. In `none` mode, owner-initiated activation checks the original request expiry and records authorization and activation in the same transaction; no prior factor challenge is needed.

Example: the user requests access at 14:00, approves at 14:01, and activation finishes at 14:01:05. A fifteen-minute lease expires at 14:16:05, not 14:15. The UI shows the exact end time and a countdown.

### 5.3 Continuity across calls and connections

Calls A, B, and C all use the same lease if each falls within its scope and deadline. Closing an HTTP connection does not revoke the lease. Opening another connection does not create a new lease. A second client key belonging to the same owner cannot borrow the first client's lease.

For v1, bind named API-key leases to their exact access-record IDs. Do not bind only to account ID, IP address, client-supplied `clientInfo`, or an MCP session identifier. For externally issued OAuth tokens, define whether the access record identifies the exact token or a verified workload identity. Default to the exact tracked access record; do not silently transfer a lease to a refreshed token based solely on a matching user `sub`.

### 5.4 Renewal and changing scope

Renewal creates a new authorization-binding record and a new lease ID under the current approval mode. It does not edit the expiry of an already approved lease. The old lease stays valid until its original expiry unless revoked. On successful replacement activation, explicitly supersede the old lease if the UI selected replacement rather than overlap.

An unlocked browser may reuse its locally held VRK to release the CEK after a new approval; the user does not need to retype the vault passphrase while that browser is still unlocked. Optional factor verification and vault unlocking are separate lifetimes. With extra approval off, renewal requires a new explicit owner start/key-release action, not an OTP or confirmation step and not automatic extension by agent traffic.

Adding a tool, expanding resource selectors, changing destination, or increasing duration requires a new owner-selected scope and authorization under the current mode. Removing a permission may take effect immediately through the current policy; an old lease must never override a newer deny.

### 5.5 Expiry and in-flight work

The guarantee is **no new dispatch admission after expiry/revocation**. A call already admitted is in flight even if its first network byte is still being scheduled. Revocation cancels its context where possible, but cannot undo an upstream operation or guarantee that no bytes already queued in the operating system will be sent.

Do not retain unused admission permits in a queue. Complete connection setup and any authorized refresh first, then recheck before admitting the actual tool call. Apply a per-call timeout. On expiry, stop new tool calls, reconnects, discovery, and refresh starts unless a separate still-active lease authorizes them.

Allow bounded cleanup of already-running calls, including encrypting a newly returned OAuth refresh token. That cleanup is not permission to start a new upstream action. The UI must distinguish “access expired” from “one earlier call is still finishing.”

### 5.6 Clock handling

Persist UTC timestamps. At activation, retain a monotonic deadline in memory **and** the absolute UTC deadline; reject when either has expired. Do not convert the in-memory monotonic deadline to UTC and expect its monotonic component to survive. Go serializes time values without that component, and on some systems monotonic time does not advance during sleep. [R19]

Use an independent wall-clock check, detect large clock discontinuities, and suspend leases after uncertain resume or clock state. Require operator clock synchronization. No local clock design protects against a malicious host administrator who controls the clock and process.

For PostgreSQL transactions, use the actual current clock when evaluating a deadline after waiting on a lock. `CURRENT_TIMESTAMP`/`now()` is fixed at transaction start; a blocked transaction must not activate an already-expired request using its earlier start time. [R20]

## 6. Permission model

### 6.1 Approval binding

The canonical approved scope contains:

```json
{
  "schema": "mcpwarden.lease-scope.v1",
  "owner_id": "local",
  "requester_access_id": "11111111-1111-4111-8111-111111111111",
  "connector_id": "22222222-2222-4222-8222-222222222222",
  "credential_id": "33333333-3333-4333-8333-333333333333",
  "credential_epoch": "1",
  "purpose": "tool_use",
  "duration_seconds": 900,
  "policy_revision": "7",
  "connector_security_revision": "2",
  "destination_profile_sha256": "<base64url SHA-256>",
  "tools": [
    {
      "tool_id": "44444444-4444-5444-8444-444444444444",
      "definition_sha256": "<base64url SHA-256>",
      "constraints": [
        {"pointer": "/owner", "operator": "equals", "value": "example-owner"},
        {"pointer": "/repo", "operator": "equals", "value": "example-repository"}
      ]
    }
  ],
  "max_calls": null
}
```

IDs are illustrative. Array ordering must be canonicalized by the application before hashing: tools by stable tool ID, constraints by an unambiguous deterministic order. Preserve case when a tool or provider treats values as case-sensitive. Do not infer provider semantics from this example.

`scope_digest = SHA-256(JCS(scope))`. The separate `request_digest` covers the scope digest, approval ID, gateway boot ID, random challenge, request expiry, effective approval mode, required verification method, and approval-policy revision. The scope digest supports deduplication; the request digest prevents approval substitution. JCS means RFC 8785, not ordinary pretty-printed JSON or PostgreSQL `jsonb::text`. [R16]

### 6.2 Constraints must be enforceable

Start with a deliberately small predicate language: required JSON pointer, exact string/boolean/integer equality, and membership in a bounded explicit set. Reject missing properties, wrong types, duplicate JSON keys, and unsupported predicates. Do not ship arbitrary expression evaluation, regular-expression policy code, or model-generated judgments as the security boundary.

An upstream tool may accept a query language or unrestricted shell command. A JSON pointer cannot establish that arbitrary SQL is read-only or that a shell command stays within a repository. Mark such tools as unconstrained, exclude them from narrow templates, or require an upstream account with independently limited authority.

Likewise, a caller-controlled URL argument can cause data movement even though the credential header itself goes only to the approved MCP endpoint. Tool scope, argument restrictions, and upstream credential scope are complementary controls.

### 6.3 Tool changes and schema pinning

A lease records the reviewed definition digest. Define that digest over the exact name, description, input/output schemas, relevant annotations, and header-mapping behavior after validated normalization. If a security-relevant definition changes, block use under the old lease and require a new owner-selected scope and activation under the current mode. Do not silently include newly discovered tools in an existing “all tools” lease.

The UI may offer “all currently selected tools,” but materialize that choice as a finite snapshot of stable IDs and digests. The protocol explicitly treats annotations from untrusted servers as untrusted; a `readOnlyHint` is not an authorization proof. [R05]

### 6.4 Multiple leases

A single call must be fully authorized by **one** matching lease. Do not combine a repository permission from lease A with a tool permission from lease B into a new authority neither approved.

For multiple matching leases, choose deterministically: prefer an exact configured scope, then the earliest expiry, then stable lease ID. Record the chosen lease. A user may approve several connectors in one UI interaction, but issue and audit a separate child lease per credential; do not release a whole-vault key to implement a convenience button.

### 6.5 Approval authority is separate from agent authority

Named client keys can discover tools, invoke allowed tools, inspect their own lease status, and optionally request a lease. They cannot approve, activate with arbitrary client-supplied decisions, change approval policy, enroll an approval factor, or turn off required verification.

Existing `admin` MCP keys should not automatically gain these abilities. Interactive owner management needs a separate server-enforced authorization path. In external-OAuth mode, add an explicit approved human-flow capability through the chosen identity provider and local binding; do not interpret `mcp:manage` alone as proof of fresh human approval.

Changing factor enrollment, recovery enrollment, approval policy, or the ability to bypass approval must itself require fresh owner authentication and the currently enrolled factor when one is required. A notification-only on/off preference does not lower the approval policy. Otherwise an attacker can disable the barrier before using the credential. [R10]

### 6.6 Initial authentication-mode support

Implement the first release against local-account browser sessions and named client access keys. The existing account login supplies the interactive owner context; sensitive security changes require fresh password verification or the already enrolled stronger factor. Vault unlocking remains separate and local.

For the shared local-operator bearer mode, possession of the same bearer token by both an agent and a browser cannot distinguish a human approval. Do not enable client-release approvals in that mode until there is a separately enrolled human approval context. For external OAuth, require a verified interactive identity-provider flow and a stable issuer/subject binding; a manually pasted `mcp:manage` token is not sufficient by itself. Reject unsupported custody/auth combinations at startup with an actionable message rather than falling back to automatic approval. Existing non-client-release deployments may retain their current behavior under an explicit legacy mode.

## 7. End-to-end approval and activation

### 7.1 Normal workflow with confirmation enabled

```text
1. Agent calls a permitted tool with its own named access key.
2. Gateway authenticates it and checks current policy.
3. No matching lease exists; gateway returns an approval-required outcome.
4. Owner opens the UI and sees caller, credential, tools, resources, and duration.
5. Browser unlocks its vault locally if needed.
6. Owner confirms this scope; a second factor completes only if `mode: step_up`.
7. Gateway records approval, but does not yet permit execution.
8. Browser unwraps this credential's CEK and sends it over HTTPS to activation.
9. Gateway validates the binding, authenticates the encrypted credential bundle,
   commits lease + audit metadata, and publishes memory-only activation.
10. Agent deliberately resumes. Many calls run under that lease without new prompts.
11. At expiry/revocation, the gateway blocks new admissions and cleans up key state.
```

The agent never receives the CEK, upstream token, OTP seed/code, notification-service secret, or a vault export. For `mode: none`, the owner skips step 6 and starts access directly during client key release; §11.2 defines the equivalent atomic transition without a separate approval challenge.

### 7.2 Approval request state machine

```text
pending -> challenging -> approved -> activated
   |           |             |
   +-----------+-------------+-> denied / cancelled / expired / stale
```

`challenging` exists only when configured verification is in progress. `confirm` may move directly from `pending` to `approved` following authenticated owner confirmation; `none` skips both the challenge and separate confirmation. In the latter case, authenticated owner activation records `approved` and `activated` atomically with `authorization_source=client_activation`. The historical state name `approved` means the binding was authorized; do not display it as proof of MFA. `approved` is not active execution. `stale` means the approved binding changed, for example the requester was revoked, the credential epoch changed, or the gateway restarted.

Terminal states are not resurrected. A new attempt after expiry receives a new request ID and challenge. Scope editing replaces a request; it does not mutate a request already sent for approval.

### 7.3 Lease state machine

```text
                    activation succeeds
                            |
                            v
                          active
                      /     |      \
                  expired revoked suspended
```

`Suspended` includes runtime restart or loss of activation material. None of these states is renewed by traffic. A new owner-started authorization/activation under the configured mode creates a new lease.

### 7.4 Concrete activation payload

**This is sensitive request-body data. It must never be logged, traced, cached, or placed in a URL.**

```http
POST /api/approvals/{approval_id}/activate
Content-Type: application/json
X-CSRF-Token: <session-bound token>
Idempotency-Key: <random operation ID>
```

```json
{
  "gateway_boot_id": "55555555-5555-4555-8555-555555555555",
  "request_digest": "<base64url SHA-256>",
  "challenge": "<base64url 32-byte challenge>",
  "credential_id": "33333333-3333-4333-8333-333333333333",
  "credential_epoch": "1",
  "cek": "<base64url 32-byte credential encryption key>"
}
```

The server derives owner and approver identity from authentication. They cannot be overridden in this body. The activation handler is not available to normal MCP-client credentials. The user-approved origin, trusted reverse proxy, and gateway are explicitly inside the TLS trust boundary.

For v1, sending this selected CEK through the trusted HTTPS endpoint is simpler than inventing a new ECDH protocol. A future independently trusted client may encrypt key releases to an enrolled executor using a reviewed standard construction; that is not required here and does not make the executor unable to read its key.

### 7.5 Validation order and atomicity

Perform bounded input parsing, authenticate the interactive caller, validate origin/CSRF, and reject unexpected fields before handling the CEK. Under the owner security gate and a database transaction:

1. Lock the relevant approval and access records in the documented order.
2. Resolve the current effective approval mode and policy revision. For `confirm` or `step_up`, require `approved`, matching confirmation/factor evidence, the expected owner, the current boot, an unexpired activation deadline, and matching challenge/request digest. For `none`, accept only an unexpired `pending` binding from an authenticated owner-initiated key-release action; set its decision and activation deadline in this same transaction with `authorization_source=client_activation`. Never accept a caller-provided approval mode.
3. Recheck requester revocation/expiry, current owner policy, connector status, credential epoch, destination digest, and tool-definition digests.
4. Check the selected CEK by decrypting the current credential record with **reconstructed expected AAD**. Do not use AAD supplied by the activating browser as authorization truth.
5. Stage the runtime material privately; it is not visible to dispatch yet.
6. Insert exactly one lease for this approval, set activation/end times, transition the approval to `activated`, and insert the audit event in the same transaction.
7. Commit; publish the activation and lease snapshot together while the owner gate is still held.
8. Wipe temporary buffers best-effort and return non-secret lease metadata.

No database transaction can be atomic with process memory across a crash. The safe recovery rule is to remain locked when memory and durable state disagree. Do not “repair” that mismatch by persisting an unwrapped CEK.

An idempotent repeat of the same activation operation returns the existing lease only when that lease and its runtime activation are still live on the same boot. It must not reset `activated_at`, extend expiry, recreate deleted memory state, or start a new grant. An ambiguous commit result requires reconciliation by operation ID; it never justifies a second lease.

### 7.6 Notification and key availability are different

A push notification or OTP verification does not itself supply this vault's CEK. If no unlocked key-holding device is available, the request can become approved but cannot activate. The UI must say “Approved — unlock your vault to activate,” not “Access granted.”

A push to a phone could complete both steps only if a future mcpwarden phone client also holds authorized vault material and implements key release. Bitwarden's documented device-login flow is a useful precedent for approved, recipient-bound key transfer, but it is not an implementation of this mcpwarden workflow. [R04]

## 8. Key hierarchy and encrypted records

### 8.1 Separate login from vault unlocking

Keep the current password-verifier and session implementation separate from vault encryption. Use a distinct vault passphrase in the first version. Do not derive a vault key from a login password that is also sent in plaintext inside HTTPS to the gateway: that gateway would then know the input needed to derive the vault key.

The browser handles the vault passphrase locally. Login recovery restores account access, not decryption. Do not store the vault passphrase, derived unlock key, VRK, or CEK in `localStorage`, `sessionStorage`, a cookie, telemetry, or an unencrypted IndexedDB object.

### 8.2 Proposed hierarchy

```text
vault passphrase -- Argon2id -- HKDF --> K_pass ----+
                                                  |
offline random recovery key -- HKDF --> K_recovery +--> wrapped VRK
                                                  |
future WebAuthn PRF -- HKDF --> K_device -----------+

VRK -- HKDF("mcpwarden/v1/credential-key-wrap") --> K_wrap
K_wrap -- AES-256-GCM wrapping --> CEK(credential, epoch)
CEK    -- AES-256-GCM ---------> encrypted credential revisions
```

Generate VRK and CEKs independently using a cryptographic random generator. Do not use owner IDs, passwords, UUIDs, timestamps, or bearer tokens as encryption keys. Use HKDF-SHA-256 for explicitly labeled key separation; use 32 zero bytes as the specified HKDF salt where the input is already secret key material and the protocol does not require a random salt. Different purposes use different `info` strings. [R17]

The same CEK may protect a small sequence of credential revisions, each with a fresh nonce. A manually replaced credential or changed authority creates a new CEK/epoch. No server-managed wrapper is permitted for CEKs in `client_release` mode. Adding such a wrapper would restore permanent server decryption and must be a separately named custody mode.

### 8.3 Passphrase profile

Initial candidate: Argon2id version 0x13, memory 65,536 KiB, time cost 3, parallelism 4, salt 16 random bytes, output 32 bytes. This follows the lower-memory recommended profile in RFC 9106. Benchmark the actual browser/phone targets before release; store parameters with each wrapper. [R14]

Then derive `K_pass` with HKDF-SHA-256, output 32 bytes, zero salt, `info = UTF8("mcpwarden/v1/passphrase-root-wrap")`. The passphrase encoding is UTF-8 without trimming or implicit Unicode normalization; document this and test international input across supported devices.

Pin a reviewed Argon2 implementation and its assets; do not load it from a runtime CDN. The chosen browser Argon2 implementation is an implementation dependency still to be selected and audited, not supplied by the AES-GCM Web Crypto example. A WASM implementation needs explicit memory cleanup and a compatible CSP. The Go `x/crypto/argon2` package is useful for independent test-vector checking, not a reason to send the passphrase to Go. [R15, R32]

The client must validate the suite, lower/upper parameter bounds, encoded lengths, and a bounded wrapper size **before** performing expensive KDF work. Reject unsupported or weaker suites rather than silently falling back. Wrapper AAD authenticates the parameters so they cannot be changed without invalidating the ciphertext. Initial hard bounds can permit only the chosen profile; adding another profile is a versioned decision.

### 8.4 AEAD envelope

Use AES-256-GCM with a 32-byte key, 12-byte random nonce, and 16-byte authentication tag. The wire record stores the nonce separately and `ciphertext || tag` together. Encode binary fields using unpadded base64url. [R15, R18]

```json
{
  "format": "mcpwarden.secret.v1",
  "algorithm": "AES-256-GCM",
  "owner_id": "local",
  "connector_id": "22222222-2222-4222-8222-222222222222",
  "credential_id": "33333333-3333-4333-8333-333333333333",
  "epoch": "1",
  "revision": "3",
  "purpose": "upstream-credential",
  "destination_profile_sha256": "<base64url SHA-256>",
  "nonce": "<base64url 12 bytes>",
  "ciphertext": "<base64url ciphertext followed by 16-byte tag>"
}
```

The AAD is the UTF-8 RFC 8785 canonical encoding of every displayed field **except** `nonce` and `ciphertext`. A decoder reconstructs it from the expected owner, connector, credential, epoch, revision, and approved destination. Do not simply decrypt using attacker-supplied identity fields and then assume their authenticity establishes authorization.

Epochs/revisions are positive decimal strings without leading zeros to avoid cross-language integer rounding. UUID strings are canonical lowercase. `owner_id` preserves the actual stable project owner identifier; it is not assumed to be a UUID because existing modes include `local` and externally derived identities.

For CEK wrappers, use the same AEAD suite but a distinct envelope format and purpose. Its AAD contains owner, root ID/version, connector, credential ID, and epoch. For root wrappers, bind owner, root ID/version, wrapper ID, wrapping method, and exact KDF parameters including salt. Do not reuse one envelope for unrelated purposes.

Never derive a nonce from a record revision or timestamp. Enforce a conservative operation cap per encryption key and rotate before the underlying library's maximum usage; a proposed cap of 2^20 writes per CEK is far above expected credential-refresh volume and below the GCM random-nonce ceiling. Track counts across all writers. A database uniqueness constraint on a credential epoch's nonce can detect accidental collisions, but is not a substitute for random generation.

### 8.5 Browser/Go interoperability

Browser encryption uses `crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: aad, tagLength: 128}, key, plaintext)`. Decryption uses the exact same AAD bytes. Go can use `aes.NewCipher` and `cipher.NewGCM` with an explicitly generated random 12-byte nonce. Keep this operation inside one reviewed helper so callers cannot accidentally choose a nonce. [R15, R18]

Go also has `NewGCMWithRandomNonce`, which uses a different nonce-prefixed API layout. Do not mix that layout with the explicit-nonce envelope without an adapter and cross-language tests. The companion interoperability fixture tests the explicit-nonce format, not the full application, KDF, recovery, or all browser implementations. [R18]

Use strict parsers: reject duplicate object keys, invalid encodings, missing/unknown fields, unsupported algorithms, oversized records, invalid tag lengths, and noncanonical identity fields. AEAD failure must produce a generic safe error, not a dump of the encrypted object or the attempted secret.

### 8.6 Credential bundle boundaries

Encrypt header **values**, API/bearer tokens, OAuth access/refresh tokens, and OAuth client secrets together as a structured credential bundle. Header names may remain visible for administration, but bind the permitted names and their destination behavior into the destination profile. Headers must be applied by a dedicated transport component, not arbitrary user-provided HTTP options.

Example plaintext shape before encryption, for illustrative fake data only:

```json
{
  "kind": "header_bundle",
  "headers": [{"name": "Authorization", "value": "Bearer EXAMPLE_ONLY"}]
}
```

The OAuth variant holds its entire current token state atomically. Do not encrypt the access token but leave the refresh token or client secret in searchable database columns.

### 8.7 What authenticated encryption does not do

AEAD detects modified or incorrectly contextualized ciphertext. It does not establish that a valid older revision is the newest one. Use durable version checks and current pointers for ordinary operation. A backup restore deliberately resets history and starts all execution locked. Protection from a malicious storage operator replaying an entire consistent old state would need an independently trusted checkpoint and is deferred.

### 8.8 Exact wrapper profiles

For interoperability, use these format/purpose pairs: root wrapper `mcpwarden.root-wrap.v1` / `vault-root`; CEK wrapper `mcpwarden.credential-wrap.v1` / `credential-key`. Both use the same explicit-nonce AES-256-GCM wire layout as §8.4, with a 32-byte plaintext key and therefore exactly 48 bytes of ciphertext plus tag.

A root wrapper's authenticated header consists of `format`, `algorithm`, `purpose`, `owner_id`, `root_id`, `root_version`, `wrapper_id`, `method`, and `kdf`. The `root_version` is a positive decimal string. `method` is `passphrase` or `recovery` in v1. Append `nonce` and `ciphertext` as fields excluded from the AAD header. Both participate in the AEAD operation: the former is the GCM nonce and the latter is the authenticated ciphertext/tag. Reject all other fields.

The passphrase `kdf` object is exactly:

```json
{
  "suite": "ARGON2ID-HKDF-SHA256",
  "argon_version": 19,
  "memory_kib": 65536,
  "iterations": 3,
  "parallelism": 4,
  "salt": "<unpadded base64url 16 random bytes>",
  "output_bytes": 32,
  "hkdf_info": "mcpwarden/v1/passphrase-root-wrap"
}
```

The recovery `kdf` object is exactly `{"suite":"HKDF-SHA256","output_bytes":32,"hkdf_info":"mcpwarden/v1/recovery-root-wrap"}`. Its input is the decoded random 32-byte recovery key, not the printable recovery string. Both HKDF steps use a fixed 32-byte all-zero salt; the Argon2 salt is separate. Root AAD is JCS of the authenticated header, including the entire validated KDF object. Fixed suite parameters are validated before deriving a key; the caller cannot choose an arbitrary `hkdf_info`.

A CEK wrapper's authenticated header is exactly `format`, `algorithm`, `purpose`, `owner_id`, `root_id`, `root_version`, `connector_id`, `credential_id`, and `epoch`. All IDs/versions follow §8.4. Derive its wrapping key with HKDF-SHA-256 from VRK, a 32-byte zero salt, 32-byte output, and `info = UTF8("mcpwarden/v1/credential-key-wrap")`. Compute AAD as JCS of that header; append `nonce` and `ciphertext` using the same binary encoding. The database schema stores a normalized subset and related identity rows; reconstruct every required header field from validated context, not from unspecified column order.

Initial parser limits should be explicit constants, for example a 64 KiB decoded credential bundle, a 256 KiB canonical approval scope, and a finite maximum tool/constraint count. These are proposed resource limits to test against real connectors, not protocol limits. Do not silently truncate secret values or approved tool sets when a limit is exceeded.

## 9. Runtime enforcement and concurrency

### 9.1 Separate metadata from secret resolution

Do not make the current error-free `catalog.Repository` reads secretly perform decryption, network KMS calls, or interactive unlock. Preserve the coherent cached metadata view. Introduce an explicit, fallible secret-activation/resolution boundary used only by execution and approved setup operations. [P0 §7.2]

A proposed package split is:

```text
internal/secret      envelope parsing, encrypted records, memory activation handles
internal/lease       scope matching, deadlines, counters, admission/revocation
internal/approval    immutable requests and approval-provider interface
internal/upstream    guarded connections, scoped OAuth refresh, credential injection
internal/proxy       caller/tool resolution and final dispatch integration
internal/catalog    durable metadata and encrypted-record adapter
internal/audit      security events and invocation attribution
```

These names are proposed extensions; they are not asserted to exist today beyond the packages listed in the handoff.

### 9.2 Runtime activation indexing

Index key material by `(owner_id, credential_id, epoch, gateway_boot_id)`. Keep a set of active lease references and a count of in-flight operations that need it. Different callers may use the same underlying credential only through independently authorized leases under the configured mode.

Expiring caller A's lease does not erase caller B's still-authorized execution. Once there are no live leases, disable all new access to the activation immediately; then drain/cancel existing work and clear material. Never let the presence of a shared activation shortcut caller-specific authorization.

A process-wide byte slice map is only a software boundary. Prefer opaque internal handles; expose methods for constrained transport use instead of returning CEK bytes to arbitrary packages. Avoid string conversions of keys. Header values necessarily enter HTTP objects; limit their lifetime and prohibit generic request dumps.

### 9.3 Ordered dispatch algorithm

For each tool call:

1. Authenticate the current request and bind it to the real access record and owner.
2. Resolve the tool by stable identity; reject hidden, removed, or disabled tools.
3. Validate arguments and current policy; find one lease covering the complete call.
4. Check boot, epoch, scope, definition, destination, caller expiry, and both clocks.
5. Perform any necessary connection setup/refresh only under current authorized maintenance access.
6. Immediately before dispatch, enter the owner security gate, recheck all mutable authorization state, and durably record admission plus any optional counter reservation.
7. Create a short-lived internal admission bound to this call and the relevant activation; release the gate and dispatch without unrelated queueing.
8. Capture actual credential epoch/revision used for transport injection.
9. Record completion or an explicit unknown/ambiguous outcome. Release activation references.

Steps 3–9 contain no human prompt when the lease is valid. Do not call an approval provider synchronously on every invocation.

### 9.4 Owner security gate

Start with a per-owner coordinator/mutex for **short security transitions**: admission, activation, revocation, disabling a provider, credential replacement, and permission change. Do not hold it while waiting for notification delivery or optional verification, reading user input, receiving an upstream tool result, or refreshing an OAuth token over the network.

Use a consistent lock order: owner security gate → database owner row → access record → connector/credential → approval/lease rows in stable ID order. Publish metadata only after durable commit. Admission and revocation must use the same coordinator, including admin-MCP actions and background callbacks.

The revocation commit/publication point is the linearization boundary: new admissions after it fail. Previously admitted work may already have side effects; cancellation is best effort. A cached grant whose revocation has not been published must never remain usable after the revocation API reports success.

### 9.5 Optional call limits

A call limit counts **admitted attempts**, not only successful responses. Reserve atomically before dispatch. A crash or ambiguous upstream failure does not refund the reservation, because the upstream may have executed. Concurrent calls must not exceed the limit.

No call limit is required for the default timed model. Keep rate/concurrency controls to bound burst size. Do not deduplicate normal calls by argument hash: an agent may legitimately repeat the same query during a working window.

### 9.6 Durability versus performance

The conservative first version writes a durable admission event before an upstream side effect. If that write fails, no new call is dispatched. Completion is appended separately; a crash can therefore leave an admitted call with unknown outcome. This does not provide exactly-once execution across a remote provider.

Measure the database/audit overhead rather than guessing it is negligible. A later batching mode must declare its weaker durability and fail-open/fail-closed behavior. Do not silently replace the existing synced-audit expectation with best-effort asynchronous logging. [P0 §7.3]

## 10. MCP compatibility and errors

### 10.1 Keep leases independent of the transport era

The 2026-07-28 specification uses per-request metadata and no protocol-level session; older revisions use an initialization/session model. A caller-bound lease works across both. Implement the authentication and dispatch boundary once, and put protocol-version-specific handling in the SDK adapter. Do not equate an HTTP keep-alive connection or legacy `Mcp-Session-Id` with authority. [R05, R06, R08]

Use the pinned official SDK for protocol encoding, request metadata, cancellation, and version compatibility. The new revision includes changes such as `resultType`; a hand-written 2025 response must not be assumed correct for all clients. [R05, R08]

### 10.2 Discovery while locked

Keep statically authorized, visible tool definitions available from the safe metadata cache while credentials are locked, with a clear locked status in the management UI. The tools remain eligible capabilities requiring an access-window prerequisite; `tools/call` must still enforce it. Keep listing order deterministic and do not vary authority merely because a connection previously made another request.

If a client/version interprets “available” more strictly, test a filtered-list variant and its change notifications. The baseline must continue to omit hidden tools. Never connect an upstream merely to refresh a locked tool list without discovery authorization.

### 10.3 Missing lease is not automatically an OAuth login failure

Distinguish layers:

| Condition | Behavior |
|---|---|
| Invalid/expired downstream bearer credential | Proper HTTP authentication failure. |
| Missing downstream OAuth scope | Protocol-appropriate insufficient-scope response. |
| Authenticated caller lacks a local execution lease | mcpwarden access-window prerequisite; do not pretend the identity provider can fix it. |
| Lease exists but no runtime key | Locked/suspended activation outcome. |
| Tool is hidden or permanently denied | Preserve current denied/unknown-tool policy and audit behavior. |

The OAuth resource-server response rules still apply to actual token/scope failures. A local lease is additional application authorization, not a new OAuth token to pass upstream. [R07]

### 10.4 Proposed interoperable application error

For an authenticated tool request blocked before execution, return a safe tool-level failure or the negotiated version's supported input-required flow. Initial fallback: an `isError` result with plain text and a namespaced `_meta` payload. Do not put a generic management object in `structuredContent` if it violates the upstream tool's advertised output schema.

Illustrative **2026-07-28 result body**; let the SDK wrap the JSON-RPC response:

```json
{
  "resultType": "complete",
  "isError": true,
  "content": [{
    "type": "text",
    "text": "MCPWARDEN_LEASE_REQUIRED: No upstream action was executed. Start an access window in the mcpwarden panel, completing any configured verification, then resume this request."
  }],
  "_meta": {
    "io.github.yaphoa.mcpwarden/access": {
      "code": "LEASE_REQUIRED",
      "approval_id": "66666666-6666-4666-8666-666666666666",
      "management_path": "/approvals/66666666-6666-4666-8666-666666666666",
      "automatic_retry": false
    }
  }
}
```

This is a proposed extension, not a standard MCP lease schema. Clients may ignore `_meta`; the text must remain useful. For earlier protocol revisions, use their SDK result form without inventing fields. [R05]

Do not encode CEKs, bearer tokens, raw arguments, or credential values in approval URLs or MCP elicitation forms. The newer multi-round-trip mechanism is an optional integration path, not permission to blindly replay an already-dispatched operation.

### 10.5 Avoid approval storms

The first blocked call may create one pending request based on a configured permission template. Equivalent blocked calls return that request's status, not another push. Keep agent-triggered push off by default. An owner may explicitly enable a deduplicated notification when a permitted client requests access, which is necessary for useful remote approval. Send only to the owner's pre-enrolled subscriptions; a request cannot choose its notification recipient. Notifications do not grant authority.

The gateway does not queue the blocked tool call for automatic execution. It returns before any upstream side effect. The UI can say “Approved; resume the agent.” A cooperating client may deliberately resubmit a request known not to have executed; the gateway must never retry an ambiguous earlier call itself. [P0 §9]

### 10.6 Stdio

Stdio has no HTTPS hop; it relies on local process/OS trust. Bind a stdio client to an explicit execution principal and enforce the same lease checks. Do not let the subprocess manufacture an owner identity or approval.

The handoff does not establish whether the stdio deployment simultaneously exposes the management API. Verify that before claiming the browser can unlock it. V1 can ship timed approval for the HTTP deployment first, keeping stdio unchanged or explicitly unavailable in client-release mode until an authenticated management path to the same runtime exists.

## 11. Optional approval, notifications, and verification

### 11.1 Product controls and supported combinations

**No external approval vendor is required.** First-party in-app review is the baseline. Three independent decisions determine behavior:

| Control | Values | Meaning |
|---|---|---|
| `approvals.mode` | `none`, `confirm`, `step_up` | No extra approval; explicit owner confirmation; or confirmation with an enrolled factor. |
| `approvals.verification.method` | `none`, `totp`, optionally `webauthn` or a reviewed device adapter | How additional verification is proven. A method must be implemented and enrolled before it is selectable. |
| `notifications.web_push.enabled` | `false`, `true` | Whether to deliver first-party browser/app review notifications. It does not choose or satisfy a verification method. |

Proposed baseline: `mode: confirm`, `verification.method: none`, Web Push off. The owner may select `none` to remove the extra confirmation entirely. A local authenticator OTP flow needs no push service. Push-assisted confirmation needs no OTP. Combining push delivery with OTP is also valid.

For the simple UI, expose **Require approval before access**, **Require additional verification**, and **Send push notifications**. Map these to the enum, not three independently trusted booleans from an MCP caller. When approval is off, factor verification for lease creation is off too; login MFA is a separate account setting and must not be disabled as a side effect.

A notification or a button in an already logged-in page is not automatically a second authentication factor. Call that mode “confirmation.” Only label it additional verification when the required enrolled factor actually succeeds. [R40]

### 11.2 Exact behavior when extra approval is disabled

`mode: none` means **no additional confirmation or OTP/push challenge**, not “no authorization.” In this client-release design, the owner still starts a bounded window in an authenticated key-holding client. That action can combine scope selection, key release, and activation without a separate Approve dialog.

1. The named MCP client may create an immutable request for its own permitted scope. This never authorizes execution.
2. The owner starts access in the UI. Authenticate that owner, validate CSRF/origin, resolve the server's effective policy, and validate the selected credential/key exactly as in §7.5.
3. Under the owner coordinator and transaction, require a live `pending` request, current boot/revisions, and `approval_mode=none`; bind the activating owner. Record `authorization_source=client_activation`, then create the fixed-duration lease and runtime activation. No `approval_attempts` success is fabricated.
4. Every MCP call still checks that particular caller's lease and runtime credential. The client never receives an unwrapped credential or activation authority.
5. After expiry or restart, a new owner-initiated window is required. A live CEK for caller A is not permission to mint a lease for caller B. Agent traffic must not silently renew a window.

This retains the original timed-window requirement. Fully unattended automatic renewal, permanent activation, or server-managed custody is a different explicit product policy; it is not inferred from turning notifications or extra approval off.

### 11.3 Separate interfaces, not a vendor-shaped core

Proposed domain sketches, not existing symbols:

```go
type NotificationSender interface {
    // Delivery cannot return an approval decision.
    Notify(ctx context.Context, target EnrolledNotificationTarget,
        notice SafeApprovalNotice) error
}

type VerificationMethod interface {
    // Challenge/proof DTOs are tagged and method-specific, with bounded sizes.
    Begin(ctx context.Context, binding ApprovalBinding) (ChallengeView, error)
    Verify(ctx context.Context, binding ApprovalBinding,
        proof VerificationProof) (VerificationEvidence, error)
}
```

The authorization service owns effective policy, immutable scope/request digests, deadlines, state transitions, and activation. `ApprovalBinding` includes owner, requester, credential epoch, boot, challenge, `approval_mode`, verification requirement, and approval-policy revision. Add those mode/revision fields to `request_digest`; the browser cannot change them after review. Strictly bind verification evidence to that request and the enrolled owner factor. Do not accept `approved: true`, a delivery receipt, or an arbitrary provider result from the browser as authority.

`none` invokes no verifier; `confirm` uses authenticated owner confirmation; `step_up` invokes the selected verifier once for that new window. The hot `tools/call` path invokes neither interface when the lease is valid. A future asynchronous external adapter can poll internally; polling is not a mandatory operation for all verification methods.

### 11.4 First-party in-app and browser push approval

**Implementation proposal:** ship an owner-scoped pending-request inbox using authenticated polling or SSE before requiring background notification support. The same review/decision endpoints work whether the user arrived through the sidebar, a notification, or a second enrolled browser.

Optional Web Push uses a service worker and `PushManager.subscribe` after an explicit notification permission gesture. The Push API supplies delivery to a web application, not human authorization. Feature-test target clients; do not promise background delivery merely because the page uses HTTPS. [R35]

Use the standard Web Push protocol for delivery, its payload encryption, and VAPID for application-server identification. VAPID identifies the sender to the push service; it does not authenticate the approving person. Prefer a maintained implementation over custom protocol cryptography. [R36–R38]

Proposed processing steps:

1. Authenticate enrollment. Store the owner/device association and encrypted subscription endpoint, `p256dh`, and `auth` material separately from vault credential encryption. A subscription is a delivery record, not a factor enrollment or vault recipient. Keep the VAPID private key in an operational secret store outside the database dump's trust boundary.
2. Treat a submitted endpoint as untrusted outbound input: require HTTPS, constrain approved push-service destinations, reject local/metadata/private destinations, revalidate DNS at connection time, and reject redirects. Never send vault credentials on this transport. See §16 and [R34].
3. Persist the access request before sending. Send only an opaque request identifier and generic text such as “An access request needs your review.” No token, key, OTP, raw arguments, credential label, or privileged approval URL is needed in the payload. Delivery TTL must not outlast request expiry.
4. A notification click opens a fixed same-origin path. The page authenticates the owner, retrieves current request details, and displays the actual caller/scope/duration. A URL is navigation, never a bearer approval capability; a GET cannot approve.
5. Confirmation uses a CSRF-protected POST. If `step_up` is configured, verify the enrolled factor before transitioning the request. Key release remains the distinct activation step; receipt or dismissal of a notification changes no permission.
6. Deduplicate equivalent requests and apply per-owner, per-client, and per-device limits plus an explicit resend cooldown. A notification delivery retry must not create a new approval, extend its expiry, or execute a tool. Drop expired/revoked subscriptions and stop retries at the local request deadline.

Browser push may involve a browser-selected external delivery service. Do not equate a self-hosted mcpwarden gateway with a fully self-hosted push network. Where external delivery is undesirable or unsupported, retain the in-app inbox. See the service role defined in [R35, R36].

A real enrolled phone/browser that also holds vault material may perform both approval and key release. An ordinary push service or authenticator app has no such material by default. No requirement to build a native mobile vault is introduced by this revision.

### 11.5 Optional authenticator OTP

For the OTP option, the initial proposal is local **TOTP** verification, rather than email/SMS codes or a mandatory cloud provider. RFC 6238 defines the time-based shared-secret construction, test vectors, bounded clock-skew handling, and rejection of reuse after successful validation. It does not bind an OTP to a tool scope or transaction by itself. [R39]

Proposed implementation requirements:

- Enroll only through fresh owner authentication; require a valid first code before activating the factor. Existing-factor replacement follows §17.5. Do not expose enrollment material through ordinary management/history APIs.
- Store each seed encrypted under a **separate operational factor-storage key**, not as a hash and not under the client CEK whose release depends on that factor. The verifier needs the seed or equivalent secure verification capability. This server-decryptable factor seed is not a server wrapper for the vault root or provider credentials; document that distinct custody boundary.
- Create a short-lived attempt bound to the request digest, enrolled factor, owner session, required method, and approval-policy revision. Verify inside the authenticated review flow; do not accept codes submitted by the MCP agent.
- Validate a deliberately small clock window and rate-limit by factor, owner, and attempt. Atomically consume the successful factor/time-step so concurrent requests cannot reuse a code. Share replay state with login verification if the same enrolled seed is used there. Keep no raw codes, seed values, enrollment QR data, or request bodies in logs.
- In the same transaction, record verified evidence for exactly that request. A cached `mfa_verified=true` flag on an account must not authorize unrelated new windows. Duplicates return the existing decision rather than granting another lease.
- Requiring a new code applies to starting/renewing a window, not to every MCP invocation. TOTP must not be described as a scope signature, vault decryption key, or phishing-resistant proof. [R39, R40]

The cryptographic validation of TOTP is standard; transaction binding, replay storage, mode selection, and lease behavior above are mcpwarden design decisions. The optional SQL companion gives storage sketches, not a tested factor implementation.

### 11.6 Enabling, disabling, and policy precedence

Keep delivery preferences separate from security policy. Turning Web Push off only stops notifications; pending requests remain visible in-app and required OTP still applies. Disabling a required factor or changing `step_up` to a weaker mode requires fresh owner authentication and the existing factor, or a deliberately enrolled recovery procedure. Never let an ordinary client/admin MCP key perform that change. [R40]

Proposed initial policy granularity is an owner default. An optional connector override can only tighten it (`none < confirm < step_up`); lower-level settings cannot weaken an operator-enforced minimum. Verification methods are not automatically interchangeable: require the configured method or an explicitly enrolled allowed alternative. A named client cannot choose a weaker mode in its access request.

For changes to approval requirements, increment an approval-policy revision, invalidate pending attempts and unactivated decisions under the prior revision, and revoke affected active leases under the same owner coordinator before reporting success. This conservative initial rule applies to both tightening and weakening, so a toggle cannot silently reinterpret an existing window. A delivery-only preference change does not revoke active leases.

Preserve `authorization_source` and policy revision in history. Turning extra approval off is an explicit security decision, not a reason to stop logging which client key used which credential.

### 11.7 Failure and fallback behavior

Push unavailable or permission denied: the same policy can still be satisfied through the authenticated inbox, because delivery is not verification. Required TOTP/WebAuthn unavailable: fail closed for new windows unless an allowed alternative was explicitly enrolled in advance. Do not silently downgrade to `none`, email, SMS, or ordinary confirmation. Existing leases retain their original deadline unless revoked by a security-policy change. Local revocation/execution lock does not depend on notification delivery or factor availability.

All notifications and verification outcomes are stale after their request expires, its policy revision changes, its caller is revoked, or the gateway restarts. A notification that arrives late opens a current status view, not an approval action.

### 11.8 External adapters are optional future integrations

Duo is only an example of a possible adapter, not a required provider, package, configuration block, milestone, or deployment prerequisite. Legacy references R11–R13 are retained for traceability only. No external adapter is needed to ship `none`, first-party `confirm`, or local TOTP. An adapter added later must meet the same immutable-request, fresh-evidence, replay, outage, and logging requirements; it cannot change the lease or key hierarchy.

WebAuthn may later provide additional verification. Its PRF extension is a separate possible vault-unlock mechanism; ordinary authentication does not derive the vault root. Prevent client-only PRF output from leaking in serialized authentication responses. [R30]

## 12. PostgreSQL model and transaction boundaries

### 12.1 Responsibilities

PostgreSQL stores encrypted bytes and structured non-secret authorization metadata. Encryption happens before secret values reach the database. `pgcrypto` executes within the database server's trust boundary and is not the implementation of client-only encryption. [R25]

The companion `reference/schema.sql` is a **candidate logical schema** for review in an empty scratch database. It is not a migration for the current repository. It concentrates on the security model and records where application-level validation is still necessary. No PostgreSQL server was available in this documentation environment, so the DDL is not claimed to be execution-tested.

### 12.2 Entity map

| Entity | Main contents | Important invariant |
|---|---|---|
| `owners` | Existing stable owner identity, auth mode, security revision | Do not collapse distinct external issuers into one namespace. |
| `local_account_verifiers` | Existing password hash/salt/parameters | No reversible login password. |
| `access_records` | Hashed caller credential, public handle, role, expiry, revocation | Hash/private token never appears in API responses or audit. |
| `connectors` | Endpoint/transport, enabled state, safe metadata, security revision | Secret values live only in encrypted credential versions. |
| `vault_roots` | Root identity/version | No root plaintext. |
| `root_wrappers` | Encrypted root + method/KDF metadata | Every wrapper is a deliberate recovery/unlock recipient. |
| `credentials` | Stable credential ID and current epoch/revision | Replacement preserves identity/history but changes authority epoch. |
| `credential_epochs` | CEK wrapped under client root, destination binding | No server-unlock wrapper in this custody mode. |
| `credential_versions` | Encrypted full credential bundle | New random nonce per revision; current pointer changes atomically. |
| `tool_definitions` | Cached schemas, stable IDs, visibility, definition digest | Finite approved tool set; no secret-dependent cache lookup. |
| `oauth_grants` | Safe grant identity, credential reference, lifecycle/CAS metadata | Access/refresh tokens remain in encrypted bundle. |
| `approval_requests` | Immutable scope/request, mode, policy revision, authorization source, and state | Decision applies to exactly these capabilities; no fabricated MFA evidence in `none` mode. |
| `approval_attempts` | Optional verification interaction, factor/method provenance | Only present when verification is attempted; duplicate proof cannot create another lease. |
| `execution_leases` | Caller, approval, epoch, scope binding, boot, deadline, state | One successful activation per approval. |
| `audit_events` | Append-only metadata and canonical argument hash | No cascading deletion or raw payloads. |

Optional factor enrollment and push-subscription storage are specified separately in `reference/approval-options.sql`. That file is a candidate extension to the base schema, not required tables for running with confirmation alone. It is also unexecuted. Effective approval mode/revision may initially come from operator configuration; UI-editable policies need the optional policy table or an equivalent durable implementation.

### 12.3 Integrity and authorization

Use composite keys and foreign keys beginning with `owner_id` wherever a child references personal state. Looking up by UUID alone is not enough. Parameterize all queries. Keep schema migration privileges separate from runtime privileges.

Use explicit owner predicates in every query. RLS can provide another boundary, but table owners/superusers and `BYPASSRLS` privileges require particular care. Set tenant context transaction-locally when using a pool; never leave one owner's setting on a connection reused for another owner. RLS does not hide data from the database operator or replace encryption. [R23]

Approval scope JSON must be parsed into a strict typed model and its canonical digest verified in application code. A `CHECK (jsonb_typeof(scope)='object')` does not prove that a scope is safe. The candidate DDL enforces structure and referential constraints, not the entire authorization protocol.

### 12.4 Transactions

| Operation | Atomic work |
|---|---|
| Mint a client key | Lock owner; remove/count expired records under existing cap rules; insert verifier and public ID; commit then publish. |
| Change login password | Verify current password; replace verifier and revoke required browser sessions together; revoke any approval contexts dependent on them. |
| Activate a lease | Lock binding rows; validate current state; insert lease + decision/audit transition; commit before runtime publication. |
| Revoke an access key | Revoke key + live leases + pending approvals; publish deny while holding security gate; cancel related work. |
| Replace a credential | Insert epoch/key wrapper/version; update current pointer; revoke old leases; preserve history. |
| Refresh OAuth | Serialize before network call; encrypt result; CAS expected epoch/revision and update grant state in one transaction. |
| Delete connector | Mark tombstone, revoke access, destroy current secret records according to retention policy; never cascade audit deletion. |
| Optional call-budget reservation | Conditional counter increment + durable admission event before upstream dispatch. |

Use row locks for cross-row caps and state transitions; a read-count-then-insert sequence without serialization is racy. Retry serialization failures only around database work that has not emitted an external side effect. PostgreSQL's transaction behavior and locking rules are the relevant implementation references. [R21, R22]

### 12.5 Example budget update

Within the transaction, after owner/security checks and with the exact lease selected:

```sql
UPDATE execution_leases
SET admitted_calls = admitted_calls + 1
WHERE owner_id = $1
  AND lease_id = $2
  AND requester_access_id = $3
  AND gateway_boot_id = $4
  AND state = 'active'
  AND expires_at > clock_timestamp()
  AND (max_calls IS NULL OR admitted_calls < max_calls)
RETURNING admitted_calls;
```

Zero rows means no admission. This query alone is **not** the full authorization check: current caller revocation, policy, epoch, scope, activation, and tool state must also be verified under the coordinator/transaction design. If `max_calls` is unset, the counter is usage attribution rather than an approval limit.

### 12.6 Single active gateway enforcement

Use an exclusive process lock for a file backend or a dedicated, session-held PostgreSQL advisory lock for the active executor. Keep the dedicated connection healthy; if ownership is lost, close the execution gate and fail closed. Do not use a transaction-pooled connection for a session advisory lock.

This reduces accidental dual startup, but is not a complete distributed fencing protocol. Active-active/failover requires workload fencing, coherent revocation, routing of key activation to the correct executor, and an explicit split-brain design. Database `LISTEN/NOTIFY` may wake a cache refresher; it is not a durable, sufficient security-consistency channel by itself. [R21, R24]

## 13. HTTP management API

All paths in this section are **proposed**, unless already identified in the handoff. Authentication, owner filtering, input limits, origin validation, and CSRF apply as appropriate. The UI and gateway remain separate services behind one user-facing HTTPS origin.

| Method/path | Caller | Purpose |
|---|---|---|
| `GET /api/vault/state` | Interactive owner | Wrapped-root availability and locked/active status; no keys. |
| `POST /api/vault/setup` | Freshly authenticated owner | Register encrypted root wrappers and initial metadata. |
| `GET /api/vault/wrappers` | Interactive owner | Fetch owner's encrypted root and credential-key wrappers. |
| `PUT /api/connections/{id}/credential` | Owner with vault unlock | Upload encrypted credential replacement under CAS. |
| `POST /api/access-requests` | Named requester or interactive owner | Create a scoped request; requester can target only its own access ID. |
| `GET /api/access-requests/{id}` | Owner or matching requester | Safe current status, not approver challenge codes or key material. |
| `POST /api/approvals/{id}/begin` | Interactive owner | Confirm the binding in `confirm`, or begin verification in `step_up`; not required in `none`. |
| `POST /api/approvals/{id}/verify` | Interactive owner | Submit typed factor proof for the exact bound attempt; no code logging. |
| `GET/PUT /api/security/approval-policy` | Owner; fresh verification for changes | View/change effective extra-approval requirements with revision checks. |
| `POST/DELETE /api/security/push-subscriptions` | Interactive owner | Enroll/remove a notification destination; never enroll an approval factor implicitly. |
| `POST /api/security/factors/totp/enroll` and `/confirm` | Freshly authenticated owner | Create a pending seed and confirm enrollment using a first valid code. |
| `DELETE /api/security/factors/{id}` | Owner with existing-factor/recovery authorization | Revoke a factor and invalidate affected approval state. |
| `POST /api/approvals/{id}/deny` | Interactive owner | Deny/cancel without requiring decryption. |
| `POST /api/approvals/{id}/activate` | Interactive owner meeting effective mode | Release selected CEK; in `none`, authorize and activate atomically without a separate approval step. |
| `GET /api/leases` | Owner; filtered self-view for client | List deadlines/scopes/usage; no secret material. |
| `DELETE /api/leases/{id}` | Owner; client may revoke only its own | Revoke immediately for future admissions. |
| `POST /api/vault/lock-execution` | Owner | Revoke all owner's leases and clear/drain runtime activation. |
| `GET /api/security/events` | Interactive owner | Owner-scoped status stream or polling endpoint. |

Use random operation IDs for idempotent management writes. Scope the idempotency key to owner, authenticated actor, route, and an immutable non-secret request digest. Do not hash or persist an activation request body that contains a CEK just to implement generic idempotency middleware.

Return `Cache-Control: no-store` for sensitive management and approval responses. No state-changing GETs, approval-by-link, wildcard credentialed CORS, or browser-supplied redirect destinations.

### 13.1 Status DTO

```json
{
  "lease_id": "77777777-7777-4777-8777-777777777777",
  "client": {"access_id": "11111111-1111-4111-8111-111111111111", "display_handle": "7Q2M", "label": "Laptop agent"},
  "credential": {"id": "33333333-3333-4333-8333-333333333333", "epoch": "1", "label": "GitHub personal"},
  "state": "active",
  "runtime_available": true,
  "activated_at": "2026-09-22T06:01:05Z",
  "expires_at": "2026-09-22T06:16:05Z",
  "admitted_calls": 18,
  "in_flight": 1,
  "approval_mode": "confirm",
  "authorization_source": "owner_confirmation",
  "verification_method": "none",
  "renewal_requires_owner_activation": true,
  "renewal_requires_confirmation": true,
  "renewal_requires_step_up": false
}
```

This is an example, not live state. `display_handle` is cosmetic. `runtime_available` must be read from the current executor, not inferred solely from a database lease row.

## 14. OAuth, discovery, and background work

### 14.1 First connection and discovery

A new encrypted connector cannot be contacted while its CEK is unavailable. Add an explicit **Connect and inspect** setup authorization. It grants only approved protocol setup and discovery, not `tools/call`. Suggested setup TTL: five minutes, bounded separately and shown to the user.

This solves the bootstrap problem: the owner cannot review an undiscovered tool set before the first authenticated discovery. Cache discovered definitions, then approve a finite tool-use scope. Discovery permission must not become a bypass through a per-provider refresh tool.

### 14.2 OAuth authorization-code flow

Preserve PKCE, one-time state, issuer/resource checks, exact redirect binding, and the existing browser-flow binding. A new OAuth grant requires an approved setup activation before code exchange. The browser can create and wrap the new CEK first, then temporarily release it for that setup. The gateway receives plaintext tokens during the approved exchange and immediately encrypts them under that CEK. This is explicitly an execution-time plaintext exposure, not purely opaque storage. [P0 §6; R29]

If setup authorization expires before the callback, do not store the authorization code in logs or redeem it later under unrelated authority. Fail safely and restart authorization. Credential-free discovery may run without a CEK only through the same destination/SSRF restrictions.

### 14.3 Refresh lifecycle

Use one refresh coordinator per `(owner, credential, epoch)` **before** the network request. Concurrent callers share the result of a single authorized refresh. A database compare-and-swap after the request does not prevent two workers from already spending the same rotating refresh token. Refresh-token replay protections make this concurrency boundary important. [R29]

After receiving a new token bundle, encrypt it with a fresh nonce; insert revision `n+1`; atomically update the current revision and grant CAS state. A refresh inside the same grant/authority keeps the same epoch, so it does not require another human approval for every token refresh. The audit records the actual revision used by each call.

Do not start background refresh while no applicable lease is active. A future unattended-maintenance mode is a separate, visible grant and custody decision, not an undocumented exception to timed access.

### 14.4 Refresh crash window

A provider can rotate a refresh token and the gateway can crash before persisting it. There is no atomic transaction spanning PostgreSQL and that provider. The result may require a new upstream login. Do not claim that CAS, database rollback, or retrying the old token always repairs it.

If the refresh was started while authorized but finishes just after expiry, permit bounded encryption/persistence cleanup to avoid discarding a valid replacement. Do not use that result to start a new tool call until another active lease allows it. Record cleanup separately from new execution.

### 14.5 Material authority changes

If a refreshed grant unexpectedly expands scope, changes issuer/resource/account, or violates the approved binding, quarantine it and require review. Manual token replacement, a new upstream account, and destination changes bump the credential/security epoch and invalidate existing leases.

### 14.6 Connection credentials and inherited state

A live upstream MCP connection, session cookie, refresh token, or stdio process may remain credential-bearing even after the raw header variable is cleared. Track and close/drain those objects when their final lease ends. Server-initiated protocol work and unsolicited upstream callbacks must not obtain a free pass around dispatch policy.

Ordinary connection reuse inside an active lease is desirable. Reuse across callers is permitted only where the protocol semantics and current owner isolation allow it; each call still carries its own validated principal and lease check.

## 15. Audit identity and key display handles

### 15.1 Record both sides of credential use

Each invocation should answer:

> Which authenticated client credential asked, which upstream credential/version was used, under which approval and lease, for which tool, and with what result?

The current handoff includes session identity but does not establish an explicit caller-access-record-to-upstream-credential linkage. Add it without removing existing timing, tool identity, canonical argument hash, and safe outcome fields. [P0 §7.3]

### 15.2 Public key handles, not secret suffixes

For new named MCP keys, use an unambiguous format such as:

```text
mcpw_<32 lowercase hex public-ID characters>_<43 base64url secret characters>
```

The secret component contains 32 random bytes. The public identifier is independently generated. Parse strictly. Store the existing SHA-256 verifier semantics over the full issued token, or deliberately version the verifier format if changing it; use constant-time comparison. Never store the raw token after showing it once.

Display a short suffix of the **public identifier**, for example `Laptop agent · …7Q2M` using a UI encoding of that identifier. The database and audit use the full public ID/access-record ID. On a display collision, show a longer handle. The handle is not an authentication factor or authorization key.

For old tokens already stored only as hashes, assign a new independent display handle. Do not require recovering the original token suffix. For upstream tokens, log a stable internal credential ID and epoch/revision, not the last four characters of an API key.

### 15.3 Audit event shape

Illustrative event; placeholder hashes and IDs are not real account data:

```json
{
  "event_id": "88888888-8888-4888-8888-888888888888",
  "event_type": "tool.dispatch.completed",
  "occurred_at": "2026-09-22T06:05:10Z",
  "owner_id": "local",
  "invocation_id": "99999999-9999-4999-8999-999999999999",
  "actor_type": "api_key",
  "actor_access_id": "11111111-1111-4111-8111-111111111111",
  "actor_public_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "actor_label_snapshot": "Laptop agent",
  "connector_id": "22222222-2222-4222-8222-222222222222",
  "credential_id": "33333333-3333-4333-8333-333333333333",
  "credential_epoch": "1",
  "credential_revision": "3",
  "tool_id": "44444444-4444-5444-8444-444444444444",
  "tool_name_snapshot": "github__get_file_contents",
  "approval_id": "66666666-6666-4666-8666-666666666666",
  "lease_id": "77777777-7777-4777-8777-777777777777",
  "scope_digest": "<SHA-256>",
  "approval_mode": "confirm",
  "approval_policy_revision": "7",
  "authorization_source": "owner_confirmation",
  "verification_method": "none",
  "arguments_hash": "<existing canonical argument SHA-256>",
  "decision": "allow",
  "result": "success",
  "error_code": null,
  "duration_ms": 248
}
```

Keep actor identity from successful server authentication; never trust an agent-provided label. Preserve historical label snapshots after rename/deletion. This proves which bearer credential authenticated, not which human was physically at the keyboard.

### 15.4 Additional events

Record request creation, challenge start, approval/denial, stale/expired requests, activation, lease expiry/revocation/suspension, credential replacement, grant refresh outcome, rejected destination, denied invocation, and manual execution lock.

Use typed event constructors and allowlisted error codes. Do not provide a generic `map[string]any` logging escape hatch for raw provider objects. Exclude Authorization/Cookie headers, custom header values, CEKs, root wrappers' decrypted values, token strings, factor seeds, OTP/challenge codes, notification subscription secrets, tool payloads, and raw upstream errors. OWASP's logging guidance is a useful baseline for identity/action attribution and secret exclusion. [R26]

### 15.5 Privacy and durability

Preserve the handoff's canonical SHA-256 argument hash in v1. Do not change its canonicalization algorithm to RFC 8785 incidentally while implementing approval hashing; they are separately versioned contracts. An unkeyed hash of low-entropy arguments is guessable, so treat it as sensitive metadata and keep it excluded from ordinary management responses as today. [P0 §7.3, §12]

Choose and document retention, for example a proposed 90-day audit window with configurable shorter periods. Operational deletion is allowed through a separately privileged retention job; “append-only” describes application writes within the retention window, not infinite retention or tamper-proof storage.

The runtime role gets INSERT and owner-filtered SELECT where needed, not UPDATE/DELETE on audit history. The schema owner can still alter data. External signed checkpoints or remote immutable storage are later hardening options, not claims made by the first version.

If a successful upstream response arrives but completion logging fails, do not tell the agent that the action definitely failed. The admission record already exists; surface an audit-health problem and preserve the actual result when possible. Never retry the action to repair its log.

## 16. Browser, HTTPS, and deployment security

### 16.1 HTTPS and trusted proxy topology

Expose the panel and remote MCP endpoint only through HTTPS with a valid certificate. Prefer TLS 1.3, retaining TLS 1.2 only for required compatibility. Fail sensitive API requests received over insecure external HTTP rather than redirecting a submitted secret body. Secure cookies and disable caching of sensitive responses. [R01, R33]

The existing separate UI/gateway services can remain behind one reverse proxy. Bind backend ports only to the intended private interface/network; do not treat a forged `X-Forwarded-Proto: https` as proof of TLS. Trust forwarded headers only from configured proxies.

If a reverse proxy terminates TLS and receives the activation CEK, it is trusted with that selected key. Use a protected internal hop; use TLS/mTLS across untrusted networks. Do not advertise secrecy from an external inspection proxy while intentionally sending activation keys through it.

### 16.2 Browser hardening

Use an explicit CSP, local pinned assets, no third-party analytics on vault pages, no unsafe evaluation, and no untrusted HTML rendering for tool descriptions. A baseline CSP should restrict scripts, connections, frames, objects, and base URLs. Add only the narrowly required WASM capability for the selected Argon2 implementation, then test it; do not enable general `unsafe-eval` as a workaround. CSP is defense in depth, not protection from an operator who controls the page and its policy. [R27]

For cookie-authenticated state changes, require CSRF tokens plus origin checking; SameSite alone is not the complete boundary. Do not put approval or unlock operations on GET routes. Set browser sessions HttpOnly/Secure with an appropriate SameSite policy; retain the distinct OAuth callback flow binding rather than weakening all cookies for redirects. [R28; P0 §5–6]

Keep root/CEK material in memory only. On UI lock, clear references, overwrite mutable buffers where practical, and terminate dedicated crypto workers. Garbage-collected runtimes do not provide a universal proof of instantaneous zeroization. A non-extractable `CryptoKey` still permits allowed operations by code executing in its security context; it is not an XSS defense. [R15]

### 16.3 Do not leak through infrastructure

Disable request/response-body capture on activation, credential creation, OAuth callback, and MCP routes. Inspect reverse-proxy logs, WAF diagnostics, tracing/APM, panic handlers, support bundles, and metrics labels. Log header **allowlists**, not merely an Authorization denylist: custom credential headers and MCP parameter-mirrored headers can contain sensitive data.

Disable core dumps for production execution, protect swap/hibernation and host backups, restrict debugger/ptrace access, do not expose pprof publicly, and avoid shell commands whose arguments contain credentials. These controls reduce accidental retention; they do not defend against a malicious root operator.

### 16.4 Destination binding and SSRF

Maintain an approved destination profile containing exact scheme/host/port, permitted endpoint path behavior, credential-bearing header names, OAuth issuer/resource/token endpoints, and permitted network category. Reject userinfo, fragments, unsupported schemes, and secret-bearing query strings in configured credential destinations.

Use a dedicated outbound transport. Validate DNS/IP policy at connection time; handle IPv4/IPv6 and rebinding; block metadata and unintended local/private destinations. Explicitly configured LAN connectors may have narrowly allowed private networks. Do not disable all validation simply because private services are legitimate. Redirects require revalidation, and private headers must not be forwarded to a newly selected origin. [R09, R34]

A destination security change invalidates leases and requires the bundle to be re-encrypted with updated destination-bound AAD. A cosmetic label change does not.

### 16.5 Stdio process isolation

Treat an upstream stdio server as executable untrusted code. Supply an allowlisted environment, not the gateway's entire environment. Never inherit the deployment catalog key, factor-storage key, notification signing key, unrelated provider tokens, cloud credentials, or Docker socket. Constrain user, filesystem, network, resources, and process lifetime. Credential-bearing child processes must stop when no live execution/setup lease authorizes them, subject to the documented drain policy. [R09]

### 16.6 Prompt injection and broad tools

Secret hiding is not sufficient: a malicious prompt can cause an agent to use legitimate tools destructively without ever reading the token. A lease must constrain real operations, and the upstream credential should have independently narrow authority. Cross-provider data flow remains possible within simultaneously approved scopes; no claim of automatic semantic data-loss prevention is made. [R31]

## 17. Lifecycle, recovery, and rotation

### 17.1 Account login is not vault recovery

The normal account login authenticates a user to management endpoints. The vault passphrase unwraps the VRK locally. They are separate secrets in v1 because the current login protocol has not been reviewed for password secrecy from the gateway. A password reset must not implicitly manufacture access to the old vault.

At setup, the browser generates a VRK and two independent wrappers: one under the passphrase-derived wrapping key and one under a random recovery key. Display the recovery key once with a checksum and a clear offline-storage instruction. Require a recovery verification exercise before marking setup complete. Store only the encrypted recovery wrapper and public format metadata; never store a server-readable copy of the recovery key.

The recovery key is full vault authority. Do not put it in push notifications, an account-reset email, ordinary browser storage, telemetry, or a backup file that also claims to be protected against its holder.

### 17.2 Changing passwords and encryption keys

| Operation | Required behavior |
|---|---|
| Change account login password | Preserve existing session-revocation behavior. This does not change vault encryption unless explicitly requested. |
| Change vault passphrase | Unlock the VRK with an existing method and create a new passphrase wrapper locally. Remove the old active wrapper after successful verification. |
| Rotate VRK | Generate a new root and rewrap each CEK; verify all wrappers before switching the active root. Does not invalidate a previously copied upstream credential. |
| Rotate CEK / credential epoch | Create a fresh CEK and encrypted record; invalidate old epoch leases and activation. |
| Rotate upstream API key | Obtain a replacement from its issuer; client encrypts it under a new CEK/epoch; revoke the old issuer credential. |
| Ordinary OAuth refresh | Encrypt a new revision under the existing CEK/epoch and update CAS state. Do not interrupt the lease merely because the token changed. |
| Remove a device or recovery method | Deny future retrieval, remove its active wrapper/enrollment, and assess whether upstream credentials need replacement. Old downloaded material cannot be recalled. |

A passphrase change protects future copies using the new wrapper. A stolen historical backup and the old passphrase may still unlock the old vault. Similarly, rotating a root cannot erase a CEK already released to an executor. Show these distinctions in the relevant confirmation dialogs.

### 17.3 Browser lock, execution lock, and restart

**Lock browser** clears local unlock material. Active execution leases continue until their approved deadline; this is the normal agent workflow.

**Stop this lease** revokes its future admissions and cancels its in-flight contexts where possible. Another caller's separately approved lease may still authorize the same credential to remain active.

**Lock all execution** revokes all of the owner's active leases, denies setup/maintenance activity, and drains/closes related upstream connections. Clear each runtime CEK when no allowed in-flight cleanup still needs it. Do not label bounded cleanup as a new permission window.

**Gateway restart** creates a new random boot ID and starts with no CEKs. Mark old active lease records suspended during initialization. Fetching a lease from PostgreSQL must never reactivate it. The owner creates a new approval/activation even if the old record has time remaining.

### 17.4 Backup and restore

Back up encrypted credential revisions, root/CEK wrappers, account verifiers, safe connector/tool metadata, approval/audit history, and migration/version metadata. Protect backups against disclosure and tampering even though credentials are encrypted: they still contain sensitive metadata and password-verifier material.

Keep the recovery key separately from the database backup. A restore drill must prove both that the account can authenticate and that a trusted client can unwrap the recovered vault. Those are different tests.

A restored deployment starts locked and with a new boot ID. Suspend restored live leases and in-progress approval attempts. Reconcile old access-key revocations and account state before opening the MCP endpoint. A restored, previously rotated OAuth refresh token may no longer work; report reauthorization required rather than replaying a historical refresh in a loop.

### 17.5 Approval-factor administration

Enrollment, removal, and replacement of an approval factor or enrolled approval device are privileged interactive security operations. A routine admin-role MCP key cannot redirect approval authority to a different account/device. Require fresh authentication and the existing factor when required, show the affected identity, audit the change, and revoke pending attempts and affected live leases under the old policy/factor revision. Keep notification subscription changes separate: a push endpoint is not authority to approve. Disabling extra approval must use this protected policy-change path, not a routine preferences PATCH. [R40]

A deliberately configured recovery procedure may restore access to the management account or replace an unavailable second factor. It must not silently bypass the client's encryption requirement. Document whether recovery invalidates all active leases; the recommended default is yes.

## 18. UX specification

### 18.1 The primary action is a timed window

Use **Allow for 15 minutes** when confirmation is enabled, or **Start access for 15 minutes** when it is off. Do not make “Allow once” the normal path or force users to repeatedly approve each step of an agent's work. A one-call option can be omitted from the first release entirely.

```text
Allow Laptop agent to use GitHub personal?

Caller             Laptop agent · …7Q2M
Credential         GitHub personal · current account
Allowed tools      Read file contents; list and read issues
Resources          example-owner / example-repository
Destination        Approved GitHub MCP endpoint
Working window     [ 15 minutes v ]

The agent may make multiple permitted calls during this window.
Your trusted gateway can use this credential until the window ends.
The credential is not returned to the agent.

[ Deny ]                              [ Allow for 15 minutes ]
```

This is an illustrative scope, not a claim that a specific provider's current tools expose exactly these selectors. Render actual configured tool names and constraints. The client label and tool description are untrusted presentation text, not identity proof or executable markup.

### 18.2 Minimize repeated work without weakening consent

Remember a user's preferred **duration and scope selection**, not approval itself. Pre-fill them for review on renewal. Keep the browser unlocked according to its own lock policy, so renewal does not necessarily require another passphrase entry. Extra confirmation and fresh factor verification depend on the selected mode. `none` offers “Start access for 15 minutes” during client activation, `confirm` offers the review action, and `step_up` adds the enrolled factor once for the new window. No mode prompts per call.

The countdown starts only after activation succeeds. Display exact local end time, remaining duration, admitted call count, and current in-flight count. A running agent does not need a visible browser tab after activation.

If the owner approves a request for a locked vault, show “Approved — unlock your vault to activate” rather than “Access granted.” Prefer opening/unlocking the vault before starting the short-lived factor challenge.

### 18.3 State labels

| State | Suggested text | Agent behavior |
|---|---|---|
| No approval | Access required | Does not invoke upstream; can create one deduplicated request. |
| Pending | Waiting for your review | May inspect safe status; does not repeatedly push. |
| Challenging | Complete verification | No execution yet. |
| Approved, not activated | Unlock vault to activate | No execution; approval expires if unused. |
| Active | Access ends at 14:16 | Multiple matching calls without another prompt. |
| Expired | Access window ended | New calls denied; explicit renewal available. |
| Revoked | Access stopped | New calls denied; old in-flight work may be finishing. |
| Suspended | Gateway restarted — start a new access window | No automatic restoration from history. |
| Provider unavailable | Access approved; provider unavailable | Do not replay side effects; show sanitized connection state. |

Separate the caller's approval status, the credential's runtime availability, and the provider's connectivity. Do not collapse them into one green “unlocked” badge.

### 18.4 Management views

Add a lease view with filters for caller, connector, credential, expiry, and state. Provide an immediate “Stop access” action that does not require a push/OTP round trip. Show each client key's public display handle and last-use attribution without exposing its token.

Add credential replacement as an explicit operation on an existing connector. Preserve connector identity and call history. Show when replacement invalidates active leases. Add audit links from the client key to its invocations, and from a lease to its approval and calls.

Do not expose raw secret values as a convenience feature in ordinary status/history APIs. The initial client encryption workflow supports entry/replacement and encrypted retrieval; an optional reveal/export feature needs its own explicit design and audit policy.

## 19. Go integration plan

### 19.1 Package boundaries

The paths below are proposed extensions to the packages identified in the handoff, not verified existing symbols.

| Package | Change |
|---|---|
| `internal/approval` | Mode-aware request/attempt state machine; first-party confirmation and optional local factor verification. |
| `internal/notification` (optional new package) | Owner-scoped inbox delivery and optional Web Push; cannot grant access. |
| `internal/lease` (new) | Immutable scope parsing, matching, deadlines, counters, activation, revocation, and owner security gate. |
| `internal/secret` (new) | Strict encrypted-envelope codecs and in-memory credential activation; no whole-vault root requirement. |
| `internal/catalog` | Safe metadata/cache interfaces and PostgreSQL adapter; encrypted-record persistence. |
| `internal/upstream` | Resolve credentials only for authorized setup/use; close or drain connections on expiry; destination guard. |
| `internal/upstreamauth` | Setup lease, single-flight refresh, epoch/revision CAS, encrypted refresh persistence. |
| `internal/proxy` | Per-invocation admission and typed audit events; structured lease-required outcomes. |
| `internal/audit` | Actor access ID/public handle, credential epoch/revision, approval and lease attribution; PostgreSQL store. |
| `cmd/mcpwarden` | Startup boot ID/active-instance lock, API wiring, safe shutdown, auth-context distinctions. |
| `ui/` | Vault setup/unlock, working-window control, optional in-app/push review and factor input, activation, lease display and revocation. |

### 19.2 Do not hide decryption inside synchronous repository reads

Preserve coherent cached metadata for SDK callbacks that cannot return repository errors. A locked credential is an expected execution state, not a missing connector or a successful empty secret lookup. Introduce an explicitly fallible execution path for authorization and secret availability.

The following is a design sketch, not a drop-in SDK implementation:

```go
// Illustrative domain API. Concrete types and existing SDK hooks must be
// verified against the project's pinned source before implementation.
type LeaseCoordinator interface {
    Request(ctx context.Context, actor AuthenticatedActor, scope Scope) (RequestView, error)
    Activate(ctx context.Context, owner InteractiveOwner, input ActivationInput) (LeaseView, error)
    Admit(ctx context.Context, actor AuthenticatedActor, call CallDescriptor) (Admission, error)
    Revoke(ctx context.Context, actor AuthorizedRevoker, leaseID string) error
}

type SecretRuntime interface {
    // Activation stores a validated credential key for this boot only.
    Stage(ctx context.Context, binding CredentialBinding, key []byte) (StagedActivation, error)
    // An opaque admission must originate from the coordinator, not the MCP caller.
    Resolve(ctx context.Context, admission Admission) (CredentialHandle, error)
    LockOwner(ctx context.Context, ownerID string) error
}
```

Do not make `CredentialHandle` printable or JSON-marshalable. Avoid storing secrets in string fields unnecessarily; treat any SDK-required string conversion as a potential extra in-memory copy. Keep logging methods redacted. These interfaces are internal capabilities, not a public API that returns credentials to an MCP client.

### 19.3 Dispatch outline

```text
1. Authenticate this request and resolve the exact access record.
2. Validate the tool route, owner, input schema, policy, visibility, and credential epoch.
3. Find a matching current-boot lease; reject safely if absent.
4. Perform any needed authorized connection setup / single-flight refresh.
5. Immediately before the tool call, take the owner security gate.
6. Recheck access, scope, current epoch, activation, limits, and deadlines.
7. Commit admission/counter/audit state; publish the admission; release the gate.
8. Resolve the already-active credential through the opaque admission.
9. Execute once with a bounded context and approved destination transport.
10. Record completion separately and release in-flight references.
```

An implementation may reorganize steps for efficiency but must preserve the linearization and failure guarantees in §9. A revocation between admission and network execution cancels that admitted work best-effort; it is not a promise to undo it. Never hold an owner mutex over a provider network call or a human approval.

### 19.4 Proposed configuration

```yaml
# Proposed configuration; not accepted by the current binary until implemented.
security:
  custody_mode: client_release
  approvals:
    mode: confirm                  # none | confirm | step_up
    verification:
      method: none                 # totp only with step_up and enrolled factor
      freshness: per_window
    request_ttl: 5m
    activation_ttl: 60s
  notifications:
    in_app: true
    web_push:
      enabled: false
      on_access_request: false     # opt-in, deduplicated/rate-limited
      vapid_private_key_env: MCPWARDEN_WEB_PUSH_VAPID_KEY # needed only when enabled
      storage_key_env: MCPWARDEN_NOTIFICATION_STORAGE_KEY # protects subscriptions
  leases:
    default_ttl: 15m
    max_ttl: 60m
    idle_timeout: 0s
    max_calls: null                # not a single-use permit
    max_concurrent_calls_per_caller: 4
    automatic_renewal: false
  audit:
    require_durable_admission: true
    retention_days: 90
  runtime:
    restart_policy: locked
    deployment_mode: single_active

storage:
  driver: postgres
  dsn_env: MCPWARDEN_DATABASE_URL

# Only needed when a factor with an encrypted server-side seed is enrolled.
# This key does NOT unwrap the client vault or provider credentials.
factor_storage:
  encryption_key_env: MCPWARDEN_FACTOR_STORAGE_KEY
```

Validate incompatible settings at startup. For example, `client_release` must reject a configuration that supplies a permanent server wrapper for the same credential CEKs. `automatic_renewal: true` is not supported by this design. `step_up` requires an implemented enrolled method; `none`/`confirm` use `method: none`. No push key, factor-storage key, or vendor credential is required when its feature is unused. Disabling a delivery channel must not weaken the effective approval mode. Keep `examples/config.yaml` synchronized with the actual parser when these options are implemented. Environment-variable names are illustrative and contain no secrets.

### 19.5 Dependency discipline

Prefer standard Go crypto and HTTP APIs, a maintained PostgreSQL driver, a vetted canonical-JSON implementation, and optional maintained Web Push/TOTP implementations only when those features are enabled. No vendor approval SDK belongs in the required dependency set. Argon2id browser support requires a separately vetted implementation; do not assume Web Crypto provides it. The Go `x/crypto/argon2` package is a reference implementation for server-side tests and offline tools, not a reason to send the vault passphrase to the server. [R15, R32]

Record dependency purpose, version, license, update policy, and security-sensitive entry points. Audit generated WASM/JavaScript and pin artifacts; avoid runtime CDN downloads. The handoff deliberately values a small dependency set. [P0 §12]

## 20. Migration and rollback

### 20.1 Establish a real baseline

Before invasive work, inspect the repository state and obtain approval for a safe baseline commit or equivalent backup. The handoff reports no commits and untracked project files; do not assume Git can restore the old installation. Back up the encrypted catalog, its necessary deployment key through a separate protected process, audit JSONL, and configuration without printing secrets. [P0 §2]

### 20.2 Migrate persistence without inventing privacy guarantees

Build the PostgreSQL adapter and migration tool against the documented repository/audit contracts. During an offline migration, preserve owner IDs, connector/tool IDs, access verifiers, expiries, lifecycle timestamps, visibility, OAuth CAS state, tombstones, audit event IDs, ordering, and argument-hash bytes exactly. Import hashes rather than recomputing from data that the audit intentionally does not retain.

A legacy operational credential cannot become retroactively unknown to the gateway that already decrypted it. Label imported, server-decryptable records as **legacy managed custody** until explicitly converted; prevent accidental use of those records through the new client-release path. Do not manufacture a client root inside the gateway and call it client-only.

The candidate schema in the bundle deliberately models the target client-release state; it is not a complete transitional legacy-custody schema. A migration implementation needs a separate, time-bounded legacy storage adapter/table or an all-at-once credential re-enrollment plan. This distinction must be settled in the migration ADR, not hidden in a default wrapper.

### 20.3 Preferred conversion path: re-enter or reauthorize

For the first implementation, the safest simple conversion is to have the owner create the client vault and re-enter/reissue static credentials in the browser, or explicitly reauthorize an OAuth connector under its setup lease. Upload the new encrypted bundle and wrapped CEK, preserve connector identity, and switch its custody state atomically after validation.

Do not add a general-purpose plaintext `GET /credentials` endpoint merely to simplify migration. Such an endpoint would change the current management API's no-secret-return property. An optional offline migration utility may operate on the user's own machine under explicit authorization, but must be separately reviewed and must not create plaintext exports or log secrets. [P0 §8]

After conversion, remove the legacy plaintext cache and deployment-readable copy according to the cutover plan. Rotate upstream credentials where establishing a new trust boundary matters; deleting an old local row cannot revoke copies held elsewhere or in backups.

### 20.4 Cutover sequence

1. Stop admissions and drain in-flight work; stop OAuth refresh starts.
2. Acquire the exclusive migration/active-instance lock.
3. Take a consistent encrypted backup and record source format/version and counts.
4. Import into an isolated target database; validate IDs, counts, ownership, verifiers, ciphertext envelopes, and audit ordering.
5. Start the new gateway with execution locked and management access restricted to the operator.
6. Complete vault setup/conversion, run representative read-only connectivity checks with explicit setup leases, and verify expiry/revocation.
7. Open the MCP endpoint; retain the previous backup under controlled retention.

Avoid unsupported live dual-write migration. Two independent sources of revocation or OAuth refresh truth can create security regressions even if both stores are encrypted.

### 20.5 Rollback is an execution-security operation

Do not roll back to a binary that bypasses required approvals while leaving the public MCP endpoint open. Rollback starts with execution stopped. Restore consistent data and software together, reconcile key revocations and changed upstream grants, and reauthorize rather than assuming restored tokens remain valid.

Document a forward-fix path for irreversible changes such as provider-side token rotation. A database snapshot cannot undo external revocation or restore a rotated refresh token's validity. Test both failure before cutover and failure after a real approved call; their recovery procedures differ.

## 21. Failure behavior

| Event | Required behavior |
|---|---|
| Browser closes after activation | Agent continues within the existing lease; no new passphrase prompt. |
| Browser closes before activation | No credential use; request/approval expires normally. |
| Optional verification succeeds but vault is locked | Await client unlock until activation deadline; verification alone supplies no CEK. |
| Extra approval is disabled | Owner-started activation proceeds without confirmation/factor; all caller/scope/time/key/audit checks still apply. |
| Push delivery is unavailable or disabled | Use the authenticated inbox under the same verification policy; delivery does not grant or deny authority. |
| Required verification method is unavailable | Fail closed for new windows; existing leases keep their deadline; local revocation remains available. |
| Provider reports bypass/remembered authentication | Does not satisfy a required fresh-verification policy; do not activate. |
| Duplicate approval callback or poll result | Same immutable decision; no second lease or extension. |
| Duplicate activation POST | Return the original successful result only while the original boot/runtime activation remains valid; never restart its clock. |
| Database is unavailable | No new admission requiring durable authorization/audit; existing in-flight calls are not automatically replayed. |
| Admission transaction is uncertain | Do not dispatch; reconcile status without issuing an upstream action. |
| Completion audit write fails after upstream success | Preserve actual result where possible; flag audit degradation/unknown completion, never replay to repair history. |
| Gateway crashes after admission | On restart, mark unresolved completion unknown and execution locked; do not assume upstream failure. |
| Gateway crashes after provider rotates refresh token | Reconcile only where provider semantics allow; otherwise require reauthorization. |
| Lease expires while a request waits for concurrency slot | Recheck before admission and deny; queue entry is not a reservation. |
| Lease expires during an in-flight call | Stop new admissions; cancel best-effort; allow bounded response/token-persistence cleanup. |
| Access key is revoked | Revoke its leases/pending approvals, deny new admissions, cancel related contexts. |
| Another caller has the same owner | Cannot borrow an active credential without its own matching lease. |
| Tool schema, destination, or security policy changes | Reject obsolete scope; require a new authorization under the current mode for changed authority. |
| Clock jumps or host resumes with uncertain deadlines | Suspend uncertain leases; do not extend a window using stale time. |
| Runtime active-instance lock is lost | Close admission gate and stop new work; operator recovery required. |
| Database is restored from backup | New boot ID, locked execution, old active leases suspended, historical revocations reconciled. |
| All client/recovery keys are lost | Existing ciphertext cannot be recovered through account reset; replace/re-enroll upstream credentials. |

## 22. Acceptance tests

These are implementation acceptance requirements, not claims that the current mcpwarden code has passed them. The companion crypto tests validate a small interoperability fixture only; they do not exercise the project, browser UI, push/OTP, PostgreSQL, or production randomness.

### 22.1 Multi-call workflow and time

| ID | Test and expected outcome |
|---|---|
| L01 | One fifteen-minute approval permits at least twenty sequential matching calls without another prompt. |
| L02 | Calls use earlier results in later arguments; no call-by-call approval occurs while constraints remain satisfied. |
| L03 | Several HTTP reconnects preserve the caller's lease; changing client access keys does not. |
| L04 | Concurrent permitted calls respect the configured concurrency limit and share the lease without human prompts. |
| L05 | A queued call whose lease expires before admission is denied without upstream dispatch. |
| L06 | Time starts at successful activation; delayed approval does not consume the working window, but stale activation is rejected. |
| L07 | Repeated traffic does not extend expiry; optional idle expiry remains disabled by default. |
| L08 | Renewal produces a new approval/lease and a visible new deadline, not an unnoticed modification of the old lease. |
| L09 | Browser lock/closure after activation does not stop valid agent work; execution lock does. |
| L10 | Expiry/revocation races are tested against admission, network start, and completion; no claim of undoing prior upstream effects. |
| L11 | Simulated wall-clock jumps, delayed transactions, suspend/resume, and process restart never extend an uncertain lease. |
| L12 | Optional max-calls budget is atomic under contention; its default is unset, not one. |

### 22.2 Identity and authorization

| ID | Test and expected outcome |
|---|---|
| A01 | Another owner cannot read, approve, activate, revoke, or use a request by guessing its UUID. |
| A02 | Another key for the same owner cannot borrow a lease, even when its CEK is already active. |
| A03 | Client-supplied names, suffixes, `clientInfo`, headers, and session IDs cannot change the authenticated actor. |
| A04 | Agent admin-role keys cannot enroll a factor, approve themselves, release keys, or bypass fresh interactive authentication. |
| A05 | Tool/resource constraints reject missing fields, wrong JSON types, alternative casing where significant, and nested-path substitutions. |
| A06 | Hidden tools and disabled providers are denied even with an otherwise matching active lease. |
| A07 | New tools and changed tool definitions are not automatically added to an old lease. |
| A08 | A call is not authorized by combining partial scopes from different leases. |
| A09 | Access-key revocation, account session replacement, and owner caps remain atomic under concurrent requests. |
| A10 | Static shared upstreams retain explicit shared-credential labeling and owner-specific caller authorization. |

### 22.3 Cryptography and lifecycle

| ID | Test and expected outcome |
|---|---|
| C01 | Browser-compatible Web Crypto and Go agree on envelope AAD, nonce placement, tag placement, and plaintext bytes. |
| C02 | Wrong key, altered ciphertext/tag, wrong owner/connector/credential/epoch/revision/purpose/destination all fail authentication. |
| C03 | Duplicate JSON keys, unknown algorithms/versions, invalid base64url, invalid lengths, and out-of-range KDF parameters fail closed. |
| C04 | Production encryption obtains fresh nonces; parallel writers respect the per-key usage policy. Deterministic fixture nonces never enter production. |
| C05 | Database/backups contain no VRK, recovery key, unwrapped CEK, or plaintext provider tokens/header values. |
| C06 | Gateway activation never receives the VRK or unrelated CEKs. |
| C07 | A restart restores metadata only; old active rows cannot recreate runtime keys. |
| C08 | Passphrase change, root rotation, CEK epoch rotation, and upstream credential rotation have distinct tested outcomes. |
| C09 | Recovery works from an independently stored recovery key; account reset alone cannot decrypt the old vault. |
| C10 | New epoch/destination invalidates old activation and leases; ordinary OAuth refresh revision does not reprompt. |
| C11 | A stale but valid encrypted snapshot is not treated as proof of freshness; restore starts locked. |

### 22.4 Optional approval, transport, OAuth, and isolation

| ID | Test and expected outcome |
|---|---|
| D01 | Configured verification success is bound to the immutable request/attempt; test deny, timeout, stale, bypass, and duplicate proofs. |
| D02 | Each enabled delivery/factor adapter passes its standard fixtures and live integration tests; disabled adapters require no credentials or network access. |
| D03 | Notification or OTP success with no key-holding client cannot activate a credential. |
| D04 | Prompt deduplication and rate limits prevent a tool loop from producing repeated pushes. |
| D05 | HTTP, forged proxy headers, cross-origin activation, CSRF, cache leakage, and unsafe redirect paths are rejected. |
| D06 | DNS rebinding, redirects, IPv4/IPv6 private/metadata destinations, and OAuth discovery URLs cannot exfiltrate private headers. |
| D07 | Stdio child processes do not inherit unrelated secrets or privileged host access. |
| D08 | Two simultaneous refresh attempts produce one provider request; CAS cannot substitute for that pre-request serialization. |
| D09 | Refresh-token rotation crash windows produce a controlled reauthorization outcome, not an infinite retry loop. |
| D10 | Both supported MCP protocol revisions negotiate correctly; lease errors do not violate tool output schemas or trigger automatic replay. |
| D11 | New MCP header/metadata pathways cannot bypass caller checks or leak tool arguments into access logs. |

### 22.5 Persistence, audit, and migration

| ID | Test and expected outcome |
|---|---|
| P01 | Composite owner foreign keys reject cross-owner references; runtime queries enforce owner scope independently. |
| P02 | Admission audit is durable before dispatch; completion outage/crash produces honest unknown state without retrying the action. |
| P03 | Logs, traces, metrics, panic paths, SQL diagnostics, and support exports contain no raw credential/tool payloads. |
| P04 | Every executed call attributes exact access ID/public handle, credential epoch/revision, lease, approval, and stable tool identity. |
| P05 | Renaming/deleting a key or connector preserves historical IDs and display snapshots. |
| P06 | Duplicate activation and management retries cannot grant multiple windows or reset time. |
| P07 | Migration preserves IDs, verifier bytes, ownership, hashes, timestamps, visibility, tombstones, and history ordering. |
| P08 | Restore starts locked; old revocations and provider token rotations are reconciled. |
| P09 | Dedicated instance-lock loss stops new admissions; two gateways cannot silently become active. |
| P10 | Runtime database role cannot update/delete audit rows or migrate schema; retention/migration privileges are separate. |
| P11 | Expiry, revocation, activation, and optional budgets pass race tests under high concurrency. |
| P12 | Repository publication occurs only after durable commit; rollback/commit failure never publishes a permission that was not committed. |

### 22.6 Optional-mode acceptance cases

| ID | Test and expected outcome |
|---|---|
| O01 | `none` starts a window through owner key release with no confirmation/factor dialog or fabricated verification event. |
| O02 | `confirm` operates using the in-app inbox with no push, OTP, external service, or vendor secret. |
| O03 | `step_up/totp` works with push off; browser push plus `confirm` works with OTP off. |
| O04 | All modes enforce identical caller/scope/expiry/audit checks; an agent cannot activate or renew itself. |
| O05 | Push click, receipt, dismissal, forged payload, stale URL, or GET never authorizes execution. |
| O06 | Push outage does not downgrade verification; inbox review preserves the configured policy. |
| O07 | Factor/mode change requires current owner security authorization; agent/admin MCP tokens cannot weaken it. |
| O08 | Security-policy change stales pending decisions and revokes affected leases before success; notification-only toggles do not. |
| O09 | TOTP reference vectors, bounded skew, atomic one-use consumption, concurrent reuse, and rate limits are tested. |
| O10 | OTP/seed/enrollment/subscription secrets stay out of logs; factor storage cannot unwrap any vault credential. |
| O11 | Cross-owner factor IDs, notification endpoints, requests, and proof substitutions are rejected. |
| O12 | No required push/OTP/vendor configuration exists when those options are disabled; cold restart still requires client key release. |

### 22.7 Required project validation

After implementation, run the handoff's build, vet, race, UI, and deployment smoke tests, plus the acceptance suites above. Record actual results and environment in `docs/progress.md`. Update protocol/security ADRs in `docs/decisions.md`. Passing standalone examples in this bundle is not a substitute. [P0 §12, §15]

## 23. Implementation milestones

| Milestone | Deliverable | Exit condition |
|---|---|---|
| M0 — Baseline and decision record | Safe repository baseline, accepted custody/lease threat model, SDK version inspection. | No ambiguity about trusting the gateway during execution; normal authorization is multi-call and timed. |
| M1 — Caller identity and lease enforcement | Public client-key handles, immutable scopes, working-window state machine, audit attribution, mock/interactive approval provider. | L/A tests pass with synthetic credentials; no per-call prompts or implicit renewals. Clearly label any server-managed development mode. |
| M2 — Client encryption and persistence | Browser root/CEK lifecycle, versioned envelopes, memory-only activation, PostgreSQL adapter/migrations, restart lock. | C/P tests, file-to-database fixtures, and recovery/restore drills pass. No permanent server unwrap route exists in client-release mode. |
| M3 — Optional notification and verification modules | First-party browser push and/or local TOTP only when selected; request binding, replay/rate limits, and independent toggles. | Enabled-feature D/O tests pass. This milestone does not block a core release with `none`/`confirm` and push/OTP off. |
| M4 — Runtime integration and hardening | OAuth setup/refresh, discovery lease, revocation/drain, SSRF protection, stdio isolation, protocol compatibility. | Full acceptance matrix and project build/vet/race/UI checks pass. |
| M5 — Controlled rollout | Documented migration, rollback, operator runbook, monitored audit health, independent review. | Read-only pilot followed by bounded write scopes; no broad agent admin keys or undocumented bypasses. |

Do not ship M1's development-only, server-decryptable mode under the final client-encryption claim. Feature readiness and security claim readiness are separate release checks.

## 24. Decisions deliberately deferred

The first version does not need a separate runner, confidential computing, an embedded OAuth authorization server, native provider adapters, a new agent protocol, or custom per-call cryptographic signatures.

Passkey-derived vault unlocking through the WebAuthn PRF extension is a possible later unlock method. Verify authenticator/browser behavior and prevent PRF outputs from being sent to the server as part of serialized authentication data. It does not replace the need for an authenticated, trusted client. Do not silently add it as a recovery wrapper before that lifecycle is designed. [R30]

Independent signed clients or extensions can reduce dependence on the gateway-served UI, but introduce their own update and device-enrollment trust. A private runner becomes relevant only for a stronger future promise that the central gateway must not receive credentials during use.

Active-active execution needs a separate fencing and secret-routing design. A PostgreSQL cluster alone does not make runtime CEKs shared, leases coherent across processes, or revocation immediate.

A mobile approval application that holds vault keys could combine notification and key release. An ordinary notification or authenticator application does not hold mcpwarden's CEK merely because it receives a message or generates a code. Until such an application is built, use the unlocked browser for activation.

## 25. References and evidence map

The version 1.0 reference catalogue is preserved from the supplied specification. The additional first-party push, OTP, and factor-management sources R35–R40 were checked for this revision on **22 September 2026**; the remaining sources were not independently rechecked during this targeted revision. They are primary project documentation, official standards, or official security guidance. They support the named mechanisms; they do not certify this proposed implementation. Product defaults, schema design, state transitions, and proposed APIs are mcpwarden design decisions.

The handoff is the only evidence for the current local repository. Published SDK documentation is not a substitute for inspecting its pinned local module. No local mcpwarden source code, live approval-provider integration, production database, or deployment was exercised while writing this document.

| ID | Primary source | Relevant implementation topic |
|---|---|---|
| P0 | [mcpwarden current-state handoff, 2026-09-22](sources/mcpwarden-current-state-2026-09-22.md) | Current architecture, repository/audit contracts, auth modes, limitations, SDK pin, and invariants. Section references in the design refer to this document. |
| R01 | [Vaultwarden: Enabling HTTPS](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-HTTPS) | HTTPS/reverse-proxy and web-vault secure-context precedent. |
| R02 | [Vaultwarden: Using the PostgreSQL Backend](https://github.com/dani-garcia/vaultwarden/wiki/Using-the-PostgreSQL-Backend) | PostgreSQL support as persistence, not a replacement for client encryption. |
| R03 | [Bitwarden Security White Paper](https://bitwarden.com/help/bitwarden-security-white-paper/) | Client key hierarchy, encrypted vault storage, key handling and memory limitations. |
| R04 | [Bitwarden: Log in with device](https://bitwarden.com/help/log-in-with-device/) | Adjacent approval-driven key transfer; requesting-device public key and fingerprint verification. |
| R05 | [MCP 2026-07-28: Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Tool-call/results contracts, metadata, schema compatibility, and multi-round-trip behavior. mcpwarden leases are application policy, not a new MCP standard. |
| R06 | [MCP 2026-07-28: Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [transport overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports), and [2025-11-25 compatibility baseline](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | Request-oriented current transport versus older session behavior; negotiation and compatibility testing. |
| R07 | [MCP 2026-07-28: Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Resource-server token validation, audience/scopes, per-request authentication, and HTTP error boundaries. |
| R08 | [Official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) | Published compatibility table and SDK entry point. Inspect the actual pinned module before patching callbacks/transports. |
| R09 | [MCP: Security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) | Token handling, OAuth discovery, SSRF, local execution and gateway trust boundaries. |
| R10 | [OWASP: Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html) | Bind consent to significant details and check immediately before execution. This proposal deliberately authorizes a bounded working window; the reference does not certify blanket multi-call consent. |
| R11 | [Cisco Duo Auth API](https://duo.com/docs/authapi) | Historical optional-adapter reference only; not required by the core or a release gate. |
| R12 | [Cisco Duo: Policy & Control](https://duo.com/docs/policy) | Historical optional-adapter reference only; no mandatory vendor policy. |
| R13 | [Duo Go API client](https://github.com/duosecurity/duo_api_golang) | Optional future integration reference; not a required Go dependency. |
| R14 | [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) | Argon2id parameters and reference test vectors; lower-memory recommended profile used as a benchmark candidate. |
| R15 | [W3C Web Cryptography API](https://www.w3.org/TR/webcrypto/) | AES-GCM/HKDF browser primitive semantics and CryptoKey behavior. Argon2 is not supplied by this API. |
| R16 | [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html) | Deterministic approval/AAD encoding; not a silent change to the existing audit argument-hash format. |
| R17 | [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html) | Domain-separated key derivation for wrapping keys. |
| R18 | [Go `crypto/cipher`](https://pkg.go.dev/crypto/cipher) | AEAD/GCM API, nonce handling, and random-nonce usage limits. Fixture tests use explicit nonces only for deterministic interoperability testing. |
| R19 | [Go `time`](https://pkg.go.dev/time) | Monotonic versus wall-clock deadlines; serialization and system sleep caveats. |
| R20 | [PostgreSQL: Date/time functions](https://www.postgresql.org/docs/current/functions-datetime.html) | Actual clock versus transaction-start timestamps during expiry checks. |
| R21 | [PostgreSQL: Explicit locking](https://www.postgresql.org/docs/current/explicit-locking.html) | Row locking and session advisory locks; lock ordering and active-instance coordination. |
| R22 | [PostgreSQL: Transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html) | Concurrent transitions, conditional updates, serialization failures, and safe database-only retries. |
| R23 | [PostgreSQL: Row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) | Defense-in-depth tenant filtering and privileged-role bypass considerations. |
| R24 | [PostgreSQL: NOTIFY](https://www.postgresql.org/docs/current/sql-notify.html) | Cache wakeups; not a complete durable distributed authorization-consistency mechanism. |
| R25 | [PostgreSQL: pgcrypto](https://www.postgresql.org/docs/current/pgcrypto.html) | SQL-side crypto runs inside the database trust boundary; not client-only encryption. |
| R26 | [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Actor/action attribution, sensitive-data exclusion, integrity, access and retention. |
| R27 | [OWASP: Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | Browser policy and script/supply-chain hardening. |
| R28 | [OWASP: Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | CSRF tokens, origin validation and cookie-authenticated approval/activation endpoints. |
| R29 | [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) | Refresh-token protection, replay defenses, binding and OAuth security requirements. |
| R30 | [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) | PRF extension and handling sensitive extension outputs; optional later vault-unlock mechanism. |
| R31 | [OWASP: MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) | Prompt/tool injection, excessive agency, transport and intermediary risks. |
| R32 | [Go `golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2) | Reference implementation for local/offline testing of Argon2id parameters. |
| R33 | [OWASP: Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | TLS versions, termination and application transport hardening. |
| R34 | [OWASP: Server-Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Destination validation, DNS/redirect handling and explicit network allowlists. |
| R35 | [W3C Push API](https://www.w3.org/TR/push-api/) | Browser subscriptions, service workers, permission, and delivery-service roles; the retrieved publication is a Working Draft, so feature-test actual browsers. |
| R36 | [RFC 8030: Generic Event Delivery Using HTTP Push](https://www.rfc-editor.org/rfc/rfc8030.html) | Web Push delivery, message TTL, subscription and delivery lifecycle. |
| R37 | [RFC 8291: Message Encryption for Web Push](https://www.rfc-editor.org/rfc/rfc8291.html) | Push payload encryption; independent of credential-vault encryption and approval evidence. |
| R38 | [RFC 8292: VAPID for Web Push](https://www.rfc-editor.org/rfc/rfc8292.html) | Sender identification to the push service; not user authentication or vault key release. |
| R39 | [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238.html) | Local authenticator OTP, shared-secret verification, reference vectors, clock skew, and successful-code replay rejection. |
| R40 | [OWASP: Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) | Distinguish confirmation from MFA; protect factor changes and recovery; avoid silent downgrade and push fatigue. |

## Evidence boundaries

The implementation design is an original proposal informed by these sources. There was no independent source-code audit of the user's repository. The SQL is a candidate schema, not an executed database migration. The bundled crypto fixture is synthetic and tests only byte-level AES-GCM interoperability and selected authentication failures, not the full key hierarchy or production security.

---

**Release criterion:** An approved working window must remain convenient for a multi-step MCP task, while the software independently enforces caller, scope, credential, expiry, and audit boundaries on every dispatch. Extra human approval is optional and, when enabled, deliberately infrequent; machine authorization is continuous.
