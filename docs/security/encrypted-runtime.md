# Encrypted credential execution

`internal/secret`, the lease material capability, and the guarded proxy execution
adapter form a tested path from a released CEK to a real MCP upstream with
durable admission on PostgreSQL or SQLite. Startup installs the adapter whenever `owner_security`
runs, for every personal connector with credentials (see
[startup integration](#startup-integration)). Such connectors store header names
only; their credentials exist only as vault ciphertext. The live deployment does
not run `owner_security` yet.

## Ciphertext and activation

`secret.Activator` reads a coherent, owner-scoped current ciphertext snapshot from
a local `RecordSource`. It constructs the expected header from the lease
authority's current owner, connector, credential, epoch, revision and destination
digest. The stored header must match exactly. AES-256-GCM authentication uses
RFC 8785 AAD, a separate 12-byte nonce, and the 16-byte tag appended to ciphertext.
The input CEK must be 32 bytes and is cleared on every exit path. No vault root,
passphrase, recovery key, or server-unlock wrapper enters this API.

The parser rejects unknown/missing/null/duplicate fields, malformed Unicode,
noncanonical IDs/versions/base64url, wrong algorithms/purposes, invalid tags and
oversized records. The encrypted record is limited to 96 KiB and plaintext to
64 KiB. Only `header_bundle` is supported here: at most 32 distinct approved
header names, each with a nonempty value of at most 16 KiB. Values containing
controls or surrounding whitespace are rejected, not silently trimmed. OAuth
bundles and refresh are still pending.

An opaque handle owns the validated header byte buffers. It has redacted format
methods, refuses JSON serialization and has no key/header getter. The handle's
only credential-bearing operation creates a constrained MCP HTTP client. The CEK
is not retained after this header-only activation; no refresh/encryption operation
exists on the handle yet. `Destroy` clears owned buffers after in-flight users
drain. Go, the cipher implementation and HTTP header strings can retain temporary
copies; this is not a claim of guaranteed zeroization.

There is deliberately no production Go encryption helper yet. The next slice
adds browser encryption/root/CEK wrappers, recovery primitives, PostgreSQL current
version CAS, nonce uniqueness and write caps. See [vault storage](vault-storage.md)
for the tested boundary and remaining owner-flow gates. Go encryption in these
tests is explicitly test-only; deterministic nonces stay in public fixtures.

## Dispatch boundary

`Proxy.Security` routes explicitly bound providers through `PrepareLeased`.
Bindings are trusted owner-scoped custody metadata, fixed from connector creation;
locked and tombstoned records keep a required binding and never fall back to
manager execution. An incomplete installed adapter fails closed. Unbound
providers (config upstreams and no-auth personal connectors) keep the manager
path. The manager never connects a bound provider.

1. Check owner, tool policy and visibility. Cached visible tool definitions remain
   listed while a bound credential is locked; listing performs no provider I/O.
2. `Service.Prepare` requires one current caller-bound tool-use lease covering the
   complete call. It reserves caller concurrency and material lifetime, but no
   tool-call budget. The owner coordinator is released before network work.
3. Open a bounded SDK connection and list tools under that maintenance capability.
   Compare the selected upstream definition, including its public namespaced name,
   against the approved digest. Discovery is capped at 16 pages / 256 tools.
4. `AdmitPrepared` rechecks the exact prepared lease and commits the counter plus
   admission event in PostgreSQL. It cannot silently switch to a different lease
   or use old material while reporting a newer credential revision.
5. `RunWithMaterial` lends material for one admitted call. Every HTTP request
   rechecks its original capability lifetime, owner/caller/policy, both clocks,
   credential revision and live activation. SDK-detached contexts cannot preserve
   authority after the callback ends. A claim permits only one `tools/call` POST.
6. Append completion to the admission store. Failure preserves the actual result;
   lost responses are never retried and are not described as safe to retry.

The ephemeral wire-argument binding uses Sonic's number-preserving decode and
deterministic encoding before SHA-256. It tolerates JSON escaping/object order
changes without rounding large integer tokens. It is separate from both RFC 8785
scope hashes and the unchanged audit argument hash, whose historical
float64 behavior is preserved. Raw arguments are not persisted by this binding.

The first adapter intentionally opens a session per call. It has no connection
pool, idle background discovery, automatic retry, keepalive, standalone SSE,
subscription, OAuth handler or credential-bearing teardown after authority ends.
The SDK's legacy DELETE teardown is rejected locally once maintenance ends; local
session resources still close. This is conservative and not load-qualified. A
future session pool needs explicit lifetime and maintenance capabilities, and
manager-path upstreams may need their own session expiry/cleanup limits.

The per-call `approval.Approver` is bypassed for this path; owner activation and
optional confirmation happen when opening the window. Maintenance during a tool
window is not the separate owner `setup_discovery` flow for registering an unknown
provider. That registration flow remains to be implemented.

## Destination guard

The versioned destination digest includes the exact endpoint, permitted
credential header names, public/private network policy, explicit private prefixes,
and the loopback-HTTP development exception. Query strings, userinfo, fragments,
noncanonical hosts/ports and ambiguous path forms are rejected. Credential names
cannot override framing, proxy, routing, MCP, browser or retry-control headers.

The dedicated transport disables environment proxies, redirects, connection reuse
and HTTP request replay. Production TLS uses the standard trust store; there is
no caller-provided TLS bypass. DNS is resolved at each connection, every returned
address must satisfy policy, and the checked IP is dialed directly without a
second lookup. Authority is rechecked after DNS and before dialing. Public mode
blocks local/private, link-local, metadata, mapped/transition, documentation and
other special-use ranges; private mode accepts only its approved private/loopback
prefixes. Plain HTTP is restricted to explicitly approved loopback addresses.

This policy was checked against the [IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/),
with an explicit block for [Azure's platform virtual address](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16).
Deployments still need to define which private prefixes an owner may select and
apply appropriate network egress controls. OAuth discovery/token endpoints and
stdio isolation are outside this header-only adapter.

## Startup integration

Guarded execution is installed whenever `owner_security` runs; the former
`custody_mode` setting is gone, and a config that still sets it fails to load.

- The owner security executor starts (new boot, earlier leases suspended) and
  loads the committed custody index and ciphertext cache before the first
  per-owner runtime exists, on both catalog backends. A load failure stops
  startup.
- A personal connector with auth type `bearer`, `api_key` or `headers` is
  bound from creation, whether or not its owner has saved a credential yet.
  Before the first save, and after the credential is removed (a tombstone),
  calls report `MCPWARDEN_LEASE_REQUIRED`. A tombstoned connector stays locked
  until it is deleted and added again, which gives it new connector and tool IDs
  and default visibility. The binding never changes after creation.
- The manager keeps a state entry for a bound connector (`custody: "vault"`) but
  never connects it, and refuses refresh (409) and calls (`upstream.ErrGuarded`).
  The catalog holds header names only, so there is no server-side credential to
  fall back to.
- Without `owner_security` the guarded adapter is not installed.
  `--stdio`, which never runs the executor, does not load credentialed
  connectors at all. The API then accepts only `none` connectors,
  and any stored credentialed connector stays locked and never dials. With
  `owner_security`, credentialed connectors are still limited to local-account
  workspaces, since only an account owner can unlock a vault, and to endpoints
  the vault destination accepts.
- Cached tool definitions stay in `tools/list` while the connector is enabled;
  each call verifies the selected definition against the upstream inside its
  window. Discovery for new credentialed connectors needs the owner setup flow
  (step 5); until then they have no tools. Browser flow tests build the gateway
  with `-tags flowtest`, which adds `PUT /api/test/discovery/<name>` to seed
  cached discovery for a vault connector without dialing; step 5 removes it.
- Each call uses the connector's configured call timeout, clamped to 5 minutes
  (30 seconds when unset). Unlike a manager call, whose timeout starts after its
  admission write and covers only the upstream, a guarded call's timeout covers
  session setup, the definition check, admission and the upstream call.
  Admission and completion are durable in the lease store. After dispatch, a
  best-effort copy of both goes to the owner's call history with credential,
  lease and approval attribution; a slow or failed copy never delays dispatch.

`TestGuardedHeaderExecution` (SQLite and PostgreSQL) drives one
connector from creation through locked calls and refused refresh, credential
save, an owner-activated window, a scope miss, disabling, restart and credential
deletion against a real SDK upstream. `TestCredentialSaveDuringCallsNeverDials`
shows that saving a credential concurrently with calls never reaches the upstream
without a lease, and `TestGuardedConnectorNeverDials` covers the manager.

## Validation and release gates

Tests authenticate the original public envelope vector and exchange ciphertext
both ways between Go and Node 20 WebCrypto, including international owner IDs.
This verifies primitive interoperability, not real-browser Argon2 performance or
the browser lifecycle. Parser tests cover tampering, strict fields, Unicode,
limits, redaction and clearing. Network tests simulate mixed/rebound DNS answers,
checked-IP dialing, forbidden ranges, private-prefix boundaries and missing use
capabilities. A fuzz target supplements those deterministic tests.

The PostgreSQL integration uses real encrypted synthetic headers, SDK downstream
and upstream servers, both `2025-11-25` and `2026-07-28` downstream protocols,
client/admin proxy views, and the restricted runtime database role. The upstream
queries the database independently before executing to verify admission is already
committed. It covers locked listing/calls, owner-only key release, wrong keys,
25 calls without renewal, reconnects, another active caller, actual credential
revision attribution, completion failure, lost responses, redirect refusal,
definition changes, revocation, and a real deferred admission commit rejection.

Before live rollout: a fresh-start deployment; setup/discovery
authorization; OAuth refresh; session/resource limits; restart/restore drills;
and load qualification. Deployment history is recorded in
[progress](../progress.md); the live deployment does not set `owner_security`.
