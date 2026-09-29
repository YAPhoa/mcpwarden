# Browser vault primitives and encrypted storage

This document covers the spec's root/credential wrapping formats, browser
cryptographic primitives, and ciphertext storage on PostgreSQL or SQLite. The
owner HTTP API (`docs/security/owner-api.md`) and the owner console's setup,
recovery, unlock, credential and access-window screens (`/vault`, see
`ui/DESIGN.md`) use them when `owner_security` is enabled. Vault custody is the
only custody: personal connectors with credentials run only through access
windows, and merely serving these assets does not activate client-release
custody.

## Browser boundary

`ui/static/security/vault-client.mjs` owns a dedicated module worker. A session can
create a random 32-byte vault root and independent recovery key, unlock with a
passphrase or recovery key, wrap independently random credential keys, authenticate
and release one selected key, change the passphrase wrapper, and lock. Lock
terminates the worker and rejects outstanding operations. A new worker starts
locked. There are no HTTP calls, local/session storage, IndexedDB writes, automatic
key release, or whole-vault export operation in these modules. The owner console
shows the returned recovery key once, requires the owner to type it back, and
proves it opens the recovery wrapper before anything is uploaded.

Passphrases use UTF-8 without trimming or Unicode normalization; malformed Unicode
is rejected. Input is bounded to 1–1024 UTF-8 bytes. The sole supported profile is
Argon2id version 19, 65,536 KiB, three iterations, four lanes and 32-byte output,
with a random 16-byte salt. HKDF-SHA-256 uses a 32-byte zero salt and the exact
purpose labels in spec §8.8. AES-256-GCM uses a random 12-byte nonce and appended
128-bit tag. IDs, versions, base64url, fields, sizes, duplicate keys and KDF
parameters are checked before derivation. AAD is reconstructed from the expected
context and includes the exact KDF object for root wrappers.

The vendored dependency is [hash-wasm 4.12.0](https://github.com/Daninet/hash-wasm/tree/v4.12.0),
with its license, published npm integrity and individual SHA-256 hashes alongside
the asset. Its [Argon2 implementation](https://github.com/Daninet/hash-wasm/blob/v4.12.0/lib/argon2.ts)
was inspected and tested against independent argon2-cffi vectors, including
international input. It is not loaded from a CDN. This is an implementation
review and compatibility check, not an independent security audit of the WASM.

The library's public API does not expose all WASM working memory for explicit
wiping. Each derivation therefore runs in a one-use nested worker that is closed
and terminated after success, failure or timeout. Owned password/key buffers are
cleared where possible. JavaScript strings, WebCrypto internals and browser
allocators can retain copies; termination is an isolation/lifetime boundary, not
a guarantee of physical memory erasure. Broader browser/device qualification and
dependency review remain release gates.

The nginx `/security/` path explicitly serves JavaScript module MIME types and a
worker CSP with same-origin scripts/workers, `wasm-unsafe-eval`, and no network
connections. It does not add `unsafe-eval` to the main panel. The owner-console
browser flows run the page under a strict same-origin CSP that allows those
workers; nginx does not yet send a page CSP. Worker isolation does not protect against a compromised
same-origin application that receives user input or asks the worker for a key.

Passphrase changes rewrap the same root; credential keys and ciphertext need not
change. Old backups/wrapper history can still be unlocked with their former
passphrase. Root rotation and credential replacement after a compromise require
a separate recovery workflow, not a claim that rewrapping erases old copies.
Recovery-key rotation, password-input clearing, logout/navigation/idle lock hooks,
recovery confirmation and accessible owner screens remain integration work.

## PostgreSQL contract

The vault tables are part of the `001_baseline.sql` schema. The migrator verifies
an exact contiguous prefix of the pinned SHA-256 ledger, applies missing versions
atomically, and reapplies least-privilege grants. Empty, edited, gapped and unknown
ledgers fail closed. The executor requires the entire current schema, and
migration still excludes an active executor through the shared advisory lock.
SQLite keeps the same tables, checks and guard triggers
([storage](../storage.md#sqlite)).

The database stores only public context and ciphertext: current root pointers,
immutable pairs of passphrase/recovery wrappers, credential heads/tombstones,
immutable credential epochs and immutable ciphertext revisions. There is no
passphrase, recovery secret, vault root, unwrapped CEK, header value or durable
server unwrap key in these records. Destination/header-name metadata stays public.
The restricted runtime role cannot delete history or update encrypted versions.
Owner isolation is enforced by the adapter's predicates and composite keys; this
single executor role is not a PostgreSQL per-owner RLS boundary.

Writes require expected current revisions. Creation starts at epoch/revision 1;
same-epoch writes increment revision exactly once and keep wrapping/destination
metadata fixed. Rotation increments epoch once and starts revision 1 with a fresh
CEK wrapper. Deletion retains the current pointer and all historical rows, and
cannot resurrect that credential ID. The catalog keeps a credential-free
connector tombstone, and a deleted connector never dials.

Uniqueness constraints reject repeated nonces within a credential epoch and
across all credential-key wraps under the same root wrapping key. SQL checks bind
the nonce columns to the actual wire envelopes. Transactional, monotonic counters
limit committed writes to 2^20 per CEK epoch and 2^20 credential-key wraps per
root. Failed writes roll back the pointer and counts. These are durable-write
limits, not a way to observe encryption attempts in an untrusted client. Root
rotation at the wrapping limit is deliberately unsupported until its full
recovery/migration flow exists; the current adapter fails closed.

`vault.Tx` extends the PostgreSQL owner transaction. Trusted, already-authorized
mutations use `Service.ChangeAtomic`: write the new ciphertext, retire pending
requests/active leases and append their revocation events in one transaction.
Only after commit does it stop old material and publish the prepared ciphertext
cache plus associated catalog authority under the owner gate. This initially
revokes all of the owner's leases conservatively. Rollback leaves the old state
usable; uncertain commit or failed publication locks access. Callbacks are never
retried. No provider I/O or shared-cache mutation is allowed in the transaction.
The immutable cache makes activation a bounded local read rather than database
I/O inside the lease transaction. Its reads and prepared snapshots own buffers.

The store intentionally provides no uncoordinated public write helper. This is
not yet the full catalog repository, account migration or OAuth refresh writer.
Owner-route authentication, CSRF, mutation-specific audit, security revisions,
startup cache loading and coordinated authority publication remain required.

## SQLite contract

The SQLite store keeps the same vault tables, CAS rules, write caps and
tombstones, and `storetest` runs the same vault cases on both databases. A nonce
is stored as its 16-character base64url text (12 bytes encode exactly, so text
uniqueness equals byte uniqueness), with checks binding it to the envelope. The
counters are triggers that refuse the write past the cap. Only ciphertext and
public metadata are stored, as on PostgreSQL. The difference is who can change
the rows: the gateway process owns the SQLite file, so the no-delete and
immutability triggers protect against bugs, not against a compromised gateway.
See the threat model in [storage](../storage.md#threat-model-sqlite-and-postgresql).

## Checks and remaining gates

Tests cover stale/concurrent writes, root wrapper CAS, nonce reuse, ciphertext
retention, tombstones, owner isolation, role restrictions, both write caps,
immutable cache snapshots, committed revocation, rollback, publication failure,
deferred commit rejection and atomic v1→v2 upgrade failure/recovery. Real MCP
dispatch tests now read the encrypted records from PostgreSQL before activation.

Go and Node WebCrypto exchange and authenticate root, recovery, CEK and credential
envelopes in both directions. Browser tests use real Firefox workers under the
intended CSP with synthetic credentials and only loopback static assets. They
verify passphrase/recovery unlock, selected key release, locking during work,
fresh-worker lock state and no browser storage. One desktop Firefox 156 run took
244 ms for setup and 152 ms for passphrase unlock; these are observations, not
device support or performance guarantees.

Run `node --test ui/tests/*.test.cjs ui/tests/*.test.mjs` and the usual Go suite with
the isolated PostgreSQL fixture enabled. For the real-browser check, supply
`PLAYWRIGHT_MODULE` (installed package's `index.mjs`) and optionally
`FIREFOX_EXECUTABLE`, then run `node ui/tests/vault-browser.mjs`.

Live rollout still needs setup discovery for new providers, OAuth
bundle/refresh lifecycle, restore/restart and load qualification. Startup now
installs the guarded adapter whenever `owner_security` runs.
No new gateway configuration switch is exposed by this slice.
