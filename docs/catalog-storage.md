# Catalog storage contract

Managed gateway state is accessed through `catalog.Repository`. The current
`catalog.Store` implementation keeps an in-memory index and atomically replaces
one AES-GCM encrypted file. Runtime, local-account authentication, access-key
management depend on the interface rather than that file implementation.

The repository contains personal connector definitions with header names only
(never values), cached tool discovery, tool visibility and provider availability,
local accounts and password material, access records, and credential-free
connector tombstones. Connector credentials are not stored here; they live in the
owner vault. A catalog from an older build that holds header values or upstream
OAuth settings is refused at load (`catalog.ErrOldFormat`: "created by an older
build; start with a new catalog"); there is no conversion. Audit history is a separate append-only concern described in
[history-storage.md](history-storage.md); its runtime boundary is `audit.Store`.

All repository implementations must:

- be safe for concurrent callers and keep every read and mutation owner-scoped;
- return defensive copies so callers cannot mutate persisted state indirectly;
- durably complete a mutation before reporting success;
- make uniqueness checks, active-credential limits, and password/session changes
  atomic with their writes;
- preserve lifecycle timestamps, stable connector IDs, deletion tombstones, and
  cached MCP tool schemas across restarts;
- assign and preserve independent, globally unique lowercase-hex public IDs for
  API-key records; never derive them from secret/verifier bytes, and retain IDs
  after rename, expiry or revocation;
- protect password hashes and salts and access-token hashes at rest, and never log
  their values; and
- release resources through `Close` after runtimes have stopped writing.

`AuthenticateAccess` compares the existing full-token SHA-256 verifier in constant
time and returns safe metadata only. `AccessByID` must return an empty record on a
missing or cross-owner lookup. Public-ID migration must not change existing
verifiers, ownership, roles, expiry, or lifecycle timestamps.

Repository reads deliberately have no error return because visibility checks run
inside synchronous MCP SDK callbacks. A remote-database adapter must load a coherent
view successfully before startup, serve these reads from that view, and publish a new
view only after a durable transaction commits. It must return database failures from
mutations rather than silently changing only the cached copy. This contract targets a
single active gateway process; safe active-active deployment additionally requires a
defined cache-invalidation/serialization protocol and is not implied by the interface.

A PostgreSQL adapter can implement `catalog.Repository` and `audit.Store` without
changing request handlers, proxy behavior, or authentication code. It should use
database constraints for connector/account/credential uniqueness, transactions or
row locks for limits and compare-and-swap changes, and indexes beginning with the
owner field. Historical audit rows must not cascade-delete with connectors. A
database adapter also needs an explicit migration and encrypted-secret format; plain
JSON or unencrypted text columns are not acceptable for secret-bearing fields.

## PostgreSQL backend

`pgcatalog.Repository` implements this contract on PostgreSQL schema v5 and is
selected with `managed_upstreams.backend: postgres`, which requires
`owner_security`. The default stays `file`. Moving data between the two is the
[catalog migration](catalog-migration.md).

Tables `catalog_accounts`, `catalog_access`, `catalog_connectors`,
`catalog_legacy_tombstones`, `catalog_discovery` and `catalog_visibility` keep
one row per record. Every secret-bearing value is in a `sealed` column:
AES-GCM under a key derived with HKDF-SHA256 from the existing catalog key, with
the row's identity as associated data. Key verifiers are indexed by an HMAC
digest, never by the verifier itself. Plain columns (owner, username, public ID,
kind, role, lifecycle times, connector name, auth type and revision) exist for
constraints and indexes. They must match the sealed payload, or loading fails.
The `grant_id` column stays NULL; a row with a grant ID is from an older build
and is refused at load. Sealing protects account data at rest under the server
key; connector credentials are never in these rows.
`catalog_state` records the import and which store is authoritative. The
runtime role cannot change it or delete catalog rows.

The repository loads and verifies every row at startup and serves reads from
that view. Each mutation runs in one owner transaction under the lease
service's owner gate (`lease.Service.Catalog`), together with its security event
and any lease revocation. The view lock is taken inside the transaction and
released only when the committed change is published. Readers never see
uncommitted state, and a failed or uncertain commit publishes nothing. An
uncertain commit or a lost session fails the repository closed: authentication
stops, mutations return `catalog storage unavailable`, and the gateway exits.
Uniqueness, the one live name per owner and hard active
limits are enforced in the transaction as well as in memory. Deleted connectors
keep a credential-free tombstone row. The file backend's guards are unused in
this mode, because the repository coordinates with the lease service itself.

A backend-only replacement preserves these interfaces. Vault credentials are
activated only through the separate, fallible guarded execution boundary (see
[encrypted runtime](security/encrypted-runtime.md)). Do not hide interactive
decryption inside these metadata reads.
