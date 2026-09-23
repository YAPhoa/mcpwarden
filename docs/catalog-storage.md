# Catalog storage contract

Managed gateway state is accessed through `catalog.Repository`. The current
`catalog.Store` implementation keeps an in-memory index and atomically replaces
one AES-GCM encrypted file. Runtime, local-account authentication, access-key
management, and upstream OAuth depend on the interface rather than that file
implementation.

The repository contains personal connector definitions and headers, cached tool
discovery, tool visibility and provider availability, local accounts and password
material, access records, OAuth client settings and grants, and credential-free
connector tombstones. Audit history is a separate append-only concern described in
[history-storage.md](history-storage.md); its runtime boundary is `audit.Store`.

All repository implementations must:

- be safe for concurrent callers and keep every read and mutation owner-scoped;
- return defensive copies so callers cannot mutate persisted state indirectly;
- durably complete a mutation before reporting success;
- make uniqueness checks, active-credential limits, password/session changes, and
  compare-and-swap OAuth grant updates atomic with their writes;
- preserve lifecycle timestamps, stable connector IDs, deletion tombstones, and
  cached MCP tool schemas across restarts;
- assign and preserve independent, globally unique lowercase-hex public IDs for
  API-key records; never derive them from secret/verifier bytes, and retain IDs
  after rename, expiry or revocation;
- protect headers, password hashes and salts, access-token hashes, OAuth client
  secrets, and OAuth grants at rest, and never log their values; and
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

The PostgreSQL catalog/history adapter and its gateway configuration are not
implemented yet. A separate [lease metadata adapter and migration command](security/lease-storage.md)
now use pgx and an isolated test database; they do not implement this repository
contract or convert live credentials. The [security specification](security/spec-v1.1/SECURITY-DESIGN.md)
contains candidate catalog SQL for later review. A backend-only replacement can preserve
these interfaces; client-release custody additionally requires a separate fallible
secret-activation boundary and runtime changes. Do not hide interactive decryption
inside these metadata reads or claim the current whole-file encryption is client-held.
