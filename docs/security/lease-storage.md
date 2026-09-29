# Lease storage and migration

This is the tested foundation for security spec v1.1. `internal/lease` implements
authorization state; `internal/lease/postgres` and `internal/lease/sqlite`
persist its metadata, together with the gateway catalog and history
([storage](../storage.md)). The guarded proxy adapter exercises real encrypted
credentials with this store; startup installs it whenever `owner_security` runs.
The live gateway does not run `owner_security` yet. The integration tests use synthetic credentials with the real envelope activator;
isolated core tests also retain simple test materials. See [encrypted execution](encrypted-runtime.md).

## Transaction and runtime contract

`Service.Request`, `Confirm`, `Activate`, `Admit`, `Revoke`, `Deny`,
`LockExecution`, `Catalog`, `ChangeAtomic` and `ChangeOwnerAtomic` use one short coordinator per owner. `Admit` produces
a single-use capability; call `Run` immediately, never enqueue it. Run rechecks
the live deadline before invoking work, and releases the coordinator before
provider I/O. Revocation before admission prevents work; after admission,
cancellation is best effort and cannot undo a provider side effect. A failed or
ambiguous admission never invokes work or retries a tool.

There is no default call budget or idle extension. Scope duration is explicit
(the planned UI default remains 900 seconds), capped by the deployment limit and
caller expiry. Renewal creates a new request and lease. The original deadline is
immutable. One lease must satisfy every constraint; matching leases are selected
by earliest expiry then lease ID. No preferred-scope selector is implemented yet.

An activation stage must verify the current encrypted record with reconstructed
expected AAD, using local bounded cryptography only. It owns returned buffers;
the service clears its input key. Material is published only after the database
commit succeeds while the owner gate remains held. An ambiguous result destroys
staged material and locks the executor even if PostgreSQL committed the row.
Existing material is cancelled on loss, revocation or expiry, and destroyed when
its admitted work drains. Go cannot prove instantaneous zeroization of all copies.

The `Authority` interface supplies coherent current caller/credential/policy/tool
metadata. Its security mutations must use the same coordinator. `Catalog` runs a
catalog change, its security events and any request or window ending in one owner
transaction, and publishes the change after commit. `ChangeAtomic` does the same
for ciphertext records. See [vault storage](vault-storage.md).

The PostgreSQL adapter uses one dedicated executor session for short
transactions and its session advisory lock. It never uses a reconnecting pool
for ownership. Losing the connection, a failed health check, SQL storage failure
or uncertain commit closes its lost signal; the lease service stops admissions
and cancels live work. A new Store/boot is required for recovery. Startup
atomically marks old pending/approved requests stale and active leases
suspended. Durable rows alone never recreate memory authority.

The health probe runs every second, only while the executor session is idle. A
busy session is bounded by its own deadline, so waiting behind a slow holder is
never read as session loss; an idle ping that fails, or takes longer than two seconds, is.
Transactions run on a statement context detached from the caller, with a
five-second deadline (thirty seconds for the startup load) and shorter
statement/row-lock timeouts. A caller that goes away mid-transaction gets its
context error, wrapped in `lease.ErrRolledBack`, before COMMIT and nothing is
committed; the session is untouched, since pgx would close a session whose
statement context ended. The catalog repository treats that error as a known
rollback: the change fails with "change not saved; try again" and is not
published, but the catalog stays up. Any
other error after its writes is an uncertain commit and still stops it. Reaching the
store deadline is a real stall and fails the store. There is no transaction
callback retry.

History pages run on a second, read-only session (`mcpwarden-history`,
`default_transaction_read_only=on`, 4.5-second statement timeout, so the
server ends a long statement before the page deadline would close the session), one
REPEATABLE READ transaction per page, so a slow page never holds the executor.
Pages take turns on that session: waiting has its own fifteen-second bound and
each page gets its full five seconds once it runs. A page that gives up waiting
never runs, and a failed page closes the session only when pgx has closed it.
A session that died while idle is replaced once within the page; otherwise a
failed open is not retried within a second. A history failure fails only that
page, never the store. Closing the store ends the running page and turns
waiting pages away, so shutdown never queues behind history. The adapter has
not been load-qualified.

Owner reads always include owner identity. Transactions lock the owner row before
sampling `clock_timestamp()`; transaction-start `now()` is unsuitable after a wait.
`synchronous_commit=on` is set on the runtime session. Fixed deadlines, operation
IDs, scope, epoch, caller and boot cannot be changed by UPDATE. Terminal rows
cannot be resurrected; counters cannot decrease or jump by more than one. An
admission updates the counter and appends its event in one transaction.
Completions append separately and must retain the admission identity snapshot.
Missing completion means unknown outcome, never permission to retry.

The schema has owners, requests, leases, allowlisted security events, invocation
events and a migration ledger, and also stores encrypted wrappers and
credential records; it contains no unwrapped keys or plaintext credential
payloads. Request scopes are authorization metadata and can themselves contain
sensitive resource identifiers; restrict database/backups accordingly. The same
schema holds the gateway catalog and indexed history (see
[storage](../storage.md)); it is not the candidate spec's client-release catalog
schema.

## Migration command and roles

The schema is one baseline,
[`001_baseline.sql`](../../internal/lease/postgres/migrations/001_baseline.sql),
at version 1. `cmd/mcpwarden-security-db` embeds it and verifies its SHA-256
hash in an ordered ledger; every later change is a numbered migration, and the
baseline is never edited. A ledger written by a development build before the
schema reset is refused with "create a new database". The baseline holds the
leases, the vault tables, per-owner approval policies (revision CAS enforced by
a trigger; the runtime role may insert and update, not delete), the catalog, and
history with its filter indexes, `history_tools` (the latest name of each tool)
and `history_open` (admissions without a stored completion). The runtime role
may insert and update catalog rows, replace discovery and visibility rows, and
insert history. It may insert and update `history_tools` and insert and delete
`history_open`, never truncate either. It cannot delete catalog rows or update
or delete history; startup checks this. The request binding CHECKs
`requests_binding_identity` and `requests_approved_mode` are wrapped in
`(…) IS TRUE`, so a binding missing its ID, boot ID, owner or (once approved)
mode is refused instead of passing as NULL.
There is no destructive down migration. Rerunning the same version is supported;
checksum drift or a newer/unexpected ledger fails closed.

Run migrations with a separate schema-owner role. Provision the runtime login
beforehand; it must not be superuser, create databases/roles, replicate, bypass
RLS, own the schema, or inherit the schema owner. The migration grants only schema
usage, metadata reads, state inserts/updates and event inserts. It grants no event
UPDATE/DELETE/TRUNCATE, schema DDL, or migration-ledger writes. Runtime startup
checks those restrictions. Audit retention must use a separately reviewed
maintenance role and workflow; no retention grant or deletion command ships here.

```sh
# Supply this environment variable through protected deployment configuration.
# Remote PostgreSQL connections should use sslmode=verify-full and trusted CAs.
go run ./cmd/mcpwarden-security-db -runtime-role mcpwarden_runtime
```

The command reads `MCPWARDEN_MIGRATION_DATABASE_URL`; it does not accept a DSN on
the command line or print driver connection errors. The migration and lease
executor contend for the same advisory lock, so a cooperating executor must stop
before schema migration.

## SQLite

The SQLite store (`internal/lease/sqlite`) keeps the same tables, keys, checks
and guard triggers in one file and passes the same contract suite
(`internal/lease/storetest`). Differences:

- It migrates itself from one embedded baseline under the lock file, at gateway
  startup or when a stdio client finds it alone; there is no migration or
  runtime role. The ledger must match the embedded
  migrations exactly, and `application_id` must identify an mcpwarden database.
- The single executor is an exclusive lock on `<path>.lock` instead of an
  advisory lock. Stdio clients hold it shared and never run the executor; the heartbeat also checks that the database and lock paths
  still name the files that were opened.
- IDs are lowercase canonical UUID text, timestamps are integer Unix
  microseconds, and guard functions are `BEFORE` triggers with null-safe
  comparisons. `OR IGNORE`, `OR REPLACE` and `REPLACE INTO` are forbidden; a test
  scans the SQL.
- Grants have no equivalent, so `BEFORE DELETE` triggers refuse deletes on the
  tables the PostgreSQL runtime role cannot delete from. They catch bugs, not a
  compromised gateway, which owns the file. See the threat model in
  [storage](../storage.md#threat-model-sqlite-and-postgresql).
- A failed statement poisons the transaction and a failed COMMIT is rolled back,
  matching PostgreSQL's aborted-transaction rule. Busy, I/O, full-disk and
  corruption errors fail the store.

## Isolated local tests

The separate Compose project binds PostgreSQL 18.6 to loopback port 55432 and a
dedicated volume. The passwords below are public synthetic fixtures. They are not
deployment credentials and are unrelated to the running gateway's configuration.

```sh
docker compose -f compose.postgres-test.yaml -p mcpwarden-security-test up -d --wait
export MCPWARDEN_TEST_DATABASE_URL='postgres://mcpwarden_migrator:mcpwarden-test-only@127.0.0.1:55432/mcpwarden_security_test?sslmode=disable'
go test -race ./internal/lease/... ./internal/jsoncodec ./internal/catalog ./internal/audit
```

Tests require that exact local fixture database name. Each test creates a random
scratch database and restricted runtime role, then removes only its own fixtures.
They do not copy application data. Without the environment variable, PostgreSQL
tests explicitly skip; ordinary unit tests still run.

Tests include real deferred commit rejection, a transport that consumes then
drops a successful COMMIT response, backend termination/lock loss, competing
executors/migration, cross-owner reads/FKs, immutable bindings, denied DDL/audit
mutation, budget contention and timestamps after row-lock waits. A PostgreSQL
database snapshot copy verifies restore suspension while preserving lease IDs,
scope hashes and deadlines. This is not yet a full application pg_dump/restore
drill or reconciliation of historical access revocations/OAuth rotations.

The local base fixture is maintained at the current security schema version with the separate
`mcpwarden_runtime_test` role, with public password `mcpwarden-runtime-test-only`,
after running the migration CLI. No caller, lease, credential or invocation rows
were imported there. Stop the fixture without deleting its volume with:

```sh
docker compose -f compose.postgres-test.yaml -p mcpwarden-security-test stop
```

## Sonic and reproducible measurements

Sonic v1.15.4 is pinned and used for sealed catalog records plus lease/SQL
metadata JSON. Settings retain HTML escaping and deterministic map order, copy
decoded strings, preserve number tokens, validate Unicode/strings and match field
names exactly. Strict decode additionally rejects unknown fields. Security input
validation separately rejects duplicate decoded keys, malformed Unicode, extra
roots, non-finite numbers and excessive size/depth before scope normalization.
RFC 8785 canonicalization uses the pinned Cyberphone implementation; ordinary
JSON encoding or PostgreSQL `jsonb::text` is never an approval hash.

Audit argument hashing keeps `encoding/json`, so its bytes never change. No
`encoding/json/v2` imports or experimental build settings remain. Sonic's native API is
confirmed on the tested linux/amd64 Go 1.27.1 host.

```sh
go test ./internal/jsoncodec -run '^$' -bench BenchmarkMetadataCodec -benchmem -benchtime=300ms -count=3
```

Local 32-tool metadata fixture, median of three runs on the Ryzen AI 9 HX PRO 370:

| Operation | Sonic | encoding/json | Allocated bytes/op (Sonic / standard) |
|---|---:|---:|---:|
| Encode | 17.4 µs | 36.1 µs | about 20.5 KB / 15.8 KB |
| Decode | 41.1 µs | 72.9 µs | about 66.7 KB / 45.0 KB |

This fixture shows roughly 2.1× faster encoding and 1.8× faster decoding, with
higher allocated bytes. Strict duplicate/depth/Unicode validation costs another
48 µs for this fixture and remains enabled at security boundaries. These are
codec microbenchmarks, not gateway throughput or latency claims. No performance
claim is made for architectures not executed here.

Primary references inspected: [Sonic Go 1.27 compatibility](https://github.com/bytedance/sonic/blob/main/docs/sonic-go127-compatibility.md),
[pinned Sonic settings](https://github.com/bytedance/sonic/blob/v1.15.4/api.go),
[RFC 8785 implementation](https://github.com/cyberphone/json-canonicalization),
[pgx v5.11.0](https://github.com/jackc/pgx/releases/tag/v5.11.0),
[PostgreSQL session locks](https://www.postgresql.org/docs/18/explicit-locking.html),
and [actual transaction clock](https://www.postgresql.org/docs/18/functions-datetime.html).
