# Storage

The gateway keeps its catalog, tool-call history, lease metadata, vault
ciphertext and approval policies in one database: a local SQLite file (the
default) or PostgreSQL. There is no file catalog and no JSONL history.

```yaml
storage:
  driver: sqlite            # sqlite (default) or postgres
  path: /data/mcpwarden.db  # sqlite only
  # database_url_env: MCPWARDEN_DATABASE_URL  # postgres only: runtime role URL
  key_env: MCPWARDEN_CREDENTIAL_KEY          # catalog sealing key, base64 32 bytes
```

Without the section the gateway uses SQLite at `/data/mcpwarden.db` (the
container path) and the key in `MCPWARDEN_CREDENTIAL_KEY`.

- The lease executor runs in every HTTP mode (operator, OAuth and accounts), so
  every catalog change commits with its security event.
- `owner_security` needs accounts mode.
- Startup opens the database, starts a new executor boot (older windows are
  suspended and pending requests become stale), loads the catalog and ends MCP
  sessions left open by the previous process. Any failure stops startup.
- A lost database session, an unknown commit outcome or a stalled statement
  stops the gateway. It never falls back; restart it once the database is
  healthy.
- A caller that disconnects is not a storage failure. Statements run on the
  store's own deadline, and a change whose caller left before COMMIT is rolled
  back.
- `--stdio` needs SQLite and never shares the database with a running gateway
  ([stdio clients](#stdio-clients)).

Removed keys are refused at startup with their replacement: `audit` (history is
in the database), `managed_upstreams` (use `storage`), and
`owner_security.database_url_env` and `database_url` (use
`storage.database_url_env`).

## Schema

Both dialects start from one baseline, `001_baseline.sql`, at version 1. Every
later change is a numbered migration on both dialects; a baseline is never
edited, because the ledger in `schema_migrations` must match the embedded
migrations exactly. An unknown, edited, partial or newer ledger is refused. A
database created by a development build before the schema reset is refused
with "created by a development build before the schema reset; create a new
database". There is no conversion or import from older builds.

## Catalog

`dbcatalog.Repository` implements `catalog.Repository`: personal connector
definitions with header names only (never values), cached tool discovery,
tool visibility and provider availability, local accounts and password
material, access records, and credential-free connector tombstones. Connector
credentials are not stored here; they live in the owner vault.

Tables `catalog_accounts`, `catalog_access`, `catalog_connectors`,
`catalog_discovery` and `catalog_visibility` keep one row per record. Every
secret-bearing value is in a `sealed` column: AES-GCM under a key derived with
HKDF-SHA256 from the catalog key, with the row's identity as associated data.
Key verifiers are indexed by an HMAC digest, never by the verifier itself.
Plain columns (owner, username, public ID, kind, role, lifecycle times,
connector name and auth type) exist for constraints and indexes. They must
match the sealed payload, or loading fails. A connector sealed by an older
build with header values or upstream OAuth settings is refused
(`catalog.ErrOldFormat`).

The repository loads and verifies every row at startup and serves reads from
that view; reads have no error return because visibility checks run inside
synchronous MCP SDK callbacks. Each mutation runs in one owner transaction
under the lease service's owner gate (`lease.Service.Catalog`), together with
its security event and any lease revocation. The view lock is taken inside the
transaction and released only when the committed change is published. Readers
never see uncommitted state, and a failed or uncertain commit publishes
nothing. An uncertain commit or a lost session fails the repository closed:
authentication stops, mutations return `catalog storage unavailable`, and the
gateway exits. Uniqueness, the one live name per owner and hard active limits
are enforced in the transaction as well as in memory. Deleted connectors keep a
credential-free tombstone row, and history rows never cascade with them.

Public IDs of API keys are independent random lowercase-hex values, never
derived from the secret, and survive rename, expiry and revocation.
`AuthenticateAccess` compares the full-token SHA-256 verifier in constant time.
This design targets a single active gateway per database. Vault credentials are
activated only through the guarded execution boundary
([encrypted runtime](security/encrypted-runtime.md)), never inside these reads.

## History

`dbcatalog.History` is the `audit.Store`. Each event is one row in
`history_events` holding the exact encoded record, plus indexed columns derived
from it: owner, event and invocation IDs, event type, tool ID and name,
upstream, status, actor, start and history times in nanoseconds, timing values
and their log2 buckets. Only schema-2 invocation events are stored:

- `invocation_id` is shared by an admission and its completion; every event
  keeps its own `event_id`. A denial before admission is a single event.
- `event_type` is `tool.dispatch.admitted`, `tool.dispatch.completed` or
  `tool.dispatch.denied`. An admission has status `unknown`, decision `allow`,
  and no completion time, timing or response claims.
- `actor_type`, `actor_access_id`, `actor_public_id` and
  `actor_label_snapshot` are validated caller metadata, independent of
  clientInfo and tool arguments. Stdio calls have actor type `stdio`.
- `argument_hash_version` is `mcpwarden.arguments.v1`: the canonical Go JSON
  hash, whose bytes never change. It is separate from RFC 8785 approval
  hashes. Raw arguments, results and credentials are never stored.
- `tool`, `upstream` are name snapshots; `tool_id` and `upstream_id` are
  stable identities. Gateway management tools use their reserved names as
  tool IDs.

Every write is its own committed transaction, so an admission is durable before
dispatch. A failed or uncertain admission blocks the call with a safe tool
error. Completion is a separate write; its failure keeps the actual tool result
and never causes a retry. An unresolved admission means the outcome is
unknown: still running, a crash before or after dispatch, or a lost completion
write. It is not proof that the call ran or that a retry is safe.
`(owner_id, event_id)` and `(owner_id, invocation_id, event_type)` are unique.

Pages show each invocation once: the completion, or the admission while no
completion is stored. They sort by history time (completion, or occurrence for
an unresolved admission), then event ID in byte order. The time-range filter
uses history time too, while the list shows the start time. Each page reads at
most the newest 25,000 matching events (1,000 pages of 25); a page beyond that
is refused, the total and timing summaries cover the same window, and the API
adds `total_capped: true` when more calls match. Older calls stay reachable
through the time range. Each filter that is set adds one bound predicate, and
every single filter has an index in history order. Those indexes hold settled
events only (everything but admissions); open admissions come from
`history_open`, which each insert keeps equal to the admissions without a stored
completion. The tool filter reads `history_tools`, which each insert moves
forward only. At 1,000,000 calls every measured page returns within 500 ms
(`TestHistoryScale`, build tag `historyscale`).

Pages never hold the executor. On PostgreSQL they run on a separate read-only
session (`mcpwarden-history`, 4.5 s statement timeout), one REPEATABLE READ
transaction per page; on SQLite on a read-only pool of two connections with a
5 s deadline. A slow page fails alone and never stops the gateway.

## SQLite

The store lives in `internal/lease/sqlite` and uses `modernc.org/sqlite`, a
pure Go driver, so the gateway builds with `CGO_ENABLED=0` for the distroless
image. The database migrates itself from the embedded baseline; there is no
separate migration role, because there is no privilege split to preserve.

**Lock file.** A gateway takes `<path>.lock` exclusively and holds it until it
exits. It retries for 30 seconds, then refuses with "database in use by another
mcpwarden process (a gateway, or --stdio clients)". The kernel releases the
lock when a process dies, so a crash never leaves a stale lock. Leave the lock
file in place: removing or replacing it, or the database file, stops the
gateway. Supported platforms are Linux and other Unix systems (`flock`) and
Windows (`LockFileEx`); others refuse to start.

**Files.** The parent directory is created 0700 and a new database 0600. A
symlinked path, a group- or world-accessible file, a path the driver would read
as a URI, and a network or FUSE filesystem (NFS, SMB/CIFS, FUSE, 9p, virtiofs,
and remote Windows drives) are refused. An unrecognized filesystem starts with
a warning. The Compose default is a local named volume.

**Settings.** WAL, `synchronous=FULL` (each commit is fsynced, so an admission
survives power loss), foreign keys on, `trusted_schema` off, and a busy timeout
of 2 seconds for the gateway and 5 seconds for stdio clients. The store
verifies them after opening and refuses a mismatch. `application_id`
identifies an mcpwarden database; an unrelated file is refused.

**Executor.** One connection serves owner transactions, history writes, the
catalog load and quiesce, serialized by the same gate as the PostgreSQL store.
An owner transaction is `BEGIN IMMEDIATE`; its clock is sampled after the write
lock is held. After a statement error the transaction is poisoned: later
statements fail without running and COMMIT is refused, as on PostgreSQL. A
heartbeat checks every second that the database and lock paths still name the
files that were opened, and pings the session when the gate is idle.

**Tables that never lose rows.** PostgreSQL enforces append-only tables with
grants. SQLite has no roles, so triggers refuse DELETE on the same tables
(`schema_migrations`, `owners`, `requests`, `leases`, the vault tables,
`approval_policies`, `catalog_accounts`, `catalog_access`, `catalog_connectors`
and `history_tools`) and UPDATE on `schema_migrations`, alongside the guard
triggers both databases share. These catch bugs, not an attacker who controls
the gateway process; see the threat model below.

**Backups.** Stop the gateway and every stdio client, then copy the volume or
file. A clean shutdown removes the WAL; after a crash, copy the `-wal` file too.
Copying the files of a database in use does not give a consistent copy. Never
open the live file with another tool (the sqlite3 CLI, a database browser): one
that holds the write lock past the busy timeout stops the gateway. Work on a
copy.

### Stdio clients

`--stdio` serves one MCP client over stdin and stdout, as Claude Desktop and
`claude mcp add` launch it. It needs SQLite; with PostgreSQL it refuses with
"--stdio needs SQLite storage; connect this client over HTTP", so no stdio
config ever holds the runtime role.

A stdio client holds the lock file shared while it serves, so any number of
clients with the same config share one database, and a gateway cannot start
beside them. It takes the lock exclusively only to create or migrate the
database, and only while no other mcpwarden process is attached:

1. It tries the lock shared, without waiting, and checks the database without
   creating it. At this build's schema it serves. A newer, unknown or edited
   ledger is refused at once. A missing, empty or older database releases the
   lock and goes to step 2.
2. It tries the lock exclusively, without waiting, checks again, and creates or
   migrates only if that is still needed. It then converts the lock to shared.
   The conversion is not atomic, so another process can take the lock in the
   gap; the client then checks again, or goes to step 3 if it holds no lock.
3. It waits 50 to 100 ms and goes back to step 1.

Each time it lets go of the lock it also closes its connection, and it records
the database file's identity before the serving connection opens and checks it
again after the version check. A file replaced while the client starts is
never served through a connection to the old file: the client goes round the
loop and serves the file at the path.

After 10 seconds without serving it refuses with "database in use by a gateway,
or needs a migration while other mcpwarden clients use it; connect over HTTP,
or close the other clients". Clients that start together on a missing database
all serve; one creates it.

A stdio client never runs the executor. It serves the config upstreams and
owner `local`'s no-auth connectors, visibility and discovery from a read-only
snapshot taken at start. Credentialed connectors are not loaded: their
credentials are in the owner vault, which only the gateway opens. A discovery
refresh stays in memory, and every other catalog change returns "stdio cannot
change the catalog; use the panel". It writes only history: each event, its
`history_tools` update and its `history_open` change in one `BEGIN IMMEDIATE`
transaction, after checking that the database and lock paths still name the
files it opened. A write that cannot get the database within the busy timeout
fails, as any failed admission does, and the call is not dispatched. A
replaced database or lock file, or a commit with an unknown outcome, stops the
client: the process exits and the MCP client can start it again. Stdio calls are recorded for owner
`local`, which the panel shows only in operator mode (a bearer token, or no
downstream auth on loopback).

Sharing needs the same host and OS user, on a local filesystem, so it does not
work through the Compose volume or a Docker Desktop bind mount. To run a
gateway and stdio clients at the same time, give them separate `storage.path`
values, or connect the clients over HTTP.

## PostgreSQL

Create the schema with `mcpwarden-security-db` and its migration role, then give
the gateway the runtime role's URL in the variable named by
`storage.database_url_env`; see [lease storage](security/lease-storage.md). The
runtime role cannot update or delete events, history or other append-only
rows, and a session advisory lock keeps one executor per database. Use a new,
empty database: one created before the schema reset is refused.

## Threat model: SQLite and PostgreSQL

| Property | PostgreSQL (runtime role) | SQLite |
|---|---|---|
| Credential confidentiality at rest | Ciphertext and wrapped keys only | Same |
| Append-only events and history against a compromised gateway | Enforced by grants: the runtime role has no UPDATE, DELETE or TRUNCATE | Not enforced. The gateway owns the file, so triggers catch bugs, not attackers |
| Integrity of authorization rows | A database administrator is a separate principal | Only the gateway host user can write, which is the gateway's own trust domain |
| Single active executor | Session advisory lock and heartbeat | Exclusive lock file on a local filesystem and an inode check |
| Clock | Database `clock_timestamp()` | Gateway host clock |
| Backups | PostgreSQL tooling, off-host | File copy on the same host unless copied off |
| Failure | Lost session: fail closed | I/O error, full disk, a stalled statement, or an external tool holding the write lock past the busy timeout: fail closed |

SQLite suits a single-host personal gateway. Use PostgreSQL for role-separated
history integrity or an off-host database.

## Tests

`internal/lease/storetest` is one contract suite that both stores run: leases,
vault CAS and write caps, cancellation, catalog rows, error mapping, poisoning,
history windows and filters, each schema rule, and the repository's atomic
change and fail-closed rules. `TestHistoryBackendEquivalence` writes the same
history to both stores and compares every query. SQLite-only tests cover the
lock file, unsafe paths, the settings, the migration ledger, a killed process,
busy and replaced files, fatal codes, forbidden conflict clauses, the history
index plans, and the stdio client: shared use, the exclusion of gateway and
clients in both directions, creation by clients that start together, the
conversion gap, migration only when alone, the version check after the
conversion, refusals without waiting, files replaced while starting or
serving, a failed commit, and a busy database refusing a call before dispatch.
`TestHistoryScale` (tag `historyscale`) holds pages to 500 ms at 1,000,000
calls on each store. The gateway's tests run on SQLite, and its owner flows
also on PostgreSQL under `TestOwnerFlowsOnPostgres`.

One difference is accepted. Six integer columns are also stored inside JSON:
the envelope's epoch and revision, the wrapped key's epoch and root version,
and the root version of both root wrappers. A value spelled as an exponent
(`1e0`) is accepted by PostgreSQL, whose jsonb stores the number 1, and refused
by SQLite. The gateway and browser write all six as strings.
