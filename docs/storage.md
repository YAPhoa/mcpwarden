# Storage

The optional `storage` section keeps the catalog, tool-call history, lease
metadata, vault ciphertext and approval policies in one database: a local SQLite
file (the default) or PostgreSQL. Without it the gateway runs as before, with the
encrypted catalog file (`managed_upstreams`) and JSONL history (`audit.path`).

```yaml
storage:
  driver: sqlite            # sqlite (default) or postgres
  path: /data/mcpwarden.db  # sqlite only
  # database_url_env: MCPWARDEN_DATABASE_URL  # postgres only: runtime role URL
  key_env: MCPWARDEN_CREDENTIAL_KEY          # catalog sealing key, base64 32 bytes
```

With `storage` set:

- `managed_upstreams` and `audit.path` must be unset. The catalog and history are
  in the database, sealed with `storage.key_env`.
- The lease executor runs in every HTTP mode (operator, OAuth and accounts), so
  every catalog change commits with its security event.
- `owner_security` needs `storage` and accounts mode. Its old
  `database_url_env` key is refused; use `storage.database_url_env`.
- `--stdio` is refused. Connect the client over HTTP.
- Startup opens the database, starts a new executor boot (older windows are
  suspended and pending requests become stale), loads the catalog and ends MCP
  sessions left open by the previous process. Any failure stops startup.
- A lost database session, an unknown commit outcome or a stalled statement
  stops the gateway. It never falls back to the files; restart it once the
  database is healthy.
- A caller that disconnects is not a storage failure. Statements run on the
  store's own deadline, and a change whose caller left before COMMIT is rolled
  back.

`managed_upstreams.backend` was replaced by this section and is refused.

## SQLite

The store lives in `internal/lease/sqlite` and uses `modernc.org/sqlite`, a pure
Go driver, so the gateway still builds with `CGO_ENABLED=0` for the distroless
image. The database migrates itself at startup from the embedded baseline; there
is no separate migration role.

**One process.** `Open` takes `<path>.lock` exclusively and holds it until the
process exits. It retries for 30 seconds, then refuses with "database in use by
another mcpwarden process". The kernel releases the lock when a process dies, so
a crash never leaves a stale lock. Leave the lock file in place: removing or
replacing it, or the database file, stops the gateway. Supported platforms are Linux and other Unix
systems (`flock`) and Windows (`LockFileEx`); others refuse to start.

**Files.** The parent directory is created 0700 and a new database 0600. A
symlinked path, a group- or world-accessible file, a path the driver would read
as a URI, and a network or FUSE filesystem (NFS, SMB/CIFS, FUSE, 9p, virtiofs,
and remote Windows drives) are refused. An unrecognized filesystem starts with a
warning. The Compose default is a local named volume.

**Settings.** WAL, `synchronous=FULL` (each commit is fsynced, so an admission
survives power loss), foreign keys on, `trusted_schema` off, and a 2 second busy
timeout. The store verifies them after opening and refuses a mismatch.
`application_id` identifies an mcpwarden database, and the ledger in
`schema_migrations` must match the embedded migrations exactly. An unrelated,
newer, edited or partial database is refused.

**Executor.** One connection serves owner transactions, history writes, the
catalog load and quiesce, serialized by the same gate as the PostgreSQL store.
An owner transaction is `BEGIN IMMEDIATE`; its clock is sampled after the write
lock is held. After a statement error the transaction is poisoned: later
statements fail without running and COMMIT is refused, as on PostgreSQL. A
heartbeat checks every second that the database and lock paths still name the
files that were opened, even under load, and pings the session when the gate
is idle. History pages use
a separate read-only pool of two connections, each page in one read transaction
with a 5 second deadline; a slow page fails alone and never stops the store.

**Tables that never lose rows.** PostgreSQL enforces append-only tables with
grants. SQLite has no roles, so triggers refuse DELETE on the same tables
(`schema_migrations`, `owners`, `requests`, `leases`, the vault tables,
`approval_policies`, `catalog_accounts`, `catalog_access`, `catalog_connectors`
and `history_tools`) and UPDATE on `schema_migrations`, alongside the guard
triggers both databases share. These catch bugs, not an attacker who controls
the gateway process; see the threat model below.

**Backups.** Stop the gateway and copy the volume. A clean shutdown removes the
WAL; after a crash, copy the `-wal` file too. Copying the files of a running
database does not give a consistent copy. Never open the live file with another
tool (the sqlite3 CLI, a database browser): one that holds the write lock past
the busy timeout stops the gateway. Work on a copy.

## PostgreSQL

Create the schema with `mcpwarden-security-db` and its migration role, then give
the gateway the runtime role's URL in the variable named by
`storage.database_url_env`; see [lease storage](security/lease-storage.md). The
runtime role cannot update or delete events, history or other append-only rows.
A database with no catalog state loads as a fresh catalog. One that holds an
import from the file catalog loads only once the import is cut over
([catalog migration](catalog-migration.md)); any other state is refused.

## Threat model: SQLite and PostgreSQL

| Property | PostgreSQL (runtime role) | SQLite |
|---|---|---|
| Credential confidentiality at rest | Ciphertext and wrapped keys only | Same |
| Append-only events, audit and history against a compromised gateway | Enforced by grants: the runtime role has no UPDATE, DELETE or TRUNCATE | Not enforced. The gateway owns the file, so triggers catch bugs, not attackers |
| Integrity of authorization rows | A database administrator is a separate principal | Only the gateway host user can write, which is the gateway's own trust domain |
| Single active executor | Session advisory lock and heartbeat | Exclusive lock file on a local filesystem and an inode check |
| Clock | Database `clock_timestamp()` | Gateway host clock |
| Backups | PostgreSQL tooling, off-host | Volume copy on the same host unless copied off |
| Failure | Lost session: fail closed | I/O error, full disk, a stalled statement, or an external tool holding the write lock past 2 seconds: fail closed |

SQLite suits a single-host personal gateway. Use PostgreSQL for role-separated
audit integrity or an off-host database.

## Tests

`internal/lease/storetest` is one contract suite that both stores run: leases,
vault CAS and write caps, cancellation, catalog rows, error mapping, poisoning,
history windows and filters, each schema rule, and the repository's atomic
change and fail-closed rules. `TestHistoryBackendEquivalence` writes the same
history to both stores and compares every query. SQLite-only tests cover the
lock file, unsafe paths, the settings, the migration ledger, a killed process,
busy and replaced files, fatal codes, forbidden conflict clauses and the
history index plans; `TestHistoryScale` (tag `historyscale`) holds pages to
500 ms at 1,000,000 calls on each store.

One difference is accepted: a vault envelope that spells its epoch or revision
as an exponent (`1e0`) is accepted by PostgreSQL, whose jsonb stores the number
1, and refused by SQLite. The gateway and browser write both as strings. The gateway's owner flows run on SQLite by default and on
PostgreSQL under `TestOwnerFlowsOnPostgres`.
