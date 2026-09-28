# Moving the catalog to PostgreSQL

Status: implemented and tested against scratch databases. It has not been run
against live data, and the live gateway still uses the encrypted file catalog.
This procedure is for review before any live migration.

The PostgreSQL backend stores the same catalog the file holds: accounts and
password verifiers, access keys and sessions, connectors with their header
names, tombstones, discovery caches and visibility. It also stores tool-call
history. Secret-bearing values stay encrypted with the existing catalog key, so
the database never holds them in plain text. Connector credentials are not part
of the catalog; they live in the owner vault. A file catalog from an older build
(with header values or upstream OAuth settings) is refused, so it cannot be
imported. See
[catalog storage](catalog-storage.md) and [history storage](history-storage.md).

## Guarantees

- **One writer.** Each migration step holds the gateway's PostgreSQL executor
  lock and an exclusive lock on `<catalog>.lock`. A running file gateway holds
  that file lock shared, and a PostgreSQL gateway holds the executor lock, so
  every step refuses to run beside either (`a gateway or another migration is
  running`). A file gateway cannot start while a step runs.
- **Consistent protected snapshot.** Import pins the SHA-256 and size of the
  catalog and history files, copies them into a 0700 directory beside the
  catalog (`.mcpwarden-import-<import id>/`, files 0600) and reads only that
  copy. Source files readable by other users are refused. If either the original
  files or the copy change before cutover, the step fails with `a source file
  changed`.
- **Complete verification.** Import and cutover both decrypt every stored row
  and compare the whole catalog with a fresh read of the snapshot, field by
  field. This covers ownership, password salts and hashes, key verifiers,
  public IDs, roles, expiry, all lifecycle timestamps, tombstones, discovery,
  visibility and header names. Every
  history line is compared byte for byte with its line number, and every
  column that history queries read (owner, event ID including derived v0 IDs,
  filters, ordering time and timing) must equal what the JSONL reader derives
  from that line. Plain database columns must agree with the encrypted
  payload, and each payload is bound to its row, so a swapped or edited row
  fails. Counts and IDs are reported but are not the check.
- **Resumable and repeatable.** The catalog imports in one transaction. History
  imports in batches, and each batch commits with its checkpoint (line count,
  byte offset and hash state). A rerun after an interruption continues from the
  last checkpoint. A rerun after success only re-verifies and never adds rows.
  Event and invocation IDs are unique per owner, so a duplicate fails the batch.
- **No fallback.** With `storage.driver: postgres` the gateway never reads the catalog
  file. It refuses to start unless PostgreSQL is the active catalog. If a
  commit outcome is unknown or the database session is lost, it fails closed:
  authentication stops, changes fail, and the process exits with `PostgreSQL
  catalog storage failed`. Restart it once the database is healthy.
- **Markers.** The migration writes `<catalog>.state` beside the file. While it
  says `importing`, `active` or `rolling_back`, the file backend refuses to
  start. After a rollback it says `rolled_back` and admits only the file the
  rollback wrote. An older backup is refused because it could revive revoked
  access. A file gateway with `owner_security` also checks the database and
  refuses unless the catalog there is absent or rolled back. Do not delete the
  marker. It is the only guard for a file gateway that runs without
  `owner_security`.
- **A marker belongs to one database.** Every step checks the marker under the
  file lock before replacing it. It must be absent or carry the import (and
  rollback) ID recorded in the database the step runs against. A marker from
  another database stops the step with `the catalog marker belongs to a
  migration in another database`, so pointing the tool at a new or empty
  database can never make a cut-over file authoritative again. The one
  exception is a `rolled_back` marker, since the file is then authoritative: a
  new import accepts it only if the catalog file is that rollback's export (an
  older copy is refused with `the catalog file is not the one the PostgreSQL
  rollback wrote`, before any row is written), keeps it inside its own marker,
  and abandoning that import puts it back. Import records itself in the
  database before it writes its marker.

## Coordination while running on PostgreSQL

Every catalog change is one owner transaction under the lease service's owner
gate. That covers accounts, passwords, keys and sessions, connectors,
visibility, availability and discovery. The same transaction writes the
change, its security event (`access.revoked`, `account.password_changed`,
`connector.deleted` and so on), and any lease revocation. Revoking an API
key or deleting a connector ends the owner's access windows in that commit;
the file mode's guard does this for key revocation only. Password changes and
session revocation end no windows. Disabling or enabling a provider, or
changing which of its tools are visible, is a connector security change: the
same commit ends that connector's pending requests and windows (other
connectors keep theirs) and moves its security revision, which access scopes
bind, so undoing the change revives neither. Repeating the current setting
changes nothing. With the file catalog and `owner_security`, such a change
ends all of the owner's windows before the file is written. The
in-memory view changes only after the commit succeeds. Hard limits on active
keys and sessions are checked in memory and again by a count inside the
transaction.
Tool-call history rows commit before the call is dispatched, as before.

## Before you start

- Owner security must be configured (accounts mode, `owner_security` with its
  transport requirements). Live `owner_security` is currently disabled, so
  cutover also turns it on.
- The PostgreSQL role setup from [lease storage](security/lease-storage.md):
  a migration role that owns the schema and an unprivileged runtime role.
- The image ships `/mcpwarden-security-db` and `/mcpwarden-catalog` next to
  the gateway. Both read `MCPWARDEN_MIGRATION_DATABASE_URL` (the migration
  role). The catalog tool also needs the gateway config and its catalog key
  variable. It prints manifests with counts, IDs, paths and digests, never
  secrets.

## Cutover

1. **Stop the gateway.** Leave the database running. For Compose:
   `docker compose stop server`.
2. **Back up.** Take the usual consistent protected backup of `/data`
   (catalog, `audit.jsonl`) and `config.yaml`, with the keys stored separately.
   Record the SHA-256 of the catalog and history files.
3. **Migrate the schema** to v4:
   `mcpwarden-security-db -runtime-role <runtime role>`.
4. **Import:** `mcpwarden-catalog -config /config/config.yaml import`. Check
   the manifest against what you expect: accounts, keys by kind, connectors,
   tombstones, history lines by schema version and owner. The source hashes
   should match step 2. `normalized.ended_mcp_sessions` counts MCP sessions left
   open in the file; they are ended at import time, exactly as a file restart
   would end them. If the import stops partway, run it again.
5. **Cut over:** `mcpwarden-catalog -config /config/config.yaml cutover`. This
   re-verifies everything against the snapshot, marks PostgreSQL active, then
   writes the `active` marker.
6. **Switch the config** to a [`storage`](storage.md) section with
   `driver: postgres` and the runtime role's URL, remove `managed_upstreams`
   and `audit.path`, and start the gateway. Startup takes the executor lock, makes old requests stale, suspends
   old windows, then loads and checks the catalog.
7. **Check:** sign in, list access keys, open call history, list connectors and
   make one tool call. `mcpwarden-catalog status` should show `active`.

**Failure before cutover.** Before step 5 the file is still authoritative and
unchanged. Run `mcpwarden-catalog abort`, keep the file configuration and start the
gateway. Abort deletes the imported rows and marks the state `aborting` in one
commit, then removes its marker or restores the `rolled_back` marker the import
replaced, and only then deletes the state. If it stops partway, the file
gateway stays blocked; run abort again against the same database to finish.
The snapshot directory is kept. Tested by
`TestAbortBeforeCutoverRestoresFileGateway`.

## Rollback after cutover

Never restore the pre-cutover backup: it would revive keys, sessions and
passwords changed since. Rollback exports the current PostgreSQL state instead.

1. **Stop the gateway.** The rollback refuses to run while it holds the executor
   lock.
2. **Run** `mcpwarden-catalog -config /config/config.yaml rollback`. In order it:
   - marks the database `rolling_back`, so no PostgreSQL gateway can load it,
     and in the same transaction makes pending requests stale and suspends
     active windows, each with a security event under the rollback ID;
   - exports the PostgreSQL catalog to the catalog file with revocations, ended
     sessions and changed passwords intact, and ends any open MCP sessions;
   - rewrites history as the verified pre-cutover bytes followed by every record
     written after cutover, in commit order;
   - reads both files back and compares them with the database (the history
     file is also opened as the gateway would open it);
   - marks the database `rolled_back`, then writes the `rolled_back` marker.

   It overwrites a catalog or history file only if the file is still the
   pre-cutover source or this rollback's own export. Anything else stops the
   rollback with `a catalog or history file changed after cutover`: move that
   file aside and run it again. If the rollback stops partway, run it again; a
   finished one only rewrites the marker.
3. **Switch the config** back to `backend: file` and start the gateway. With
   owner security it starts with a new boot, and suspended windows stay ended.

The manifest's `reauthorize_connectors` list is always empty: connectors hold no
upstream OAuth grants.

Access windows never survive the rollback. An approved call that was running
keeps its admission record. If its completion was never written, history shows
it as unknown, and the call is never replayed. Tested by
`testPostgresCatalogLossAndRollback` (a real approved window, key revocation,
password change and new history, then database loss, rollback
and a file restart) and `TestRollbackResumesAndRefusesReplacedFiles`.

**Forward fixes.** A database snapshot or rollback cannot undo changes made
outside the gateway. If a provider rotated or revoked a credential, save the new
one in the vault. If a key or password leaked, revoke or change it after the rollback
as usual. Credentials copied elsewhere must be rotated at the provider.

## Limits

- One gateway process per catalog. There is no active-active mode.
- A second import after a rollback is not supported yet. It needs a fresh
  database, or the catalog rows removed by hand.
- The PostgreSQL backend requires accounts mode with owner security. It does
  not support external OAuth mode or `--stdio`.
- Migration requires a Unix host for the file lock.
- The snapshot directory holds the encrypted catalog and the history file. Keep
  it with your backups and delete it once you no longer need it.
- File tombstones never recorded an owner, so they are imported without one.
