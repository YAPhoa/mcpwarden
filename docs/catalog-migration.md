# Moving the catalog to PostgreSQL

Status: implemented and tested against scratch databases. It has not been run
against live data, and the live gateway still uses the encrypted file catalog.
This procedure is for review before any live migration.

The PostgreSQL backend stores the same catalog the file holds: accounts and
password verifiers, access keys and sessions, connectors with headers and OAuth
grants, tombstones, discovery caches and visibility. It also stores tool-call
history. Secret-bearing values stay encrypted with the existing catalog key
(legacy server-managed custody), so the database never holds them in plain
text. Browser-controlled credential access is a later step. See
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
  visibility, headers, OAuth settings and grants, and grant revisions. Every
  history line is compared byte for byte with its line number, so event IDs
  (including derived v0 IDs), argument hashes and order are preserved. Plain
  database columns must agree with the encrypted payload, and each payload is
  bound to its row, so a swapped or edited row fails. Counts and IDs are
  reported but are not the check.
- **Resumable and repeatable.** The catalog imports in one transaction. History
  imports in batches, and each batch commits with its checkpoint (line count,
  byte offset and hash state). A rerun after an interruption continues from the
  last checkpoint. A rerun after success only re-verifies and never adds rows.
  Event and invocation IDs are unique per owner, so a duplicate fails the batch.
- **No fallback.** With `backend: postgres` the gateway never reads the catalog
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

## Coordination while running on PostgreSQL

Every catalog change is one owner transaction under the lease service's owner
gate. That covers accounts, passwords, keys and sessions, connectors, OAuth
grants, visibility, availability and discovery. The same transaction writes the
change, its security event (`access.revoked`, `account.password_changed`,
`connector.oauth_saved` and so on), and any lease revocation. Revoking an API
key or deleting a connector ends the owner's access windows in that commit;
the file mode's guard does this for key revocation only. Password changes and session revocation end no windows. The
in-memory view changes only after the commit succeeds. Hard limits on active
keys and sessions are checked in memory and again by a count inside the
transaction. OAuth grant updates use compare-and-swap on the stored grant ID.
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
6. **Switch the config** to `managed_upstreams.backend: postgres` and start the
   gateway. Startup takes the executor lock, makes old requests stale, suspends
   old windows, then loads and checks the catalog.
7. **Check:** sign in, list access keys, open call history, list connectors and
   make one tool call. `mcpwarden-catalog status` should show `active`.

**Failure before cutover.** Before step 5 the file is still authoritative and
unchanged. Run `mcpwarden-catalog abort` (it deletes the imported rows and
state, then removes the marker; the snapshot directory is kept), keep
`backend: file` and start the gateway. Tested by
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
   - drops every OAuth grant that changed after cutover and lists those
     connectors under `reauthorize_connectors`;
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
4. **Reauthorize** each connector in `reauthorize_connectors` from the panel.

Access windows never survive the rollback. An approved call that was running
keeps its admission record. If its completion was never written, history shows
it as unknown, and the call is never replayed. Tested by
`testPostgresCatalogLossAndRollback` (a real approved window, key revocation,
password change, OAuth rotation and new history, then database loss, rollback
and a file restart) and `TestRollbackResumesAndRefusesReplacedFiles`.

**Forward fixes.** A database snapshot or rollback cannot undo changes made
outside the gateway. If a provider rotated or revoked a token, reauthorize that
connector. If a key or password leaked, revoke or change it after the rollback
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
