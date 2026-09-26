// Package postgres persists lease metadata, ciphertext and append-only events.
// It is deliberately separate from the legacy catalog and credential custody.
package postgres

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

//go:embed migrations/001_leases.sql
var migration string

//go:embed migrations/002_vault.sql
var vaultMigration string

//go:embed migrations/003_owner_api.sql
var ownerMigration string

//go:embed migrations/004_catalog.sql
var catalogMigration string

//go:embed migrations/005_history_index.sql
var historyMigration string

var migrations = []string{migration, vaultMigration, ownerMigration, catalogMigration, historyMigration}

const SchemaVersion = 5

const executorLock int64 = 0x4d43505753454331 // MCPWSEC1, shared by migration and executor

// ExecutorLock is the session advisory lock the gateway executor holds. Catalog
// import, cutover and rollback hold it too, so they never run beside a gateway.
const ExecutorLock = executorLock

// CheckSchema requires the full current schema.
func CheckSchema(ctx context.Context, db queryer) error {
	n, err := appliedMigrations(ctx, db)
	if err != nil || n != SchemaVersion {
		return ErrMigration
	}
	return nil
}

// Attributes such as CREATEROLE are not inherited automatically, but membership
// may still permit SET ROLE. Check the reachable roles, not just current_user.
const unsafeRole = `(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
    OR rolname IN ('pg_execute_server_program','pg_write_server_files','pg_read_server_files','pg_signal_backend','pg_read_all_data','pg_write_all_data'))`

var ErrMigration = errors.New("security schema migration failed")

func migrationHash() string {
	return checksum(migration)
}

func checksum(sql string) string {
	sum := sha256.Sum256([]byte(sql))
	return hex.EncodeToString(sum[:])
}

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// appliedMigrations requires an exact, nonempty prefix of the pinned ledger.
// A newer binary may extend it; unknown versions, holes and edits fail closed.
func appliedMigrations(ctx context.Context, db queryer) (int, error) {
	rows, err := db.Query(ctx, "SELECT version,sha256 FROM mcpwarden_security.schema_migrations ORDER BY version")
	if err != nil {
		return 0, ErrMigration
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var version int
		var hash string
		if rows.Scan(&version, &hash) != nil || n >= len(migrations) || version != n+1 || hash != checksum(migrations[n]) {
			return 0, ErrMigration
		}
		n++
	}
	if rows.Err() != nil || n == 0 {
		return 0, ErrMigration
	}
	return n, nil
}

// Migrate uses a deployment/migration connection, never the runtime role. The
// runtime role must already exist and must not own this schema or inherit its
// owner. Passwords and DSNs are never returned in errors. Version/checksum drift
// fails closed; this migration does not convert the legacy encrypted catalog.
func Migrate(ctx context.Context, conn *pgx.Conn, runtimeRole string) error {
	if runtimeRole == "" {
		return ErrMigration
	}
	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", executorLock).Scan(&locked); err != nil {
		return ErrMigration
	}
	if !locked {
		return lease.ErrLocked
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = conn.Exec(cleanup, "SELECT pg_advisory_unlock($1)", executorLock)
	}()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return ErrMigration
	}
	defer tx.Rollback(context.Background())
	var safe bool
	err = tx.QueryRow(ctx, `SELECT rolname <> current_user AND NOT EXISTS
        (SELECT 1 FROM pg_roles WHERE `+unsafeRole+` AND pg_has_role($1,oid,'MEMBER'))
        FROM pg_roles WHERE rolname=$1`, runtimeRole).Scan(&safe)
	if err != nil || !safe {
		return ErrMigration
	}
	var present bool
	if err = tx.QueryRow(ctx, "SELECT to_regclass('mcpwarden_security.schema_migrations') IS NOT NULL").Scan(&present); err != nil {
		return ErrMigration
	}
	applied := 0
	if present {
		if applied, err = appliedMigrations(ctx, tx); err != nil {
			return ErrMigration
		}
	}
	for i := applied; i < len(migrations); i++ {
		if _, err = tx.Exec(ctx, migrations[i], pgx.QueryExecModeSimpleProtocol); err != nil {
			return ErrMigration
		}
		if _, err = tx.Exec(ctx, "INSERT INTO mcpwarden_security.schema_migrations(version,sha256) VALUES ($1,$2)", i+1, checksum(migrations[i])); err != nil {
			return ErrMigration
		}
	}
	if err = tx.QueryRow(ctx, `SELECT NOT pg_has_role($1,nspowner,'MEMBER') FROM pg_namespace WHERE nspname='mcpwarden_security'`, runtimeRole).Scan(&safe); err != nil || !safe {
		return ErrMigration
	}
	role := pgx.Identifier{runtimeRole}.Sanitize()
	for _, sql := range []string{
		"REVOKE ALL ON SCHEMA mcpwarden_security FROM " + role,
		"REVOKE ALL ON ALL TABLES IN SCHEMA mcpwarden_security FROM " + role,
		"GRANT USAGE ON SCHEMA mcpwarden_security TO " + role,
		"GRANT SELECT ON ALL TABLES IN SCHEMA mcpwarden_security TO " + role,
		"GRANT INSERT, UPDATE ON mcpwarden_security.owners,mcpwarden_security.requests,mcpwarden_security.leases TO " + role,
		"GRANT INSERT ON mcpwarden_security.security_events,mcpwarden_security.invocation_events TO " + role,
		"GRANT INSERT, UPDATE ON mcpwarden_security.vault_roots,mcpwarden_security.credential_heads,mcpwarden_security.credential_epochs TO " + role,
		"GRANT INSERT ON mcpwarden_security.vault_wrapper_sets,mcpwarden_security.credential_versions TO " + role,
		"GRANT INSERT, UPDATE ON mcpwarden_security.approval_policies TO " + role,
		// Catalog rows are never deleted by the runtime: revocations and
		// connector deletions are updates that leave tombstones. Only the
		// discovery cache and per-provider visibility are removable.
		"GRANT INSERT, UPDATE ON mcpwarden_security.catalog_accounts,mcpwarden_security.catalog_access,mcpwarden_security.catalog_connectors TO " + role,
		"GRANT INSERT, UPDATE, DELETE ON mcpwarden_security.catalog_discovery,mcpwarden_security.catalog_visibility TO " + role,
		"GRANT INSERT ON mcpwarden_security.history_events TO " + role,
		// Each history insert maintains the tool list and the open calls in
		// the same transaction; history_events stays insert-only.
		"GRANT INSERT, UPDATE ON mcpwarden_security.history_tools TO " + role,
		"GRANT INSERT, DELETE ON mcpwarden_security.history_open TO " + role,
	} {
		if _, err = tx.Exec(ctx, sql); err != nil {
			return ErrMigration
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ErrMigration
	}
	return nil
}
