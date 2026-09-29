package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

//go:embed migrations/001_baseline.sql
var baseline string

var migrations = []string{baseline}

// SchemaVersion is the migration count this binary applies and requires.
const SchemaVersion = 1

// applicationID marks a SQLite file as an mcpwarden database ("MCPW").
const applicationID = 0x4d435057

var (
	// ErrMigration is a ledger this binary cannot use: an unknown or edited
	// migration, or a hole.
	ErrMigration = errors.New("storage database schema is not one this build knows; create a new database")
	// ErrNewer is a database created by a newer mcpwarden.
	ErrNewer = errors.New("storage database was created by a newer mcpwarden")
	// ErrForeign is a SQLite file that is not an mcpwarden database.
	ErrForeign = errors.New("storage.path holds a SQLite database that is not an mcpwarden database")
)

func checksum(sql string) string {
	sum := sha256.Sum256([]byte(sql))
	return hex.EncodeToString(sum[:])
}

// migrate creates or upgrades the schema in one IMMEDIATE transaction. The
// caller holds the lock file exclusively, so no other mcpwarden process is
// attached.
func migrate(ctx context.Context, conn *sql.Conn) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	applied, err := ledger(ctx, tx)
	if err != nil {
		return err
	}
	if applied == 0 {
		if _, err := tx.ExecContext(ctx, "PRAGMA application_id = 1296257111"); err != nil {
			return err
		}
	}
	now := time.Now().UTC().UnixMicro()
	for i := applied; i < len(migrations); i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, sha256, applied_at) VALUES ($1, $2, $3)", i+1, checksum(migrations[i]), now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(len(migrations))); err != nil {
		return err
	}
	return tx.Commit()
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// ledger returns how many migrations are applied: zero for a new, empty
// file. It refuses a foreign file, an unknown or edited migration, a hole,
// and a newer schema.
func ledger(ctx context.Context, db queryer) (int, error) {
	var app, version, tables int
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return 0, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, err
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&tables); err != nil {
		return 0, err
	}
	if app == 0 && version == 0 && tables == 0 {
		return 0, nil
	}
	if app != applicationID {
		return 0, ErrForeign
	}
	rows, err := db.QueryContext(ctx, "SELECT version, sha256 FROM schema_migrations ORDER BY version")
	if err != nil {
		return 0, ErrMigration
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil || v != n+1 {
			return 0, ErrMigration
		}
		if n >= len(migrations) {
			return 0, ErrNewer
		}
		if sum != checksum(migrations[n]) {
			return 0, ErrMigration
		}
		n++
	}
	if rows.Err() != nil || n == 0 {
		return 0, ErrMigration
	}
	if version != n {
		if version > len(migrations) {
			return 0, ErrNewer
		}
		return 0, ErrMigration
	}
	return n, nil
}
