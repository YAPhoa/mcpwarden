package sqlite

import (
	"errors"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/custody"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/vault"
	driver "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// errPoisoned is returned for a statement on a transaction whose earlier
// statement failed. It is never a constraint error, as PostgreSQL's aborted
// transaction (25P02) is not.
var errPoisoned = errors.New("transaction aborted by an earlier statement")

func code(err error) (int, bool) {
	var e *driver.Error
	if errors.As(err, &e) {
		return e.Code(), true
	}
	return 0, false
}

// constraint matches PostgreSQL's 23505, 23514 and 23503: unique and primary
// key, check, trigger (RAISE(ABORT)) and foreign key. NOT NULL is not one of
// them, as PostgreSQL maps no NOT NULL violation.
func constraint(err error) bool {
	c, ok := code(err)
	if !ok {
		return false
	}
	switch c {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY, sqlite3.SQLITE_CONSTRAINT_CHECK,
		sqlite3.SQLITE_CONSTRAINT_TRIGGER, sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
		return true
	}
	return false
}

// fatal codes mean SQLite may already have ended the transaction, or the
// session is no longer trustworthy. They stop the executor in every family.
func fatal(err error) bool {
	c, ok := code(err)
	if !ok {
		return false
	}
	switch c & 0xff {
	case sqlite3.SQLITE_INTERRUPT, sqlite3.SQLITE_BUSY, sqlite3.SQLITE_NOMEM, sqlite3.SQLITE_FULL, sqlite3.SQLITE_IOERR,
		sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB, sqlite3.SQLITE_READONLY, sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_PROTOCOL:
		return true
	}
	return false
}

// Per-family mapping, identical to the PostgreSQL owner transaction method of
// the same name. Driver text never leaves the store.
func leaseError(err error) error {
	if err == nil {
		return nil
	}
	return lease.ErrStorage
}

func vaultError(err error) error {
	if err == nil {
		return nil
	}
	if constraint(err) {
		return vault.ErrConflict
	}
	return lease.ErrStorage
}

func custodyError(err error) error {
	if err == nil {
		return nil
	}
	if constraint(err) {
		return custody.ErrConflict
	}
	return lease.ErrStorage
}

func catalogError(err error) error {
	if err == nil {
		return nil
	}
	if constraint(err) {
		return catalogdb.ErrConflict
	}
	return catalogdb.ErrStorage
}
