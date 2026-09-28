// Package storetest is the behavior contract every lease store (PostgreSQL,
// SQLite) must meet: leases, vault ciphertext, cancellation, catalog rows,
// history, error mapping, and the catalog repository running on the store. Each store's tests call Run with a Database that
// knows how to reach its own scratch database; backend-only behavior
// (privileges, locks, files) stays in that store's own tests.
package storetest

import (
	"context"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/custody"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// Store is what the gateway needs from a lease store.
type Store interface {
	lease.Store
	catalogdb.Store
	Complete(context.Context, audit.Record) error
	LoadCustody(context.Context) (custody.Snapshot, error)
	Close(context.Context) error
}

// Database is one scratch database, fresh for each test. SQL passed to it
// uses bare table names and $N parameters.
type Database interface {
	// Driver is "postgres" or "sqlite".
	Driver() string
	// Open opens a store on the database and closes it at cleanup.
	Open(t *testing.T) Store
	// Exec runs a statement outside the store with the runtime's rights.
	Exec(t *testing.T, sql string, args ...any) error
	// Refused reports whether err from Exec is the database refusing the
	// statement: a constraint, guard or privilege, never a syntax error.
	Refused(err error) bool
	// Constraint reports whether err from Exec is a constraint or guard.
	Constraint(err error) bool
	// Int and Text read one value as the database owner.
	Int(t *testing.T, sql string, args ...any) int64
	Text(t *testing.T, sql string, args ...any) string
	// Seed runs sql as the database owner with table's guards disabled, to
	// set up states that would take a million writes to reach.
	Seed(t *testing.T, table, sql string)
	// FailCommit makes every later transaction that inserts into table fail
	// at COMMIT, after all its statements succeeded.
	FailCommit(t *testing.T, table string)
	// HoldOwner holds the lock an owner transaction for owner waits on,
	// until release is called.
	HoldOwner(t *testing.T, owner string) (release func())
	// Lose ends the open store's database session, as a server restart or
	// a replaced file would; the store must notice on its own.
	Lose(t *testing.T)
	// Rule names what refused a statement from Exec, for asserting which
	// rule fired: SQLite's extended result code and message, or
	// PostgreSQL's SQLSTATE, constraint name and message.
	Rule(err error) string
	// SlowWrites slows every later insert into table so that three of them
	// run past the store's transaction deadline. On PostgreSQL each stays
	// under the session's statement timeout, so the deadline, not the
	// server, ends the transaction.
	SlowWrites(t *testing.T, table string)
	// BulkHistory inserts n settled events for owner directly: event i
	// ("e" and six digits) at history time i, over four tools, three
	// upstreams, two statuses and seven actors.
	BulkHistory(t *testing.T, owner string, n int)
}

// Run runs the contract against fresh databases from open.
func Run(t *testing.T, open func(t *testing.T) Database) {
	for _, c := range []struct {
		name string
		fn   func(*testing.T, Database)
	}{
		{"DurabilityAndIsolation", testDurabilityAndIsolation},
		{"AtomicBudget", testAtomicBudget},
		{"AdmissionCommitFailure", testAdmissionCommitFailure},
		{"ClockAfterOwnerLock", testClockAfterOwnerLock},
		{"RestartQuiescesLeases", testRestartQuiescesLeases},
		{"CompletionBinding", testCompletionBinding},
		{"DenyApproved", testDenyApproved},
		{"TerminalLeaseStaysTerminal", testTerminalLeaseStaysTerminal},
		{"CanonicalIDs", testCanonicalIDs},
		{"VaultCASIsolationAndRetention", testVaultCASIsolationAndRetention},
		{"VaultWriteCap", testVaultWriteCap},
		{"VaultNonceBindingsAndWrappingKeyCap", testVaultNonceBindingsAndWrappingKeyCap},
		{"VaultCommitFailureDoesNotPublish", testVaultCommitFailureDoesNotPublish},
		{"EnvelopeEpochTyping", testEnvelopeEpochTyping},
		{"VaultMutationCommit", testVaultMutationCommit},
		{"VaultMutationRollback", testVaultMutationRollback},
		{"VaultMutationPublishFailure", testVaultMutationPublishFailure},
		{"CancelledCallerCommitsNothing", testCancelledCallerCommitsNothing},
		{"CancelledViewAndRevoke", testCancelledViewAndRevoke},
		{"LongHolderIsNotSessionLoss", testLongHolderIsNotSessionLoss},
		{"CatalogRows", testCatalogRows},
		{"ErrorMapping", testErrorMapping},
		{"PoisonedTransaction", testPoisonedTransaction},
		{"SchemaRules", testSchemaRules},
		{"CatalogStatementPastDeadline", testCatalogStatementPastDeadline},
		{"HistoryWindow", testHistoryWindow},
		{"HistoryRangesUseHistoryTime", testHistoryRangesUseHistoryTime},
		{"HistoryToolListForwardOnly", testHistoryToolListForwardOnly},
		{"HistoryOpenCalls", testHistoryOpenCalls},
		{"HistoryFiltersOpenCalls", testHistoryFiltersOpenCalls},
		{"RepositoryCommitsAtomically", testRepositoryCommitsAtomically},
		{"RepositoryFailsClosed", testRepositoryFailsClosed},
		{"RolledBackCancelled", testRolledBackCancelled},
		{"RolledBackDeadline", testRolledBackDeadline},
		{"RolledBackQueued", testRolledBackQueued},
		{"UncertainCommitStopsCatalog", testUncertainCommitStopsCatalog},
		{"ProviderChangesMoveRevision", testProviderChangesMoveRevision},
		{"StaleSessionsEndAtStartup", testStaleSessionsEndAtStartup},
	} {
		t.Run(c.name, func(t *testing.T) { c.fn(t, open(t)) })
	}
}

// pick returns the statement for db's driver.
func pick(db Database, postgres, sqlite string) string {
	if db.Driver() == "postgres" {
		return postgres
	}
	return sqlite
}

func stillOpen(t *testing.T, s Store) {
	t.Helper()
	select {
	case <-s.Lost():
		t.Fatal("the store stopped")
	default:
	}
}

func stopped(t *testing.T, s Store) {
	t.Helper()
	select {
	case <-s.Lost():
	default:
		t.Fatal("the store kept running")
	}
}

// refused fails unless sql is refused by the database.
func refused(t *testing.T, db Database, sql string, args ...any) {
	t.Helper()
	if err := db.Exec(t, sql, args...); !db.Refused(err) {
		t.Fatalf("not refused: %s: %v", sql, err)
	}
}

// guarded fails unless sql is refused by a constraint or guard.
func guarded(t *testing.T, db Database, sql string, args ...any) {
	t.Helper()
	if err := db.Exec(t, sql, args...); !db.Constraint(err) {
		t.Fatalf("not guarded: %s: %v", sql, err)
	}
}
