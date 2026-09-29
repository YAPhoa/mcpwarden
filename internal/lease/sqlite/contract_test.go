package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/lease/sqlite"
	"github.com/yaphoa/mcpwarden/internal/lease/storetest"
	driver "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// contractDB runs the shared contract on a database file in a temporary
// directory. Its helpers use a second connection to the same file, which the
// store's lock file does not exclude.
type contractDB struct {
	path string
	raw  *sql.DB
}

func TestContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Database {
		path := filepath.Join(t.TempDir(), "mcpwarden.db")
		// Create and migrate the file before the helpers connect to it.
		s, err := sqlite.Open(t.Context(), path, sqlite.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		raw, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { raw.Close() })
		return &contractDB{path: path, raw: raw}
	})
}

func (d *contractDB) Driver() string { return "sqlite" }

func (d *contractDB) Open(t *testing.T) storetest.Store {
	t.Helper()
	s, err := sqlite.Open(t.Context(), d.path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

func (d *contractDB) Exec(t *testing.T, sql string, args ...any) error {
	t.Helper()
	_, err := d.raw.ExecContext(t.Context(), sql, args...)
	return err
}

// Refused: SQLite has no privileges, so only constraints and guards refuse.
func (d *contractDB) Refused(err error) bool { return d.Constraint(err) }

func (d *contractDB) Constraint(err error) bool {
	var e *driver.Error
	return errors.As(err, &e) && e.Code()&0xff == sqlite3.SQLITE_CONSTRAINT
}

func (d *contractDB) Rule(err error) string {
	var e *driver.Error
	if !errors.As(err, &e) {
		return fmt.Sprint(err)
	}
	return fmt.Sprintf("%d %s", e.Code(), e.Error())
}

// SlowWrites adds a trigger that counts a three-way cross join of 3,000 rows
// before each insert. SQLite refuses a WITH clause inside a trigger, so the
// rows live in their own table.
func (d *contractDB) SlowWrites(t *testing.T, table string) {
	t.Helper()
	for _, statement := range []string{
		"CREATE TABLE IF NOT EXISTS slow_rows (x INTEGER)",
		"INSERT INTO slow_rows WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 3000) SELECT x FROM c",
		"CREATE TRIGGER slow_" + table + " BEFORE INSERT ON " + table + " BEGIN SELECT count(*) FROM slow_rows a, slow_rows b, slow_rows c; END",
	} {
		if err := d.Exec(t, statement); err != nil {
			t.Fatal(err)
		}
	}
}

func (d *contractDB) Int(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := d.raw.QueryRowContext(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatal(sql, err)
	}
	return n
}

func (d *contractDB) Text(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := d.raw.QueryRowContext(t.Context(), sql, args...).Scan(&s); err != nil {
		t.Fatal(sql, err)
	}
	return s
}

// Seed drops table's triggers, runs sql and recreates them, in one
// transaction.
func (d *contractDB) Seed(t *testing.T, table, statement string) {
	t.Helper()
	tx, err := d.raw.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(t.Context(), "SELECT name, sql FROM sqlite_schema WHERE type='trigger' AND tbl_name=$1", table)
	if err != nil {
		t.Fatal(err)
	}
	var names, create []string
	for rows.Next() {
		var name, sql string
		if err := rows.Scan(&name, &sql); err != nil {
			t.Fatal(err)
		}
		names, create = append(names, name), append(create, sql)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, err := tx.ExecContext(t.Context(), "DROP TRIGGER "+name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(t.Context(), statement); err != nil {
		t.Fatal(err)
	}
	for _, sql := range create {
		if _, err := tx.ExecContext(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// FailCommit adds a row with a dangling deferred foreign key to every
// transaction that inserts into table; SQLite refuses it at COMMIT.
func (d *contractDB) FailCommit(t *testing.T, table string) {
	t.Helper()
	name := "fail_commit_" + table
	for _, sql := range []string{
		"CREATE TABLE " + name + " (owner_id TEXT REFERENCES owners(owner_id) DEFERRABLE INITIALLY DEFERRED)",
		"CREATE TRIGGER " + name + " AFTER INSERT ON " + table + " BEGIN INSERT INTO " + name + " VALUES ('no such owner'); END",
	} {
		if _, err := d.raw.ExecContext(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
}

// HoldOwner holds the database write lock, which every owner transaction
// takes first.
func (d *contractDB) HoldOwner(t *testing.T, _ string) func() {
	t.Helper()
	c, err := d.raw.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	return func() {
		if _, err := c.ExecContext(context.Background(), "COMMIT"); err != nil {
			t.Error(err)
		}
		c.Close()
	}
}

func (d *contractDB) BulkHistory(t *testing.T, owner string, n int) {
	t.Helper()
	_, err := d.raw.ExecContext(t.Context(), `WITH RECURSIVE g(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM g WHERE i < $2)
        INSERT INTO history_events
        (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,timed,failed,forwarded,
         handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record)
        SELECT $1, 'e'||printf('%06d',i), 2, 'tool.dispatch.completed', 'inv-'||'e'||printf('%06d',i), 'tool-'||(i%4), 'tool '||(i%4), 'up-'||(i%3), CASE WHEN i%5=0 THEN 'timeout' ELSE 'ok' END,
         'actor-'||(i%7), i, i, 1, i%5=0, 1, 100, 10, 90, 6, 3, 6,
         json_object('schema_version',2,'event_id','e'||printf('%06d',i),'owner',$1)
        FROM g`, owner, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.raw.ExecContext(t.Context(), "ANALYZE"); err != nil {
		t.Fatal(err)
	}
}

// Lose moves the database file away; the store's heartbeat sees that its
// path no longer names the file it opened.
func (d *contractDB) Lose(t *testing.T) {
	t.Helper()
	if err := os.Rename(d.path, d.path+".moved"); err != nil {
		t.Fatal(err)
	}
}
