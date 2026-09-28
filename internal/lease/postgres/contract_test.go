package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres/pgtest"
	"github.com/yaphoa/mcpwarden/internal/lease/storetest"
)

// contractDB runs the shared contract on a scratch database. Exec logs in as
// the restricted runtime role; the other helpers use the schema owner.
type contractDB struct {
	admin   *pgx.Conn
	runtime string
}

func TestContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Database {
		d := pgtest.New(t)
		if _, err := d.Admin.Exec(t.Context(), "SET search_path=mcpwarden_security"); err != nil {
			t.Fatal(err)
		}
		return &contractDB{admin: d.Admin, runtime: d.RuntimeDSN}
	})
}

func (d *contractDB) Driver() string { return "postgres" }

func (d *contractDB) Open(t *testing.T) storetest.Store {
	t.Helper()
	s, err := postgres.Open(t.Context(), d.runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

func (d *contractDB) Exec(t *testing.T, sql string, args ...any) error {
	t.Helper()
	config, err := pgx.ParseConfig(d.runtime)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = "mcpwarden_security"
	c, err := pgx.ConnectConfig(t.Context(), config)
	if err != nil {
		t.Fatal("runtime test connection failed")
	}
	defer c.Close(context.Background())
	_, err = c.Exec(t.Context(), sql, args...)
	return err
}

func code(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

// Refused: an integrity constraint (class 23) or missing privilege.
func (d *contractDB) Refused(err error) bool {
	return d.Constraint(err) || code(err) == "42501"
}

func (d *contractDB) Constraint(err error) bool { return strings.HasPrefix(code(err), "23") }

func (d *contractDB) Rule(err error) string {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return fmt.Sprint(err)
	}
	return pg.Code + " " + pg.ConstraintName + " " + pg.Message
}

// SlowWrites makes each insert sleep 2.5 s, under the executor's 3 s
// statement timeout.
func (d *contractDB) SlowWrites(t *testing.T, table string) {
	t.Helper()
	name := "slow_" + table
	_, err := d.admin.Exec(t.Context(), `CREATE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2.5); RETURN NEW; END $$;
        CREATE TRIGGER `+name+` BEFORE INSERT ON `+pgx.Identifier{table}.Sanitize()+` FOR EACH ROW EXECUTE FUNCTION `+name+`();`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal(err)
	}
}

func (d *contractDB) Int(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := d.admin.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatal(sql, err)
	}
	return n
}

func (d *contractDB) Text(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := d.admin.QueryRow(t.Context(), sql, args...).Scan(&s); err != nil {
		t.Fatal(sql, err)
	}
	return s
}

func (d *contractDB) Seed(t *testing.T, table, sql string) {
	t.Helper()
	name := pgx.Identifier{table}.Sanitize()
	_, err := d.admin.Exec(t.Context(), "ALTER TABLE "+name+" DISABLE TRIGGER USER;"+sql+";ALTER TABLE "+name+" ENABLE TRIGGER USER", pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal(err)
	}
}

func (d *contractDB) FailCommit(t *testing.T, table string) {
	t.Helper()
	name := "fail_commit_" + table
	_, err := d.admin.Exec(t.Context(), `CREATE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure'; END $$;
        CREATE CONSTRAINT TRIGGER `+name+` AFTER INSERT ON `+pgx.Identifier{table}.Sanitize()+` DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION `+name+`();`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal(err)
	}
}

func (d *contractDB) HoldOwner(t *testing.T, owner string) func() {
	t.Helper()
	tx, err := d.admin.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), "SELECT owner_id FROM owners WHERE owner_id=$1 FOR UPDATE", owner); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := tx.Commit(t.Context()); err != nil {
			t.Error(err)
		}
	}
}

func (d *contractDB) BulkHistory(t *testing.T, owner string, n int) {
	t.Helper()
	bulk(t, d.admin, owner, n)
}

func (d *contractDB) Lose(t *testing.T) {
	t.Helper()
	if _, err := d.admin.Exec(t.Context(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mcpwarden-security' AND datname=current_database()"); err != nil {
		t.Fatal(err)
	}
}
