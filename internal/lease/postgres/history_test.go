package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

func historyEvent(owner, id, kind, invocation, toolID, tool string, ns int64) catalogdb.HistoryRow {
	status := "ok"
	if kind == "" {
		kind, invocation = "tool.dispatch.completed", "inv-"+id
	}
	if kind == "tool.dispatch.admitted" {
		status = "unknown"
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": 2, "event_id": id, "owner": owner})
	return catalogdb.HistoryRow{OwnerID: owner, EventID: id, SchemaVersion: 2, EventType: kind, InvocationID: invocation, ToolID: toolID,
		Tool: tool, Upstream: "up", Status: status, TSNano: ns, HistoryNano: ns, Record: string(raw)}
}

// A database from a development build before the schema reset is refused,
// never converted: migration and the runtime both name the reset.
func TestSchemaResetRefused(t *testing.T) {
	db := testDatabase(t)
	if _, err := db.admin.Exec(t.Context(), "UPDATE mcpwarden_security.schema_migrations SET sha256=$1 WHERE version=1", preResetBaseline); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db.admin, db.role); !errors.Is(err, ErrSchemaReset) {
		t.Fatal("migration of a pre-reset ledger:", err)
	}
	if _, err := Open(t.Context(), db.runtimeDSN); !errors.Is(err, ErrSchemaReset) {
		t.Fatal("runtime open of a pre-reset ledger:", err)
	}
	for version := 2; version <= 6; version++ {
		if _, err := db.admin.Exec(t.Context(), "INSERT INTO mcpwarden_security.schema_migrations(version,sha256) VALUES ($1,$2)", version, strings.Repeat("0", 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(t.Context(), db.admin, db.role); !errors.Is(err, ErrSchemaReset) {
		t.Fatal("migration of a six-version ledger:", err)
	}
}

func page(s *Store) error {
	return s.ReadHistory(context.Background(), func(ctx context.Context, db DB) error {
		_, err := QueryHistory(ctx, db, catalogdb.HistoryQuery{Owner: "alice", Limit: 25})
		return err
	})
}

func historyPIDs(t *testing.T, f *databaseFixture) []int32 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var pids []int32
		rows, err := f.admin.Query(t.Context(), "SELECT pid FROM pg_stat_activity WHERE application_name='mcpwarden-history' AND datname=current_database() ORDER BY pid")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var pid int32
			if err := rows.Scan(&pid); err != nil {
				t.Fatal(err)
			}
			pids = append(pids, pid)
		}
		rows.Close()
		// A terminated backend can linger briefly; wait for one session.
		if len(pids) <= 1 || time.Now().After(deadline) {
			return pids
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func sleepPage(s *Store, d time.Duration, ran *bool) error {
	return s.ReadHistory(context.Background(), func(ctx context.Context, db DB) error {
		if ran != nil {
			*ran = true
		}
		_, err := db.Exec(ctx, "SELECT pg_sleep($1)", d.Seconds())
		return err
	})
}

// A history session that died while idle is replaced once within the page.
// A page that never ran leaves a healthy session open. A failed page fails
// only itself, and a failed open is not retried within a second. The clock is
// fixed, so the reopen limit does not depend on test speed.
func TestHistorySessionFailure(t *testing.T) {
	f := testDatabase(t)
	s := f.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.reader.now = func() time.Time { return now }
	if err := page(s); err != nil {
		t.Fatal(err)
	}
	var readOnly string
	if err := s.ReadHistory(t.Context(), func(ctx context.Context, db DB) error {
		return db.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly)
	}); err != nil || readOnly != "on" {
		t.Fatal("history session is not read-only:", readOnly, err)
	}
	first := historyPIDs(t, f)
	if len(first) != 1 {
		t.Fatal("history sessions:", first)
	}
	terminate := func() {
		t.Helper()
		if _, err := f.admin.Exec(t.Context(), "SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity WHERE application_name='mcpwarden-history' AND datname=current_database()"); err != nil {
			t.Fatal(err)
		}
		if pids := historyPIDs(t, f); len(pids) != 0 {
			t.Fatal("history session survived termination:", pids)
		}
	}

	// Died while idle: the page reopens the session once and succeeds, even
	// within a second of the last open.
	terminate()
	if err := page(s); err != nil {
		t.Fatal("page on a session that died while idle:", err)
	}
	second := historyPIDs(t, f)
	if len(second) != 1 || second[0] == first[0] {
		t.Fatal("history session not replaced:", first, second)
	}

	// An expired page never runs and leaves the session open.
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Millisecond))
	defer cancel()
	ran := false
	if err := s.ReadHistory(expired, func(context.Context, DB) error { ran = true; return nil }); err == nil || ran {
		t.Fatal("expired page ran:", err, ran)
	}
	// A page that fails on a healthy session, here by the statement
	// timeout, also leaves it open.
	if err := s.ReadHistory(t.Context(), func(ctx context.Context, db DB) error {
		_, err := db.Exec(ctx, "SET LOCAL statement_timeout = 50; SELECT pg_sleep(1)")
		return err
	}); err == nil {
		t.Fatal("statement timeout did not fail the page")
	}
	if pids := historyPIDs(t, f); !reflect.DeepEqual(pids, second) {
		t.Fatal("a failed page closed a healthy session:", second, pids)
	}
	// pg_stat_activity can still list a session the client just closed, so
	// check the backend a page actually runs on.
	var pid int32
	if err := s.ReadHistory(t.Context(), func(ctx context.Context, db DB) error {
		return db.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid)
	}); err != nil || pid != second[0] {
		t.Fatal("a failed page replaced a healthy session:", second, pid, err)
	}

	// The replacement open fails: the page fails, and the next page does not
	// connect again until a second has passed.
	good := s.reader.config
	bad := good.Copy()
	bad.Database = "mcpwarden_no_such_database"
	s.reader.config = bad
	terminate()
	if err := page(s); err == nil {
		t.Fatal("a page succeeded without a session")
	}
	s.reader.config = good
	if err := page(s); err == nil {
		t.Fatal("the session reopened within a second of a failed open")
	}
	if pids := historyPIDs(t, f); len(pids) != 0 {
		t.Fatal("history session opened within the reopen limit:", pids)
	}
	stillOpen(t, s)
	if err := s.WithOwner(t.Context(), "alice", func(lease.Tx) error { return nil }); err != nil {
		t.Fatal("executor affected by a history failure:", err)
	}
	now = now.Add(time.Second)
	if err := page(s); err != nil {
		t.Fatal("the history session did not reopen:", err)
	}
}

// Each page's deadline starts when it gets the session, so queued pages that
// each use most of it all succeed. A page that gives up waiting never runs and
// leaves the session open.
func TestHistoryPagesQueue(t *testing.T) {
	f := testDatabase(t)
	s := f.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	s.reader.limit = time.Second
	if err := page(s); err != nil {
		t.Fatal(err)
	}
	session := historyPIDs(t, f)

	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 3 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- sleepPage(s, 800*time.Millisecond, nil) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("queued page:", err)
		}
	}

	s.reader.wait = 200 * time.Millisecond
	held := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		held <- s.ReadHistory(context.Background(), func(ctx context.Context, db DB) error {
			close(started)
			_, err := db.Exec(ctx, "SELECT pg_sleep(0.6)")
			return err
		})
	}()
	<-started
	ran := false
	if err := sleepPage(s, 0, &ran); err == nil || ran {
		t.Fatal("a page that gave up waiting ran:", err, ran)
	}
	if err := <-held; err != nil {
		t.Fatal("the page holding the session failed:", err)
	}
	if pids := historyPIDs(t, f); !reflect.DeepEqual(pids, session) {
		t.Fatal("history session changed:", session, pids)
	}

	s.reader.wait = historyWait
	errs = make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- page(s) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent page:", err)
		}
	}
	stillOpen(t, s)
}

// Close does not queue behind pages: it ends the running page, turns waiting
// pages away and closes the executor session within its context.
func TestHistoryCloseEndsPages(t *testing.T) {
	f := testDatabase(t)
	s, err := Open(t.Context(), f.runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	if err := page(s); err != nil {
		t.Fatal(err)
	}
	running := make(chan struct{})
	errs := make(chan error, 4)
	go func() {
		errs <- s.ReadHistory(context.Background(), func(ctx context.Context, db DB) error {
			close(running)
			_, err := db.Exec(ctx, "SELECT pg_sleep(3)")
			return err
		})
	}()
	<-running
	for range 3 {
		go func() { errs <- sleepPage(s, 3*time.Second, nil) }()
	}
	time.Sleep(100 * time.Millisecond) // let the pages queue
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	began := time.Now()
	if err := s.Close(ctx); err != nil {
		t.Fatal("close:", err)
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Fatal("close waited behind pages:", took)
	}
	for range 4 {
		if err := <-errs; err == nil {
			t.Fatal("a page succeeded across close")
		}
	}
	if err := page(s); !errors.Is(err, lease.ErrLocked) {
		t.Fatal("page after close:", err)
	}
	// The executor session is gone, so a new store can take ownership.
	next := f.store(t)
	if err := next.Start(t.Context(), identity.New()); err != nil {
		t.Fatal("start after close:", err)
	}
}
