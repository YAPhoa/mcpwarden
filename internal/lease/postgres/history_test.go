package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

func historyEvent(owner, id, kind, invocation, toolID, tool string, ns int64) catalogdb.HistoryRow {
	version, status := 1, "ok"
	if kind != "" {
		version = 2
	}
	if kind == "tool.dispatch.admitted" {
		status = "unknown"
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": version, "event_id": id, "owner": owner})
	return catalogdb.HistoryRow{OwnerID: owner, EventID: id, SchemaVersion: version, EventType: kind, InvocationID: invocation, ToolID: toolID,
		Tool: tool, Upstream: "up", Status: status, TSNano: ns, HistoryNano: ns, Record: string(raw), Source: "live"}
}

// historyEvents mixes renames, out-of-order completions and open calls.
func historyEvents() []catalogdb.HistoryRow {
	var rows []catalogdb.HistoryRow
	for i := range 9 {
		inv := fmt.Sprintf("inv-%d", i)
		tool := fmt.Sprintf("tool-%d", i%3)
		admitted := historyEvent("alice", "a-"+inv, "tool.dispatch.admitted", inv, tool, fmt.Sprintf("name-%d", i), int64(100+i))
		completed := historyEvent("alice", "c-"+inv, "tool.dispatch.completed", inv, tool, fmt.Sprintf("name-%d", i), int64(200-i))
		switch i % 3 {
		case 0:
			rows = append(rows, admitted, completed)
		case 1:
			rows = append(rows, completed, admitted)
		case 2:
			rows = append(rows, admitted)
		}
	}
	return append(rows, historyEvent("bob", "b-1", "", "", "tool-0", "bob tool", 50), historyEvent("alice", "v1", "", "", "", "no id", 10))
}

func derived(t *testing.T, c *pgx.Conn) (tools, open []string) {
	t.Helper()
	for sql, out := range map[string]*[]string{
		"SELECT owner_id||'/'||tool_id||'='||tool||'@'||last_ns||'/'||last_event_id FROM mcpwarden_security.history_tools ORDER BY 1": &tools,
		"SELECT owner_id||'/'||invocation_id||'@'||history_ns||'/'||event_id FROM mcpwarden_security.history_open ORDER BY 1":         &open,
	} {
		rows, err := c.Query(t.Context(), sql)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			*out = append(*out, s)
		}
		rows.Close()
	}
	return tools, open
}

// Migration 005's backfill gives the same tool list and open calls as live
// writes of the same events.
func TestHistoryBackfillMatchesLiveWrites(t *testing.T) {
	events := historyEvents()
	live := testDatabase(t)
	for _, r := range events {
		if err := pgx.BeginFunc(t.Context(), live.admin, func(tx pgx.Tx) error { return catalogdb.InsertHistory(t.Context(), tx, r) }); err != nil {
			t.Fatal(err)
		}
	}
	old := testDatabase(t)
	if _, err := old.admin.Exec(t.Context(), "DROP SCHEMA mcpwarden_security CASCADE"); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		if _, err := old.admin.Exec(t.Context(), migrations[i], pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal(err)
		}
		if _, err := old.admin.Exec(t.Context(), "INSERT INTO mcpwarden_security.schema_migrations(version,sha256) VALUES ($1,$2)", i+1, checksum(migrations[i])); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range events {
		_, err := old.admin.Exec(t.Context(), `INSERT INTO mcpwarden_security.history_events
            (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,
             timed,failed,forwarded,handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record,source)
            VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8,$9,'',$10,$10,false,false,false,0,0,0,0,0,0,$11,'live')`,
			r.OwnerID, r.EventID, r.SchemaVersion, r.EventType, r.InvocationID, r.ToolID, r.Tool, r.Upstream, r.Status, r.HistoryNano, r.Record)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(t.Context(), old.admin, old.role); err != nil {
		t.Fatal(err)
	}
	liveTools, liveOpen := derived(t, live.admin)
	oldTools, oldOpen := derived(t, old.admin)
	if !reflect.DeepEqual(liveTools, oldTools) || !reflect.DeepEqual(liveOpen, oldOpen) {
		t.Fatalf("backfill differs from live writes:\nlive %v %v\nbackfill %v %v", liveTools, liveOpen, oldTools, oldOpen)
	}
	if len(liveOpen) != 3 || len(liveTools) != 4 {
		t.Fatal("unexpected fixture shape:", liveTools, liveOpen)
	}
}

func page(s *Store) error {
	return s.ReadHistory(context.Background(), func(ctx context.Context, db catalogdb.DB) error {
		_, err := catalogdb.QueryHistory(ctx, db, catalogdb.HistoryQuery{Owner: "alice", Limit: 25})
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
	return s.ReadHistory(context.Background(), func(ctx context.Context, db catalogdb.DB) error {
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
	if err := s.ReadHistory(t.Context(), func(ctx context.Context, db catalogdb.DB) error {
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
	if err := s.ReadHistory(expired, func(context.Context, catalogdb.DB) error { ran = true; return nil }); err == nil || ran {
		t.Fatal("expired page ran:", err, ran)
	}
	// A page that fails on a healthy session, here by the statement
	// timeout, also leaves it open.
	if err := s.ReadHistory(t.Context(), func(ctx context.Context, db catalogdb.DB) error {
		_, err := db.Exec(ctx, "SET LOCAL statement_timeout = 50; SELECT pg_sleep(1)")
		return err
	}); err == nil {
		t.Fatal("statement timeout did not fail the page")
	}
	if pids := historyPIDs(t, f); !reflect.DeepEqual(pids, second) {
		t.Fatal("a failed page closed a healthy session:", second, pids)
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
		held <- s.ReadHistory(context.Background(), func(ctx context.Context, db catalogdb.DB) error {
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
		errs <- s.ReadHistory(context.Background(), func(ctx context.Context, db catalogdb.DB) error {
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
