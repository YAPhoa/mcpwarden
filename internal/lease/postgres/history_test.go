package postgres

import (
	"context"
	"encoding/json"
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

// A failed history session fails only that page. The executor stays up and
// the next page, a second later, reopens the session; pages may overlap.
func TestHistorySessionFailureAndConcurrency(t *testing.T) {
	f := testDatabase(t)
	s := f.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	if err := page(s); err != nil {
		t.Fatal(err)
	}
	var readOnly string
	if err := s.ReadHistory(t.Context(), func(ctx context.Context, db catalogdb.DB) error {
		return db.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly)
	}); err != nil || readOnly != "on" {
		t.Fatal("history session is not read-only:", readOnly, err)
	}
	if _, err := f.admin.Exec(t.Context(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mcpwarden-history' AND datname=current_database()"); err != nil {
		t.Fatal(err)
	}
	if err := page(s); err == nil {
		t.Fatal("a page on a terminated session succeeded")
	}
	if err := page(s); err == nil {
		t.Fatal("the session reopened within a second")
	}
	stillOpen(t, s)
	if err := s.WithOwner(t.Context(), "alice", func(lease.Tx) error { return nil }); err != nil {
		t.Fatal("executor affected by a history failure:", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := page(s); err != nil {
		t.Fatal("the history session did not reopen:", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
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
}
