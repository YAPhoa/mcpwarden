package catalogdb_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres/pgtest"
)

func event(owner, id, kind, invocation, toolID, tool, upstream, status string, ns int64) catalogdb.HistoryRow {
	version := 1
	if kind != "" {
		version = 2
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": version, "event_id": id, "owner": owner})
	return catalogdb.HistoryRow{OwnerID: owner, EventID: id, SchemaVersion: version, EventType: kind, InvocationID: invocation, ToolID: toolID, Tool: tool,
		Upstream: upstream, Status: status, TSNano: ns, HistoryNano: ns, Record: string(raw), Source: "live"}
}

func insert(t *testing.T, db *pgx.Conn, rows ...catalogdb.HistoryRow) {
	t.Helper()
	for _, r := range rows {
		err := pgx.BeginFunc(t.Context(), db, func(tx pgx.Tx) error { return catalogdb.InsertHistory(t.Context(), tx, r) })
		if err != nil {
			t.Fatal(r.EventID, err)
		}
	}
}

func query(t *testing.T, db *pgx.Conn, q catalogdb.HistoryQuery) catalogdb.HistoryResult {
	t.Helper()
	if q.Limit == 0 {
		q.Limit = 25
	}
	var out catalogdb.HistoryResult
	err := pgx.BeginFunc(t.Context(), db, func(tx pgx.Tx) error {
		var err error
		out, err = catalogdb.QueryHistory(t.Context(), tx, q)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func ids(rows []catalogdb.HistoryRow) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.EventID)
	}
	return strings.Join(out, ",")
}

// bulk inserts n timed events for owner, event i at history time i, spread
// over two tools, two upstreams, two statuses and two actors.
func bulk(t *testing.T, db *pgx.Conn, owner string, n int) {
	t.Helper()
	_, err := db.Exec(t.Context(), `INSERT INTO mcpwarden_security.history_events
        (owner_id,event_id,schema_version,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,timed,failed,forwarded,
         handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record,source)
        SELECT $1, 'e'||lpad(g::text,6,'0'), 1, 'tool-'||(g%4), 'tool '||(g%4), 'up-'||(g%3), CASE WHEN g%5=0 THEN 'timeout' ELSE 'ok' END,
         'actor-'||(g%7), g, g, true, g%5=0, true, 100, 10, 90, 6, 3, 6,
         json_build_object('schema_version',1,'event_id','e'||lpad(g::text,6,'0'),'owner',$1::text)::text, 'live'
        FROM generate_series(1,$2::int) g`, owner, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), "ANALYZE mcpwarden_security.history_events"); err != nil {
		t.Fatal(err)
	}
}

// Every page reads at most the newest 25,000 matching events; a page that
// ends beyond them is refused, and more matches are reported as capped.
func TestHistoryWindow(t *testing.T) {
	db := pgtest.New(t).Admin
	bulk(t, db, "alice", catalogdb.HistoryWindow+10)
	first := query(t, db, catalogdb.HistoryQuery{Owner: "alice"})
	if first.Total != catalogdb.HistoryWindow || !first.Capped || first.TimedCalls != catalogdb.HistoryWindow || first.Records[0].EventID != "e025010" {
		t.Fatal("first page:", first.Total, first.Capped, first.TimedCalls, first.Records[0].EventID)
	}
	if first.Handler.Count != catalogdb.HistoryWindow || first.FailedCalls != int64(catalogdb.HistoryWindow/5) {
		t.Fatal("timings do not cover the window:", first.Handler.Count, first.FailedCalls)
	}
	last := query(t, db, catalogdb.HistoryQuery{Owner: "alice", Offset: catalogdb.HistoryWindow - 25})
	if len(last.Records) != 25 || last.Records[24].EventID != "e000011" {
		t.Fatal("last page:", ids(last.Records))
	}
	err := pgx.BeginFunc(t.Context(), db, func(tx pgx.Tx) error {
		_, err := catalogdb.QueryHistory(t.Context(), tx, catalogdb.HistoryQuery{Owner: "alice", Offset: catalogdb.HistoryWindow - 24, Limit: 25})
		return err
	})
	if !errors.Is(err, catalogdb.ErrHistoryWindow) {
		t.Fatal("a page beyond the window was served:", err)
	}
	older := query(t, db, catalogdb.HistoryQuery{Owner: "alice", HasTo: true, ToNano: 11})
	if older.Total != 10 || older.Capped || older.Records[0].EventID != "e000010" {
		t.Fatal("older calls are not reachable with a time range:", older.Total, older.Capped)
	}
	exact := query(t, db, catalogdb.HistoryQuery{Owner: "alice", HasFrom: true, FromNano: 11})
	if exact.Total != catalogdb.HistoryWindow || exact.Capped {
		t.Fatal("exactly 25,000 matches are not capped:", exact.Total, exact.Capped)
	}
}

// Each single filter and a time range read their own index, so a return to
// catch-all predicates fails here. Plans are generic, as for a prepared
// statement, so bound values cannot fold a catch-all away; sorts and bitmap
// scans are off so the small test table cannot hide a missing ordered index.
func TestHistoryPlansUseFilterIndexes(t *testing.T) {
	db := pgtest.New(t).Admin
	bulk(t, db, "alice", 5000)
	insert(t, db, event("alice", "open-1", "tool.dispatch.admitted", "inv-1", "tool-1", "tool 1", "up-1", "unknown", 6000))
	if _, err := db.Exec(t.Context(), "ANALYZE mcpwarden_security.history_open"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		q     catalogdb.HistoryQuery
		index string
	}{
		"none":     {catalogdb.HistoryQuery{}, "history_owner_recent"},
		"range":    {catalogdb.HistoryQuery{HasFrom: true, FromNano: 100, HasTo: true, ToNano: 200}, "history_owner_recent"},
		"tool":     {catalogdb.HistoryQuery{ToolID: "tool-1"}, "history_owner_tool"},
		"upstream": {catalogdb.HistoryQuery{Upstream: "up-1"}, "history_owner_upstream"},
		"gateway":  {catalogdb.HistoryQuery{Upstream: "__gateway__"}, "history_owner_upstream"},
		"status":   {catalogdb.HistoryQuery{Status: "timeout"}, "history_owner_status"},
		"actor":    {catalogdb.HistoryQuery{ActorAccessID: "actor-1"}, "history_owner_actor"},
		"unknown":  {catalogdb.HistoryQuery{Status: "unknown"}, "history_open_recent"},
	} {
		c.q.Owner = "alice"
		sql, args := catalogdb.Window(c.q)
		var plan []string
		err := pgx.BeginFunc(t.Context(), db, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), "SET LOCAL enable_seqscan=off; SET LOCAL enable_bitmapscan=off; SET LOCAL enable_sort=off; SET LOCAL plan_cache_mode=force_generic_plan; DEALLOCATE ALL", pgx.QueryExecModeSimpleProtocol); err != nil {
				return err
			}
			// A generic plan, as for a prepared statement: bound values
			// cannot fold a catch-all predicate away.
			if _, err := tx.Exec(t.Context(), "PREPARE page AS "+sql+"SELECT count(*) FROM win", pgx.QueryExecModeSimpleProtocol); err != nil {
				return err
			}
			var literals []string
			for _, a := range args {
				switch v := a.(type) {
				case string:
					literals = append(literals, "'"+strings.ReplaceAll(v, "'", "''")+"'")
				default:
					literals = append(literals, fmt.Sprint(v))
				}
			}
			rows, err := tx.Query(t.Context(), "EXPLAIN EXECUTE page("+strings.Join(literals, ",")+")", pgx.QueryExecModeSimpleProtocol)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					return err
				}
				plan = append(plan, line)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(name, err)
		}
		text := strings.Join(plan, "\n")
		if !strings.Contains(text, c.index) || strings.Contains(text, "Seq Scan on history_events") {
			t.Errorf("%s does not use %s:\n%s", name, c.index, text)
		}
	}
}

// Ranges filter on history time (completion, or admission while the outcome
// is unknown), which is the list's order; the list still carries start times.
func TestHistoryRangesUseHistoryTime(t *testing.T) {
	db := pgtest.New(t).Admin
	started := event("alice", "late", "", "", "tool-1", "tool", "up", "ok", 300)
	started.TSNano = 150 // started inside the range, finished after it
	insert(t, db, event("alice", "inside", "", "", "tool-1", "tool", "up", "ok", 150), started,
		event("alice", "open", "tool.dispatch.admitted", "inv", "tool-1", "tool", "up", "unknown", 160))
	got := query(t, db, catalogdb.HistoryQuery{Owner: "alice", HasFrom: true, FromNano: 100, HasTo: true, ToNano: 200})
	if ids(got.Records) != "open,inside" || got.Total != 2 {
		t.Fatal("range:", ids(got.Records), got.Total)
	}
	got = query(t, db, catalogdb.HistoryQuery{Owner: "alice", Status: "unknown", HasFrom: true, FromNano: 100, HasTo: true, ToNano: 200})
	if ids(got.Records) != "open" {
		t.Fatal("unknown range:", ids(got.Records))
	}
}

// The tool list moves forward only, whatever order events arrive in, and
// matches the latest visible name of each tool.
func TestHistoryToolListForwardOnly(t *testing.T) {
	db := pgtest.New(t).Admin
	insert(t, db,
		event("alice", "e2", "", "", "tool-1", "renamed", "up-2", "ok", 200),
		event("alice", "e1", "", "", "tool-1", "original", "up-1", "ok", 100), // stored late, older
		event("alice", "e3", "", "", "tool-2", "other", "up-1", "ok", 300),
		event("alice", "e3b", "", "", "tool-2", "other again", "up-1", "ok", 300), // same time, larger event ID wins
		event("alice", "e0", "", "", "", "no id", "up-1", "ok", 400),
		event("bob", "b1", "", "", "tool-1", "bob's", "up-9", "ok", 500),
	)
	got := query(t, db, catalogdb.HistoryQuery{Owner: "alice"})
	var names []string
	for _, tool := range got.Tools {
		names = append(names, tool.ToolID+"="+tool.Tool+"@"+tool.Upstream)
	}
	if strings.Join(names, ",") != "tool-1=renamed@up-2,tool-2=other again@up-1" {
		t.Fatal("tool list:", names)
	}
}

// history_open holds exactly the admissions without a stored completion, in
// either arrival order, so the unknown filter gives the visible unknown rows.
func TestHistoryOpenCalls(t *testing.T) {
	db := pgtest.New(t).Admin
	var rows []catalogdb.HistoryRow
	for i := range 6 {
		inv := fmt.Sprintf("inv-%d", i)
		admitted := event("alice", "a"+inv, "tool.dispatch.admitted", inv, "tool-1", "tool", "up", "unknown", int64(100+i))
		completed := event("alice", "c"+inv, "tool.dispatch.completed", inv, "tool-1", "tool", "up", "ok", int64(200+i))
		switch i % 3 {
		case 0: // in order
			rows = append(rows, admitted, completed)
		case 1: // completion stored first
			rows = append(rows, completed, admitted)
		case 2: // still open
			rows = append(rows, admitted)
		}
	}
	insert(t, db, rows...)
	unknown := query(t, db, catalogdb.HistoryQuery{Owner: "alice", Status: "unknown"})
	if ids(unknown.Records) != "ainv-5,ainv-2" || unknown.Total != 2 {
		t.Fatal("unknown filter:", ids(unknown.Records), unknown.Total)
	}
	all := query(t, db, catalogdb.HistoryQuery{Owner: "alice"})
	var visible []string
	for _, r := range all.Records {
		if r.Status == "unknown" {
			visible = append(visible, r.EventID)
		}
	}
	if strings.Join(visible, ",") != ids(unknown.Records) || all.Total != 6 {
		t.Fatal("unknown rows differ from the visible history:", visible, all.Total)
	}
	var open int
	if err := db.QueryRow(context.Background(), "SELECT count(*) FROM mcpwarden_security.history_open").Scan(&open); err != nil || open != 2 {
		t.Fatal("history_open:", open, err)
	}
}
