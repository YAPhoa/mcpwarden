package postgres_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres/pgtest"
)

func event(owner, id, kind, invocation, toolID, tool, upstream, status string, ns int64) catalogdb.HistoryRow {
	if kind == "" {
		kind, invocation = "tool.dispatch.completed", "inv-"+id
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": 2, "event_id": id, "owner": owner})
	return catalogdb.HistoryRow{OwnerID: owner, EventID: id, SchemaVersion: 2, EventType: kind, InvocationID: invocation, ToolID: toolID, Tool: tool,
		Upstream: upstream, Status: status, TSNano: ns, HistoryNano: ns, Record: string(raw)}
}

func insert(t *testing.T, db *pgx.Conn, rows ...catalogdb.HistoryRow) {
	t.Helper()
	for _, r := range rows {
		err := pgx.BeginFunc(t.Context(), db, func(tx pgx.Tx) error { return postgres.InsertHistory(t.Context(), tx, r) })
		if err != nil {
			t.Fatal(r.EventID, err)
		}
	}
}

// bulk inserts n timed events for owner, event i at history time i, spread
// over two tools, two upstreams, two statuses and two actors.
func bulk(t *testing.T, db *pgx.Conn, owner string, n int) {
	t.Helper()
	_, err := db.Exec(t.Context(), `INSERT INTO mcpwarden_security.history_events
        (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,timed,failed,forwarded,
         handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record)
        SELECT $1, 'e'||lpad(g::text,6,'0'), 2, 'tool.dispatch.completed', 'inv-'||'e'||lpad(g::text,6,'0'), 'tool-'||(g%4), 'tool '||(g%4), 'up-'||(g%3), CASE WHEN g%5=0 THEN 'timeout' ELSE 'ok' END,
         'actor-'||(g%7), g, g, true, g%5=0, true, 100, 10, 90, 6, 3, 6,
         json_build_object('schema_version',2,'event_id','e'||lpad(g::text,6,'0'),'owner',$1::text)::text
        FROM generate_series(1,$2::int) g`, owner, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), "ANALYZE mcpwarden_security.history_events"); err != nil {
		t.Fatal(err)
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
		"unknown":  {catalogdb.HistoryQuery{Status: "unknown"}, "history_owner_status"},
	} {
		c.q.Owner = "alice"
		sql, args := postgres.Window(c.q)
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
		// Every page also merges open calls from history_open.
		if !strings.Contains(text, c.index) || !strings.Contains(text, "history_open_recent") || strings.Contains(text, "Seq Scan on history_events") {
			t.Errorf("%s does not use %s:\n%s", name, c.index, text)
		}
	}
}
