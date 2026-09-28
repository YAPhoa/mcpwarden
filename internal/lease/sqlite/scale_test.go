//go:build historyscale

package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
)

// TestHistoryScale holds history pages to 500 ms at 1,000,000 calls
// (2,000,000 events) for one owner, with the PostgreSQL test's data and
// cases. The gateway never runs ANALYZE, so the plans run without
// statistics. Run it without the race detector:
// go test -tags historyscale -run Scale ./internal/lease/sqlite
func TestHistoryScale(t *testing.T) {
	path := tempPath(t)
	if err := openStore(t, path).Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=synchronous(OFF)")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	// Call g: 90% on upstream busy, 1% on tool rare, 5% timeouts, 50
	// actors; every thousandth call is still open (no completion).
	for _, stmt := range []string{
		`WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM g WHERE n < 1000000), k(kind) AS (VALUES ('a'),('c'))
         INSERT INTO history_events
         (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,
          timed,failed,forwarded,handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record)
         SELECT 'alice', k.kind||printf('%07d', g.n), 2,
          CASE k.kind WHEN 'a' THEN 'tool.dispatch.admitted' ELSE 'tool.dispatch.completed' END, 'inv-'||g.n,
          CASE WHEN g.n%100=1 THEN 'rare' ELSE 'tool-'||(g.n%10) END, 'tool', CASE WHEN g.n%10=0 THEN 'quiet' ELSE 'busy' END,
          CASE WHEN k.kind='a' THEN 'unknown' WHEN g.n%20=0 THEN 'timeout' ELSE 'ok' END, 'actor-'||(g.n%50),
          2*g.n, CASE k.kind WHEN 'a' THEN 2*g.n ELSE 2*g.n+1 END,
          k.kind='c', k.kind='c' AND g.n%20=0, k.kind='c', 100, 10, 90, 6, 3, 6,
          json_object('schema_version', 2, 'event_id', k.kind||printf('%07d', g.n), 'owner', 'alice')
         FROM g, k WHERE NOT (k.kind='c' AND g.n%1000=0)`,
		`INSERT INTO history_open(owner_id,invocation_id,history_ns,event_id)
         SELECT owner_id,invocation_id,history_ns,event_id FROM history_events h WHERE event_type='tool.dispatch.admitted'
         AND NOT EXISTS (SELECT 1 FROM history_events c WHERE c.owner_id=h.owner_id AND c.invocation_id=h.invocation_id AND c.event_type='tool.dispatch.completed')`,
		`INSERT INTO history_tools(owner_id,tool_id,tool,upstream,last_ns,last_event_id)
         SELECT owner_id,tool_id,tool,upstream,history_ns,event_id FROM (SELECT owner_id,tool_id,tool,upstream,history_ns,event_id,
          row_number() OVER (PARTITION BY owner_id,tool_id ORDER BY history_ns DESC, event_id DESC) AS rn FROM history_events) WHERE rn=1`,
	} {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	var stats int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name='sqlite_stat1'").Scan(&stats); err != nil || stats != 0 {
		t.Fatal("the database has statistics:", stats, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded in %s", time.Since(start).Round(time.Second))

	s := openStore(t, path)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		q    catalogdb.HistoryQuery
		held bool
	}{
		{"unfiltered", catalogdb.HistoryQuery{}, true},
		{"tool", catalogdb.HistoryQuery{ToolID: "tool-3"}, true},
		{"rare tool", catalogdb.HistoryQuery{ToolID: "rare"}, true},
		{"upstream", catalogdb.HistoryQuery{Upstream: "quiet"}, true},
		{"status", catalogdb.HistoryQuery{Status: "timeout"}, true},
		{"actor", catalogdb.HistoryQuery{ActorAccessID: "actor-7"}, true},
		{"unknown", catalogdb.HistoryQuery{Status: "unknown"}, true},
		{"upstream and tool", catalogdb.HistoryQuery{Upstream: "busy", ToolID: "rare"}, true},
		{"oldest tenth", catalogdb.HistoryQuery{HasTo: true, ToNano: 200001}, true},
		{"last page", catalogdb.HistoryQuery{Offset: catalogdb.HistoryWindow - 25}, true},
		{"actor and status", catalogdb.HistoryQuery{ActorAccessID: "actor-10", Status: "timeout"}, false},
	}
	for _, c := range cases {
		c.q.Owner, c.q.Limit = "alice", 25
		var best time.Duration
		var result catalogdb.HistoryResult
		for i := range 3 {
			began := time.Now()
			var err error
			if result, err = s.QueryHistory(t.Context(), c.q); err != nil {
				t.Fatal(c.name, err)
			}
			if took := time.Since(began); i == 0 || took < best {
				best = took
			}
		}
		t.Logf("%-18s %4d ms  total %d capped %v rows %d tools %d", c.name, best.Milliseconds(), result.Total, result.Capped, len(result.Records), len(result.Tools))
		if len(result.Records) == 0 {
			t.Errorf("%s returned no rows", c.name)
		}
		if c.held && best > 500*time.Millisecond {
			t.Errorf("%s took %s, over 500 ms", c.name, best)
		}
	}
	// An admission written while a page runs completes normally.
	done := make(chan error, 1)
	go func() {
		_, err := s.QueryHistory(t.Context(), catalogdb.HistoryQuery{Owner: "alice", ActorAccessID: "actor-10", Status: "timeout", Limit: 25})
		done <- err
	}()
	row := catalogdb.HistoryRow{OwnerID: "alice", EventID: "during", SchemaVersion: 2, EventType: "tool.dispatch.admitted", InvocationID: "inv-during",
		ToolID: "tool-1", Tool: "tool", Upstream: "busy", Status: "unknown", ActorAccessID: "actor-1", TSNano: 3_000_000, HistoryNano: 3_000_000,
		Record: `{"schema_version":2,"event_id":"during","owner":"alice"}`}
	began := time.Now()
	if err := s.InsertHistory(t.Context(), row); err != nil {
		t.Fatal("admission during a page:", err)
	}
	t.Logf("admission during a page: %d ms", time.Since(began).Milliseconds())
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
