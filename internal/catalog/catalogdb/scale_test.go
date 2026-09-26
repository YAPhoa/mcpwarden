//go:build historyscale

package catalogdb_test

import (
	"context"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres/pgtest"
)

// TestHistoryScale holds history pages to 500 ms at 1,000,000 calls
// (2,000,000 events) for one owner, on the read session. Run it without the
// race detector: go test -tags historyscale -run Scale ./internal/catalog/catalogdb
func TestHistoryScale(t *testing.T) {
	db := pgtest.New(t)
	admin := db.Admin
	start := time.Now()
	// Call g: 90% on upstream busy, 1% on tool rare (on busy), 5% timeouts,
	// 50 actors; every thousandth call is still open (no completion).
	for _, sql := range []string{
		`INSERT INTO mcpwarden_security.history_events
         (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,
          timed,failed,forwarded,handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record,source)
         SELECT 'alice', e.id, 2, e.kind, 'inv-'||g, CASE WHEN g%100=1 THEN 'rare' ELSE 'tool-'||(g%10) END, 'tool', CASE WHEN g%10=0 THEN 'quiet' ELSE 'busy' END,
          e.status, 'actor-'||(g%50), 2*g, e.ns, e.timed, e.status='timeout', e.timed, 100, 10, 90, 6, 3, 6,
          json_build_object('schema_version',2,'event_id',e.id,'owner','alice')::text, 'live'
         FROM generate_series(1,1000000) g,
         LATERAL (VALUES ('a'||lpad(g::text,7,'0'), 'tool.dispatch.admitted', 'unknown', 2*g::bigint, false),
                         ('c'||lpad(g::text,7,'0'), 'tool.dispatch.completed', CASE WHEN g%20=0 THEN 'timeout' ELSE 'ok' END, 2*g::bigint+1, true)) AS e(id,kind,status,ns,timed)
         WHERE NOT (e.kind='tool.dispatch.completed' AND g%1000=0)`,
		`INSERT INTO mcpwarden_security.history_open(owner_id,invocation_id,history_ns,event_id)
         SELECT owner_id,invocation_id,history_ns,event_id FROM mcpwarden_security.history_events h WHERE event_type='tool.dispatch.admitted'
         AND NOT EXISTS (SELECT 1 FROM mcpwarden_security.history_events c WHERE c.owner_id=h.owner_id AND c.invocation_id=h.invocation_id AND c.event_type='tool.dispatch.completed')`,
		`INSERT INTO mcpwarden_security.history_tools(owner_id,tool_id,tool,upstream,last_ns,last_event_id)
         SELECT DISTINCT ON (tool_id) owner_id,tool_id,tool,upstream,history_ns,event_id FROM mcpwarden_security.history_events
         ORDER BY tool_id, history_ns DESC, event_id COLLATE "C" DESC`,
		`ANALYZE mcpwarden_security.history_events`, `ANALYZE mcpwarden_security.history_open`, `ANALYZE mcpwarden_security.history_tools`,
	} {
		if _, err := admin.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("loaded in %s", time.Since(start).Round(time.Second))
	store, err := postgres.Open(t.Context(), db.RuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(context.Background())
	if err := store.Start(t.Context(), identity.New()); err != nil {
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
			err := store.ReadHistory(t.Context(), func(ctx context.Context, tx catalogdb.DB) error {
				var err error
				result, err = catalogdb.QueryHistory(ctx, tx, c.q)
				return err
			})
			if err != nil {
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
		done <- store.ReadHistory(t.Context(), func(ctx context.Context, tx catalogdb.DB) error {
			_, err := catalogdb.QueryHistory(ctx, tx, catalogdb.HistoryQuery{Owner: "alice", ActorAccessID: "actor-10", Status: "timeout", Limit: 25})
			return err
		})
	}()
	row := event("alice", "during", "tool.dispatch.admitted", "inv-during", "tool-1", "tool", "busy", "unknown", 3_000_000)
	began := time.Now()
	if err := store.Run(t.Context(), func(ctx context.Context, tx catalogdb.DB) error { return catalogdb.InsertHistory(ctx, tx, row) }); err != nil {
		t.Fatal("admission during a page:", err)
	}
	t.Logf("admission during a page: %d ms", time.Since(began).Milliseconds())
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
