package storetest_test

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres/pgtest"
	"github.com/yaphoa/mcpwarden/internal/lease/sqlite"
)

// The same history rows, written through each store's InsertHistory, give
// identical QueryHistory results. The rows mix schema versions, open and out-of-order calls,
// renames, gateway tools, time ties and event IDs whose byte order differs
// from a locale order.
func TestHistoryBackendEquivalence(t *testing.T) {
	pg := pgtest.New(t)
	ps, err := postgres.Open(t.Context(), pg.RuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close(context.Background())
	if err := ps.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	ss, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "mcpwarden.db"), sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close(context.Background())
	if err := ss.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}

	rng := mrand.New(mrand.NewPCG(14, 1))
	alphabet := []rune("aAbB09-_zZé")
	id := func() string {
		r := make([]rune, 6)
		for i := range r {
			r[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(r)
	}
	type tool struct{ id, name, upstream string }
	tools := []tool{{"t-a", "alpha", "up-1"}, {"t-b", "béta", "up-1"}, {"t-C", "gamma", "up-2"}, {"t-gw", "manage", ""}}
	statuses := []string{"ok", "error", "timeout"}
	seen := map[string]bool{}
	var rows []catalogdb.HistoryRow
	row := func(owner, kind, inv, status string, tl tool, ns int64) catalogdb.HistoryRow {
		eid := id()
		for seen[owner+eid] {
			eid = id()
		}
		seen[owner+eid] = true
		version := 1
		if kind != "" {
			version = 2
		}
		raw, _ := json.Marshal(map[string]any{"schema_version": version, "event_id": eid, "owner": owner})
		timed := rng.IntN(3) > 0
		return catalogdb.HistoryRow{OwnerID: owner, EventID: eid, SchemaVersion: version, EventType: kind, InvocationID: inv,
			ToolID: tl.id, Tool: tl.name, Upstream: tl.upstream, Status: status, ActorAccessID: fmt.Sprint("actor-", rng.IntN(4)),
			TSNano: ns - int64(rng.IntN(5)), HistoryNano: ns, Timed: timed, Failed: status != "ok", Forwarded: timed && rng.IntN(2) == 0,
			HandlerUS: int64(rng.IntN(1_000_000)), GatewayUS: int64(rng.IntN(10_000)), UpstreamUS: int64(rng.IntN(1_000_000)),
			HandlerBucket: rng.IntN(32), GatewayBucket: rng.IntN(32), UpstreamBucket: rng.IntN(32), Record: string(raw), Source: "live"}
	}
	for i := 0; i < 1500; i++ {
		owner := "alice"
		if i%7 == 0 {
			owner = "bob"
		}
		tl := tools[rng.IntN(len(tools))]
		if i > 1000 && tl.id == "t-a" {
			tl.name = "alpha-renamed"
		}
		ns := int64(1000 + i/3) // ties: three events share each time
		status := statuses[rng.IntN(len(statuses))]
		inv := identity.New()
		switch rng.IntN(5) {
		case 0: // schema v1
			rows = append(rows, row(owner, "", "", status, tl, ns))
		case 1: // admitted and completed in order
			rows = append(rows, row(owner, "tool.dispatch.admitted", inv, "unknown", tl, ns), row(owner, "tool.dispatch.completed", inv, status, tl, ns+1))
		case 2: // completion stored first
			rows = append(rows, row(owner, "tool.dispatch.completed", inv, status, tl, ns+1), row(owner, "tool.dispatch.admitted", inv, "unknown", tl, ns))
		case 3: // still open
			rows = append(rows, row(owner, "tool.dispatch.admitted", inv, "unknown", tl, ns))
		case 4: // denied
			rows = append(rows, row(owner, "tool.dispatch.denied", inv, "denied", tl, ns))
		}
	}
	for _, r := range rows {
		if err := ps.InsertHistory(t.Context(), r); err != nil {
			t.Fatal("postgres", r.EventID, err)
		}
		if err := ss.InsertHistory(t.Context(), r); err != nil {
			t.Fatal("sqlite", r.EventID, err)
		}
	}
	queries := []catalogdb.HistoryQuery{
		{Owner: "alice", Limit: 25}, {Owner: "alice", Limit: 100, Offset: 300}, {Owner: "alice", Limit: 7, Offset: 1},
		{Owner: "bob", Limit: 50}, {Owner: "alice", ToolID: "t-a", Limit: 25}, {Owner: "alice", ToolID: "t-C", Limit: 25},
		{Owner: "alice", Upstream: "up-1", Limit: 25}, {Owner: "alice", Upstream: "__gateway__", Limit: 25},
		{Owner: "alice", Status: "unknown", Limit: 25}, {Owner: "alice", Status: "timeout", Limit: 25}, {Owner: "alice", Status: "denied", Limit: 25},
		{Owner: "alice", ActorAccessID: "actor-2", Limit: 25}, {Owner: "alice", Upstream: "up-1", ToolID: "t-b", Limit: 25},
		{Owner: "alice", ActorAccessID: "actor-1", Status: "ok", Limit: 25},
		{Owner: "alice", HasFrom: true, FromNano: 1200, Limit: 25}, {Owner: "alice", HasTo: true, ToNano: 1100, Limit: 25},
		{Owner: "alice", HasFrom: true, FromNano: 1100, HasTo: true, ToNano: 1101, Limit: 25},
		{Owner: "alice", ToolID: "none", Limit: 25}, {Owner: "carol", Limit: 25},
	}
	strip := func(r catalogdb.HistoryResult) catalogdb.HistoryResult {
		for i := range r.Records {
			r.Records[i].Source, r.Records[i].SourceLine = "", 0
		}
		for i := range r.Tools {
			r.Tools[i].Source, r.Tools[i].SourceLine = "", 0
		}
		return r
	}
	for _, q := range queries {
		a, errA := ps.QueryHistory(t.Context(), q)
		b, errB := ss.QueryHistory(t.Context(), q)
		if (errA == nil) != (errB == nil) {
			t.Errorf("%+v: postgres err %v, sqlite err %v", q, errA, errB)
			continue
		}
		a, b = strip(a), strip(b)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%+v differs: postgres total %d capped %v rows %d tools %d timed %d failed %d | sqlite total %d capped %v rows %d tools %d timed %d failed %d",
				q, a.Total, a.Capped, len(a.Records), len(a.Tools), a.TimedCalls, a.FailedCalls, b.Total, b.Capped, len(b.Records), len(b.Tools), b.TimedCalls, b.FailedCalls)
			for i := 0; i < len(a.Records) && i < len(b.Records); i++ {
				if !reflect.DeepEqual(a.Records[i], b.Records[i]) {
					t.Logf("first differing row %d:\n pg %+v\n sq %+v", i, a.Records[i], b.Records[i])
					break
				}
			}
			if !reflect.DeepEqual(a.Handler, b.Handler) || !reflect.DeepEqual(a.Gateway, b.Gateway) || !reflect.DeepEqual(a.Forward, b.Forward) {
				t.Logf("aggregates differ:\n pg %+v %+v %+v\n sq %+v %+v %+v", a.Handler, a.Gateway, a.Forward, b.Handler, b.Gateway, b.Forward)
			}
			if !reflect.DeepEqual(a.Tools, b.Tools) {
				t.Logf("tools differ:\n pg %+v\n sq %+v", a.Tools, b.Tools)
			}
		}
	}
}
