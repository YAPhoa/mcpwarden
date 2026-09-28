package storetest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
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

func insert(t *testing.T, s Store, rows ...catalogdb.HistoryRow) {
	t.Helper()
	for _, r := range rows {
		if err := s.InsertHistory(t.Context(), r); err != nil {
			t.Fatal(r.EventID, err)
		}
	}
}

func query(t *testing.T, s Store, q catalogdb.HistoryQuery) catalogdb.HistoryResult {
	t.Helper()
	if q.Limit == 0 {
		q.Limit = 25
	}
	out, err := s.QueryHistory(t.Context(), q)
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

// Every page reads at most the newest 25,000 matching events; a page that
// ends beyond them is refused, and more matches are reported as capped.
func testHistoryWindow(t *testing.T, db Database) {
	s := started(t, db)
	db.BulkHistory(t, "alice", catalogdb.HistoryWindow+10)
	first := query(t, s, catalogdb.HistoryQuery{Owner: "alice"})
	if first.Total != catalogdb.HistoryWindow || !first.Capped || first.TimedCalls != catalogdb.HistoryWindow || first.Records[0].EventID != "e025010" {
		t.Fatal("first page:", first.Total, first.Capped, first.TimedCalls, first.Records[0].EventID)
	}
	if first.Handler.Count != catalogdb.HistoryWindow || first.FailedCalls != int64(catalogdb.HistoryWindow/5) {
		t.Fatal("timings do not cover the window:", first.Handler.Count, first.FailedCalls)
	}
	last := query(t, s, catalogdb.HistoryQuery{Owner: "alice", Offset: catalogdb.HistoryWindow - 25})
	if len(last.Records) != 25 || last.Records[24].EventID != "e000011" {
		t.Fatal("last page:", ids(last.Records))
	}
	if _, err := s.QueryHistory(t.Context(), catalogdb.HistoryQuery{Owner: "alice", Offset: catalogdb.HistoryWindow - 24, Limit: 25}); !errors.Is(err, catalogdb.ErrHistoryWindow) {
		t.Fatal("a page beyond the window was served:", err)
	}
	older := query(t, s, catalogdb.HistoryQuery{Owner: "alice", HasTo: true, ToNano: 11})
	if older.Total != 10 || older.Capped || older.Records[0].EventID != "e000010" {
		t.Fatal("older calls are not reachable with a time range:", older.Total, older.Capped)
	}
	exact := query(t, s, catalogdb.HistoryQuery{Owner: "alice", HasFrom: true, FromNano: 11})
	if exact.Total != catalogdb.HistoryWindow || exact.Capped {
		t.Fatal("exactly 25,000 matches are not capped:", exact.Total, exact.Capped)
	}
	stillOpen(t, s)
}

// Ranges filter on history time (completion, or admission while the outcome
// is unknown), which is the list's order; the list still carries start times.
func testHistoryRangesUseHistoryTime(t *testing.T, db Database) {
	s := started(t, db)
	late := event("alice", "late", "", "", "tool-1", "tool", "up", "ok", 300)
	late.TSNano = 150 // started inside the range, finished after it
	insert(t, s, event("alice", "inside", "", "", "tool-1", "tool", "up", "ok", 150), late,
		event("alice", "open", "tool.dispatch.admitted", "inv", "tool-1", "tool", "up", "unknown", 160))
	got := query(t, s, catalogdb.HistoryQuery{Owner: "alice", HasFrom: true, FromNano: 100, HasTo: true, ToNano: 200})
	if ids(got.Records) != "open,inside" || got.Total != 2 {
		t.Fatal("range:", ids(got.Records), got.Total)
	}
	got = query(t, s, catalogdb.HistoryQuery{Owner: "alice", Status: "unknown", HasFrom: true, FromNano: 100, HasTo: true, ToNano: 200})
	if ids(got.Records) != "open" {
		t.Fatal("unknown range:", ids(got.Records))
	}
	all := query(t, s, catalogdb.HistoryQuery{Owner: "alice"})
	for _, r := range all.Records {
		if r.EventID == "late" && (r.TSNano != 150 || r.HistoryNano != 300) {
			t.Fatal("late call times:", r.TSNano, r.HistoryNano)
		}
	}
}

// The tool list moves forward only, whatever order events arrive in, and
// matches the latest visible name of each tool.
func testHistoryToolListForwardOnly(t *testing.T, db Database) {
	s := started(t, db)
	insert(t, s,
		event("alice", "e2", "", "", "tool-1", "renamed", "up-2", "ok", 200),
		event("alice", "e1", "", "", "tool-1", "original", "up-1", "ok", 100), // stored late, older
		event("alice", "e3", "", "", "tool-2", "other", "up-1", "ok", 300),
		event("alice", "e3b", "", "", "tool-2", "other again", "up-1", "ok", 300), // same time, larger event ID wins
		event("alice", "e0", "", "", "", "no id", "up-1", "ok", 400),
		event("bob", "b1", "", "", "tool-1", "bob's", "up-9", "ok", 500),
	)
	got := query(t, s, catalogdb.HistoryQuery{Owner: "alice"})
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
func testHistoryOpenCalls(t *testing.T, db Database) {
	s := started(t, db)
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
	insert(t, s, rows...)
	unknown := query(t, s, catalogdb.HistoryQuery{Owner: "alice", Status: "unknown"})
	if ids(unknown.Records) != "ainv-5,ainv-2" || unknown.Total != 2 {
		t.Fatal("unknown filter:", ids(unknown.Records), unknown.Total)
	}
	all := query(t, s, catalogdb.HistoryQuery{Owner: "alice"})
	var visible []string
	for _, r := range all.Records {
		if r.Status == "unknown" {
			visible = append(visible, r.EventID)
		}
	}
	if strings.Join(visible, ",") != ids(unknown.Records) || all.Total != 6 {
		t.Fatal("unknown rows differ from the visible history:", visible, all.Total)
	}
	if open := db.Int(t, "SELECT count(*) FROM history_open"); open != 2 {
		t.Fatal("history_open:", open)
	}
}
