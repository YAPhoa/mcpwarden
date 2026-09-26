package audit

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestHashArgsCanonical(t *testing.T) {
	a := HashArgs(json.RawMessage(`{"b":2,"a":{"z":1,"c":3}}`))
	b := HashArgs(json.RawMessage(`{ "a": {"c":3,"z":1}, "b":2 }`))
	if a != b {
		t.Fatal("argument hash depends on JSON key order")
	}
}

func TestEventOrderingAndIdentitySurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	for _, id := range []string{"c", "a", "b"} {
		r := NewRecord()
		r.EventID, r.Owner, r.UpstreamID = id, "alice", "provider-id"
		r.CompletedAt = base
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for page, id := range []string{"c", "b", "a"} {
		rows, total, err := w.History("alice", "", page+1, 1)
		if err != nil || total != 3 || len(rows) != 1 {
			t.Fatalf("query: %v %d %v", rows, total, err)
		}
		if rows[0].EventID != id || rows[0].SchemaVersion != 1 || rows[0].UpstreamID != "provider-id" || !rows[0].CompletedAt.Equal(base) {
			t.Fatalf("changed event: %+v", rows[0])
		}
	}
}

func TestLegacyReadDoesNotRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit")
	legacy := []byte("{\"owner\":\"alice\",\"ts\":\"2026-09-21T00:00:00Z\",\"duration_ms\":5}\n")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	a, _, err := w.History("alice", "", 1, 25)
	if err != nil || len(a) != 1 {
		t.Fatal(err)
	}
	b, _, _ := w.History("alice", "", 1, 25)
	if a[0].EventID == "" || a[0].EventID != b[0].EventID || a[0].SchemaVersion != 0 || a[0].CompletedAt.Sub(a[0].TS) != 5*time.Millisecond {
		t.Fatalf("legacy normalization: %+v", a[0])
	}
	actual, _ := os.ReadFile(path)
	if string(actual) != string(legacy) {
		t.Fatal("legacy log rewritten")
	}
}

func TestRejectCorruptOrFutureLog(t *testing.T) {
	for _, raw := range []string{"{broken}\n", "{}", "null\n", "{\"schema_version\":2}\n", "{\"schema_version\":1}\n"} {
		path := filepath.Join(t.TempDir(), "audit")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if w, err := Open(path); err == nil {
			w.Close()
			t.Fatalf("accepted %q", raw)
		}
		actual, _ := os.ReadFile(path)
		if string(actual) != raw {
			t.Fatal("corrupt log modified")
		}
	}
}

type shortWriter struct{ calls int }

func (w *shortWriter) Write(b []byte) (int, error) { w.calls++; return len(b) - 1, nil }

func TestShortWriteStopsFurtherAppends(t *testing.T) {
	out := &shortWriter{}
	w := &Writer{out: out}
	for range 2 {
		if err := w.Write(NewRecord()); err != io.ErrShortWrite {
			t.Fatalf("got %v", err)
		}
	}
	if out.calls != 1 {
		t.Fatal("appended after partial write")
	}
}

func TestHistoryOrdersByCompletionBeforeID(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	base := time.Now().UTC()
	for i, id := range []string{"a", "z"} {
		r := NewRecord()
		r.EventID, r.Owner, r.ToolID, r.Tool = id, "alice", "tool", id
		r.CompletedAt = base.Add(-time.Duration(i) * time.Hour)
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	rows, _, refs, err := w.QueryHistory(HistoryFilter{Owner: "alice", Page: 1, Size: 1})
	if err != nil || len(rows) != 1 || rows[0].EventID != "a" || len(refs) != 1 || refs[0].Name != "a" {
		t.Fatalf("ordering: %v %v %v", rows, refs, err)
	}
}

func TestHistoryReportsCorruptionAfterOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := os.WriteFile(path, []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.History("alice", "", 1, 25); err == nil {
		t.Fatal("silently skipped corrupt row")
	}
}
func TestConcurrentJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Write(Record{Tool: "mock__echo", Status: "ok"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, line := range bytesSplitLines(b) {
		var v Record
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 50 {
		t.Fatalf("got %d lines", count)
	}
}
func bytesSplitLines(b []byte) [][]byte {
	out := [][]byte{}
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	return out
}

func TestHistoryOwnerToolPaginationAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		if err := w.Write(Record{Owner: "alice", ToolID: "uuid-a", Status: "ok", DurationMS: int64(i), ResponseItems: 2}); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []Record{{Owner: "bob", ToolID: "uuid-a"}, {Owner: "alice", ToolID: "uuid-b"}, {ToolID: "uuid-a"}} {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	w, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rows, total, err := w.History("alice", "uuid-a", 2, 25)
	if err != nil || total != 60 || len(rows) != 25 || rows[0].DurationMS != 34 || rows[24].DurationMS != 10 {
		t.Fatalf("bad history: total=%d rows=%v err=%v", total, rows, err)
	}
	rows, total, err = w.History("alice", "uuid-a", 3, 25)
	if err != nil || total != 60 || len(rows) != 10 || rows[9].DurationMS != 0 {
		t.Fatal("bad final page")
	}
	_, total, _ = w.History("charlie", "uuid-a", 1, 25)
	if total != 0 {
		t.Fatal("cross-owner history")
	}
}

func TestHistoryFiltersKeepOwnerBoundaries(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	base := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	for _, r := range []Record{
		{Owner: "alice", ToolID: "a", Tool: "alpha", Status: "ok", TS: base, CompletedAt: base},
		{Owner: "alice", ToolID: "a", Tool: "alpha", Status: "timeout", TS: base.Add(time.Hour), CompletedAt: base.Add(time.Hour)},
		{Owner: "alice", ToolID: "b", Tool: "beta", Status: "timeout", TS: base.Add(2 * time.Hour), CompletedAt: base.Add(2 * time.Hour)},
		{Owner: "bob", ToolID: "private", Tool: "secret", Status: "timeout", TS: base.Add(time.Hour), CompletedAt: base.Add(time.Hour)},
		// Time ranges match history time: this call started inside the
		// range but finished after it.
		{Owner: "alice", ToolID: "a", Tool: "alpha", Status: "timeout", TS: base.Add(90 * time.Minute), CompletedAt: base.Add(3 * time.Hour)},
	} {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	rows, total, options, err := w.QueryHistory(HistoryFilter{Owner: "alice", Status: "timeout", From: base.Add(time.Hour), To: base.Add(2 * time.Hour), Page: 1, Size: 25})
	if err != nil || total != 1 || len(rows) != 1 || rows[0].ToolID != "a" || len(options) != 2 {
		t.Fatalf("bad filter result: %v %d %v %v", rows, total, options, err)
	}
	for _, option := range options {
		if option.Name == "secret" {
			t.Fatal("cross-owner filter option")
		}
	}
}

func TestHistoryUpstreamFilter(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, r := range []Record{{Owner: "alice", ToolID: "a", Upstream: "drive"}, {Owner: "alice", ToolID: "b", Upstream: "drive"}, {Owner: "alice", ToolID: "c", Upstream: "kaggle"}, {Owner: "bob", ToolID: "d", Upstream: "drive"}} {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	rows, total, options, err := w.QueryHistory(HistoryFilter{Owner: "alice", Upstream: "drive", Page: 1, Size: 25})
	if err != nil || total != 2 || len(rows) != 2 || len(options) != 3 {
		t.Fatal("bad service filtering")
	}
	for _, row := range rows {
		if row.Upstream != "drive" {
			t.Fatal("other service leaked")
		}
	}
}

func TestPerformanceAcrossPagesAndOwners(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		if err := w.Write(Record{Owner: "alice", Upstream: "drive", Status: "ok", Timing: &Timing{HandlerUS: 110, UpstreamUS: 100, GatewayUS: 10, Forwarded: true}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []Record{
		{Owner: "alice", Upstream: "drive", Status: "denied", Timing: &Timing{HandlerUS: 20, GatewayUS: 20}},
		{Owner: "bob", Upstream: "drive", Timing: &Timing{HandlerUS: 999999}},
		{Owner: "alice", Upstream: "kaggle", Timing: &Timing{HandlerUS: 999999}},
		{Owner: "alice", Upstream: "drive", DurationMS: 999999},
	} {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	w, err = Open(w.path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rows, total, _, stats, err := w.QueryHistoryPerformance(HistoryFilter{Owner: "alice", Upstream: "drive", Page: 2, Size: 25})
	if err != nil || total != 62 || len(rows) != 25 || stats.TimedCalls != 61 || stats.FailedCalls != 1 || stats.Upstream.Count != 60 || stats.Upstream.MeanUS != 100 || stats.Gateway.MaxUS != 20 || stats.Handler.P95UpperUS != 110 {
		t.Fatalf("incorrect persistent, filtered aggregation: total=%d stats=%+v err=%v", total, stats, err)
	}
}
