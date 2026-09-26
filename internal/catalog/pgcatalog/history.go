package pgcatalog

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
)

// History is the indexed audit.Store. Each write is its own committed
// transaction on the executor session, so a successful admission is durable
// before dispatch. A failed or uncertain write is returned; the caller never
// retries the tool, and a commit failure also stops the executor session.
// Pages read on a separate read-only session, so they never hold the executor.
type History struct{ db HistoryDB }

// HistoryDB writes on the executor session and reads on the history session.
type HistoryDB interface {
	Run(ctx context.Context, fn func(context.Context, catalogdb.DB) error) error
	ReadHistory(ctx context.Context, fn func(context.Context, catalogdb.DB) error) error
}

var _ audit.Store = (*History)(nil)

func NewHistory(db HistoryDB) *History { return &History{db: db} }

func (h *History) Write(r audit.Record) error {
	r, raw, err := audit.Encode(r)
	if err != nil {
		return err
	}
	row := historyRow(r, string(raw))
	row.Source = "live"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.db.Run(ctx, func(ctx context.Context, db catalogdb.DB) error { return catalogdb.InsertHistory(ctx, db, row) }); err != nil {
		return fmt.Errorf("history write failed")
	}
	return nil
}

// historyRow derives the indexed columns. r must be the normalized record
// (audit.Encode or audit.ParseLine).
func historyRow(r audit.Record, raw string) catalogdb.HistoryRow {
	row := catalogdb.HistoryRow{OwnerID: r.Owner, EventID: r.EventID, SchemaVersion: r.SchemaVersion, EventType: r.EventType,
		InvocationID: r.InvocationID, ToolID: r.ToolID, Tool: r.Tool, Upstream: r.Upstream, Status: r.Status,
		ActorAccessID: r.ActorAccessID, TSNano: r.TS.UnixNano(), HistoryNano: audit.HistoryTime(r).UnixNano(), Record: raw}
	if r.Timing != nil {
		row.Timed, row.Failed, row.Forwarded = true, r.Status != "ok", r.Timing.Forwarded
		row.HandlerUS, row.GatewayUS, row.UpstreamUS = r.Timing.HandlerUS, r.Timing.GatewayUS, r.Timing.UpstreamUS
		row.HandlerBucket, row.GatewayBucket, row.UpstreamBucket = audit.Bucket(r.Timing.HandlerUS), audit.Bucket(r.Timing.GatewayUS), audit.Bucket(r.Timing.UpstreamUS)
	}
	return row
}

// decodeHistory restores a stored record as the JSONL reader returns it,
// including the derived fields of v0 records.
func decodeHistory(row catalogdb.HistoryRow) (audit.Record, error) {
	var r audit.Record
	if err := json.Unmarshal([]byte(row.Record), &r); err != nil {
		return r, fmt.Errorf("stored history record is invalid")
	}
	if r.SchemaVersion == 0 {
		r.EventID = row.EventID
		r.CompletedAt = r.TS.Add(time.Duration(r.DurationMS) * time.Millisecond)
	}
	if r.EventID != row.EventID || r.Owner != row.OwnerID {
		return r, fmt.Errorf("stored history record is invalid")
	}
	return r, nil
}

func (h *History) QueryHistoryPerformance(q audit.HistoryFilter) ([]audit.Record, int, []audit.ToolRef, audit.Performance, error) {
	var stats audit.Performance
	if q.Page < 1 || q.Size < 1 || q.Page*q.Size > catalogdb.HistoryWindow {
		return nil, 0, nil, stats, fmt.Errorf("invalid pagination")
	}
	query := catalogdb.HistoryQuery{Owner: q.Owner, ToolID: q.ToolID, Status: q.Status, Upstream: q.Upstream, ActorAccessID: q.ActorAccessID,
		HasFrom: !q.From.IsZero(), HasTo: !q.To.IsZero(), Offset: (q.Page - 1) * q.Size, Limit: q.Size}
	if query.HasFrom {
		query.FromNano = q.From.UnixNano()
	}
	if query.HasTo {
		query.ToNano = q.To.UnixNano()
	}
	var result catalogdb.HistoryResult
	err := h.db.ReadHistory(context.Background(), func(ctx context.Context, db catalogdb.DB) error {
		var err error
		result, err = catalogdb.QueryHistory(ctx, db, query)
		return err
	})
	if err != nil {
		return nil, 0, nil, stats, fmt.Errorf("history unavailable")
	}
	out := []audit.Record{}
	for _, row := range result.Records {
		r, err := decodeHistory(row)
		if err != nil {
			return nil, 0, nil, stats, err
		}
		out = append(out, r)
	}
	tools := []audit.ToolRef{}
	for _, t := range result.Tools {
		tools = append(tools, audit.ToolRef{ID: t.ToolID, Name: t.Tool, Upstream: t.Upstream})
	}
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Name == tools[j].Name {
			return tools[i].ID < tools[j].ID
		}
		return tools[i].Name < tools[j].Name
	})
	stats.TimedCalls, stats.FailedCalls, stats.Capped = result.TimedCalls, result.FailedCalls, result.Capped
	stats.Handler = audit.LatencyFromBuckets(result.Handler.Count, result.Handler.Sum, result.Handler.Max, result.Handler.Buckets)
	stats.Gateway = audit.LatencyFromBuckets(result.Gateway.Count, result.Gateway.Sum, result.Gateway.Max, result.Gateway.Buckets)
	stats.Upstream = audit.LatencyFromBuckets(result.Forward.Count, result.Forward.Sum, result.Forward.Max, result.Forward.Buckets)
	return out, result.Total, tools, stats, nil
}
