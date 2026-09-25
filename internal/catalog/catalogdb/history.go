package catalogdb

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// HistoryRow is one tool-call history event. Record is the exact stored JSON;
// the other fields are derived from it for filtering, ordering and summaries.
type HistoryRow struct {
	OwnerID, EventID                 string
	SchemaVersion                    int
	EventType, InvocationID          string
	ToolID, Tool, Upstream, Status   string
	ActorAccessID                    string
	TSNano, HistoryNano              int64
	Timed, Failed, Forwarded         bool
	HandlerUS, GatewayUS, UpstreamUS int64
	HandlerBucket, GatewayBucket     int
	UpstreamBucket                   int
	Record                           string
	Source                           string // legacy or live
	SourceLine                       int64
}

func InsertHistory(ctx context.Context, db DB, h HistoryRow) error {
	var line any
	if h.Source == "legacy" {
		line = h.SourceLine
	}
	return one(db.Exec(ctx, `INSERT INTO mcpwarden_security.history_events
        (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,
         timed,failed,forwarded,handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record,source,source_line)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,
		h.OwnerID, h.EventID, h.SchemaVersion, text(h.EventType), text(h.InvocationID), h.ToolID, h.Tool, h.Upstream, h.Status, h.ActorAccessID,
		h.TSNano, h.HistoryNano, h.Timed, h.Failed, h.Forwarded, h.HandlerUS, h.GatewayUS, h.UpstreamUS,
		h.HandlerBucket, h.GatewayBucket, h.UpstreamBucket, h.Record, h.Source, line))
}

// HistoryQuery mirrors audit.HistoryFilter; Upstream "__gateway__" selects
// gateway management tools. Zero times are unbounded.
type HistoryQuery struct {
	Owner, ToolID, Status, Upstream, ActorAccessID string
	FromNano, ToNano                               int64
	HasFrom, HasTo                                 bool
	Offset, Limit                                  int
}

type LatencyAggregate struct {
	Count, Sum, Max int64
	Buckets         [32]int64
}

type HistoryResult struct {
	Records                   []HistoryRow
	Total                     int
	Tools                     []HistoryRow // ToolID, Tool, Upstream only
	TimedCalls, FailedCalls   int64
	Handler, Gateway, Forward LatencyAggregate
}

// visible is every event an owner's history shows: all events except an
// admission whose completion is also stored.
const visible = `SELECT h.* FROM mcpwarden_security.history_events h WHERE h.owner_id=$1 AND NOT (h.event_type='tool.dispatch.admitted'
    AND EXISTS (SELECT 1 FROM mcpwarden_security.history_events c WHERE c.owner_id=h.owner_id AND c.invocation_id=h.invocation_id
    AND c.event_type='tool.dispatch.completed'))`

const matching = `SELECT * FROM visible v WHERE ($2='' OR v.actor_access_id=$2)
    AND ($3='' OR ($3='__gateway__' AND v.upstream='') OR v.upstream=$3)
    AND ($4='' OR v.tool_id=$4) AND ($5='' OR v.status=$5)
    AND (NOT $6 OR v.ts_ns >= $7) AND (NOT $8 OR v.ts_ns < $9)`

// QueryHistory returns one page ordered by history time then event ID
// (byte order), the total match count, timing aggregates over every match and
// the latest name snapshot of each tool across all of the owner's history.
func QueryHistory(ctx context.Context, db DB, q HistoryQuery) (HistoryResult, error) {
	var out HistoryResult
	if q.Owner == "" {
		return out, nil
	}
	args := []any{q.Owner, q.ActorAccessID, q.Upstream, q.ToolID, q.Status, q.HasFrom, q.FromNano, q.HasTo, q.ToNano}
	with := "WITH visible AS (" + visible + "), matching AS (" + matching + ") "
	err := each(ctx, db, with+`SELECT owner_id,event_id,schema_version,coalesce(event_type,''),coalesce(invocation_id,''),tool_id,tool,upstream,status,
        actor_access_id,ts_ns,history_ns,record FROM matching ORDER BY history_ns DESC, event_id COLLATE "C" DESC OFFSET $10 LIMIT $11`, func(r pgx.Rows) error {
		var h HistoryRow
		if err := r.Scan(&h.OwnerID, &h.EventID, &h.SchemaVersion, &h.EventType, &h.InvocationID, &h.ToolID, &h.Tool, &h.Upstream, &h.Status,
			&h.ActorAccessID, &h.TSNano, &h.HistoryNano, &h.Record); err != nil {
			return err
		}
		out.Records = append(out.Records, h)
		return nil
	}, append(args, q.Offset, q.Limit)...)
	if err != nil {
		return HistoryResult{}, err
	}
	if err := db.QueryRow(ctx, with+`SELECT count(*), count(*) FILTER (WHERE timed), count(*) FILTER (WHERE timed AND failed) FROM matching`, args...).
		Scan(&out.Total, &out.TimedCalls, &out.FailedCalls); err != nil {
		return HistoryResult{}, ErrStorage
	}
	err = each(ctx, db, with+`SELECT 'h', handler_bucket, count(*), sum(handler_us), max(handler_us) FROM matching WHERE timed GROUP BY handler_bucket
        UNION ALL SELECT 'g', gateway_bucket, count(*), sum(gateway_us), max(gateway_us) FROM matching WHERE timed GROUP BY gateway_bucket
        UNION ALL SELECT 'u', upstream_bucket, count(*), sum(upstream_us), max(upstream_us) FROM matching WHERE timed AND forwarded GROUP BY upstream_bucket`, func(r pgx.Rows) error {
		var metric string
		var bucket int
		var count, sum, max int64
		if err := r.Scan(&metric, &bucket, &count, &sum, &max); err != nil {
			return ErrStorage
		}
		target := &out.Handler
		switch metric {
		case "g":
			target = &out.Gateway
		case "u":
			target = &out.Forward
		}
		target.Count += count
		target.Sum += sum
		target.Buckets[bucket] += count
		if max > target.Max {
			target.Max = max
		}
		return nil
	}, args...)
	if err != nil {
		return HistoryResult{}, err
	}
	err = each(ctx, db, `WITH visible AS (`+visible+`) SELECT DISTINCT ON (tool_id) tool_id,tool,upstream FROM visible WHERE tool_id<>''
        ORDER BY tool_id, history_ns DESC, event_id COLLATE "C" DESC`, func(r pgx.Rows) error {
		var h HistoryRow
		if err := r.Scan(&h.ToolID, &h.Tool, &h.Upstream); err != nil {
			return ErrStorage
		}
		out.Tools = append(out.Tools, h)
		return nil
	}, q.Owner)
	if err != nil {
		return HistoryResult{}, err
	}
	return out, nil
}

// LegacyHistory streams imported rows in source line order, for verification.
func LegacyHistory(ctx context.Context, db DB, fn func(line int64, record string) error) error {
	return each(ctx, db, `SELECT source_line,record FROM mcpwarden_security.history_events WHERE source='legacy' ORDER BY source_line`, func(r pgx.Rows) error {
		var line int64
		var record string
		if err := r.Scan(&line, &record); err != nil {
			return ErrStorage
		}
		return fn(line, record)
	})
}

// LiveHistory streams events the PostgreSQL gateway wrote, in insertion order.
func LiveHistory(ctx context.Context, db DB, fn func(seq int64, record string) error) error {
	return each(ctx, db, `SELECT seq,record FROM mcpwarden_security.history_events WHERE source='live' ORDER BY seq`, func(r pgx.Rows) error {
		var seq int64
		var record string
		if err := r.Scan(&seq, &record); err != nil {
			return ErrStorage
		}
		return fn(seq, record)
	})
}
