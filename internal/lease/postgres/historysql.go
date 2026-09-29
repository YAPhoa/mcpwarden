package postgres

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
)

// InsertHistory stores one event and, in the same transaction, moves the
// tool list forward and keeps history_open equal to the admissions whose
// completion is not stored. Writes may arrive out of order: an admission
// stored after its completion opens nothing.
func InsertHistory(ctx context.Context, db DB, h catalogdb.HistoryRow) error {
	if err := one(db.Exec(ctx, `INSERT INTO mcpwarden_security.history_events
        (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,
         timed,failed,forwarded,handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
		h.OwnerID, h.EventID, h.SchemaVersion, text(h.EventType), text(h.InvocationID), h.ToolID, h.Tool, h.Upstream, h.Status, h.ActorAccessID,
		h.TSNano, h.HistoryNano, h.Timed, h.Failed, h.Forwarded, h.HandlerUS, h.GatewayUS, h.UpstreamUS,
		h.HandlerBucket, h.GatewayBucket, h.UpstreamBucket, h.Record)); err != nil {
		return err
	}
	switch h.EventType {
	case "tool.dispatch.admitted":
		if _, err := db.Exec(ctx, `INSERT INTO mcpwarden_security.history_open(owner_id,invocation_id,history_ns,event_id)
            SELECT $1,$2,$3,$4 WHERE NOT EXISTS (SELECT 1 FROM mcpwarden_security.history_events
            WHERE owner_id=$1 AND invocation_id=$2 AND event_type='tool.dispatch.completed')`, h.OwnerID, h.InvocationID, h.HistoryNano, h.EventID); err != nil {
			return classify(err)
		}
	case "tool.dispatch.completed":
		if _, err := db.Exec(ctx, `DELETE FROM mcpwarden_security.history_open WHERE owner_id=$1 AND invocation_id=$2`, h.OwnerID, h.InvocationID); err != nil {
			return classify(err)
		}
	}
	// The list shows visible events only. An admission whose completion is
	// stored is hidden, and the completion carries the same name snapshot at a
	// later or equal history time, so skipping hidden admissions changes
	// nothing the forward-only rule would not.
	if h.ToolID == "" {
		return nil
	}
	if _, err := db.Exec(ctx, `INSERT INTO mcpwarden_security.history_tools AS t(owner_id,tool_id,tool,upstream,last_ns,last_event_id)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (owner_id,tool_id) DO UPDATE SET tool=excluded.tool, upstream=excluded.upstream,
        last_ns=excluded.last_ns, last_event_id=excluded.last_event_id
        WHERE (excluded.last_ns, excluded.last_event_id) > (t.last_ns, t.last_event_id)`,
		h.OwnerID, h.ToolID, h.Tool, h.Upstream, h.HistoryNano, h.EventID); err != nil {
		return classify(err)
	}
	return nil
}

// settled matches every event except admissions. The history shows settled
// events and the admissions still in history_open (no completion stored), so
// no page walks the admissions of finished calls. The filter indexes are
// partial on this exact predicate.
const settled = `h.event_type <> 'tool.dispatch.admitted'`

// window builds the newest catalogdb.HistoryWindow+1 matching visible events with
// their position in history order: settled events from the filter's index,
// merged with open admissions from history_open. Each filter that is set adds
// one bound predicate, so the planner can use that filter's index; there are
// no catch-all predicates.
func window(q catalogdb.HistoryQuery) (string, []any) {
	args := []any{q.Owner}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	var filters []string
	if q.Status != "" {
		filters = append(filters, "h.status="+arg(q.Status))
	}
	if q.ActorAccessID != "" {
		filters = append(filters, "h.actor_access_id="+arg(q.ActorAccessID))
	}
	switch q.Upstream {
	case "":
	case "__gateway__":
		filters = append(filters, "h.upstream=''")
	default:
		filters = append(filters, "h.upstream="+arg(q.Upstream))
	}
	if q.ToolID != "" {
		filters = append(filters, "h.tool_id="+arg(q.ToolID))
	}
	rangeOn := func(table string) []string {
		var out []string
		if q.HasFrom {
			out = append(out, table+".history_ns >= "+arg(q.FromNano))
		}
		if q.HasTo {
			out = append(out, table+".history_ns < "+arg(q.ToNano))
		}
		return out
	}
	limit := strconv.Itoa(catalogdb.HistoryWindow + 1)
	done := append(append([]string{"h.owner_id=$1", settled}, filters...), rangeOn("h")...)
	open := append(append([]string{"o.owner_id=$1"}, rangeOn("o")...), filters...)
	return `WITH win AS MATERIALIZED (SELECT w.*, row_number() OVER (ORDER BY w.history_ns DESC, w.event_id COLLATE "C" DESC) AS pos FROM (
        (SELECT h.* FROM mcpwarden_security.history_events h WHERE ` + strings.Join(done, " AND ") + `
         ORDER BY h.history_ns DESC, h.event_id COLLATE "C" DESC LIMIT ` + limit + `)
        UNION ALL
        (SELECT h.* FROM mcpwarden_security.history_open o JOIN mcpwarden_security.history_events h ON h.owner_id=o.owner_id AND h.event_id=o.event_id
         WHERE ` + strings.Join(open, " AND ") + ` ORDER BY o.history_ns DESC, o.event_id COLLATE "C" DESC LIMIT ` + limit + `)
        ) w ORDER BY w.history_ns DESC, w.event_id COLLATE "C" DESC LIMIT ` + limit + `) `, args
}

// QueryHistory returns one page ordered by history time then event ID (byte
// order), the match count and timing aggregates over the newest catalogdb.HistoryWindow
// matches, and the latest name snapshot of each tool the owner has used. The
// page, the count and the timings come from one statement, so the window is
// read once.
func QueryHistory(ctx context.Context, db DB, q catalogdb.HistoryQuery) (catalogdb.HistoryResult, error) {
	var out catalogdb.HistoryResult
	if q.Offset < 0 || q.Limit < 1 || q.Offset+q.Limit > catalogdb.HistoryWindow {
		return out, catalogdb.ErrHistoryWindow
	}
	if q.Owner == "" {
		return out, nil
	}
	with, args := window(q)
	n, w := len(args), strconv.Itoa(catalogdb.HistoryWindow)
	const none = `NULL::text,NULL::text,NULL::int,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::bigint,NULL::bigint,NULL::text`
	in := `FROM win WHERE timed AND pos <= ` + w
	var total int64
	err := each(ctx, db, with+`SELECT 'r', pos, 0::bigint, 0::bigint, 0::bigint, owner_id, event_id, schema_version::int, coalesce(event_type,''), coalesce(invocation_id,''),
        tool_id, tool, upstream, status, actor_access_id, ts_ns, history_ns, record FROM win WHERE pos > $`+strconv.Itoa(n+1)+` AND pos <= $`+strconv.Itoa(n+2)+`
        UNION ALL SELECT 's', count(*), count(*) FILTER (WHERE timed AND pos <= `+w+`), count(*) FILTER (WHERE timed AND failed AND pos <= `+w+`), 0, `+none+` FROM win
        UNION ALL SELECT 'h', handler_bucket, count(*), sum(handler_us)::bigint, max(handler_us), `+none+` `+in+` GROUP BY handler_bucket
        UNION ALL SELECT 'g', gateway_bucket, count(*), sum(gateway_us)::bigint, max(gateway_us), `+none+` `+in+` GROUP BY gateway_bucket
        UNION ALL SELECT 'u', upstream_bucket, count(*), sum(upstream_us)::bigint, max(upstream_us), `+none+` `+in+` AND forwarded GROUP BY upstream_bucket
        ORDER BY 1, 2`, func(r pgx.Rows) error {
		var kind string
		var key, a, b, c int64
		var h struct {
			owner, id, eventType, invocation, toolID, tool, upstream, status, actor, record *string
			version                                                                         *int
			ts, hist                                                                        *int64
		}
		if err := r.Scan(&kind, &key, &a, &b, &c, &h.owner, &h.id, &h.version, &h.eventType, &h.invocation, &h.toolID, &h.tool, &h.upstream, &h.status,
			&h.actor, &h.ts, &h.hist, &h.record); err != nil {
			return catalogdb.ErrStorage
		}
		switch kind {
		case "r":
			if h.owner == nil || h.id == nil || h.version == nil || h.record == nil || h.ts == nil || h.hist == nil {
				return catalogdb.ErrStorage
			}
			out.Records = append(out.Records, catalogdb.HistoryRow{OwnerID: *h.owner, EventID: *h.id, SchemaVersion: *h.version, EventType: *h.eventType,
				InvocationID: *h.invocation, ToolID: *h.toolID, Tool: *h.tool, Upstream: *h.upstream, Status: *h.status, ActorAccessID: *h.actor,
				TSNano: *h.ts, HistoryNano: *h.hist, Record: *h.record})
		case "s":
			total, out.TimedCalls, out.FailedCalls = key, a, b
		case "h", "g", "u":
			if key < 0 || key >= 32 {
				return catalogdb.ErrStorage
			}
			target := &out.Handler
			switch kind {
			case "g":
				target = &out.Gateway
			case "u":
				target = &out.Forward
			}
			target.Count += a
			target.Sum += b
			target.Buckets[key] += a
			if c > target.Max {
				target.Max = c
			}
		}
		return nil
	}, append(args, int64(q.Offset), int64(q.Offset+q.Limit))...)
	if err != nil {
		return catalogdb.HistoryResult{}, err
	}
	out.Total, out.Capped = int(min(total, catalogdb.HistoryWindow)), total > catalogdb.HistoryWindow
	err = each(ctx, db, `SELECT tool_id,tool,upstream FROM mcpwarden_security.history_tools WHERE owner_id=$1 ORDER BY tool_id`, func(r pgx.Rows) error {
		var h catalogdb.HistoryRow
		if err := r.Scan(&h.ToolID, &h.Tool, &h.Upstream); err != nil {
			return catalogdb.ErrStorage
		}
		out.Tools = append(out.Tools, h)
		return nil
	}, q.Owner)
	if err != nil {
		return catalogdb.HistoryResult{}, err
	}
	return out, nil
}
