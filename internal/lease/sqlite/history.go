package sqlite

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// historyDeadline bounds one history page, from waiting for a read
// connection to the last row.
var historyDeadline = 5 * time.Second

// InsertHistory stores one event in its own IMMEDIATE transaction on the
// executor, so a successful admission is durable before dispatch. In the same
// transaction it moves the tool list forward and keeps history_open equal to
// the admissions whose completion is not stored. Writes may arrive out of
// order: an admission stored after its completion opens nothing.
func (s *Store) InsertHistory(ctx context.Context, h catalogdb.HistoryRow) error {
	return s.run(ctx, ownerDeadline, func(t *tx) error { return insertHistory(t, h) })
}

func insertHistory(t *tx, h catalogdb.HistoryRow) error {
	if err := one(t.exec(`INSERT INTO history_events
        (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,
         timed,failed,forwarded,handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
		h.OwnerID, h.EventID, h.SchemaVersion, optText(h.EventType), optText(h.InvocationID), h.ToolID, h.Tool, h.Upstream, h.Status, h.ActorAccessID,
		h.TSNano, h.HistoryNano, h.Timed, h.Failed, h.Forwarded, h.HandlerUS, h.GatewayUS, h.UpstreamUS,
		h.HandlerBucket, h.GatewayBucket, h.UpstreamBucket, h.Record)); err != nil {
		return err
	}
	switch h.EventType {
	case "tool.dispatch.admitted":
		if _, err := t.exec(`INSERT INTO history_open(owner_id,invocation_id,history_ns,event_id)
            SELECT $1,$2,$3,$4 WHERE NOT EXISTS (SELECT 1 FROM history_events
            WHERE owner_id=$1 AND invocation_id=$2 AND event_type='tool.dispatch.completed')`, h.OwnerID, h.InvocationID, h.HistoryNano, h.EventID); err != nil {
			return catalogError(err)
		}
	case "tool.dispatch.completed":
		if _, err := t.exec(`DELETE FROM history_open WHERE owner_id=$1 AND invocation_id=$2`, h.OwnerID, h.InvocationID); err != nil {
			return catalogError(err)
		}
	}
	// The list shows visible events only; see the PostgreSQL store.
	if h.ToolID == "" {
		return nil
	}
	if _, err := t.exec(`INSERT INTO history_tools AS t(owner_id,tool_id,tool,upstream,last_ns,last_event_id)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (owner_id,tool_id) DO UPDATE SET tool=excluded.tool, upstream=excluded.upstream,
        last_ns=excluded.last_ns, last_event_id=excluded.last_event_id
        WHERE (excluded.last_ns, excluded.last_event_id) > (t.last_ns, t.last_event_id)`,
		h.OwnerID, h.ToolID, h.Tool, h.Upstream, h.HistoryNano, h.EventID); err != nil {
		return catalogError(err)
	}
	return nil
}

// settled matches every event except admissions. The filter indexes are
// partial on this exact predicate, which SQLite matches term by term.
const settled = `(h.event_type IS NULL OR h.event_type <> 'tool.dispatch.admitted')`

// window builds the newest HistoryWindow+1 matching visible events with their
// position in history order, as the PostgreSQL store does: settled events
// from the filter's index merged with open admissions. It is MATERIALIZED, so
// the whole index scan happens in the statement's first step, where the page
// deadline interrupts it: modernc stops a statement only before its first
// row.
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
	return `WITH win AS MATERIALIZED (SELECT w.*, row_number() OVER (ORDER BY w.history_ns DESC, w.event_id DESC) AS pos FROM (
        SELECT * FROM (SELECT h.* FROM history_events h WHERE ` + strings.Join(done, " AND ") + `
         ORDER BY h.history_ns DESC, h.event_id DESC LIMIT ` + limit + `)
        UNION ALL
        SELECT * FROM (SELECT h.* FROM history_open o JOIN history_events h ON h.owner_id=o.owner_id AND h.event_id=o.event_id
         WHERE ` + strings.Join(open, " AND ") + ` ORDER BY o.history_ns DESC, o.event_id DESC LIMIT ` + limit + `)
        ) w ORDER BY w.history_ns DESC, w.event_id DESC LIMIT ` + limit + `) `, args
}

// QueryHistory returns one page ordered by history time then event ID (byte
// order), the match count and timing aggregates over the newest
// HistoryWindow matches, and the latest name snapshot of each tool, all from
// one read transaction on the read pool. A failed page never fails the store.
func (s *Store) QueryHistory(ctx context.Context, q catalogdb.HistoryQuery) (catalogdb.HistoryResult, error) {
	var out catalogdb.HistoryResult
	if q.Offset < 0 || q.Limit < 1 || q.Offset+q.Limit > catalogdb.HistoryWindow {
		return out, catalogdb.ErrHistoryWindow
	}
	select {
	case <-s.lost:
		return out, lease.ErrLocked
	default:
	}
	if q.Owner == "" {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, historyDeadline)
	defer cancel()
	defer context.AfterFunc(s.ctx, cancel)()
	tx, err := s.reads.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, catalogdb.ErrStorage
	}
	defer tx.Rollback()
	with, args := window(q)
	n, w := len(args), strconv.Itoa(catalogdb.HistoryWindow)
	const none = `NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL`
	in := `FROM win WHERE timed AND pos <= ` + w
	rows, err := tx.QueryContext(ctx, with+`SELECT 'r', pos, 0, 0, 0, owner_id, event_id, schema_version, coalesce(event_type,''), coalesce(invocation_id,''),
        tool_id, tool, upstream, status, actor_access_id, ts_ns, history_ns, record FROM win WHERE pos > $`+strconv.Itoa(n+1)+` AND pos <= $`+strconv.Itoa(n+2)+`
        UNION ALL SELECT 's', count(*), count(*) FILTER (WHERE timed AND pos <= `+w+`), count(*) FILTER (WHERE timed AND failed AND pos <= `+w+`), 0, `+none+` FROM win
        UNION ALL SELECT 'h', handler_bucket, count(*), sum(handler_us), max(handler_us), `+none+` `+in+` GROUP BY handler_bucket
        UNION ALL SELECT 'g', gateway_bucket, count(*), sum(gateway_us), max(gateway_us), `+none+` `+in+` GROUP BY gateway_bucket
        UNION ALL SELECT 'u', upstream_bucket, count(*), sum(upstream_us), max(upstream_us), `+none+` `+in+` AND forwarded GROUP BY upstream_bucket
        ORDER BY 1, 2`, append(args, int64(q.Offset), int64(q.Offset+q.Limit))...)
	if err != nil {
		return catalogdb.HistoryResult{}, catalogdb.ErrStorage
	}
	var total int64
	for rows.Next() {
		var kind string
		var key, a, b, c int64
		var h struct {
			owner, id, eventType, invocation, toolID, tool, upstream, status, actor, record *string
			version                                                                         *int
			ts, hist                                                                        *int64
		}
		if err := rows.Scan(&kind, &key, &a, &b, &c, &h.owner, &h.id, &h.version, &h.eventType, &h.invocation, &h.toolID, &h.tool, &h.upstream, &h.status,
			&h.actor, &h.ts, &h.hist, &h.record); err != nil {
			rows.Close()
			return catalogdb.HistoryResult{}, catalogdb.ErrStorage
		}
		switch kind {
		case "r":
			if h.owner == nil || h.id == nil || h.version == nil || h.record == nil || h.ts == nil || h.hist == nil {
				rows.Close()
				return catalogdb.HistoryResult{}, catalogdb.ErrStorage
			}
			out.Records = append(out.Records, catalogdb.HistoryRow{OwnerID: *h.owner, EventID: *h.id, SchemaVersion: *h.version, EventType: *h.eventType,
				InvocationID: *h.invocation, ToolID: *h.toolID, Tool: *h.tool, Upstream: *h.upstream, Status: *h.status, ActorAccessID: *h.actor,
				TSNano: *h.ts, HistoryNano: *h.hist, Record: *h.record})
		case "s":
			total, out.TimedCalls, out.FailedCalls = key, a, b
		case "h", "g", "u":
			if key < 0 || key >= 32 {
				rows.Close()
				return catalogdb.HistoryResult{}, catalogdb.ErrStorage
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
	}
	if rows.Err() != nil || rows.Close() != nil {
		return catalogdb.HistoryResult{}, catalogdb.ErrStorage
	}
	out.Total, out.Capped = int(min(total, catalogdb.HistoryWindow)), total > catalogdb.HistoryWindow
	rows, err = tx.QueryContext(ctx, `SELECT tool_id,tool,upstream FROM history_tools WHERE owner_id=$1 ORDER BY tool_id`, q.Owner)
	if err != nil {
		return catalogdb.HistoryResult{}, catalogdb.ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var h catalogdb.HistoryRow
		if err := rows.Scan(&h.ToolID, &h.Tool, &h.Upstream); err != nil {
			return catalogdb.HistoryResult{}, catalogdb.ErrStorage
		}
		out.Tools = append(out.Tools, h)
	}
	if rows.Err() != nil || ctx.Err() != nil {
		return catalogdb.HistoryResult{}, catalogdb.ErrStorage
	}
	return out, nil
}
