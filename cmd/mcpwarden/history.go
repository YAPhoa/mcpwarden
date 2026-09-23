package main

import (
	"github.com/yaphoa/mcpwarden/internal/audit"
	"net/http"
	"strconv"
	"time"
)

func (rs *runtimes) history(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		var err error
		page, err = strconv.Atoi(raw)
		if err != nil || page < 1 || page > 1000 {
			http.Error(w, "invalid page", 400)
			return
		}
	}

	q := audit.HistoryFilter{Owner: requestOwner(r), ActorAccessID: r.URL.Query().Get("actor_access_id"), Upstream: r.URL.Query().Get("upstream"), ToolID: r.URL.Query().Get("tool_id"), Status: r.URL.Query().Get("status"), Page: page, Size: 25}
	switch q.Status {
	case "", "ok", "tool_error", "protocol_error", "timeout", "denied", "unavailable", "unknown", "audit_error":
	default:
		http.Error(w, "invalid status", 400)
		return
	}
	for key, target := range map[string]*time.Time{"from": &q.From, "to": &q.To} {
		if raw := r.URL.Query().Get(key); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				http.Error(w, "invalid time", 400)
				return
			}
			*target = parsed
		}
	}
	if !q.From.IsZero() && !q.To.IsZero() && !q.From.Before(q.To) {
		http.Error(w, "invalid time range", 400)
		return
	}
	rows, total, toolOptions, performance, err := rs.audit.QueryHistoryPerformance(q)
	if err != nil {
		http.Error(w, "history unavailable", 503)
		return
	}
	type item struct {
		EventType     string        `json:"event_type,omitempty"`
		InvocationID  string        `json:"invocation_id,omitempty"`
		OccurredAt    time.Time     `json:"occurred_at,omitzero"`
		ActorType     string        `json:"actor_type,omitempty"`
		ActorAccessID string        `json:"actor_access_id,omitempty"`
		ActorPublicID string        `json:"actor_public_id,omitempty"`
		ActorLabel    string        `json:"actor_label_snapshot,omitempty"`
		EventID       string        `json:"event_id"`
		CompletedAt   time.Time     `json:"completed_at,omitzero"`
		UpstreamID    string        `json:"upstream_id,omitempty"`
		Timing        *audit.Timing `json:"timing,omitempty"`
		TS            time.Time     `json:"ts"`
		Tool          string        `json:"tool"`
		ToolID        string        `json:"tool_id"`
		Upstream      string        `json:"upstream"`
		Status        string        `json:"status"`
		Decision      string        `json:"decision"`
		DurationMS    *int64        `json:"duration_ms,omitempty"`
		ResponseItems *int          `json:"response_items,omitempty"`
		Structured    *bool         `json:"structured,omitempty"`
	}
	out := []item{}
	for _, v := range rows {
		row := item{EventType: v.EventType, InvocationID: v.InvocationID, OccurredAt: v.OccurredAt,
			ActorType: v.ActorType, ActorAccessID: v.ActorAccessID, ActorPublicID: v.ActorPublicID, ActorLabel: v.ActorLabel,
			EventID: v.EventID, CompletedAt: v.CompletedAt, UpstreamID: v.UpstreamID, Timing: v.Timing,
			TS: v.TS, Tool: v.Tool, ToolID: v.ToolID, Upstream: v.Upstream, Status: v.Status, Decision: v.Decision,
		}
		if v.EventType != audit.DispatchAdmitted {
			row.DurationMS, row.ResponseItems, row.Structured = &v.DurationMS, &v.ResponseItems, &v.Structured
		}
		out = append(out, row)
	}
	jsonResponse(w, 200, map[string]any{"items": out, "total": total, "page": page, "page_size": 25, "tools": toolOptions, "performance": performance})
}
