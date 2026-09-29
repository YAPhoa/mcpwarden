package catalogdb

import "errors"

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
}

// HistoryWindow is the most events a history query reads: the newest this
// many matching visible events. It equals the page limit (1,000 pages of 25).
const HistoryWindow = 25000

// HistoryQuery mirrors audit.HistoryFilter; Upstream "__gateway__" selects
// gateway management tools. Time bounds apply to history time and zero times
// are unbounded. Offset plus Limit must stay within HistoryWindow.
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

// HistoryResult covers the window: Total counts at most HistoryWindow matches
// and Capped reports that more exist; timings cover the same window.
type HistoryResult struct {
	Records                   []HistoryRow
	Total                     int
	Capped                    bool
	Tools                     []HistoryRow // ToolID, Tool, Upstream only
	TimedCalls, FailedCalls   int64
	Handler, Gateway, Forward LatencyAggregate
}

// ErrHistoryWindow refuses a page that ends beyond the window.
var ErrHistoryWindow = errors.New("history page is beyond the newest 25,000 calls")
