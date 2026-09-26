package audit

import (
	"bufio"
	"bytes"
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

// Timing measures the proxy handler excluding audit persistence and response encoding.
// Upstream includes SDK serialization, transport, remote execution and decoding.
// AdmissionUS reports the separate pre-dispatch persistence cost.
type Timing struct {
	HandlerUS   int64 `json:"handler_us"`
	UpstreamUS  int64 `json:"upstream_us"`
	GatewayUS   int64 `json:"gateway_us"`
	Forwarded   bool  `json:"forwarded"`
	AdmissionUS int64 `json:"admission_us,omitempty"`
}

type Record struct {
	CredentialID           string    `json:"credential_id,omitempty"`
	CredentialEpoch        string    `json:"credential_epoch,omitempty"`
	CredentialRevision     string    `json:"credential_revision,omitempty"`
	ApprovalID             string    `json:"approval_id,omitempty"`
	LeaseID                string    `json:"lease_id,omitempty"`
	ScopeDigest            string    `json:"scope_digest,omitempty"`
	ApprovalMode           string    `json:"approval_mode,omitempty"`
	ApprovalPolicyRevision string    `json:"approval_policy_revision,omitempty"`
	AuthorizationSource    string    `json:"authorization_source,omitempty"`
	VerificationMethod     string    `json:"verification_method,omitempty"`
	EventType              string    `json:"event_type,omitempty"`
	InvocationID           string    `json:"invocation_id,omitempty"`
	OccurredAt             time.Time `json:"occurred_at,omitzero"`
	ActorType              string    `json:"actor_type,omitempty"`
	ActorAccessID          string    `json:"actor_access_id,omitempty"`
	ActorPublicID          string    `json:"actor_public_id,omitempty"`
	ActorLabel             string    `json:"actor_label_snapshot,omitempty"`
	ArgsHashVersion        string    `json:"argument_hash_version,omitempty"`
	SchemaVersion          int       `json:"schema_version"`
	EventID                string    `json:"event_id"`
	CompletedAt            time.Time `json:"completed_at,omitzero"`
	UpstreamID             string    `json:"upstream_id,omitempty"`
	Timing                 *Timing   `json:"timing,omitempty"`
	Owner                  string    `json:"owner,omitempty"`
	ToolID                 string    `json:"tool_id,omitempty"`
	ResponseItems          int       `json:"response_items"`
	Structured             bool      `json:"structured"`
	TS                     time.Time `json:"ts"`
	Session                string    `json:"session"`
	Tool                   string    `json:"tool"`
	Upstream               string    `json:"upstream"`
	ArgsSHA256             string    `json:"args_sha256"`
	Decision               string    `json:"decision"`
	Status                 string    `json:"status"`
	DurationMS             int64     `json:"duration_ms"`
}

// Appender persists immutable events. A successful DispatchAdmitted write MUST
// be durable before returning; a sink that cannot guarantee this must reject it.
// Callers retain EventID on storage retries. An uncertain write must never cause
// dispatch or a retry of the tool itself.
type Appender interface{ Write(Record) error }

type Reader interface {
	QueryHistoryPerformance(HistoryFilter) ([]Record, int, []ToolRef, Performance, error)
}

type Store interface {
	Appender
	Reader
}

// NewRecord assigns identity before persistence so it survives storage retries.
func NewRecord() Record {
	return Record{SchemaVersion: 1, EventID: identity.New(), TS: time.Now().UTC()}
}

type Writer struct {
	mu     sync.Mutex
	out    io.Writer
	file   *os.File
	path   string
	failed error
}

func Open(path string) (*Writer, error) {
	if path == "" {
		return &Writer{out: io.Discard}, nil
	}
	if path == "-" {
		return &Writer{out: os.Stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	w := &Writer{out: f, file: f, path: path}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("audit log must be a regular file")
	}
	if err == nil && info.Size() > 0 {
		var last [1]byte
		_, err = f.ReadAt(last[:], info.Size()-1)
		if err == nil && last[0] != '\n' {
			err = fmt.Errorf("audit log has an unterminated final record")
		}
	}
	if err == nil {
		_, _, _, err = w.QueryHistory(HistoryFilter{Page: 1, Size: 1})
	}
	// Persist the directory entry too, so a newly created log cannot disappear
	// after an admission has been synced and its tool has executed.
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		var dir *os.File
		dir, err = os.Open(filepath.Dir(path))
		if err == nil {
			err = dir.Sync()
			_ = dir.Close()
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return w, nil
}

// Encode applies the writer's defaults and validation and returns the exact
// bytes every history backend stores for a new event.
func Encode(r Record) (Record, []byte, error) {
	if r.SchemaVersion == 0 {
		r.SchemaVersion = 1
	}
	if r.SchemaVersion != 1 && r.SchemaVersion != 2 {
		return r, nil, fmt.Errorf("unsupported audit schema version")
	}
	if r.EventID == "" {
		r.EventID = identity.New()
	}
	if r.CompletedAt.IsZero() && r.EventType != DispatchAdmitted {
		r.CompletedAt = time.Now().UTC()
	}
	if r.SchemaVersion == 2 {
		if r.OccurredAt.IsZero() {
			r.OccurredAt = r.CompletedAt
		}
		if err := validateInvocationEvent(r); err != nil {
			return r, nil, err
		}
	} else if r.EventType != "" || r.InvocationID != "" {
		return r, nil, fmt.Errorf("invocation events require audit schema 2")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return r, nil, err
	}
	if len(b) >= 1<<20-1 {
		return r, nil, fmt.Errorf("audit record exceeds JSONL size limit")
	}
	return r, b, nil
}

func (w *Writer) Write(r Record) error {
	r, b, err := Encode(r)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return w.failed
	}
	if r.EventType == DispatchAdmitted && w.file == nil {
		return fmt.Errorf("durable admission requires an open audit file")
	}
	b = append(b, '\n')
	n, err := w.out.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil && w.file != nil {
		err = w.file.Sync()
	}
	// Stop after uncertain persistence, avoiding appends onto a partial record.
	w.failed = err
	return err
}
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Sync()
	err2 := w.file.Close()
	w.file = nil
	if err != nil {
		return err
	}
	return err2
}
func HashArgs(args any) string {
	b, _ := json.Marshal(args)
	var value any
	if json.Unmarshal(b, &value) == nil {
		b, _ = json.Marshal(value)
	} // sorted keys, including RawMessage.
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// History reads metadata for one owner only. Old records without an owner are
// never attributed to a user. Keep only enough recent matches for this page.

type HistoryFilter struct {
	Owner, ToolID, Status, Upstream string
	ActorAccessID                   string
	From, To                        time.Time
	Page, Size                      int
}
type ToolRef struct {
	Upstream string `json:"upstream"`
	ID       string `json:"id"`
	Name     string `json:"name"`
}

func (w *Writer) History(owner, toolID string, page, size int) ([]Record, int, error) {
	rows, total, _, err := w.QueryHistory(HistoryFilter{Owner: owner, ToolID: toolID, Page: page, Size: size})
	return rows, total, err
}
func (w *Writer) QueryHistory(q HistoryFilter) ([]Record, int, []ToolRef, error) {
	return w.queryHistory(q, nil)
}

func (w *Writer) QueryHistoryPerformance(q HistoryFilter) ([]Record, int, []ToolRef, Performance, error) {
	var stats Performance
	rows, total, refs, err := w.queryHistory(q, &stats)
	return rows, total, refs, stats, err
}

func (w *Writer) queryHistory(q HistoryFilter, stats *Performance) ([]Record, int, []ToolRef, error) {
	if q.Page < 1 || q.Page > 1000 || q.Size < 1 || q.Size > 100 {
		return nil, 0, nil, fmt.Errorf("invalid pagination")
	}
	if w.path == "" {
		return nil, 0, nil, fmt.Errorf("persistent audit history is not configured")
	}
	f, err := os.Open(w.path)
	if err != nil {
		return nil, 0, nil, err
	}
	defer f.Close()
	capacity := q.Page * q.Size
	recent := recordHeap{}
	total := 0
	refs := map[string]ToolRef{}
	latest := map[string]Record{}
	// Normal append order retains only unresolved calls. The second map also
	// handles completion-before-admission imports without relying on log order.
	pending := map[string]Record{}
	completedBeforeAdmission := map[string]bool{}
	consider := func(r Record) {
		if old, ok := latest[r.ToolID]; r.ToolID != "" && (!ok || older(old, r)) {
			refs[r.ToolID] = ToolRef{ID: r.ToolID, Name: r.Tool, Upstream: r.Upstream}
			latest[r.ToolID] = r
		}
		if (q.ActorAccessID != "" && r.ActorAccessID != q.ActorAccessID) || (q.Upstream != "" && !((q.Upstream == "__gateway__" && r.Upstream == "") || q.Upstream == r.Upstream)) || (q.ToolID != "" && r.ToolID != q.ToolID) || (q.Status != "" && r.Status != q.Status) || (!q.From.IsZero() && HistoryTime(r).Before(q.From)) || (!q.To.IsZero() && !HistoryTime(r).Before(q.To)) {
			return
		}
		if stats != nil {
			stats.observe(r)
		}
		if len(recent) < capacity {
			heap.Push(&recent, r)
		} else if older(recent[0], r) {
			recent[0] = r
			heap.Fix(&recent, 0)
		}
		total++
	}
	// Readers must not observe a partially written event from this writer.
	w.mu.Lock()
	defer w.mu.Unlock()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		r, err := ParseLine(line, scanner.Bytes())
		if err != nil {
			return nil, 0, nil, err
		}
		if r.Owner != q.Owner || q.Owner == "" {
			continue
		}
		if r.EventType == DispatchAdmitted {
			if completedBeforeAdmission[r.InvocationID] {
				delete(completedBeforeAdmission, r.InvocationID)
			} else {
				pending[r.InvocationID] = r
			}
			continue
		}
		if r.EventType == DispatchCompleted {
			if _, exists := pending[r.InvocationID]; exists {
				delete(pending, r.InvocationID)
			} else {
				completedBeforeAdmission[r.InvocationID] = true
			}
		}
		consider(r)
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, nil, err
	}
	for _, r := range pending {
		// An admission proves neither network dispatch nor completion. Never
		// fabricate a completion timestamp, response, failure, or safe retry.
		consider(r)
	}
	out := []Record{}
	sort.Slice(recent, func(i, j int) bool { return older(recent[j], recent[i]) })
	for i := (q.Page - 1) * q.Size; i < capacity && i < total; i++ {
		out = append(out, recent[i])
	}
	options := []ToolRef{}
	for _, ref := range refs {
		options = append(options, ref)
	}
	sort.Slice(options, func(i, j int) bool {
		if options[i].Name == options[j].Name {
			return options[i].ID < options[j].ID
		}
		return options[i].Name < options[j].Name
	})
	return out, total, options, nil
}

// ParseLine decodes one JSONL line (without its line terminator) exactly as the
// history reader does, including the v0 event ID derived from the line number
// and raw bytes. line counts from 1.
func ParseLine(line int, raw []byte) (Record, error) {
	var r Record
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(trimmed, &r) != nil {
		return r, fmt.Errorf("invalid audit record at line %d", line)
	}
	if r.SchemaVersion < 0 || r.SchemaVersion > 2 {
		return r, fmt.Errorf("unsupported audit schema at line %d", line)
	}
	if r.SchemaVersion == 0 {
		// Stable for repeated imports of this unchanged source file. Keep v0.
		r.EventID = identity.Derive(identity.Namespace, fmt.Sprintf("audit-v0:%d:%s", line, raw))
		r.CompletedAt = r.TS.Add(time.Duration(r.DurationMS) * time.Millisecond)
	} else if r.SchemaVersion == 2 {
		if err := validateInvocationEvent(r); err != nil {
			return r, fmt.Errorf("invalid invocation event at line %d", line)
		}
	} else if r.EventID == "" || r.CompletedAt.IsZero() || r.EventType != "" || r.InvocationID != "" {
		return r, fmt.Errorf("incomplete audit record at line %d", line)
	}
	return r, nil
}

// HistoryTime is the ordering time: completion, or occurrence for an
// unresolved admission.
func HistoryTime(r Record) time.Time { return historyTime(r) }

// History ordering is completed_at DESC, event_id DESC, independent of ingestion.
func older(a, b Record) bool {
	if historyTime(a).Equal(historyTime(b)) {
		return a.EventID < b.EventID
	}
	return historyTime(a).Before(historyTime(b))
}

func historyTime(r Record) time.Time {
	if r.EventType == DispatchAdmitted {
		return r.OccurredAt
	}
	return r.CompletedAt
}

type recordHeap []Record

func (h recordHeap) Len() int           { return len(h) }
func (h recordHeap) Less(i, j int) bool { return older(h[i], h[j]) }
func (h recordHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *recordHeap) Push(v any)        { *h = append(*h, v.(Record)) }
func (h *recordHeap) Pop() any          { a := *h; v := a[len(a)-1]; *h = a[:len(a)-1]; return v }
