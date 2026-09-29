package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// Encode applies the defaults and validation and returns the exact bytes every
// history backend stores for a new event. Only schema 2 invocation events are
// stored.
func Encode(r Record) (Record, []byte, error) {
	if r.SchemaVersion != 2 {
		return r, nil, fmt.Errorf("unsupported audit schema version")
	}
	if r.EventID == "" {
		r.EventID = identity.New()
	}
	if r.CompletedAt.IsZero() && r.EventType != DispatchAdmitted {
		r.CompletedAt = time.Now().UTC()
	}
	if r.OccurredAt.IsZero() {
		r.OccurredAt = r.CompletedAt
	}
	if err := validateInvocationEvent(r); err != nil {
		return r, nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return r, nil, err
	}
	if len(b) >= 1<<20-1 {
		return r, nil, fmt.Errorf("audit record exceeds the size limit")
	}
	return r, b, nil
}

// HashArgs is the canonical argument hash stored in audit records. Its bytes
// must not change.
func HashArgs(args any) string {
	b, _ := json.Marshal(args)
	var value any
	if json.Unmarshal(b, &value) == nil {
		b, _ = json.Marshal(value)
	} // sorted keys, including RawMessage.
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

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

// HistoryTime is the ordering time: completion, or occurrence for an
// unresolved admission.
func HistoryTime(r Record) time.Time { return historyTime(r) }

func historyTime(r Record) time.Time {
	if r.EventType == DispatchAdmitted {
		return r.OccurredAt
	}
	return r.CompletedAt
}
