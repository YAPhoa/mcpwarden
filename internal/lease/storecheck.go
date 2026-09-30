package lease

import (
	"bytes"
	"strconv"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

// Checks every Store applies before writing, so the stores agree on what
// they accept.

// CheckLease verifies a lease against its activated request.
func CheckLease(owner string, l Lease, r Request) error {
	if l.OwnerID != owner || !identity.Valid(l.ID) || !identity.Valid(l.OperationID) {
		return ErrDenied
	}
	if r.State != "activated" || r.LeaseID != l.ID || l.CallerID != r.Scope.RequesterAccessID || l.CredentialID != r.Scope.CredentialID || l.Epoch != r.Scope.CredentialEpoch || l.BootID != r.BootID || l.ScopeDigest != r.ScopeDigest || l.ActivationActorID != r.ApproverID || (l.MaxCalls == nil) != (r.Scope.MaxCalls == nil) || l.MaxCalls != nil && *l.MaxCalls != *r.Scope.MaxCalls || l.ExpiresAt.Sub(l.ActivatedAt) > time.Duration(r.Scope.DurationSeconds)*time.Second {
		return ErrDenied
	}
	if _, err := strconv.ParseInt(l.Epoch, 10, 64); err != nil {
		return ErrDenied
	}
	return nil
}

// eventSources are the authorization sources of activation events and the
// outcomes of a setup window that ended after its one discovery run.
var eventSources = map[string]bool{"": true, "client_activation": true, "owner_confirmation": true, "setup_completed": true, "setup_failed": true}

var eventReasons = map[string]bool{"": true, "key": true, "stale": true, "denied": true, "not_found": true, "locked": true, "api_key": true}

func optionalVersion(v string) bool {
	if v == "" {
		return true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == v
}

// ValidEvent reports whether e is an allowlisted event for owner.
func ValidEvent(owner string, e Event) bool {
	if e.OwnerID != owner || !identity.Valid(e.ID) || !identity.Valid(e.BootID) || e.At.IsZero() || e.ActorID != "" && !identity.Valid(e.ActorID) || !eventSources[e.Source] {
		return false
	}
	return (e.CredentialID == "" || identity.Valid(e.CredentialID)) && (e.SubjectID == "" || identity.Valid(e.SubjectID)) && optionalVersion(e.Epoch) && optionalVersion(e.Revision) &&
		(e.Mode == "" || e.Mode == "none" || e.Mode == "confirm") && eventReasons[e.Reason]
}

// CheckAdmission verifies a dispatch admission against its active lease and
// request at now.
func CheckAdmission(r audit.Record, l Lease, request Request, now time.Time) error {
	if l.State != "active" || !now.Before(l.ExpiresAt) || r.ApprovalID != l.RequestID || r.ActorAccessID != l.CallerID || r.CredentialID != l.CredentialID || r.CredentialEpoch != l.Epoch || r.ScopeDigest != l.ScopeDigest || r.UpstreamID != request.Scope.ConnectorID || r.ApprovalMode != request.Mode || r.ApprovalPolicyRevision != request.ApprovalPolicyRevision || r.AuthorizationSource != request.AuthorizationSource {
		return ErrDenied
	}
	return nil
}

// SameInvocation reports whether a completion carries its admission's
// identity snapshot.
func SameInvocation(completed, admitted audit.Record) bool {
	return bytes.Equal(invocationOrigin(completed), invocationOrigin(admitted))
}

func invocationOrigin(r audit.Record) []byte {
	r.EventID, r.EventType, r.Decision, r.Status = "", "", "", ""
	r.OccurredAt, r.CompletedAt = time.Time{}, time.Time{}
	r.Timing = nil
	r.DurationMS, r.ResponseItems, r.Structured = 0, 0, false
	b, _ := json.Marshal(r)
	return b
}
