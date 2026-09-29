package audit

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

const (
	DispatchAdmitted  = "tool.dispatch.admitted"
	DispatchCompleted = "tool.dispatch.completed"
	DispatchDenied    = "tool.dispatch.denied"
	ArgumentHashV1    = "mcpwarden.arguments.v1"
)

// NewInvocation defaults to no admission. Callers select DispatchCompleted only
// after the corresponding admission has been durably persisted.
func NewInvocation(ctx context.Context, owner string) Record {
	r := Record{SchemaVersion: 2, EventID: identity.New(), InvocationID: identity.New(),
		TS: time.Now().UTC(), Owner: owner, EventType: DispatchDenied,
		ActorType: "unattributed", ArgsHashVersion: ArgumentHashV1}
	if a, ok := identity.ActorFrom(ctx); ok && a.Owner == owner {
		r.ActorType, r.ActorAccessID, r.ActorPublicID, r.ActorLabel = a.Kind, a.AccessID, a.PublicID, a.Label
	}
	return r
}

// Admission takes an immutable identity snapshot without any response/timing
// claims. Reuse the invocation ID, but give each event its own persistent ID.
func (r Record) Admission() Record {
	r.EventID = identity.New()
	r.EventType = DispatchAdmitted
	r.OccurredAt = time.Now().UTC()
	r.CompletedAt = time.Time{}
	r.Decision, r.Status = "allow", "unknown"
	r.Timing, r.DurationMS, r.ResponseItems, r.Structured = nil, 0, 0, false
	return r
}

// ValidateInvocation applies the event contract to the history stores.
func ValidateInvocation(r Record) error {
	if r.SchemaVersion != 2 {
		return fmt.Errorf("invalid audit invocation event")
	}
	return validateInvocationEvent(r)
}

func validateInvocationEvent(r Record) error {
	invalid := func() error { return fmt.Errorf("invalid audit invocation event") }
	if !identity.Valid(r.EventID) || !identity.Valid(r.InvocationID) || r.Owner == "" || r.ToolID == "" || r.Tool == "" || r.TS.IsZero() || r.OccurredAt.IsZero() || r.ArgsHashVersion != ArgumentHashV1 {
		return invalid()
	}
	if hash, err := hex.DecodeString(r.ArgsSHA256); err != nil || len(hash) != 32 {
		return invalid()
	}
	switch r.ActorType {
	case "api_key", "browser":
		if r.ActorAccessID == "" {
			return invalid()
		}
	case "oauth", "operator", "stdio", "unattributed":
	default:
		return invalid()
	}
	if r.ActorPublicID != "" && !identity.ValidPublicID(r.ActorPublicID) {
		return invalid()
	}
	if r.CredentialID != "" || r.CredentialEpoch != "" || r.CredentialRevision != "" || r.ApprovalID != "" || r.LeaseID != "" || r.ScopeDigest != "" || r.ApprovalMode != "" || r.ApprovalPolicyRevision != "" || r.AuthorizationSource != "" || r.VerificationMethod != "" {
		version := func(s string) bool {
			n, err := strconv.ParseInt(s, 10, 64)
			return err == nil && n > 0 && strconv.FormatInt(n, 10) == s
		}
		hash, err := base64.RawURLEncoding.Strict().DecodeString(r.ScopeDigest)
		if !identity.Valid(r.CredentialID) || !identity.Valid(r.ApprovalID) || !identity.Valid(r.LeaseID) || !identity.Valid(r.ToolID) || !identity.Valid(r.UpstreamID) || !identity.Valid(r.ActorAccessID) || !identity.ValidPublicID(r.ActorPublicID) || r.ActorType != "api_key" || !version(r.CredentialEpoch) || !version(r.CredentialRevision) || !version(r.ApprovalPolicyRevision) || err != nil || len(hash) != 32 || base64.RawURLEncoding.EncodeToString(hash) != r.ScopeDigest || r.VerificationMethod != "none" {
			return invalid()
		}
		if !(r.ApprovalMode == "none" && r.AuthorizationSource == "client_activation" || r.ApprovalMode == "confirm" && r.AuthorizationSource == "owner_confirmation") {
			return invalid()
		}
	}
	switch r.EventType {
	case DispatchAdmitted:
		if r.Decision != "allow" || r.Status != "unknown" || !r.CompletedAt.IsZero() || r.Timing != nil || r.DurationMS != 0 || r.ResponseItems != 0 || r.Structured {
			return invalid()
		}
	case DispatchCompleted, DispatchDenied:
		if r.CompletedAt.IsZero() || !r.CompletedAt.Equal(r.OccurredAt) {
			return invalid()
		}
		if r.EventType == DispatchCompleted && r.Decision != "allow" || r.EventType == DispatchDenied && r.Decision != "deny" {
			return invalid()
		}
		switch r.Status {
		case "ok", "tool_error", "protocol_error", "timeout", "denied", "unavailable", "audit_error":
		default:
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}
