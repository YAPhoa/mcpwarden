package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

func invocationFixture(owner, access string) Record {
	ctx := identity.WithActor(context.Background(), identity.Actor{Owner: owner, AccessID: access,
		PublicID: strings.Repeat("a", 32), Kind: "api_key", Label: "Original key label"})
	r := NewInvocation(ctx, owner)
	r.ToolID, r.Tool, r.UpstreamID, r.Upstream = "tool-id", "remote__read", "provider-id", "remote"
	r.ArgsSHA256 = HashArgs(json.RawMessage(`{"test":true}`))
	r.Decision, r.Status = "allow", "ok"
	return r
}

func completeFixture(r Record) Record {
	r.EventType = DispatchCompleted
	r.CompletedAt = time.Now().UTC()
	r.OccurredAt = r.CompletedAt
	r.Timing = &Timing{HandlerUS: 10, UpstreamUS: 8, GatewayUS: 2, Forwarded: true}
	return r
}

func TestAdmissionRequiresValidEvent(t *testing.T) {
	r := invocationFixture("alice", "key-a").Admission()
	for _, mutate := range []func(*Record){
		func(r *Record) { r.EventType = "unknown.event" },
		func(r *Record) { r.CompletedAt = time.Now().UTC() },
		func(r *Record) { r.Status = "ok" },
		func(r *Record) { r.Timing = &Timing{} },
		func(r *Record) { r.ActorPublicID = "invalid" },
		func(r *Record) { r.ActorAccessID = "" },
		func(r *Record) { r.ArgsSHA256 = "bad" },
		func(r *Record) { r.ArgsHashVersion = "new-unreviewed-hash" },
	} {
		bad := r
		mutate(&bad)
		if err := validateInvocationEvent(bad); err == nil {
			t.Fatal("invalid event accepted")
		}
	}
}

func TestLeaseAttributionIsAnAtomicMetadataBundle(t *testing.T) {
	r := invocationFixture("alice", identity.New()).Admission()
	r.ToolID, r.UpstreamID = identity.New(), identity.New()
	r.CredentialID, r.ApprovalID, r.LeaseID = identity.New(), identity.New(), identity.New()
	r.CredentialEpoch, r.CredentialRevision, r.ApprovalPolicyRevision = "1", "2", "3"
	r.ScopeDigest = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	r.ApprovalMode, r.AuthorizationSource, r.VerificationMethod = "none", "client_activation", "none"
	if err := ValidateInvocation(r); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Record){
		func(r *Record) { r.CredentialID = "" }, func(r *Record) { r.CredentialEpoch = "01" }, func(r *Record) { r.ApprovalID = "not-an-id" },
		func(r *Record) { r.ActorType = "browser" }, func(r *Record) { r.ActorPublicID = "" }, func(r *Record) { r.ScopeDigest = "wrong" },
		func(r *Record) { r.ApprovalMode = "confirm" }, func(r *Record) { r.VerificationMethod = "totp" }, func(r *Record) { r.SchemaVersion = 1 },
	} {
		bad := r
		mutate(&bad)
		if ValidateInvocation(bad) == nil {
			t.Fatal("partial/substituted lease attribution accepted")
		}
	}
	r.ApprovalMode, r.AuthorizationSource = "confirm", "owner_confirmation"
	if err := ValidateInvocation(r); err != nil {
		t.Fatal(err)
	}
	r.Status = "ok"
	if err := ValidateInvocation(completeFixture(r)); err != nil {
		t.Fatal(err)
	}
}
