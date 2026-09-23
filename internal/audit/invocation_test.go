package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
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

func TestAdmissionUnknownUntilCompletionAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/audit"
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := invocationFixture("alice", "key-a")
	admitted := r.Admission()
	if err := w.Write(admitted); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rows, total, _, stats, err := w.QueryHistoryPerformance(HistoryFilter{Owner: "alice", ActorAccessID: "key-a", Status: "unknown", Page: 1, Size: 25})
	if err != nil || total != 1 || len(rows) != 1 || stats.TimedCalls != 0 {
		t.Fatalf("unknown history: %d %v", total, err)
	}
	got := rows[0]
	if got.EventType != DispatchAdmitted || got.InvocationID != r.InvocationID || got.EventID != admitted.EventID || !got.CompletedAt.IsZero() || got.ActorLabel != "Original key label" || got.ArgsSHA256 != r.ArgsSHA256 {
		t.Fatal("admission lost identity or fabricated completion")
	}
	r = completeFixture(r)
	if err := w.Write(r); err != nil {
		t.Fatal(err)
	}
	rows, total, _, stats, err = w.QueryHistoryPerformance(HistoryFilter{Owner: "alice", Page: 1, Size: 25})
	if err != nil || total != 1 || len(rows) != 1 || rows[0].EventID != r.EventID || stats.TimedCalls != 1 {
		t.Fatalf("completion counted incorrectly: %d %v", total, err)
	}
	_, total, _ = w.History("bob", "", 1, 25)
	if total != 0 {
		t.Fatal("cross-owner history")
	}
	_, total, _, _ = w.QueryHistory(HistoryFilter{Owner: "alice", Status: "unknown", Page: 1, Size: 25})
	if total != 0 {
		t.Fatal("completed invocation remained unknown")
	}
	data, _ := os.ReadFile(path)
	if len(bytesSplitLines(data)) != 2 {
		t.Fatal("completion rewrote or removed the admission")
	}
}

func TestInvocationImportOrderOwnerIsolationAndLegacyPreservation(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		path := t.TempDir() + "/audit"
		legacy := "{\"owner\":\"alice\",\"ts\":\"2026-09-21T00:00:00Z\",\"duration_ms\":5}\n"
		if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
			t.Fatal(err)
		}
		w, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		r := invocationFixture("alice", "key-a")
		admitted, completed := r.Admission(), completeFixture(r)
		events := []Record{admitted, completed}
		if reverse {
			events[0], events[1] = events[1], events[0]
		}
		for _, event := range events {
			if err := w.Write(event); err != nil {
				t.Fatal(err)
			}
		}
		unresolved := invocationFixture("alice", "key-b").Admission()
		if err := w.Write(unresolved); err != nil {
			t.Fatal(err)
		}
		other := completeFixture(invocationFixture("bob", "key-b"))
		other.InvocationID = unresolved.InvocationID
		if err := w.Write(other); err != nil {
			t.Fatal(err)
		}
		rows, total, _, _, err := w.QueryHistoryPerformance(HistoryFilter{Owner: "alice", ActorAccessID: "key-b", Page: 1, Size: 25})
		if err != nil || total != 1 || len(rows) != 1 || rows[0].Status != "unknown" {
			t.Fatal("another owner's completion matched the admission")
		}
		_, total, _ = w.History("alice", "", 1, 25)
		if total != 3 {
			t.Fatal("import order changed call count")
		}
		w.Close()
		data, _ := os.ReadFile(path)
		if !strings.HasPrefix(string(data), legacy) {
			t.Fatal("legacy history rewritten")
		}
	}
}

func TestAdmissionRequiresDurableSinkAndValidEvent(t *testing.T) {
	r := invocationFixture("alice", "key-a").Admission()
	w := &Writer{out: io.Discard}
	if err := w.Write(r); err == nil {
		t.Fatal("discard sink authorized dispatch")
	}
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
