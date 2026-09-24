package main

import (
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/secret"
)

// The owner UI computes destination digests in the browser. These vectors are
// shared with ui/tests/owner-core.test.mjs so both sides hash the same JCS bytes.
func TestDestinationDigestVectorsSharedWithUI(t *testing.T) {
	for _, c := range []struct {
		d    secret.Destination
		want string
	}{
		{secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: "https://mcp.example.com/v1/mcp", HeaderNames: []string{"x-api-key", "authorization"}, Network: "public", PrivatePrefixes: []string{}}, "vVapFskaiqc3HytDT_xPi4e9f9FFo2SDHLGMcktEZt0"},
		{secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: "http://localhost:4100/mcp", HeaderNames: []string{"x-api-key"}, Network: "private", PrivatePrefixes: []string{"::1/128", "127.0.0.0/8"}, AllowLoopbackHTTP: true}, "pRRjQdr_3IR_Ey6EaicfR6WZ-eEgHX9rBWiAjyNANPk"},
	} {
		got, err := c.d.Digest()
		if err != nil || got != c.want {
			t.Fatalf("digest for %s = %q, %v; want %q", c.d.Endpoint, got, err, c.want)
		}
	}
}

// The UI reads recently ended windows and current ciphertext; neither read can
// restore a window or expose anything the server could decrypt.
func TestOwnerLeaseHistoryAndWrapperEnvelopes(t *testing.T) {
	f := newOwnerFixture(t)
	_, record := f.provision("none")

	var wrappers struct {
		Credentials []credentialSummary `json:"credentials"`
	}
	f.expect(req{path: "/api/vault/wrappers", user: "alice"}, 200, &wrappers)
	if len(wrappers.Credentials) != 1 || string(wrappers.Credentials[0].Envelope) != string(record.Envelope) || len(wrappers.Credentials[0].WrappedKey) == 0 {
		t.Fatal("wrappers route did not return the current encrypted envelope")
	}
	var selectable []credentialSummary
	f.expect(req{path: "/api/vault/credentials", key: "agent"}, 200, &selectable)
	if len(selectable) != 1 || selectable[0].Envelope != nil || selectable[0].WrappedKey != nil {
		t.Fatal("selectable credential list exposes ciphertext to a key")
	}

	activate := func(key string) leaseView {
		request := f.requestAccess(key, record.CredentialID)
		var out leaseView
		f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, &out)
		return out
	}
	first, second := activate("agent"), activate("other-agent")
	f.expect(req{method: "DELETE", path: "/api/leases/" + first.LeaseID, user: "alice"}, 204, nil)

	var active, all, own []leaseView
	f.expect(req{path: "/api/leases", user: "alice"}, 200, &active)
	if len(active) != 1 || active[0].LeaseID != second.LeaseID || active[0].EndedAt != nil {
		t.Fatalf("active windows %+v", active)
	}
	f.expect(req{path: "/api/leases?include=ended", user: "alice"}, 200, &all)
	if len(all) != 2 || all[1].LeaseID != first.LeaseID || all[1].State != "revoked" || all[1].RuntimeAvailable || all[1].EndedAt == nil || all[1].EndedAt.Before(first.ActivatedAt) {
		t.Fatalf("ended window missing or misreported: %+v", all)
	}
	// A key sees only its own history, and reading history never revives it.
	f.expect(req{path: "/api/leases?include=ended", key: "agent"}, 200, &own)
	if len(own) != 1 || own[0].LeaseID != first.LeaseID || own[0].State != "revoked" {
		t.Fatalf("key history %+v", own)
	}
	f.expect(req{path: "/api/leases?include=ended", user: "bob"}, 200, &own)
	if len(own) != 0 {
		t.Fatal("another owner saw alice's windows")
	}
	f.expect(req{path: "/api/leases?include=all", user: "alice"}, 400, nil)

	// Restart suspends the live window; it then appears only as history.
	f.restart()
	f.expect(req{path: "/api/leases", user: "alice"}, 200, &active)
	if len(active) != 0 {
		t.Fatal("window survived restart", active)
	}
	f.expect(req{path: "/api/leases?include=ended", user: "alice"}, 200, &all)
	states := map[string]string{}
	for _, l := range all {
		states[l.LeaseID] = l.State
		if l.RuntimeAvailable || l.EndedAt == nil || time.Since(*l.EndedAt) > time.Minute {
			t.Fatalf("ended window reported as usable: %+v", l)
		}
	}
	if states[first.LeaseID] != "revoked" || states[second.LeaseID] != "suspended" {
		t.Fatalf("states after restart %v", states)
	}
}
