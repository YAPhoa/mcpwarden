package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/secret"
)

type pausingAudit struct {
	audit.Appender
	tool             string
	reached, release chan struct{}
	once             sync.Once
}

func (a *pausingAudit) Write(r audit.Record) error {
	if r.EventType == audit.DispatchAdmitted && r.Tool == a.tool {
		first := false
		a.once.Do(func() { first = true })
		if first {
			close(a.reached)
			<-a.release
		}
	}
	return a.Appender.Write(r)
}

type slowHistory struct {
	audit.Appender
	delay time.Duration
}

func (h slowHistory) Write(r audit.Record) error {
	if r.EventType == audit.DispatchAdmitted {
		time.Sleep(h.delay)
		return errors.New("history unavailable")
	}
	return h.Appender.Write(r)
}

type callResult struct {
	text   string
	failed bool
}

func asyncCall(s *mcp.ClientSession, tool string) chan callResult {
	done := make(chan callResult, 1)
	go func() {
		res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"repo": "example"}})
		if err != nil {
			done <- callResult{err.Error(), true}
			return
		}
		done <- callResult{res.Content[0].(*mcp.TextContent).Text, res.IsError}
	}()
	return done
}

func guardedRaceFixture(t *testing.T) (*headerUpstream, *ownerFixture, *guardedGateway, string) {
	upstream := newHeaderUpstream(t)
	f := newOwnerFixture(t, upstream.server.URL+"/mcp")
	f.destination = &secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: f.entry.URL, HeaderNames: []string{"authorization"}, Network: "private", PrivatePrefixes: []string{"127.0.0.1/32"}, AllowLoopbackHTTP: true}
	alice := f.owners["alice"]
	g := f.guardedGateway()
	awaitRuntime(t, func() bool { e, ok := g.rs.get(alice).proxy.Registry.Lookup("remote__search"); return ok && e.Healthy })
	return upstream, f, g, alice
}

// A legacy call that chose the legacy path before the custody switch but whose
// durable admission lands after it must not run on the old session.
func TestLegacyAdmissionAfterConversionIsDenied(t *testing.T) {
	upstream, f, g, alice := guardedRaceFixture(t)
	const legacy = "Bearer legacy-synthetic"
	rt := g.rs.get(alice)
	pause := &pausingAudit{Appender: rt.proxy.Audit, tool: "remote__search", reached: make(chan struct{}), release: make(chan struct{})}
	rt.proxy.Audit = pause
	agent := g.client(t, f.keys["agent"])

	done := asyncCall(agent, "remote__search")
	<-pause.reached // Selected the legacy path; its durable admission has not been written.
	calls, legacyRequests := upstream.calls.Load(), upstream.requests(legacy)

	g.rs.mu.Lock() // Another runtime operation holds rs.mu.
	provisioned := make(chan struct{})
	go func() { defer close(provisioned); f.provision("none") }()
	deadline := time.Now().Add(10 * time.Second)
	for !g.rs.guarded.bound(alice, f.entry.ID) {
		if time.Now().After(deadline) {
			g.rs.mu.Unlock()
			t.Fatal("custody head never published")
		}
		time.Sleep(5 * time.Millisecond)
	}
	lock := f.do(req{method: "POST", path: "/api/vault/lock-execution", user: "alice", body: "{}"})

	close(pause.release) // The old call's admission completes after publication and the lock.
	r := <-done
	ran, usedLegacy := upstream.calls.Load() > calls, upstream.requests(legacy) > legacyRequests
	g.rs.mu.Unlock()
	<-provisioned
	t.Logf("lock-execution=%d result=%q is_error=%v upstream_ran=%v legacy_header_used=%v", lock.Code, r.text, r.failed, ran, usedLegacy)
	if ran || usedLegacy || !r.failed || !strings.Contains(r.text, "MCPWARDEN_LEASE_REQUIRED") {
		t.Fatal("a legacy call admitted after the custody switch executed upstream")
	}
	if lock.Code != http.StatusNoContent {
		t.Fatalf("lock-execution = %d", lock.Code)
	}
}

// The best-effort history copy must not run between admission and dispatch,
// where a slow copy would spend the call's timeout.
func TestHistoryCopyDoesNotDelayDispatch(t *testing.T) {
	upstream, f, g, alice := guardedRaceFixture(t)
	_, record := f.provision("none")
	agent := g.client(t, f.keys["agent"])
	request := f.requestAccess("agent", record.CredentialID)
	f.expect(req{method: "POST", path: "/api/approvals/" + request.ID + "/activate", user: "alice", idempotency: identity.New(), body: f.activation(f.ownerRequest(request.ID), f.cek)}, 200, nil)
	if text, failed := callText(t, agent, "remote__search"); failed {
		t.Fatalf("baseline leased call: %q", text)
	}
	rt := g.rs.get(alice)
	rt.proxy.Security.Timeout = func(registry.Entry) time.Duration { return 500 * time.Millisecond }
	rt.proxy.Security.History = slowHistory{Appender: rt.proxy.Security.History, delay: 750 * time.Millisecond}
	calls := upstream.calls.Load()
	text, failed := callText(t, agent, "remote__search")
	t.Logf("result=%q is_error=%v upstream_calls_delta=%d", text, failed, upstream.calls.Load()-calls)
	if failed || upstream.calls.Load() == calls {
		t.Fatal("a slow best-effort history copy prevented dispatch of an admitted call")
	}
}
