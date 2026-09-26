package main

import (
	"context"
	"errors"
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
	awaitRuntime(t, func() bool { _, ok := g.rs.get(alice).proxy.Registry.Lookup("remote__search"); return ok })
	return upstream, f, g, alice
}

// Calls racing the owner's first credential save stay locked: storing a
// credential opens no window, so no call reaches the upstream.
func TestCredentialSaveDuringCallsNeverDials(t *testing.T) {
	upstream, f, g, _ := guardedRaceFixture(t)
	agent := g.client(t, f.keys["agent"])
	stop := make(chan struct{})
	results := make(chan callResult, 1024)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				case r := <-asyncCall(agent, "remote__search"):
					results <- r
				}
			}
		}()
	}
	_, record := f.provision("none")
	after := asyncCall(agent, "remote__search")
	close(stop)
	wg.Wait()
	close(results)
	last := <-after
	n := 1
	for r := range results {
		n++
		if !r.failed || !strings.Contains(r.text, "MCPWARDEN_LEASE_REQUIRED") {
			t.Fatalf("call during the save: %q", r.text)
		}
	}
	if !last.failed || !strings.Contains(last.text, "MCPWARDEN_LEASE_REQUIRED") {
		t.Fatalf("call after the save: %q", last.text)
	}
	t.Logf("calls=%d credential=%s", n, record.CredentialID)
	if upstream.calls.Load() != 0 || upstream.total() != 0 {
		t.Fatal("a locked connector reached the upstream")
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
