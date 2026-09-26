package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/approval"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

// guardedDenialCall runs one call against an unreachable upstream
// and returns its result and the JSONL audit records it wrote.
func guardedDenialCall(t *testing.T, u config.Upstream, security *LeasedExecution) (*mcp.CallToolResult, []audit.Record) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol, err := policy.New(config.Policy{Default: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/audit.jsonl"
	log, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	p := New(registry.New(), pol, approval.None{}, log, logger)
	p.Owner = "owner"
	p.Security = security
	m := upstream.New([]config.Upstream{u}, logger, p.Changed)
	p.Manager = m
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Close()
	// A healthy entry, so the call passes routing and reaches the manager.
	// Production never publishes a guarded connector as healthy; this checks
	// the backstop after admission.
	p.Changed(u.Name, []*mcp.Tool{{Name: "search", InputSchema: map[string]any{"type": "object"}}}, true)
	name := u.Name + "__search"
	res, err := p.call(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name, Arguments: []byte(`{}`)}}, name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	return res, records
}

func assertGuardedDenial(t *testing.T, res *mcp.CallToolResult, records []audit.Record) {
	t.Helper()
	if !res.IsError || !strings.HasPrefix(res.Content[0].(*mcp.TextContent).Text, "MCPWARDEN_LEASE_REQUIRED") {
		t.Fatalf("result = %+v", res.Content[0])
	}
	if len(records) != 2 || records[0].EventType != audit.DispatchAdmitted || records[1].EventType != audit.DispatchCompleted {
		t.Fatalf("audit records = %+v, want admission and completion", records)
	}
	done := records[1]
	if done.Status != "denied" || done.Decision != "allow" {
		t.Fatalf("completion status=%q decision=%q", done.Status, done.Decision)
	}
	if done.Timing == nil || done.Timing.Forwarded || done.Timing.UpstreamUS != 0 {
		t.Fatalf("denied completion counted as upstream traffic: %+v", done.Timing)
	}
}

// Backstop: a guarded connector that reached dispatch without a lease adapter
// gets ErrGuarded from the manager, and nothing is forwarded. Without the
// vault a real call stops earlier, as unavailable, before admission.
func TestGuardedManagerRecordsDenial(t *testing.T) {
	res, records := guardedDenialCall(t, config.Upstream{Name: "g", Transport: "http", URL: "http://127.0.0.1:1/mcp", Timeout: time.Second, Guarded: true}, nil)
	assertGuardedDenial(t, res, records)
}
