package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/approval"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/testutil"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

type failingAppender struct {
	*audit.Writer
	failType string
}

func (w failingAppender) Write(r audit.Record) error {
	if r.EventType == w.failType {
		return errors.New("synthetic-private-error-do-not-log")
	}
	return w.Writer.Write(r)
}

func TestDispatchAuditFailuresNeverCauseExecutionOrReplay(t *testing.T) {
	for _, failType := range []string{audit.DispatchAdmitted, audit.DispatchCompleted, ""} {
		t.Run(failType, func(t *testing.T) {
			log, err := audit.Open(t.TempDir() + "/audit")
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			remote := testutil.NewMock(time.Second)
			defer remote.Close()
			var calls atomic.Int32
			remote.Add("checked", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				calls.Add(1)
				// The upstream itself checks that admission is already visible
				// through the real file reader before performing its work.
				rows, total, err := log.History("alice", "", 1, 25)
				if err != nil || total != 1 || len(rows) != 1 || rows[0].EventType != audit.DispatchAdmitted || rows[0].ActorAccessID != "key-a" {
					t.Error("upstream executed without persisted caller admission")
				}
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "upstream-success"}}}, nil
			})
			var diagnostic bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&diagnostic, nil))
			pol, _ := policy.New(config.Policy{Default: "allow"})
			p := New(registry.New(), pol, approval.None{}, failingAppender{log, failType}, logger)
			p.Owner = "alice"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager := upstream.New([]config.Upstream{{Name: "remote", Transport: "http", URL: remote.HTTP.URL, Timeout: time.Second}}, logger, p.Changed)
			p.Manager = manager
			manager.Start(ctx)
			defer manager.Close()
			await(t, 5*time.Second, func() bool { r, ok := p.Registry.Lookup("remote__checked"); return ok && r.Healthy })
			ctx = identity.WithActor(ctx, identity.Actor{Owner: "alice", AccessID: "key-a", Kind: "api_key", PublicID: strings.Repeat("a", 32), Label: "Authenticated label"})
			result, err := p.call(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{"actor_access_id":"forged","label":"forged"}`)}}, "remote__checked")
			if err != nil {
				t.Fatal(err)
			}
			wantCalls := int32(1)
			if failType == audit.DispatchAdmitted {
				wantCalls = 0
				if !result.IsError || result.StructuredContent != nil || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "No upstream action was executed") {
					t.Fatal("missing safe pre-dispatch error")
				}
			} else if result.IsError || result.Content[0].(*mcp.TextContent).Text != "upstream-success" {
				t.Fatal("audit failure replaced the actual upstream result")
			}
			if calls.Load() != wantCalls {
				t.Fatalf("unexpected dispatch/retry count: %d", calls.Load())
			}
			rows, total, err := log.History("alice", "", 1, 25)
			if err != nil || total != 1 || len(rows) != 1 {
				t.Fatalf("audit history: %d %v", total, err)
			}
			wantStatus := "ok"
			if failType == audit.DispatchAdmitted {
				wantStatus = "audit_error"
			} else if failType == audit.DispatchCompleted {
				wantStatus = "unknown"
			}
			if rows[0].Status != wantStatus || rows[0].ActorAccessID != "key-a" || rows[0].ActorLabel != "Authenticated label" {
				t.Fatal("incorrect outcome or spoofed actor attribution")
			}
			manager.Close() // Join background logging before inspecting its buffer.
			if strings.Contains(diagnostic.String(), "synthetic-private-error-do-not-log") || strings.Contains(diagnostic.String(), "forged") {
				t.Fatal("raw failure or tool arguments reached diagnostics")
			}
		})
	}
}
