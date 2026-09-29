package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

// testDB is the gateway's real storage backend on a temporary SQLite file.
type testDB struct {
	*storageBackend
	once sync.Once
}

// close stops the executor and releases the database; it is safe to call
// again at cleanup.
func (d *testDB) close() { d.once.Do(d.storageBackend.close) }

// testStorage opens storage as run does, with no external services. It fills
// in cfg.Storage when unset; cfg.Accounts selects accounts mode. Calling it
// again with the same cfg after close reopens the same database.
func testStorage(t *testing.T, cfg *config.Config) *testDB {
	t.Helper()
	if cfg.Storage == nil {
		cfg.Storage = &config.Storage{Driver: "sqlite", Path: filepath.Join(t.TempDir(), "mcpwarden.db"), Key: base64.StdEncoding.EncodeToString(randBytes(32))}
	}
	pol, _ := policy.New(config.Policy{Default: "allow"})
	b, err := openStorage(t.Context(), *cfg, pol, slog.New(slog.NewTextHandler(io.Discard, nil)), func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	d := &testDB{storageBackend: b}
	t.Cleanup(d.close)
	return d
}

// historyPage reads the first page of an owner's history, optionally for one
// tool.
func historyPage(h audit.Reader, owner, toolID string) ([]audit.Record, int, error) {
	rows, total, _, _, err := h.QueryHistoryPerformance(audit.HistoryFilter{Owner: owner, ToolID: toolID, Page: 1, Size: 25})
	return rows, total, err
}

// completedCall is a stored-shape completion of an unattributed call.
func completedCall(owner, tool, toolID, upstream string) audit.Record {
	r := audit.NewInvocation(context.Background(), owner)
	r.Tool, r.ToolID, r.Upstream = tool, toolID, upstream
	r.ArgsSHA256 = audit.HashArgs(json.RawMessage(`{}`))
	r.EventType, r.Decision, r.Status = audit.DispatchCompleted, "allow", "ok"
	r.CompletedAt = time.Now().UTC()
	r.OccurredAt = r.CompletedAt
	return r
}
