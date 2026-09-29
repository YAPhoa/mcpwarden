package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
)

func TestUnknownHistoryOmitsCompletionMetadata(t *testing.T) {
	var cfg config.Config
	log := testStorage(t, &cfg).history
	r := audit.NewInvocation(context.Background(), "alice")
	r.ToolID, r.Tool, r.ArgsSHA256 = "tool-id", "remote__echo", audit.HashArgs(json.RawMessage(`{}`))
	if err := log.Write(r.Admission()); err != nil {
		t.Fatal(err)
	}
	rs := &runtimes{audit: log}
	req := httptest.NewRequest("GET", "http://localhost/api/history?status=unknown", nil)
	req = req.WithContext(withAccess(req.Context(), catalog.AccessRecord{Owner: "alice", Kind: "operator"}))
	w := httptest.NewRecorder()
	rs.history(w, req)
	var body struct {
		Items []map[string]json.RawMessage `json:"items"`
		Total int                          `json:"total"`
	}
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Total != 1 || len(body.Items) != 1 {
		t.Fatal("missing unknown-outcome history")
	}
	for _, key := range []string{"completed_at", "duration_ms", "response_items", "structured", "timing", "args_sha256", "argument_hash_version", "owner", "session"} {
		if _, exists := body.Items[0][key]; exists {
			t.Fatalf("unknown history exposed or fabricated %s", key)
		}
	}
}
