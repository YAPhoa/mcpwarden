package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
)

func TestSmoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db", "mcpwarden.db")
	s, err := Open(t.Context(), path, Options{Warn: func(m string) { t.Log(m) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	rows, err := s.LoadCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rows)
	if _, err := s.LoadCustody(t.Context()); err != nil {
		t.Fatal(err)
	}
	r := catalogdb.HistoryRow{OwnerID: "alice", EventID: "e1", SchemaVersion: 1, ToolID: "t", Tool: "x", Upstream: "u", Status: "ok", TSNano: 1, HistoryNano: 1, Record: "{}"}
	if err := s.InsertHistory(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	res, err := s.QueryHistory(t.Context(), catalogdb.HistoryQuery{Owner: "alice", Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", res)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err = Open(t.Context(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.Close(context.Background())
}
