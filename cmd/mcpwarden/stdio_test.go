package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/dbcatalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

// --stdio refuses PostgreSQL before connecting: a stdio config would need
// the runtime role and the catalog key.
func TestStdioRefusesPostgres(t *testing.T) {
	t.Setenv("TEST_STORAGE_KEY", base64.StdEncoding.EncodeToString(randBytes(32)))
	t.Setenv("TEST_DATABASE_URL", "postgres://nobody@127.0.0.1:1/none")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "storage:\n  driver: postgres\n  database_url_env: TEST_DATABASE_URL\n  key_env: TEST_STORAGE_KEY\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(path, true, slog.New(slog.NewTextHandler(io.Discard, nil))); !errors.Is(err, errStdioStorage) {
		t.Fatal("stdio accepted PostgreSQL:", err)
	}
}

func stdioSession(t *testing.T, g *stdioGateway) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := g.server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "1"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// Stdio clients share one database. Each serves owner local's no-auth
// connectors from a snapshot, keeps discovery in memory, refuses catalog
// changes, and records its calls for owner local with actor type stdio.
func TestStdioSharesDatabaseAndWritesOnlyHistory(t *testing.T) {
	_, upstreamHTTP := upstreamForUser(t, "echo")
	// Registered first, so it runs after the stdio gateways have closed
	// their upstream sessions.
	t.Cleanup(upstreamHTTP.Close)
	cfg := config.Config{Upstreams: []config.Upstream{{Name: "cfgup", Transport: "http", URL: upstreamHTTP.URL, Timeout: 5 * time.Second}}}
	db := testStorage(t, &cfg)
	for _, e := range []catalog.Entry{
		{Owner: "local", Name: "open", URL: "https://example.com/mcp", AuthType: "none"},
		{Owner: "local", Name: "keyed", URL: "https://example.com/keyed", AuthType: "api_key", HeaderNames: []string{"X-API-Key"}},
		{Owner: "someone", Name: "theirs", URL: "https://example.com/theirs", AuthType: "none"},
	} {
		if err := db.repo.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	db.close()

	pol, _ := policy.New(config.Policy{Default: "allow"})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var gateways []*stdioGateway
	for range 2 {
		g, err := openStdio(t.Context(), cfg, pol, logger)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(g.close)
		gateways = append(gateways, g)
	}
	g := gateways[0]
	var names []string
	for _, e := range g.rs.store.List("local") {
		names = append(names, e.Name)
	}
	if !slices.Equal(names, []string{"open"}) || len(g.rs.store.List("someone")) != 0 {
		t.Fatal("snapshot connectors", names)
	}
	if err := g.rs.store.Add(catalog.Entry{Owner: "local", Name: "more", URL: "https://example.com/more", AuthType: "none"}); !errors.Is(err, dbcatalog.ErrReadOnly) {
		t.Fatal("stdio changed the catalog:", err)
	}
	if err := g.rs.store.SetProviderEnabled("local", "open", false); !errors.Is(err, dbcatalog.ErrReadOnly) {
		t.Fatal("stdio changed the catalog:", err)
	}

	for i, g := range gateways {
		cs := stdioSession(t, g)
		deadline := time.Now().Add(10 * time.Second)
		for {
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "cfgup__echo", Arguments: map[string]any{}})
			if err == nil && !res.IsError {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("stdio call", i, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	if _, ok := g.rs.store.Discovery("local", "cfgup"); !ok {
		t.Fatal("discovery not kept in memory")
	}

	raw, err := sql.Open("sqlite", cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var discovered int
	if err := raw.QueryRow("SELECT count(*) FROM catalog_discovery").Scan(&discovered); err != nil || discovered != 0 {
		t.Fatal("stdio wrote discovery", discovered, err)
	}
	rows, err := raw.Query("SELECT owner_id, event_type, record FROM history_events WHERE status = 'ok'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	completed := 0
	for rows.Next() {
		var owner, kind, record string
		if err := rows.Scan(&owner, &kind, &record); err != nil {
			t.Fatal(err)
		}
		var r struct {
			ActorType string `json:"actor_type"`
		}
		if err := json.Unmarshal([]byte(record), &r); err != nil || owner != "local" || r.ActorType != "stdio" {
			t.Fatal("stdio history row", owner, r.ActorType, err)
		}
		if kind == "tool.dispatch.completed" {
			completed++
		}
	}
	if completed != 2 {
		t.Fatal("completed stdio calls", completed)
	}
}

// A stdio client cannot start while a gateway holds the database.
func TestStdioRefusedBesideGateway(t *testing.T) {
	var cfg config.Config
	testStorage(t, &cfg)
	pol, _ := policy.New(config.Policy{Default: "allow"})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, err := openStdio(ctx, cfg, pol, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "connect over HTTP") {
		t.Fatal("stdio beside a gateway:", err)
	}
}

// A stdio call's admission is committed before the upstream sees the call.
// A write lock held elsewhere past the busy timeout refuses the call without
// dispatch, and the client serves again once the lock is released.
func TestStdioAdmissionDurableAndBusyRefused(t *testing.T) {
	var calls atomic.Int32
	var admittedAtDispatch atomic.Int64
	var dbPath string
	s := mcp.NewServer(&mcp.Implementation{Name: "count", Version: "1"}, nil)
	s.AddTool(&mcp.Tool{Name: "count", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		db, err := sql.Open("sqlite", dbPath+"?_pragma=query_only(1)")
		if err == nil {
			var n int64
			if db.QueryRowContext(ctx, "SELECT count(*) FROM history_events WHERE event_type='tool.dispatch.admitted'").Scan(&n) == nil {
				admittedAtDispatch.Store(n)
			}
			db.Close()
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "counted"}}}, nil
	})
	srv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil))
	t.Cleanup(srv.Close)
	cfg := config.Config{Upstreams: []config.Upstream{{Name: "cfgup", Transport: "http", URL: srv.URL, Timeout: 5 * time.Second}}}
	testStorage(t, &cfg).close()
	dbPath = cfg.Storage.Path
	pol, _ := policy.New(config.Policy{Default: "allow"})
	g, err := openStdio(t.Context(), cfg, pol, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.close)
	cs := stdioSession(t, g)
	call := func() (*mcp.CallToolResult, error) {
		return cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "cfgup__count", Arguments: map[string]any{}})
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := call()
		if err == nil && !res.IsError {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first call:", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if admittedAtDispatch.Load() != 1 {
		t.Fatal("admission not committed before dispatch:", admittedAtDispatch.Load())
	}

	holder, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	conn, err := holder.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	res, err := call()
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "No upstream action was executed") {
		t.Fatal("call under a held write lock:", err, res)
	}
	if calls.Load() != before {
		t.Fatal("dispatched without an admission")
	}
	if _, err := conn.ExecContext(t.Context(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if res, err := call(); err != nil || res.IsError {
		t.Fatal("call after release:", err, res)
	}
}

// runStdio stops once its client stops trusting the database.
func TestStdioStopsWhenDatabaseLost(t *testing.T) {
	_, upstreamHTTP := upstreamForUser(t, "echo")
	t.Cleanup(upstreamHTTP.Close)
	cfg := config.Config{Upstreams: []config.Upstream{{Name: "cfgup", Transport: "http", URL: upstreamHTTP.URL, Timeout: 5 * time.Second}}}
	testStorage(t, &cfg).close()
	pol, _ := policy.New(config.Policy{Default: "allow"})
	ct, st := mcp.NewInMemoryTransports()
	done := make(chan error, 1)
	go func() {
		done <- runStdio(t.Context(), cfg, pol, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
	}()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "1"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if err := os.Rename(cfg.Storage.Path, cfg.Storage.Path+".moved"); err != nil {
		t.Fatal(err)
	}
	// The next history write finds the file replaced. Discovery may still
	// be running, so call until one call reaches the admission write.
	go func() {
		for range 200 {
			if _, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "cfgup__echo", Arguments: map[string]any{}}); err == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errStdioLost) {
			t.Fatal("runStdio:", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runStdio kept serving")
	}
}
