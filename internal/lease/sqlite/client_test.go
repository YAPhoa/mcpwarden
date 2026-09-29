package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

func openClient(t *testing.T, path string) *Client {
	t.Helper()
	c, err := OpenClient(t.Context(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func shortWaits(t *testing.T) {
	t.Helper()
	client, gateway := clientWait, lockWait
	clientWait, lockWait = 300*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { clientWait, lockWait = client, gateway })
}

func clientEvent(owner, id, kind string) catalogdb.HistoryRow {
	return catalogdb.HistoryRow{OwnerID: owner, EventID: id, SchemaVersion: 2, EventType: kind, InvocationID: "inv-" + id,
		ToolID: "t", Tool: "x", Upstream: "u", Status: "ok", TSNano: 1, HistoryNano: 1, Record: "{}"}
}

func count(t *testing.T, path, table string) int {
	t.Helper()
	db := raw(t, path)
	defer db.Close()
	var n int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(table, err)
	}
	return n
}

// Clients share the file under the shared lock, and each history write is
// committed before InsertHistory returns.
func TestClientsShareAndWriteHistory(t *testing.T) {
	path := tempPath(t)
	a := openClient(t, path)
	b := openClient(t, path)
	if got := pragma(t, a.db, "busy_timeout"); got != fmt.Sprint(clientBusyTimeout) {
		t.Fatal("client busy timeout", got)
	}
	var wg sync.WaitGroup
	for i, c := range []*Client{a, b} {
		for j := range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := c.InsertHistory(t.Context(), clientEvent("local", fmt.Sprintf("e%d-%d", i, j), "tool.dispatch.admitted")); err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	if n := count(t, path, "history_events"); n != 20 {
		t.Fatal("history rows", n)
	}
	if n := count(t, path, "history_open"); n != 20 {
		t.Fatal("open admissions", n)
	}
	if err := a.InsertHistory(t.Context(), clientEvent("local", "e0-0", "tool.dispatch.admitted")); !errors.Is(err, catalogdb.ErrConflict) {
		t.Fatal("duplicate event", err)
	}
	if err := a.InsertHistory(t.Context(), clientEvent("local", "done", "tool.dispatch.completed")); err != nil {
		t.Fatal("client stopped after a refused write", err)
	}
	rows, err := b.LoadOwner(t.Context(), "local")
	if err != nil || len(rows.Connectors)+len(rows.Accounts)+len(rows.Access)+len(rows.Discovery)+len(rows.Visibility) != 0 {
		t.Fatal("load owner", rows, err)
	}
}

// LoadOwner returns only that owner's rows.
func TestClientLoadsOneOwner(t *testing.T) {
	path := tempPath(t)
	s := openStore(t, path)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"local", "alice"} {
		err := s.WithOwner(t.Context(), owner, func(x lease.Tx) error {
			return x.(catalogdb.OwnerTx).CatalogRows().PutDiscovery(catalogdb.Discovery{OwnerID: owner, Provider: "p", UpdatedAt: time.Now(), Sealed: []byte(owner)})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, path)
	rows, err := c.LoadOwner(t.Context(), "local")
	if err != nil || len(rows.Discovery) != 1 || rows.Discovery[0].OwnerID != "local" {
		t.Fatal("owner rows", rows, err)
	}
}

// A gateway and stdio clients never use one database together: each
// refuses after its wait.
func TestGatewayAndClientsExcludeEachOther(t *testing.T) {
	shortWaits(t)
	path := tempPath(t)
	s := openStore(t, path)
	start := time.Now()
	if _, err := OpenClient(t.Context(), path, Options{}); !errors.Is(err, ErrClientBusy) || !errors.Is(err, lease.ErrLocked) {
		t.Fatal("client beside a gateway:", err)
	}
	if time.Since(start) < clientWait {
		t.Fatal("client did not wait")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := openClient(t, path)
	if _, err := Open(t.Context(), path, Options{}); !errors.Is(err, ErrInUse) {
		t.Fatal("gateway beside a client:", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	openStore(t, path)
}

// Clients that start together on a missing database all serve, and the
// schema is created once.
func TestClientsCreateTogether(t *testing.T) {
	path := tempPath(t)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := OpenClient(t.Context(), path, Options{})
			if err != nil {
				t.Error(err)
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}()
	}
	wg.Wait()
	if n := count(t, path, "schema_migrations"); n != 1 {
		t.Fatal("ledger rows", n)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("database mode", err)
	}
}

// Another process can take the lock in the gap of the exclusive-to-shared
// conversion. The converting client goes round the loop: it serves beside
// a client and refuses beside a gateway.
func TestConversionGap(t *testing.T) {
	for _, other := range []string{"client", "gateway"} {
		t.Run(other, func(t *testing.T) {
			shortWaits(t)
			path := tempPath(t)
			var took error
			convertHook = func() {
				convertHook = nil
				if other == "client" {
					var c *Client
					if c, took = OpenClient(context.Background(), path, Options{}); took == nil {
						t.Cleanup(func() { _ = c.Close() })
					}
				} else {
					var s *Store
					if s, took = Open(context.Background(), path, Options{}); took == nil {
						t.Cleanup(func() { _ = s.Close(context.Background()) })
					}
				}
			}
			t.Cleanup(func() { convertHook = nil })
			c, err := OpenClient(t.Context(), path, Options{})
			if took != nil {
				t.Fatal("other process in the gap:", took)
			}
			switch {
			case other == "client" && err != nil:
				t.Fatal("client beside a client:", err)
			case other == "gateway" && !errors.Is(err, ErrClientBusy):
				t.Fatal("client beside a gateway:", err)
			}
			if c != nil {
				c.Close()
			}
		})
	}
}

// A client that needs a migration waits for the other clients to leave and
// refuses if they stay; it migrates once it is alone.
func TestClientMigratesOnlyAlone(t *testing.T) {
	shortWaits(t)
	path := tempPath(t)
	old := openClient(t, path)
	defer func(m []string) { migrations = m }(migrations)
	migrations = append(migrations[:len(migrations):len(migrations)], "CREATE TABLE client_test_v2(x INTEGER)")
	if _, err := OpenClient(t.Context(), path, Options{}); !errors.Is(err, ErrClientBusy) {
		t.Fatal("migration beside another client:", err)
	}
	if n := count(t, path, "schema_migrations"); n != 1 {
		t.Fatal("migrated beside another client", n)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	openClient(t, path)
	if n := count(t, path, "schema_migrations"); n != 2 {
		t.Fatal("not migrated", n)
	}
	if got := pragma(t, raw(t, path), "user_version"); got != "2" {
		t.Fatal("user_version", got)
	}
}

// A newer, edited or foreign database is refused at once, without waiting.
func TestClientRefusesUnknownSchema(t *testing.T) {
	path := tempPath(t)
	s := openStore(t, path)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	db := raw(t, path)
	for _, stmt := range []string{"DROP TRIGGER schema_migrations_append_only", "INSERT INTO schema_migrations VALUES (2, '" + strings.Repeat("a", 64) + "', 0)", "PRAGMA user_version = 2"} {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatal(stmt, err)
		}
	}
	db.Close()
	start := time.Now()
	if _, err := OpenClient(t.Context(), path, Options{}); !errors.Is(err, ErrNewer) {
		t.Fatal("newer schema:", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("refusal waited")
	}
	// The refusal released the lock.
	shortWaits(t)
	if _, err := Open(t.Context(), path, Options{}); !errors.Is(err, ErrNewer) {
		t.Fatal("gateway after a refused client:", err)
	}
}

// A replaced database file stops the client before its next write.
func TestReplacedFileStopsClient(t *testing.T) {
	path := tempPath(t)
	c := openClient(t, path)
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertHistory(t.Context(), clientEvent("local", "e1", "tool.dispatch.admitted")); !errors.Is(err, lease.ErrLocked) {
		t.Fatal("write after replacement:", err)
	}
	select {
	case <-c.Lost():
	default:
		t.Fatal("client not stopped")
	}
}
