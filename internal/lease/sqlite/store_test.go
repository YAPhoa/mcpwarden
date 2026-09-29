package sqlite

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/custody"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
	sqlite3 "modernc.org/sqlite/lib"
)

func openStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(t.Context(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

func tempPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "data", "mcpwarden.db")
}

// raw opens a second connection to path, outside the store.
func raw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func pragma(t *testing.T, c interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, name string) string {
	t.Helper()
	var v string
	if err := c.QueryRowContext(t.Context(), "PRAGMA "+name).Scan(&v); err != nil {
		t.Fatal(name, err)
	}
	return v
}

func TestOpenSettingsAndIdentity(t *testing.T) {
	path := tempPath(t)
	s := openStore(t, path)
	for name, want := range map[string]string{"journal_mode": "wal", "synchronous": "2", "foreign_keys": "1", "trusted_schema": "0",
		"busy_timeout": fmt.Sprint(busyTimeout), "query_only": "0", "application_id": fmt.Sprint(applicationID), "user_version": fmt.Sprint(SchemaVersion)} {
		if got := pragma(t, s.conn, name); got != want {
			t.Errorf("executor %s = %s, want %s", name, got, want)
		}
	}
	if got := pragma(t, s.reads, "query_only"); got != "1" {
		t.Error("history reads are writable")
	}
	for _, p := range []string{path, path + ".lock"} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Errorf("%s mode %v", filepath.Base(p), info.Mode().Perm())
		}
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		t.Error("storage directory mode", info.Mode().Perm(), err)
	}
}

// One process holds the database: a second one waits for the lock, then
// gives up with a message naming the cause.
func TestSecondOpenWaitsThenRefuses(t *testing.T) {
	path := tempPath(t)
	first := openStore(t, path)
	defer func(d time.Duration) { lockWait = d }(lockWait)
	lockWait = 300 * time.Millisecond
	start := time.Now()
	if _, err := Open(t.Context(), path, Options{}); !errors.Is(err, ErrInUse) || !errors.Is(err, lease.ErrLocked) {
		t.Fatal("second open:", err)
	}
	if waited := time.Since(start); waited < lockWait {
		t.Fatal("second open did not wait:", waited)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	openStore(t, path)
}

func TestUnsafePathsAreRefused(t *testing.T) {
	for _, path := range []string{"", ":memory:", "file:x.db", "x.db?mode=memory", "x.db#frag"} {
		if _, err := Open(t.Context(), path, Options{}); err == nil || !strings.Contains(err.Error(), "plain file path") {
			t.Errorf("%q: %v", path, err)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("permission bits and symbolic links are Unix checks")
	}
	path := tempPath(t)
	s := openStore(t, path)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), path, Options{}); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatal("readable database:", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), link, Options{}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatal("symlinked database:", err)
	}
	dir := filepath.Join(filepath.Dir(path), "dir.db")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), dir, Options{}); err == nil {
		t.Fatal("a directory was opened as the database")
	}
	// A symbolic link in place of the lock file is refused too.
	other := tempPath(t)
	if err := os.MkdirAll(filepath.Dir(other), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".lock", other+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), other, Options{}); err == nil {
		t.Fatal("symlinked lock file accepted")
	}
}

// Only an empty file or an mcpwarden database of a known schema is opened.
func TestLedgerRefusals(t *testing.T) {
	cases := map[string]struct {
		setup []string
		want  error
	}{
		"foreign tables":        {[]string{"CREATE TABLE notes(x)"}, ErrForeign},
		"foreign application":   {[]string{"PRAGMA application_id = 7", "CREATE TABLE notes(x)"}, ErrForeign},
		"newer user version":    {[]string{"PRAGMA user_version = 99"}, ErrNewer},
		"newer ledger":          {[]string{"DROP TRIGGER schema_migrations_append_only", "INSERT INTO schema_migrations VALUES (2, '" + strings.Repeat("a", 64) + "', 0)", "PRAGMA user_version = 2"}, ErrNewer},
		"edited migration":      {[]string{"DROP TRIGGER schema_migrations_append_only", "UPDATE schema_migrations SET sha256 = '" + strings.Repeat("e", 64) + "'"}, ErrMigration},
		"before schema reset":   {[]string{"DROP TRIGGER schema_migrations_append_only", "UPDATE schema_migrations SET sha256 = '" + preResetBaseline + "'"}, ErrSchemaReset},
		"missing ledger":        {[]string{"DROP TRIGGER schema_migrations_no_delete", "DELETE FROM schema_migrations"}, ErrMigration},
		"user version mismatch": {[]string{"PRAGMA user_version = 0"}, ErrMigration},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := tempPath(t)
			if strings.HasPrefix(name, "foreign") {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				s := openStore(t, path)
				if err := s.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			db := raw(t, path)
			for _, stmt := range c.setup {
				if _, err := db.ExecContext(t.Context(), stmt); err != nil {
					t.Fatal(stmt, err)
				}
			}
			db.Close()
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(t.Context(), path, Options{}); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			// A stdio client refuses it with the same error, at once.
			start := time.Now()
			if _, err := OpenClient(t.Context(), path, Options{}); !errors.Is(err, c.want) {
				t.Fatalf("client: got %v, want %v", err, c.want)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("client refusal waited")
			}
		})
	}
	// An empty file, as a crash between create and migrate leaves, is new.
	path := tempPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	openStore(t, path)
}

// SQLite's busy wait is the only bound on BEGIN IMMEDIATE. A write lock held
// past it (only another connection to the file can hold one) is a stall:
// the store fails closed.
func TestBusyDatabaseFailsClosed(t *testing.T) {
	path := tempPath(t)
	s := openStore(t, path)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	c, err := raw(t, path).Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer c.ExecContext(context.Background(), "ROLLBACK")
	if err := s.WithOwner(t.Context(), "alice", func(lease.Tx) error { return nil }); err != lease.ErrStorage {
		t.Fatal("busy database:", err)
	}
	select {
	case <-s.Lost():
	default:
		t.Fatal("a busy database did not stop the store")
	}
}

// The heartbeat notices a replaced lock file, as it does a replaced database.
func TestReplacedLockFileStopsStore(t *testing.T) {
	path := tempPath(t)
	s := openStore(t, path)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Lost():
	case <-time.After(4 * time.Second):
		t.Fatal("replaced lock file not detected")
	}
}

// A busy executor hands the gate from one owner transaction to the next, so
// the file checks cannot wait for an idle gate: a replaced database or a
// removed lock file stops the store while writers commit back to back.
func TestReplacedFilesStopBusyStore(t *testing.T) {
	for _, replace := range []struct {
		name string
		do   func(path string) error
	}{
		{"database", func(path string) error { return os.Rename(path, path+".moved") }},
		{"lock", func(path string) error { return os.Remove(path + ".lock") }},
	} {
		t.Run(replace.name, func(t *testing.T) {
			path := tempPath(t)
			s := openStore(t, path)
			if err := s.Start(t.Context(), identity.New()); err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var commits atomic.Int64
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						if s.WithOwner(context.Background(), "alice", func(lease.Tx) error { return nil }) == nil {
							commits.Add(1)
						}
					}
				}()
			}
			defer func() { close(stop); wg.Wait() }()
			for commits.Load() < 100 {
				time.Sleep(time.Millisecond)
			}
			if err := replace.do(path); err != nil {
				t.Fatal(err)
			}
			select {
			case <-s.Lost():
			case <-time.After(3 * time.Second):
				t.Fatalf("store kept running under load after its %s file was replaced (%d commits)", replace.name, commits.Load())
			}
		})
	}
}

// A fatal SQLite code stops the store even when the transaction is still
// open and the statement's own family would only fail the change. A
// read-only refusal (query_only standing in for a file that turned
// read-only) leaves the transaction open, so only the fatal list stops the
// store; SQLITE_FULL would not show it, since SQLite rolls that back itself
// and the failed ROLLBACK stops the store anyway.
func TestFatalCodeStopsStore(t *testing.T) {
	s := openStore(t, tempPath(t))
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	var rc int
	err := s.WithOwner(t.Context(), "alice", func(ltx lease.Tx) error {
		x := ltx.(*ownerTx)
		if _, err := x.t.exec("PRAGMA query_only=1"); err != nil {
			return err
		}
		err := x.CatalogRows().PutDiscovery(catalogdb.Discovery{OwnerID: "alice", Provider: "files", Sealed: []byte("x")})
		rc, _ = code(x.t.err)
		return err
	})
	if err == nil || rc&0xff != sqlite3.SQLITE_READONLY {
		t.Fatal("read-only refusal:", err, rc)
	}
	select {
	case <-s.Lost():
	default:
		t.Fatal("a fatal SQLite code left the store running")
	}
}

// A process killed after COMMIT returned keeps the commit, and its lock ends
// with it.
func TestKilledProcessKeepsCommits(t *testing.T) {
	path := tempPath(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
	cmd.Env = append(os.Environ(), "MCPWARDEN_SQLITE_CHILD="+path)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var event string
	lines := bufio.NewScanner(out)
	for lines.Scan() {
		if id, ok := strings.CutPrefix(lines.Text(), "committed "); ok {
			event = id
			break
		}
	}
	if event == "" {
		_ = cmd.Process.Kill()
		t.Fatal("child did not commit")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	s := openStore(t, path)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	found := false
	if err := s.WithOwner(t.Context(), "alice", func(tx lease.Tx) error {
		events, err := tx.(custody.Tx).SecurityEvents(10)
		for _, e := range events {
			found = found || e.ID == event
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("a committed event was lost")
	}
}

// TestCrashChild is the process TestKilledProcessKeepsCommits kills.
func TestCrashChild(t *testing.T) {
	path := os.Getenv("MCPWARDEN_SQLITE_CHILD")
	if path == "" {
		t.Skip("run by TestKilledProcessKeepsCommits")
	}
	s, err := Open(context.Background(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background(), identity.New()); err != nil {
		t.Fatal(err)
	}
	event := identity.New()
	if err := s.WithOwner(context.Background(), "alice", func(tx lease.Tx) error {
		return tx.Event(lease.Event{ID: event, OwnerID: "alice", Type: "execution.locked", At: tx.Now(), BootID: identity.New()})
	}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("committed " + event)
	time.Sleep(time.Minute)
}

// Conflict clauses that silently skip or replace a row would hide guard
// failures; no statement uses them.
func TestNoSilentConflictClauses(t *testing.T) {
	banned := regexp.MustCompile(`(?i)\bOR\s+(IGNORE|REPLACE)\b|\bREPLACE\s+INTO\b`)
	files, _ := filepath.Glob("*.go")
	sqlFiles, _ := filepath.Glob("migrations/*.sql")
	for _, f := range append(files, sqlFiles...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := banned.Find(b); m != nil {
			t.Errorf("%s uses %q", f, m)
		}
	}
}

func bulkHistory(t *testing.T, db *sql.DB, owner string, n int) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `WITH RECURSIVE g(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM g WHERE i < $2)
        INSERT INTO history_events
        (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,timed,failed,forwarded,
         handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record)
        SELECT $1, 'e'||printf('%07d',i), 2, 'tool.dispatch.completed', 'inv-'||'e'||printf('%07d',i), 'tool-'||(i%4), 'tool '||(i%4), 'up-'||(i%3), CASE WHEN i%5=0 THEN 'timeout' ELSE 'ok' END,
         'actor-'||(i%7), i, i, 1, i%5=0, 1, 100, 10, 90, 6, 3, 6, '{}'
        FROM g`, owner, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "ANALYZE"); err != nil {
		t.Fatal(err)
	}
}

// Each single filter and a time range read their own index, in history
// order, and open calls come from history_open.
func TestHistoryPlansUseFilterIndexes(t *testing.T) {
	path := tempPath(t)
	s := openStore(t, path)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	bulkHistory(t, raw(t, path), "alice", 5000)
	for name, c := range map[string]struct {
		q     catalogdb.HistoryQuery
		index string
	}{
		"none":     {catalogdb.HistoryQuery{}, "history_owner_recent"},
		"range":    {catalogdb.HistoryQuery{HasFrom: true, FromNano: 100, HasTo: true, ToNano: 200}, "history_owner_recent"},
		"tool":     {catalogdb.HistoryQuery{ToolID: "tool-1"}, "history_owner_tool"},
		"upstream": {catalogdb.HistoryQuery{Upstream: "up-1"}, "history_owner_upstream"},
		"gateway":  {catalogdb.HistoryQuery{Upstream: "__gateway__"}, "history_owner_upstream"},
		"status":   {catalogdb.HistoryQuery{Status: "timeout"}, "history_owner_status"},
		"actor":    {catalogdb.HistoryQuery{ActorAccessID: "actor-1"}, "history_owner_actor"},
		// With a tool filter the other terms never pick the index.
		"upstream and tool": {catalogdb.HistoryQuery{Upstream: "up-1", ToolID: "tool-1"}, "history_owner_tool"},
		"status and tool":   {catalogdb.HistoryQuery{Status: "timeout", ToolID: "tool-1"}, "history_owner_tool"},
		"actor and tool":    {catalogdb.HistoryQuery{ActorAccessID: "actor-1", ToolID: "tool-1"}, "history_owner_tool"},
	} {
		c.q.Owner = "alice"
		with, args := window(c.q)
		rows, err := s.reads.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+with+"SELECT count(*) FROM win", args...)
		if err != nil {
			t.Fatal(name, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		text := strings.Join(plan, "\n")
		if !strings.Contains(text, "history_open_recent") {
			t.Errorf("%s does not read open calls from history_open:\n%s", name, text)
		}
		// The index gives history order, so the arm stops at its LIMIT
		// instead of sorting every match.
		found := false
		for i, line := range plan {
			if strings.HasPrefix(line, "SEARCH h USING INDEX "+c.index+" ") {
				found = true
				if i+1 < len(plan) && strings.HasPrefix(plan[i+1], "USE TEMP B-TREE") {
					t.Errorf("%s sorts the index scan:\n%s", name, text)
				}
			}
			if line == "SCAN h" || line == "SCAN o" {
				t.Errorf("%s scans a whole table:\n%s", name, text)
			}
		}
		if !found {
			t.Errorf("%s does not use %s:\n%s", name, c.index, text)
		}
	}
}

// A page that runs past its deadline fails alone: the store keeps running
// and the next page is served.
func TestSlowHistoryPageDoesNotStopStore(t *testing.T) {
	if raceEnabled {
		t.Skip("timing test; runs without the race detector")
	}
	path := tempPath(t)
	s := openStore(t, path)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	// Tool and actor alternate together, so each filter's index holds
	// 150,000 candidates and the pair matches none: a sparse page reads them
	// all.
	db := raw(t, path)
	if _, err := db.ExecContext(t.Context(), `WITH RECURSIVE g(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM g WHERE i < 300000)
        INSERT INTO history_events
        (owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,timed,failed,forwarded,
         handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record)
        SELECT 'alice', 'e'||i, 2, 'tool.dispatch.completed', 'inv-'||'e'||i, 'tool-'||(i%2), 'tool', 'up', 'ok', 'actor-'||(i%2), i, i, 1, 0, 1, 100, 10, 90, 6, 3, 6, '{}' FROM g`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "ANALYZE"); err != nil {
		t.Fatal(err)
	}
	defer func(d time.Duration) { historyDeadline = d }(historyDeadline)
	q := catalogdb.HistoryQuery{Owner: "alice", ToolID: "tool-0", ActorAccessID: "actor-1", Limit: 25}
	historyDeadline = 5 * time.Second
	start := time.Now()
	if _, err := s.QueryHistory(t.Context(), q); err != nil {
		t.Fatal(err)
	}
	full := time.Since(start)
	t.Log("full sparse page:", full)
	historyDeadline = full / 10
	start = time.Now()
	if _, err := s.QueryHistory(t.Context(), q); !errors.Is(err, catalogdb.ErrStorage) {
		t.Fatal("slow page:", err, full)
	}
	if took := time.Since(start); took > full/2 {
		t.Fatal("the deadline did not interrupt the scan:", took, full)
	}
	select {
	case <-s.Lost():
		t.Fatal("a slow page stopped the store")
	default:
	}
	historyDeadline = 5 * time.Second
	if got, err := s.QueryHistory(t.Context(), catalogdb.HistoryQuery{Owner: "alice", Limit: 25}); err != nil || len(got.Records) != 25 {
		t.Fatal("next page:", err)
	}
	if err := s.InsertHistory(t.Context(), catalogdb.HistoryRow{OwnerID: "alice", EventID: "after", SchemaVersion: 2, EventType: "tool.dispatch.completed", InvocationID: "inv-after", ToolID: "t", Tool: "x", Upstream: "u", Status: "ok", Record: "{}"}); err != nil {
		t.Fatal("write after a slow page:", err)
	}
}

// Each durability and safety setting is checked: a connection that differs in
// any one of them is refused.
func TestSettingsRefused(t *testing.T) {
	good := map[string]string{"busy_timeout": "busy_timeout(" + fmt.Sprint(busyTimeout) + ")", "foreign_keys": "foreign_keys(1)",
		"journal_mode": "journal_mode(WAL)", "synchronous": "synchronous(FULL)", "trusted_schema": "trusted_schema(0)"}
	for name, bad := range map[string]string{"": "", "journal_mode": "journal_mode(DELETE)", "synchronous": "synchronous(NORMAL)",
		"foreign_keys": "foreign_keys(0)", "trusted_schema": "trusted_schema(1)", "busy_timeout": "busy_timeout(10000)"} {
		var pragmas []string
		for key, p := range good {
			if key == name {
				p = bad
			}
			pragmas = append(pragmas, p)
		}
		db, err := sql.Open("sqlite", dsn(filepath.Join(t.TempDir(), "settings.db"), pragmas...))
		if err != nil {
			t.Fatal(err)
		}
		c, err := db.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		err = checkPragmas(t.Context(), c, busyTimeout, false)
		if name == "" && err != nil {
			t.Error("required settings refused:", err)
		}
		if name != "" && err == nil {
			t.Errorf("%s accepted", bad)
		}
		c.Close()
		db.Close()
	}
}
