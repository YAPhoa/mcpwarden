package pgcatalog

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/catalog/dbcatalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres/pgtest"
	"github.com/yaphoa/mcpwarden/internal/lease/storetest"
)

// fixture is a realistic file catalog and history on a scratch database. All
// credentials are synthetic.
type fixture struct {
	t      *testing.T
	db     *pgtest.Database
	src    Sources
	alice  string
	bob    string
	lines  int
	tokens map[string]string // name -> secret hash
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := pgtest.New(t)
	dir := t.TempDir()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	f := &fixture{t: t, db: db, alice: "account:" + identity.New(), bob: "account:" + identity.New(), tokens: map[string]string{},
		src: Sources{CatalogPath: filepath.Join(dir, "catalog.enc"), CatalogKey: base64.StdEncoding.EncodeToString(raw), HistoryPath: filepath.Join(dir, "audit.jsonl")}}
	store, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []catalog.Account{{ID: f.alice, Username: "alice"}, {ID: f.bob, Username: "bob"}} {
		a.Salt, a.PasswordHash, a.Iterations = []byte("synthetic-salt-"+a.Username), []byte("synthetic-hash-"+a.Username), 1000
		must(store.AddAccount(a))
	}
	future := time.Now().Add(24 * time.Hour).UTC()
	access := []catalog.AccessRecord{
		{ID: identity.New(), Owner: f.alice, Name: "agent", Kind: "api_key", Role: "client", ExpiresAt: future},
		{ID: identity.New(), Owner: f.alice, Name: "revoked", Kind: "api_key", Role: "admin", ExpiresAt: future},
		{ID: identity.New(), Owner: f.alice, Name: "Browser", Kind: "browser", Role: "admin", ExpiresAt: future, Device: "Firefox"},
		{ID: identity.New(), Owner: f.alice, Name: "MCP session", Kind: "mcp", Role: "client", ParentID: "parent"},
		{ID: identity.New(), Owner: f.bob, Name: "expired", Kind: "api_key", Role: "client", ExpiresAt: time.Now().Add(-time.Hour).UTC()},
	}
	for i, a := range access {
		a.SecretHash = fmt.Sprintf("%064x", i+1)
		if a.Kind == "api_key" {
			a.PublicID = identity.NewPublicID()
		}
		must(store.AddAccess(a))
		f.tokens[a.Name] = a.SecretHash
		if a.Name == "revoked" {
			must(store.RevokeAccess(f.alice, a.ID))
		}
	}
	entries := []catalog.Entry{
		{ID: identity.New(), Owner: f.alice, Name: "remote", URL: "https://example.com/mcp", AuthType: "bearer", HeaderNames: []string{"Authorization"}, CallTimeout: "45s"},
		{ID: identity.New(), Owner: f.alice, Name: "keyed", URL: "https://example.com/keyed", AuthType: "headers", HeaderNames: []string{"X-API-Key", "X-Tenant"}},
		{ID: identity.New(), Owner: f.alice, Name: "gone", URL: "https://example.com/gone"},
		{ID: identity.New(), Owner: f.bob, Name: "svc", URL: "https://example.com/svc", AuthType: "none"},
	}
	for _, e := range entries {
		must(store.Add(e))
	}
	must(store.SetDiscovery(f.alice, "remote", []*mcp.Tool{{Name: "search", Description: "Synthetic", InputSchema: map[string]any{"type": "object"}}}))
	must(store.SetVisibility(f.alice, "remote", catalog.Visibility{Mode: "selected", Enabled: []string{"remote__search"}}))
	must(store.SetProviderEnabled(f.bob, "svc", false))
	must(store.Delete(f.alice, "gone"))
	must(store.Close())

	// History: v0 lines (one with CRLF), then v1 records and v2 invocations,
	// including an admission without completion.
	var v0 strings.Builder
	for i := 0; i < 5; i++ {
		fmt.Fprintf(&v0, `{"ts":"2026-01-0%dT10:00:00.123456789Z","owner":%q,"session":"s","tool":"remote__search","upstream":"remote","args_sha256":"%064x","decision":"allow","status":"ok","duration_ms":%d,"response_items":1,"structured":false}`, i+1, f.alice, i, i*7)
		if i == 2 {
			v0.WriteString("\r")
		}
		v0.WriteString("\n")
	}
	must(os.WriteFile(f.src.HistoryPath, []byte(v0.String()), 0600))
	w, err := audit.Open(f.src.HistoryPath)
	must(err)
	for i := 0; i < 8; i++ {
		owner := f.alice
		if i%3 == 0 {
			owner = f.bob
		}
		must(w.Write(audit.Record{Owner: owner, Tool: "remote__search", ToolID: identity.Derive(entries[0].ID, "search"), Upstream: "remote", Decision: "allow", Status: []string{"ok", "tool_error"}[i%2],
			ArgsSHA256: fmt.Sprintf("%064x", 100+i), TS: time.Now().UTC(), Timing: &audit.Timing{HandlerUS: int64(100 * (i + 1)), GatewayUS: 10, UpstreamUS: int64(90 * (i + 1)), Forwarded: true}}))
	}
	for i := 0; i < 3; i++ {
		ctx := identity.WithActor(context.Background(), identity.Actor{Owner: f.alice, AccessID: access[0].ID, PublicID: identity.NewPublicID(), Kind: "api_key", Label: "agent"})
		r := audit.NewInvocation(ctx, f.alice)
		r.ToolID, r.Tool, r.Upstream = identity.Derive(entries[0].ID, "search"), "remote__search", "remote"
		r.ArgsSHA256 = fmt.Sprintf("%064x", 200+i)
		must(w.Write(r.Admission()))
		if i < 2 {
			r.EventType, r.Decision, r.Status = audit.DispatchCompleted, "allow", "ok"
			r.CompletedAt = time.Now().UTC()
			r.OccurredAt = r.CompletedAt
			r.Timing = &audit.Timing{HandlerUS: 500, GatewayUS: 20, UpstreamUS: 480, Forwarded: true}
			must(w.Write(r))
		}
	}
	must(w.Close())
	f.lines = 5 + 8 + 5
	return f
}

func (f *fixture) importAll(opts Options) Manifest {
	f.t.Helper()
	m, err := Import(f.t.Context(), f.db.Admin, f.src, opts)
	if err != nil {
		f.t.Fatal(err)
	}
	return m
}

func (f *fixture) cutover() {
	f.t.Helper()
	f.importAll(Options{})
	if _, err := Cutover(f.t.Context(), f.db.Admin, f.src); err != nil {
		f.t.Fatal(err)
	}
}

type noAuthority struct{}

func (noAuthority) Caller(string, string) (lease.Caller, bool) { return lease.Caller{}, false }
func (noAuthority) Credential(string, string) (lease.Credential, bool) {
	return lease.Credential{}, false
}

type noActivator struct{}

func (noActivator) Stage(context.Context, string, lease.Credential, []byte) (lease.Material, error) {
	return nil, errors.New("no activation in catalog tests")
}

// gateway starts the runtime side as the PostgreSQL backend does.
func (f *fixture) gateway() (*dbcatalog.Repository, *postgres.Store, *lease.Service, *bool) {
	f.t.Helper()
	db, err := postgres.Open(f.t.Context(), f.db.RuntimeDSN)
	if err != nil {
		f.t.Fatal(err)
	}
	service, err := lease.New(f.t.Context(), db, noAuthority{}, noActivator{}, lease.DefaultOptions())
	if err != nil {
		f.t.Fatal(err)
	}
	failed := new(bool)
	repo, err := dbcatalog.New(f.src.CatalogKey, db, func() { *failed = true })
	if err != nil {
		f.t.Fatal(err)
	}
	if err := repo.Load(f.t.Context()); err != nil {
		f.t.Fatal(err)
	}
	repo.Attach(service)
	f.t.Cleanup(func() {
		service.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = db.Close(ctx)
	})
	return repo, db, service, failed
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.Admin.QueryRow(f.t.Context(), sql, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestImportPreservesCatalogAndHistory(t *testing.T) {
	f := newFixture(t)
	source, _, err := catalog.ReadSnapshot(f.src.CatalogPath, f.src.CatalogKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := f.importAll(Options{BatchLines: 4})
	if m.Accounts != 2 || m.Connectors != 3 || m.Tombstones != 1 || m.Discovery != 1 || m.Visibility != 2 || m.Access["api_key"] != 3 || m.Access["browser"] != 1 ||
		m.HistoryLines != int64(f.lines) || m.HistoryVersions["0"] != 5 || m.HistoryVersions["1"] != 8 || m.HistoryVersions["2"] != 5 || m.Normalized.EndedMCPSessions != 1 {
		t.Fatalf("manifest: %+v", m)
	}
	if info, err := os.Stat(m.Snapshot); err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("snapshot directory is not protected", err)
	}
	// Until cutover the file gateway cannot start, and PostgreSQL is not active.
	if _, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey); err == nil {
		t.Fatal("file backend opened during import")
	}
	if _, err := Cutover(t.Context(), f.db.Admin, f.src); err != nil {
		t.Fatal(err)
	}
	repo, db, _, _ := f.gateway()

	// Ownership, verifiers, roles, expiry, timestamps and grants are exact.
	for _, owner := range []string{f.alice, f.bob} {
		var want []catalog.Entry
		for _, e := range source.Entries {
			if e.Owner == owner {
				// List returns copies sorted by name, as the file store does.
				want = append(want, e)
			}
		}
		sort.Slice(want, func(i, j int) bool { return want[i].Name < want[j].Name })
		got := repo.List(owner)
		if !reflect.DeepEqual(got, want) {
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			t.Fatalf("connectors for %s differ:\n%s\n%s", owner, g, w)
		}
	}
	for _, a := range source.Access {
		got, ok := repo.AccessByID(a.Owner, a.ID)
		want := a
		want.SecretHash = ""
		if a.Kind == "mcp" {
			if got.EndedAt.IsZero() {
				t.Fatal("open MCP session was not ended")
			}
			want.EndedAt, want.UpdatedAt = got.EndedAt, got.UpdatedAt
		}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("access record %s differs", a.Name)
		}
	}
	if _, ok := repo.AuthenticateAccess(f.tokens["agent"], "api_key"); !ok {
		t.Fatal("active key does not authenticate")
	}
	for _, name := range []string{"revoked", "expired"} {
		if _, ok := repo.AuthenticateAccess(f.tokens[name], "api_key"); ok {
			t.Fatal(name, "key authenticates after import")
		}
	}
	if v := repo.Visibility(f.alice, "remote"); v.Mode != "selected" || !repo.ToolVisible(f.alice, "remote", "remote__search") {
		t.Fatal("visibility changed")
	}
	if !repo.Visibility(f.bob, "svc").Disabled {
		t.Fatal("disabled provider was enabled")
	}
	if d, ok := repo.Discovery(f.alice, "remote"); !ok || len(d.Tools) != 1 {
		t.Fatal("discovery lost")
	}
	if n := f.count("SELECT count(*) FROM mcpwarden_security.catalog_legacy_tombstones"); n != 1 {
		t.Fatal("tombstone lost", n)
	}

	// History answers exactly as the JSONL reader over the same bytes.
	file, err := audit.Open(filepath.Join(m.Snapshot, "history.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	history := dbcatalog.NewHistory(db)
	for _, q := range []audit.HistoryFilter{
		{Owner: f.alice, Page: 1, Size: 5}, {Owner: f.alice, Page: 2, Size: 5}, {Owner: f.alice, Page: 3, Size: 5},
		{Owner: f.bob, Page: 1, Size: 100}, {Owner: f.alice, Status: "unknown", Page: 1, Size: 10},
		{Owner: f.alice, Status: "tool_error", Upstream: "remote", Page: 1, Size: 10},
		{Owner: f.alice, From: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC), Page: 1, Size: 10},
	} {
		wantRows, wantTotal, wantTools, wantStats, err := file.QueryHistoryPerformance(q)
		if err != nil {
			t.Fatal(err)
		}
		gotRows, gotTotal, gotTools, gotStats, err := history.QueryHistoryPerformance(q)
		if err != nil {
			t.Fatal(err)
		}
		// Stored aggregates give sum/count; the reader keeps a streaming mean.
		for _, pair := range [][2]*audit.Latency{{&gotStats.Handler, &wantStats.Handler}, {&gotStats.Gateway, &wantStats.Gateway}, {&gotStats.Upstream, &wantStats.Upstream}} {
			if math.Abs(pair[0].MeanUS-pair[1].MeanUS) > 1e-9*math.Max(1, pair[1].MeanUS) {
				t.Fatalf("mean latency differs for %+v", q)
			}
			pair[0].MeanUS = pair[1].MeanUS
		}
		if gotTotal != wantTotal || !reflect.DeepEqual(gotRows, wantRows) || !reflect.DeepEqual(gotTools, wantTools) || !reflect.DeepEqual(gotStats, wantStats) {
			a, _ := json.Marshal([]any{gotRows, gotTools, gotStats})
			b, _ := json.Marshal([]any{wantRows, wantTools, wantStats})
			t.Fatalf("history differs for %+v: total %d/%d\n%s\n%s", q, gotTotal, wantTotal, a, b)
		}
	}
}

func TestImportResumesWithoutDuplicates(t *testing.T) {
	f := newFixture(t)
	stop := errors.New("interrupted")
	_, err := Import(t.Context(), f.db.Admin, f.src, Options{BatchLines: 3, AfterBatch: func(lines int64) error {
		if lines == 6 {
			return stop
		}
		return nil
	}})
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
	if st, _, _ := Status(t.Context(), f.db.Admin); st.State != "importing" || st.HistoryLines != 6 {
		t.Fatalf("checkpoint: %s %d", st.State, st.HistoryLines)
	}
	if _, err := Cutover(t.Context(), f.db.Admin, f.src); !errors.Is(err, ErrState) {
		t.Fatal("cutover of a partial import", err)
	}
	first := f.importAll(Options{BatchLines: 3})
	again := f.importAll(Options{})
	if n := f.count("SELECT count(*) FROM mcpwarden_security.history_events"); n != f.lines {
		t.Fatal("history rows after resume", n)
	}
	if first.CatalogDigest != again.CatalogDigest || first.HistoryLines != again.HistoryLines || first.ImportID != again.ImportID {
		t.Fatal("repeated import changed the result")
	}
	if n := f.count("SELECT count(*) FROM mcpwarden_security.catalog_access"); n != 5 {
		t.Fatal("catalog rows duplicated", n)
	}
}

func TestImportRefusesUnsafeOrChangedSources(t *testing.T) {
	t.Run("readable by others", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Chmod(f.src.CatalogPath, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Import(t.Context(), f.db.Admin, f.src, Options{}); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatal("imported a world-readable catalog", err)
		}
	})
	t.Run("history appended mid-import", func(t *testing.T) {
		f := newFixture(t)
		stop := errors.New("interrupted")
		_, _ = Import(t.Context(), f.db.Admin, f.src, Options{BatchLines: 2, AfterBatch: func(int64) error { return stop }})
		raw, _ := os.ReadFile(f.src.HistoryPath)
		if err := os.WriteFile(f.src.HistoryPath, append(raw, raw[:strings.IndexByte(string(raw), '\n')+1]...), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Import(t.Context(), f.db.Admin, f.src, Options{}); !errors.Is(err, ErrSourceMoved) {
			t.Fatal(err)
		}
	})
	t.Run("catalog changed before cutover", func(t *testing.T) {
		f := newFixture(t)
		f.importAll(Options{})
		snap, _, _ := catalog.ReadSnapshot(f.src.CatalogPath, f.src.CatalogKey, time.Now())
		if err := catalog.WriteSnapshot(f.src.CatalogPath, f.src.CatalogKey, snap); err != nil {
			t.Fatal(err)
		}
		if _, err := Cutover(t.Context(), f.db.Admin, f.src); !errors.Is(err, ErrSourceMoved) {
			t.Fatal(err)
		}
	})
	t.Run("snapshot changed before cutover", func(t *testing.T) {
		f := newFixture(t)
		m := f.importAll(Options{})
		if err := os.WriteFile(filepath.Join(m.Snapshot, "history.jsonl"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Cutover(t.Context(), f.db.Admin, f.src); !errors.Is(err, ErrSourceMoved) {
			t.Fatal(err)
		}
	})
	t.Run("target not empty", func(t *testing.T) {
		f := newFixture(t)
		f.importAll(Options{})
		if _, err := f.db.Admin.Exec(t.Context(), "DELETE FROM mcpwarden_security.catalog_state"); err != nil {
			t.Fatal(err)
		}
		// The importing marker now has no state in this database.
		if _, err := Import(t.Context(), f.db.Admin, f.src, Options{}); !errors.Is(err, ErrMarker) {
			t.Fatal(err)
		}
		if err := catalog.RemoveMarker(f.src.CatalogPath); err != nil {
			t.Fatal(err)
		}
		if _, err := Import(t.Context(), f.db.Admin, f.src, Options{}); !errors.Is(err, ErrNotEmpty) {
			t.Fatal(err)
		}
	})
	t.Run("gateway running", func(t *testing.T) {
		f := newFixture(t)
		store, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if _, err := Import(t.Context(), f.db.Admin, f.src, Options{}); !errors.Is(err, ErrLocked) {
			t.Fatal(err)
		}
	})
}

func TestVerificationDetectsTampering(t *testing.T) {
	for name, sql := range map[string]string{
		// Flip every bit of one byte: writing a fixed value left the row unchanged
		// whenever the random ciphertext already held it (1 run in 256).
		"sealed byte":      "UPDATE mcpwarden_security.catalog_access SET sealed = set_byte(sealed, 29, get_byte(sealed, 29) # 255) WHERE access_id = (SELECT min(access_id) FROM mcpwarden_security.catalog_access)",
		"swapped payloads": "UPDATE mcpwarden_security.catalog_access a SET sealed = b.sealed FROM mcpwarden_security.catalog_access b WHERE a.access_id = (SELECT min(access_id) FROM mcpwarden_security.catalog_access) AND b.access_id = (SELECT max(access_id) FROM mcpwarden_security.catalog_access)",
		"plain role":       "UPDATE mcpwarden_security.catalog_access SET role = CASE role WHEN 'admin' THEN 'client' ELSE 'admin' END WHERE kind = 'api_key' AND access_id = (SELECT min(access_id) FROM mcpwarden_security.catalog_access WHERE kind = 'api_key')",
		"expiry":           "UPDATE mcpwarden_security.catalog_access SET expires_at = expires_at + interval '1 day' WHERE expires_at IS NOT NULL",
		"grant revision":   "UPDATE mcpwarden_security.catalog_connectors SET grant_revision = 1 WHERE deleted_at IS NULL",
		"history bytes":    "UPDATE mcpwarden_security.history_events SET record = replace(record, '\"status\":\"ok\"', '\"status\":\"ok\" ') WHERE source_line = 3",
		"history row":      "DELETE FROM mcpwarden_security.history_events WHERE source_line = 7",
		"history order":    "UPDATE mcpwarden_security.history_events SET source_line = source_line + 1000 WHERE source_line = 1",
		// Queries read the derived columns, so each must match its line.
		"history v0 event id":  "UPDATE mcpwarden_security.history_events SET event_id = event_id || '-changed' WHERE source_line = 1",
		"history owner column": "UPDATE mcpwarden_security.history_events SET owner_id = owner_id || '-other' WHERE source_line = 6",
		"history filter":       "UPDATE mcpwarden_security.history_events SET status = 'denied' WHERE source_line = 7",
		"history time order":   "UPDATE mcpwarden_security.history_events SET history_ns = history_ns + 1 WHERE source_line = 2",
		"history timing":       "UPDATE mcpwarden_security.history_events SET handler_us = handler_us + 1 WHERE source_line = (SELECT min(source_line) FROM mcpwarden_security.history_events WHERE timed)",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.importAll(Options{})
			if _, err := f.db.Admin.Exec(t.Context(), sql); err != nil {
				t.Fatal(err)
			}
			if _, err := Cutover(t.Context(), f.db.Admin, f.src); err == nil {
				t.Fatal("cutover accepted tampered rows")
			}
			if st, _, _ := Status(t.Context(), f.db.Admin); st.State != "imported" {
				t.Fatal("state changed", st.State)
			}
		})
	}
}

// Failure before cutover: abort leaves the file backend exactly as it was.
func TestAbortBeforeCutoverRestoresFileGateway(t *testing.T) {
	f := newFixture(t)
	before, _, _ := fileHash(f.src.CatalogPath)
	history, _, _ := fileHash(f.src.HistoryPath)
	f.importAll(Options{})
	if err := Abort(t.Context(), f.db.Admin, f.src); err != nil {
		t.Fatal(err)
	}
	if n := f.count("SELECT count(*) FROM mcpwarden_security.history_events") + f.count("SELECT count(*) FROM mcpwarden_security.catalog_state") +
		f.count("SELECT count(*) FROM mcpwarden_security.history_tools") + f.count("SELECT count(*) FROM mcpwarden_security.history_open"); n != 0 {
		t.Fatal("rows left after abort", n)
	}
	if after, _, _ := fileHash(f.src.CatalogPath); after != before {
		t.Fatal("abort changed the catalog file")
	}
	if after, _, _ := fileHash(f.src.HistoryPath); after != history {
		t.Fatal("abort changed the history file")
	}
	store, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	// The import is repeated after the abort; its open admission and tool
	// names are rebuilt from the history, not left over.
	f.cutover()
	if err := Abort(t.Context(), f.db.Admin, f.src); !errors.Is(err, ErrState) {
		t.Fatal("abort after cutover", err)
	}
	_, db, _, _ := f.gateway()
	indexed := dbcatalog.NewHistory(db)
	unknown, total, tools, _, err := indexed.QueryHistoryPerformance(audit.HistoryFilter{Owner: f.alice, Status: "unknown", Page: 1, Size: 25})
	if err != nil || total != 1 || len(unknown) != 1 || unknown[0].EventType != audit.DispatchAdmitted || len(tools) != 1 || tools[0].Name != "remote__search" {
		t.Fatal("history after a repeated import:", total, tools, err)
	}
	all, _, _, _, err := indexed.QueryHistoryPerformance(audit.HistoryFilter{Owner: f.alice, Page: 1, Size: 25})
	if err != nil {
		t.Fatal(err)
	}
	open := 0
	for _, r := range all {
		if r.Status == "unknown" {
			open++
		}
	}
	if open != 1 {
		t.Fatal("unknown filter differs from the visible history:", open)
	}
}

func TestRollbackResumesAndRefusesReplacedFiles(t *testing.T) {
	f := newFixture(t)
	f.cutover()
	repo, db, service, _ := f.gateway()
	agent, ok := repo.AuthenticateAccess(f.tokens["agent"], "api_key")
	if !ok {
		t.Fatal("agent key missing")
	}
	if err := repo.RevokeAccess(f.alice, agent.ID); err != nil {
		t.Fatal(err)
	}
	live := audit.Record{Owner: f.alice, Tool: "remote__search", Upstream: "remote", Decision: "allow", Status: "ok", TS: time.Now().UTC(), ArgsSHA256: strings.Repeat("b", 64)}
	if err := dbcatalog.NewHistory(db).Write(live); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(t.Context(), f.db.Admin, f.src); !errors.Is(err, ErrLocked) {
		t.Fatal("rollback ran beside a PostgreSQL gateway", err)
	}
	f.stop(service, db)
	// An access window still open when the rollback starts.
	window, err := postgres.Open(t.Context(), f.db.RuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	leaseID := storetest.ActiveWindow(t, window)
	f.closeStore(window)

	// Interrupted after the database left the active state.
	st, _, _ := Status(t.Context(), f.db.Admin)
	st, err = beginRollback(t.Context(), f.db.Admin, st)
	if err != nil {
		t.Fatal(err)
	}
	// The rollback ends the window, with its event under the rollback ID.
	if n := f.count("SELECT count(*) FROM mcpwarden_security.leases WHERE lease_id=$1 AND state='suspended'", leaseID); n != 1 {
		t.Fatal("rollback left the window open")
	}
	if n := f.count("SELECT count(*) FROM mcpwarden_security.security_events WHERE event_type='lease.suspended' AND lease_id=$1 AND boot_id=$2", leaseID, st.RollbackID); n != 1 {
		t.Fatal("window suspension not audited under the rollback", n)
	}
	if _, err := f.gatewayErr(); !errors.Is(err, catalogdb.ErrNotActive) {
		t.Fatal("PostgreSQL gateway loaded while rolling back", err)
	}
	// A file someone put back is never overwritten silently.
	if err := os.WriteFile(f.src.CatalogPath, []byte("not the source"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(t.Context(), f.db.Admin, f.src); !errors.Is(err, ErrReplaced) {
		t.Fatal(err)
	}
	if err := os.Remove(f.src.CatalogPath); err != nil {
		t.Fatal(err)
	}
	m, err := Rollback(t.Context(), f.db.Admin, f.src)
	if err != nil {
		t.Fatal(err)
	}
	if m.RollbackID != st.RollbackID || m.SuspendedLeases != 1 || m.LegacyHistory != int64(f.lines) || m.LiveHistory != 1 || m.EndedMCP != 0 {
		t.Fatalf("manifest: %+v", m)
	}
	again, err := Rollback(t.Context(), f.db.Admin, f.src)
	if err != nil || again.RollbackID != m.RollbackID || again.HistorySHA256 != m.HistorySHA256 {
		t.Fatal("repeated rollback", err)
	}
	// History is the pinned bytes plus the new record; the file gateway reads it.
	source, _ := os.ReadFile(filepath.Join(SnapshotDir(f.src, st.ImportID), "history.jsonl"))
	exported, _ := os.ReadFile(f.src.HistoryPath)
	if !strings.HasPrefix(string(exported), string(source)) || strings.Count(string(exported[len(source):]), "\n") != 1 {
		t.Fatal("history export is not the source plus new records")
	}
	var rec audit.Record
	if json.Unmarshal(exported[len(source):len(exported)-1], &rec) != nil || rec.ArgsSHA256 != live.ArgsSHA256 {
		t.Fatal("new history record changed")
	}
	store, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, ok := store.AuthenticateAccess(f.tokens["agent"], "api_key"); ok {
		t.Fatal("rollback revived a key revoked after cutover")
	}
	if st, _, _ := Status(t.Context(), f.db.Admin); st.State != "rolled_back" {
		t.Fatal(st.State)
	}
	if _, err := f.gatewayErr(); !errors.Is(err, catalogdb.ErrNotActive) {
		t.Fatal("PostgreSQL gateway loaded after rollback", err)
	}
	if marker, ok, err := catalog.ReadMarker(f.src.CatalogPath); err != nil || !ok || marker.State != "rolled_back" || marker.RollbackID != m.RollbackID {
		t.Fatal("marker", marker, err)
	}
}

// stop closes a gateway and waits until PostgreSQL has released its executor
// lock. The server drops session locks when the backend exits, which can
// happen after the client has closed, so a migration started at once could
// still see the lock held.
func (f *fixture) stop(service *lease.Service, db *postgres.Store) {
	f.t.Helper()
	service.Close()
	f.closeStore(db)
}

// closeStore closes a store and waits until the server has released its
// session lock: the backend exits after the client closes, not before.
func (f *fixture) closeStore(db *postgres.Store) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = db.Close(ctx)
	for {
		var held bool
		if err := f.db.Admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_database d ON d.oid = l.database WHERE l.locktype = 'advisory' AND d.datname = current_database() AND l.pid <> pg_backend_pid())").Scan(&held); err != nil {
			f.t.Fatal(err)
		}
		if !held {
			return
		}
		select {
		case <-ctx.Done():
			f.t.Fatal("gateway lock was not released")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (f *fixture) gatewayErr() (*dbcatalog.Repository, error) {
	db, err := postgres.Open(f.t.Context(), f.db.RuntimeDSN)
	if err != nil {
		return nil, err
	}
	defer f.closeStore(db)
	if err := db.Start(f.t.Context(), identity.New()); err != nil {
		return nil, err
	}
	repo, err := dbcatalog.New(f.src.CatalogKey, db, nil)
	if err != nil {
		return nil, err
	}
	return repo, repo.Load(f.t.Context())
}

// A marker guards the database that wrote it. Another database cannot replace
// or remove it, so an empty target never makes a cut-over file authoritative.
// A rolled_back marker is kept inside the import that replaces it and restored
// if that import is abandoned.
func TestMarkerBelongsToItsDatabase(t *testing.T) {
	f := newFixture(t)
	f.cutover()
	active, _, err := catalog.ReadMarker(f.src.CatalogPath)
	if err != nil || active.State != "active" {
		t.Fatal("marker after cutover", active, err)
	}
	other := pgtest.New(t)
	unchanged := func(want catalog.Marker) {
		t.Helper()
		got, ok, err := catalog.ReadMarker(f.src.CatalogPath)
		if err != nil || !ok || !reflect.DeepEqual(got, want) {
			t.Fatal("marker changed", got, err)
		}
	}
	if _, err := Import(t.Context(), other.Admin, f.src, Options{}); !errors.Is(err, ErrMarker) {
		t.Fatal("import into another database replaced the active marker", err)
	}
	if err := Abort(t.Context(), other.Admin, f.src); !errors.Is(err, ErrMarker) {
		t.Fatal("abort in another database", err)
	}
	if _, err := Cutover(t.Context(), other.Admin, f.src); err == nil {
		t.Fatal("cutover in another database")
	}
	unchanged(active)
	if _, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey); err == nil {
		t.Fatal("file backend opened while PostgreSQL is active")
	}

	// After a rollback the file is authoritative again, so a fresh database may
	// import it; abandoning that import restores the rollback's guard.
	m, err := Rollback(t.Context(), f.db.Admin, f.src)
	if err != nil {
		t.Fatal(err)
	}
	rolled, _, _ := catalog.ReadMarker(f.src.CatalogPath)
	next, err := Import(t.Context(), other.Admin, f.src, Options{})
	if err != nil {
		t.Fatal(err)
	}
	importing, _, _ := catalog.ReadMarker(f.src.CatalogPath)
	if importing.State != "importing" || importing.ImportID != next.ImportID || importing.Previous == nil || *importing.Previous != rolled {
		t.Fatal("importing marker", importing)
	}
	if _, err := Rollback(t.Context(), f.db.Admin, f.src); !errors.Is(err, ErrMarker) {
		t.Fatal("finished rollback rewrote another import's marker", err)
	}
	if err := Abort(t.Context(), other.Admin, f.src); err != nil {
		t.Fatal(err)
	}
	unchanged(rolled)
	store, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey)
	if err != nil {
		t.Fatal("rollback export refused after abort", err)
	}
	store.Close()
	if old, err := os.ReadFile(filepath.Join(SnapshotDir(f.src, m.ImportID), "catalog")); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(f.src.CatalogPath, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey); err == nil {
		t.Fatal("pre-cutover catalog opened after the abandoned import")
	}
}

// After a rollback only the exported file may be imported again. An older
// copy placed beside the rolled_back marker is refused before any row is
// written, and the marker stays.
func TestImportAfterRollbackRequiresTheExport(t *testing.T) {
	f := newFixture(t)
	f.cutover()
	repo, db, service, _ := f.gateway()
	agent, ok := repo.AuthenticateAccess(f.tokens["agent"], "api_key")
	if !ok {
		t.Fatal("agent key missing")
	}
	if err := repo.RevokeAccess(f.alice, agent.ID); err != nil {
		t.Fatal(err)
	}
	f.stop(service, db)
	m, err := Rollback(t.Context(), f.db.Admin, f.src)
	if err != nil {
		t.Fatal(err)
	}
	rolled, _, _ := catalog.ReadMarker(f.src.CatalogPath)
	export, err := os.ReadFile(f.src.CatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(SnapshotDir(f.src, m.ImportID), "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.src.CatalogPath, old, 0600); err != nil {
		t.Fatal(err)
	}
	other := pgtest.New(t)
	if _, err := Import(t.Context(), other.Admin, f.src, Options{}); !errors.Is(err, ErrNotExport) {
		t.Fatal("imported a pre-cutover copy after rollback", err)
	}
	if marker, _, err := catalog.ReadMarker(f.src.CatalogPath); err != nil || !reflect.DeepEqual(marker, rolled) {
		t.Fatal("refused import changed the marker", marker, err)
	}
	var rows int
	if err := other.Admin.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM mcpwarden_security.catalog_state) + (SELECT count(*) FROM mcpwarden_security.catalog_access)").Scan(&rows); err != nil || rows != 0 {
		t.Fatal("refused import wrote rows", rows, err)
	}
	// The export itself imports, and the revoked key stays revoked.
	if err := os.WriteFile(f.src.CatalogPath, export, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(t.Context(), other.Admin, f.src, Options{}); err != nil {
		t.Fatal(err)
	}
	var revoked bool
	if err := other.Admin.QueryRow(t.Context(), "SELECT revoked_at IS NOT NULL FROM mcpwarden_security.catalog_access WHERE access_id=$1", agent.ID).Scan(&revoked); err != nil || !revoked {
		t.Fatal("re-import revived the revoked key", revoked, err)
	}
}

// Abort keeps its state row, marked aborting, until the marker is cleaned up.
// An abort interrupted after its database commit finishes on the next run,
// and another database still cannot touch the marker.
func TestAbortResumesAfterItsDatabaseCommit(t *testing.T) {
	f := newFixture(t)
	f.importAll(Options{})
	importing, _, _ := catalog.ReadMarker(f.src.CatalogPath)
	// The first abort's database transaction committed, then it stopped.
	if _, err := f.db.Admin.Exec(t.Context(), `DELETE FROM mcpwarden_security.history_events; DELETE FROM mcpwarden_security.catalog_discovery;
		DELETE FROM mcpwarden_security.catalog_visibility; DELETE FROM mcpwarden_security.catalog_legacy_tombstones;
		DELETE FROM mcpwarden_security.catalog_connectors; DELETE FROM mcpwarden_security.catalog_access; DELETE FROM mcpwarden_security.catalog_accounts;
		UPDATE mcpwarden_security.catalog_state SET state = 'aborting'`); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := Status(t.Context(), f.db.Admin); st.State != "aborting" {
		t.Fatal(st.State)
	}
	if _, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey); err == nil {
		t.Fatal("file backend opened during an unfinished abort")
	}
	if _, err := Import(t.Context(), f.db.Admin, f.src, Options{}); !errors.Is(err, ErrState) {
		t.Fatal("import during an unfinished abort", err)
	}
	other := pgtest.New(t)
	if err := Abort(t.Context(), other.Admin, f.src); !errors.Is(err, ErrMarker) {
		t.Fatal("another database cleaned up the marker", err)
	}
	if marker, _, _ := catalog.ReadMarker(f.src.CatalogPath); !reflect.DeepEqual(marker, importing) {
		t.Fatal("marker changed", marker)
	}
	if err := Abort(t.Context(), f.db.Admin, f.src); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := catalog.ReadMarker(f.src.CatalogPath); ok {
		t.Fatal("marker left after the resumed abort")
	}
	if st, exists, _ := Status(t.Context(), f.db.Admin); exists {
		t.Fatal("state left after the resumed abort", st.State)
	}
	store, err := catalog.Open(f.src.CatalogPath, f.src.CatalogKey)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()

	// Stopped after the marker cleanup but before the state was deleted.
	f.importAll(Options{})
	st, _, _ := Status(t.Context(), f.db.Admin)
	if _, err := f.db.Admin.Exec(t.Context(), "UPDATE mcpwarden_security.catalog_state SET state = 'aborting'"); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RemoveMarker(f.src.CatalogPath); err != nil {
		t.Fatal(err)
	}
	if err := Abort(t.Context(), f.db.Admin, f.src); err != nil {
		t.Fatal(err)
	}
	if _, exists, _ := Status(t.Context(), f.db.Admin); exists {
		t.Fatal("state left after the second resumed abort", st.ImportID)
	}
}

// Above 25,000 matches the readers differ on purpose: PostgreSQL counts the
// newest 25,000 and reports the rest as capped, while the JSONL reader, which
// PR 4 removes, still counts everything. Below the window they agree (see
// TestImportPreservesCatalogAndHistory).
func TestCappedHistoryDiffersFromJSONL(t *testing.T) {
	f := newFixture(t)
	file, err := os.OpenFile(f.src.HistoryPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lines strings.Builder
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 25010 {
		fmt.Fprintf(&lines, `{"ts":%q,"owner":%q,"session":"s","tool":"remote__search","upstream":"remote","args_sha256":"%064x","decision":"allow","status":"ok","duration_ms":1,"response_items":1,"structured":false}`+"\n",
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano), f.alice, i)
	}
	if _, err := file.WriteString(lines.String()); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	jsonl, err := audit.Open(f.src.HistoryPath)
	if err != nil {
		t.Fatal(err)
	}
	_, fileTotal, _, _, err := jsonl.QueryHistoryPerformance(audit.HistoryFilter{Owner: f.alice, Page: 1, Size: 25})
	jsonl.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.cutover()
	_, db, _, _ := f.gateway()
	_, total, _, stats, err := dbcatalog.NewHistory(db).QueryHistoryPerformance(audit.HistoryFilter{Owner: f.alice, Page: 1, Size: 25})
	if err != nil {
		t.Fatal(err)
	}
	if fileTotal <= 25000 || total != 25000 || !stats.Capped {
		t.Fatal("capped difference:", fileTotal, total, stats.Capped)
	}
	if _, _, _, _, err := dbcatalog.NewHistory(db).QueryHistoryPerformance(audit.HistoryFilter{Owner: f.alice, Page: 1001, Size: 25}); err == nil {
		t.Fatal("a page beyond the window was served")
	}
}
