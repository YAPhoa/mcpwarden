package storetest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/dbcatalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// The catalog repository on each store: changes commit with their security
// events, refused and rolled-back changes leave it running, and anything
// with an unknown outcome stops it.

type noAuthority struct{}

func (noAuthority) Caller(string, string) (lease.Caller, bool) { return lease.Caller{}, false }
func (noAuthority) Credential(string, string) (lease.Credential, bool) {
	return lease.Credential{}, false
}

type noActivator struct{}

func (noActivator) Stage(context.Context, string, lease.Credential, []byte) (lease.Material, error) {
	return nil, lease.ErrKey
}

// gateway is a running catalog on one store.
type gateway struct {
	repo    *dbcatalog.Repository
	store   Store
	service *lease.Service
	failed  *bool
}

func catalogKey() string {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	return base64.StdEncoding.EncodeToString(raw)
}

func openGateway(t *testing.T, db Database, key string) *gateway {
	t.Helper()
	store := db.Open(t)
	service, err := lease.New(t.Context(), store, noAuthority{}, noActivator{}, lease.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	failed := new(bool)
	repo, err := dbcatalog.New(key, store, func() { *failed = true })
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	repo.Attach(service)
	return &gateway{repo: repo, store: store, service: service, failed: failed}
}

func (g *gateway) stop(t *testing.T) {
	t.Helper()
	g.service.Close()
	if err := g.store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// accounts adds alice and bob, and a no-auth connector "remote" for alice
// with one discovered, visible tool.
func accounts(t *testing.T, repo *dbcatalog.Repository) (alice, bob string) {
	t.Helper()
	alice, bob = "account:"+identity.New(), "account:"+identity.New()
	for _, a := range []catalog.Account{{ID: alice, Username: "alice"}, {ID: bob, Username: "bob"}} {
		a.Salt, a.PasswordHash, a.Iterations = []byte("synthetic-salt-"+a.Username), []byte("synthetic-hash-"+a.Username), 1000
		if err := repo.AddAccount(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Add(catalog.Entry{Owner: alice, Name: "remote", URL: "https://example.com/mcp", AuthType: "none"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetDiscovery(alice, "remote", []*mcp.Tool{{Name: "search", Description: "Synthetic", InputSchema: map[string]any{"type": "object"}}}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetVisibility(alice, "remote", catalog.Visibility{Mode: "selected", Enabled: []string{"remote__search"}}); err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

func connectorID(t *testing.T, repo *dbcatalog.Repository, owner, name string) string {
	t.Helper()
	for _, e := range repo.List(owner) {
		if e.Name == name {
			return e.ID
		}
	}
	t.Fatal("no connector", name)
	return ""
}

func testRepositoryCommitsAtomically(t *testing.T, db Database) {
	key := catalogKey()
	g := openGateway(t, db, key)
	alice, _ := accounts(t, g.repo)
	// Each change commits with its security event.
	agent := catalog.AccessRecord{Owner: alice, Name: "agent", Kind: "api_key", Role: "client", PublicID: identity.NewPublicID(), SecretHash: strings.Repeat("f", 64)}
	if err := g.repo.AddAccess(agent); err != nil {
		t.Fatal(err)
	}
	if n := db.Int(t, "SELECT count(*) FROM security_events WHERE owner_id=$1 AND event_type='access.created'", alice); n != 1 {
		t.Fatal("access.created events", n)
	}
	// The active limit holds in the database transaction: concurrent
	// additions never exceed it.
	var wg sync.WaitGroup
	for i := range 2 * catalog.MaxAPIKeys {
		wg.Go(func() {
			_ = g.repo.AddAccess(catalog.AccessRecord{Owner: alice, Name: "k", Kind: "api_key", Role: "client", PublicID: identity.NewPublicID(), SecretHash: fmt.Sprintf("%063x%d", i, 1)})
		})
	}
	wg.Wait()
	if n := db.Int(t, "SELECT count(*) FROM catalog_access WHERE owner_id=$1 AND kind='api_key' AND revoked_at IS NULL AND ended_at IS NULL AND deleted_at IS NULL", alice); n != catalog.MaxAPIKeys {
		t.Fatal("active key limit", n)
	}
	// A refused change publishes nothing, records no event and leaves the
	// repository running.
	created := db.Int(t, "SELECT count(*) FROM security_events WHERE event_type='connector.created'")
	if err := g.repo.Add(catalog.Entry{Owner: alice, Name: "remote", URL: "https://example.com/other", AuthType: "none"}); err == nil {
		t.Fatal("duplicate connector name accepted")
	}
	if n := db.Int(t, "SELECT count(*) FROM security_events WHERE event_type='connector.created'"); n != created || *g.failed || len(g.repo.List(alice)) != 1 {
		t.Fatal("refused change recorded an event, failed the repository or published", n)
	}
	// A restart loads what was committed.
	before := g.repo.AccessList(alice)
	g.stop(t)
	restarted := openGateway(t, db, key)
	if got := restarted.repo.AccessList(alice); len(got) != len(before) {
		t.Fatal("access after restart:", len(got), len(before))
	}
	if _, ok := restarted.repo.AuthenticateAccess(agent.SecretHash, "api_key"); !ok {
		t.Fatal("key does not authenticate after restart")
	}
	if !restarted.repo.ToolVisible(alice, "remote", "remote__search") {
		t.Fatal("visibility lost on restart")
	}
}

// Losing the database fails closed: no authentication from the stale view,
// no change reported as saved, and no fallback.
func testRepositoryFailsClosed(t *testing.T, db Database) {
	g := openGateway(t, db, catalogKey())
	alice, _ := accounts(t, g.repo)
	agent := catalog.AccessRecord{Owner: alice, Name: "agent", Kind: "api_key", Role: "client", PublicID: identity.NewPublicID(), SecretHash: strings.Repeat("e", 64)}
	if err := g.repo.AddAccess(agent); err != nil {
		t.Fatal(err)
	}
	db.Lose(t)
	deadline := time.Now().Add(5 * time.Second)
	for !g.repo.Failed() {
		if time.Now().After(deadline) {
			t.Fatal("storage loss not detected")
		}
		_ = g.repo.TouchAccess(alice, "missing")
		time.Sleep(20 * time.Millisecond)
	}
	stopped(t, g.store)
	if _, ok := g.repo.AuthenticateAccess(agent.SecretHash, "api_key"); ok {
		t.Fatal("authenticated after storage loss")
	}
	if err := g.repo.SetVisibility(alice, "remote", catalog.Visibility{Mode: "all"}); !errors.Is(err, dbcatalog.ErrUnavailable) {
		t.Fatal("change without storage", err)
	}
	if g.repo.Visibility(alice, "remote").Mode != "selected" {
		t.Fatal("uncommitted visibility published")
	}
}

// cancelBeforeCommit ends the repository's context after the mutation, just
// before COMMIT.
type cancelBeforeCommit struct{ dbcatalog.Coordinator }

func (c cancelBeforeCommit) Catalog(ctx context.Context, owner string, mutation func(lease.Tx) (func(), lease.Ending, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return c.Coordinator.Catalog(ctx, owner, func(tx lease.Tx) (func(), lease.Ending, error) {
		publish, ending, err := mutation(tx)
		if err == nil {
			cancel()
		}
		return publish, ending, err
	})
}

// deadlineBeforeCommit uses most of the repository's own deadline before the
// owner transaction, as a queue can, and lets it expire before COMMIT while
// the store's deadline still holds.
type deadlineBeforeCommit struct {
	dbcatalog.Coordinator
	left time.Duration
}

func (c deadlineBeforeCommit) Catalog(ctx context.Context, owner string, mutation func(lease.Tx) (func(), lease.Ending, error)) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("catalog context has no deadline")
	}
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(c.left))
	defer cancel()
	if deadline.Before(time.Now().Add(c.left)) {
		return errors.New("catalog deadline shorter than the test needs")
	}
	return c.Coordinator.Catalog(ctx, owner, func(tx lease.Tx) (func(), lease.Ending, error) {
		publish, ending, err := mutation(tx)
		if err == nil {
			<-ctx.Done()
		}
		return publish, ending, err
	})
}

// expiredInQueue ends the repository's context before the transaction
// starts, as a long queue can.
type expiredInQueue struct{ dbcatalog.Coordinator }

func (c expiredInQueue) Catalog(ctx context.Context, owner string, mutation func(lease.Tx) (func(), lease.Ending, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	return c.Coordinator.Catalog(ctx, owner, mutation)
}

func testRolledBackCancelled(t *testing.T, db Database) {
	rolledBack(t, db, func(c dbcatalog.Coordinator) dbcatalog.Coordinator { return cancelBeforeCommit{c} })
}
func testRolledBackDeadline(t *testing.T, db Database) {
	rolledBack(t, db, func(c dbcatalog.Coordinator) dbcatalog.Coordinator { return deadlineBeforeCommit{c, time.Second} })
}
func testRolledBackQueued(t *testing.T, db Database) {
	rolledBack(t, db, func(c dbcatalog.Coordinator) dbcatalog.Coordinator { return expiredInQueue{c} })
}

// A change the store rolled back before COMMIT, or one that gave up in the
// queue, committed nothing: it fails, publishes nothing, and leaves the
// catalog and the gateway running.
func rolledBack(t *testing.T, db Database, wrap func(dbcatalog.Coordinator) dbcatalog.Coordinator) {
	g := openGateway(t, db, catalogKey())
	alice, _ := accounts(t, g.repo)
	g.repo.Attach(wrap(g.service))
	if err := g.repo.Add(catalog.Entry{Owner: alice, Name: "rolled-back", URL: "https://example.test/mcp", AuthType: "none"}); !errors.Is(err, dbcatalog.ErrNotSaved) {
		t.Fatal("rolled-back change:", err)
	}
	if n := db.Int(t, "SELECT count(*) FROM catalog_connectors WHERE name='rolled-back'"); n != 0 {
		t.Fatal("rolled-back connector committed")
	}
	for _, e := range g.repo.List(alice) {
		if e.Name == "rolled-back" {
			t.Fatal("rolled-back connector published")
		}
	}
	stillOpen(t, g.store)
	if *g.failed || g.repo.Failed() {
		t.Fatal("a rolled-back change stopped the catalog")
	}
	g.repo.Attach(g.service)
	if err := g.repo.Add(catalog.Entry{Owner: alice, Name: "after", URL: "https://example.test/mcp", AuthType: "none"}); err != nil {
		t.Fatal("next change:", err)
	}
}

// commitThenFail lets the real transaction commit and then reports storage
// loss, as a lost COMMIT acknowledgement would.
type commitThenFail struct{ dbcatalog.Coordinator }

func (c commitThenFail) Catalog(ctx context.Context, owner string, mutation func(lease.Tx) (func(), lease.Ending, error)) error {
	if err := c.Coordinator.Catalog(ctx, owner, mutation); err != nil {
		return err
	}
	return lease.ErrStorage
}

// Any other error after the writes leaves the outcome unknown, so the catalog
// stops and refuses further changes.
func testUncertainCommitStopsCatalog(t *testing.T, db Database) {
	g := openGateway(t, db, catalogKey())
	alice, _ := accounts(t, g.repo)
	g.repo.Attach(commitThenFail{g.service})
	if err := g.repo.Add(catalog.Entry{Owner: alice, Name: "uncertain", URL: "https://example.test/mcp", AuthType: "none"}); !errors.Is(err, dbcatalog.ErrUnavailable) {
		t.Fatal("uncertain commit:", err)
	}
	if !*g.failed || !g.repo.Failed() {
		t.Fatal("an uncertain commit left the catalog up")
	}
	g.repo.Attach(g.service)
	if err := g.repo.Add(catalog.Entry{Owner: alice, Name: "after", URL: "https://example.test/mcp", AuthType: "none"}); !errors.Is(err, dbcatalog.ErrUnavailable) {
		t.Fatal("change after an uncertain commit:", err)
	}
}

// Provider availability and tool visibility are connector security: a real
// change moves the revision scopes bind, a repeated one changes nothing, and
// the revision survives a restart.
func testProviderChangesMoveRevision(t *testing.T, db Database) {
	key := catalogKey()
	g := openGateway(t, db, key)
	alice, _ := accounts(t, g.repo)
	remote := connectorID(t, g.repo, alice, "remote")
	events := func() int64 {
		return db.Int(t, "SELECT count(*) FROM security_events WHERE owner_id=$1 AND event_type IN ('connector.availability_changed','connector.visibility_changed')", alice)
	}
	revision := func() string { return g.repo.ConnectorSecurityRevision(alice, remote) }
	base, baseEvents := revision(), events()
	var n int
	if _, err := fmt.Sscan(base, &n); err != nil {
		t.Fatal("revision", base)
	}
	steps := []struct {
		name   string
		change func() error
		moved  int
	}{
		{"enable while enabled", func() error { return g.repo.SetProviderEnabled(alice, "remote", true) }, 0},
		{"disable", func() error { return g.repo.SetProviderEnabled(alice, "remote", false) }, 1},
		{"disable again", func() error { return g.repo.SetProviderEnabled(alice, "remote", false) }, 1},
		{"enable", func() error { return g.repo.SetProviderEnabled(alice, "remote", true) }, 2},
		{"same visibility", func() error {
			return g.repo.SetVisibility(alice, "remote", catalog.Visibility{Mode: "selected", Enabled: []string{"remote__search"}})
		}, 2},
		{"hide the tool", func() error {
			return g.repo.SetVisibility(alice, "remote", catalog.Visibility{Mode: "selected", Enabled: []string{}})
		}, 3},
	}
	for _, step := range steps {
		if err := step.change(); err != nil {
			t.Fatal(step.name, err)
		}
		if want := fmt.Sprint(n + step.moved); revision() != want || events() != baseEvents+int64(step.moved) {
			t.Fatal(step.name, revision(), events())
		}
	}
	g.stop(t)
	restarted := openGateway(t, db, key)
	if got := restarted.repo.ConnectorSecurityRevision(alice, remote); got != fmt.Sprint(n+3) {
		t.Fatal("revision after reload", got)
	}
}

// No MCP session survives a restart: EndStaleSessions ends every open one
// with an event, and the owner can open new sessions afterwards.
func testStaleSessionsEndAtStartup(t *testing.T, db Database) {
	key := catalogKey()
	g := openGateway(t, db, key)
	_, bob := accounts(t, g.repo)
	var ids []string
	for i := range 10 {
		a := catalog.AccessRecord{ID: identity.New(), Owner: bob, Name: fmt.Sprintf("session %d", i), Kind: "mcp", Role: "client", ParentID: "parent", SecretHash: fmt.Sprintf("%064x", 900+i)}
		if err := g.repo.AddAccess(a); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
	}
	g.stop(t) // unclean for the sessions: nothing ended them
	g = openGateway(t, db, key)
	if err := g.repo.EndStaleSessions(); err != nil {
		t.Fatal(err)
	}
	for _, a := range g.repo.AccessList(bob) {
		if a.Kind == "mcp" && a.EndedAt.IsZero() {
			t.Fatal("open MCP session after restart:", a.Name)
		}
	}
	if n := db.Int(t, "SELECT count(*) FROM security_events WHERE event_type='access.ended'"); n != int64(len(ids)) {
		t.Fatal("access.ended events:", n)
	}
	next := catalog.AccessRecord{ID: identity.New(), Owner: bob, Name: "session 11", Kind: "mcp", Role: "client", ParentID: "parent", SecretHash: fmt.Sprintf("%064x", 999)}
	if err := g.repo.AddAccess(next); err != nil {
		t.Fatal("a new session after restart:", err)
	}
	g.stop(t)
	restarted := openGateway(t, db, key)
	if a, ok := restarted.repo.AccessByID(bob, ids[0]); !ok || a.EndedAt.IsZero() {
		t.Fatal("ending was not committed")
	}
}

// testRepositoryAccessLimits: the hard active limits hold under concurrent
// mints, the browser and OAuth sessions share one limit, a revocation frees a
// slot, and another owner cannot revoke.
func testRepositoryAccessLimits(t *testing.T, db Database) {
	g := openGateway(t, db, catalogKey())
	var wg sync.WaitGroup
	var mu sync.Mutex
	minted := 0
	for i := range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.repo.AddAccess(catalog.AccessRecord{Owner: "alice", Name: fmt.Sprint(i), Kind: "api_key", Role: "client", SecretHash: fmt.Sprint("key", i)}) == nil {
				mu.Lock()
				minted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if minted != catalog.MaxAPIKeys {
		t.Fatalf("concurrent mints: %d, want %d", minted, catalog.MaxAPIKeys)
	}
	first := g.repo.AccessList("alice")[0]
	if err := g.repo.RevokeAccess("bob", first.ID); err == nil {
		t.Fatal("another owner revoked the key")
	}
	if err := g.repo.RevokeAccess("alice", first.ID); err != nil {
		t.Fatal(err)
	}
	if err := g.repo.AddAccess(catalog.AccessRecord{Owner: "alice", Name: "replacement", Kind: "api_key", Role: "admin", SecretHash: "replacement"}); err != nil {
		t.Fatal("revocation did not free a slot:", err)
	}
	for i := range catalog.MaxLoginSessions {
		if err := g.repo.AddAccess(catalog.AccessRecord{Owner: "alice", Name: "device", Kind: "browser", Role: "admin", SecretHash: fmt.Sprint("browser", i), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.repo.ObserveOAuth("alice", "oauth", "client", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("OAuth bypassed the shared session limit")
	}
	for i := range catalog.MaxMCPSessions {
		if err := g.repo.AddAccess(catalog.AccessRecord{Owner: "alice", Name: "app", Kind: "mcp", Role: "client", SecretHash: fmt.Sprint("mcp", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.repo.AddAccess(catalog.AccessRecord{Owner: "alice", Name: "extra", Kind: "mcp", Role: "client", SecretHash: "extra"}); err == nil {
		t.Fatal("MCP session limit bypassed")
	}
	if err := g.repo.AddAccess(catalog.AccessRecord{Owner: "bob", Name: "own", Kind: "api_key", Role: "client", SecretHash: "bob"}); err != nil {
		t.Fatal("alice's limit applied to bob:", err)
	}
}
