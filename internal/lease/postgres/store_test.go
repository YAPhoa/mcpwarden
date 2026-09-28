package postgres

import (
	"bytes"
	"context"
	"errors"
	"github.com/yaphoa/mcpwarden/internal/vault"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

type databaseFixture struct {
	admin, master              *pgx.Conn
	runtimeDSN, role, database string
}

func testDatabase(t *testing.T) *databaseFixture {
	t.Helper()
	dsn := os.Getenv("MCPWARDEN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set MCPWARDEN_TEST_DATABASE_URL to the isolated Compose fixture")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database connection")
	}
	if config.Database != "mcpwarden_security_test" || !(config.Host == "localhost" || config.Host == "127.0.0.1" || config.Host == "::1") {
		t.Fatal("integration tests require the local mcpwarden_security_test fixture")
	}
	ctx := t.Context()
	master, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	name := "mcpwarden_lease_test_" + strings.ReplaceAll(identity.New(), "-", "")
	role := "mcpw_rt_" + strings.ReplaceAll(identity.New(), "-", "")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := master.Exec(cleanup, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		if err != nil {
			t.Error("scratch database cleanup failed")
		}
		_, err = master.Exec(cleanup, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize())
		if err != nil {
			t.Error("scratch role cleanup failed")
		}
		_ = master.Close(cleanup)
	})
	if _, err = master.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN PASSWORD 'test-only-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
		t.Fatal("test role creation failed")
	}
	if _, err = master.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("scratch database creation failed")
	}
	copy := config.Copy()
	copy.Database = name
	admin, err := pgx.ConnectConfig(ctx, copy)
	if err != nil {
		t.Fatal("scratch database connection failed")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	if err = Migrate(ctx, admin, role); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, admin, role); err != nil {
		t.Fatal("migration is not idempotent:", err)
	}
	runtimeURL := url.URL{Scheme: "postgres", User: url.UserPassword(role, "test-only-password"), Host: net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port))), Path: "/" + name, RawQuery: "sslmode=disable"}
	return &databaseFixture{admin: admin, master: master, runtimeDSN: runtimeURL.String(), role: role, database: name}
}
func (f *databaseFixture) store(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.Context(), f.runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}
func (f *databaseFixture) runtime(t *testing.T) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(t.Context(), f.runtimeDSN)
	if err != nil {
		t.Fatal("runtime test connection failed")
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != code {
		t.Fatalf("expected SQLSTATE %s, got %v", code, err)
	}
}

type authority struct {
	caller, browser lease.Caller
	credential      lease.Credential
}

func (a *authority) Caller(owner, id string) (lease.Caller, bool) {
	if owner != a.caller.Owner {
		return lease.Caller{}, false
	}
	if id == a.caller.AccessID {
		return a.caller, true
	}
	if id == a.browser.AccessID {
		return a.browser, true
	}
	return lease.Caller{}, false
}
func (a *authority) Credential(owner, id string) (lease.Credential, bool) {
	return a.credential, owner == a.caller.Owner && id == a.credential.ID
}

type material struct{ destroyed atomic.Int32 }

func (m *material) Destroy() { m.destroyed.Add(1) }

type activator struct{ m material }

func (a *activator) Stage(_ context.Context, _ string, _ lease.Credential, key []byte) (lease.Material, error) {
	if key[0] != 42 {
		return nil, lease.ErrKey
	}
	return &a.m, nil
}

type serviceFixture struct {
	service         *lease.Service
	store           *Store
	authority       *authority
	activator       *activator
	scope           lease.Scope
	caller, browser context.Context
	request         lease.Request
	active          lease.Lease
}

func newService(t *testing.T, store *Store, budget *int64, mode string) *serviceFixture {
	t.Helper()
	definition, _ := lease.DefinitionDigest([]byte(`{"name":"files.search","inputSchema":{"type":"object"}}`))
	destination, _ := lease.DefinitionDigest([]byte(`{"url":"https://example.invalid/mcp"}`))
	toolID := identity.New()
	a := &authority{caller: lease.Caller{Actor: identity.Actor{Owner: "alice", AccessID: identity.New(), Kind: "api_key", Label: "test caller", PublicID: identity.NewPublicID()}, Active: true}, browser: lease.Caller{Actor: identity.Actor{Owner: "alice", AccessID: identity.New(), Kind: "browser"}, Active: true, Interactive: true}, credential: lease.Credential{ID: identity.New(), ConnectorID: identity.New(), Epoch: "1", Revision: "1", PolicyRevision: "1", ConnectorSecurityRevision: "1", ApprovalPolicyRevision: "1", ApprovalMode: mode, Enabled: true, DestinationDigest: destination, Tools: map[string]lease.Tool{toolID: {ID: toolID, DefinitionDigest: definition, Allowed: true, Visible: true}}}}
	scope := lease.Scope{Schema: lease.ScopeSchema, OwnerID: "alice", RequesterAccessID: a.caller.AccessID, ConnectorID: a.credential.ConnectorID, CredentialID: a.credential.ID, CredentialEpoch: "1", PolicyRevision: "1", ConnectorSecurityRevision: "1", DestinationDigest: destination, DurationSeconds: 900, Purpose: "tool_use", Tools: []lease.ToolScope{{ToolID: toolID, DefinitionDigest: definition, Constraints: []lease.Constraint{}}}, MaxCalls: budget}
	act := &activator{}
	opts := lease.DefaultOptions()
	opts.MaxConcurrent = 128
	s, err := lease.New(t.Context(), store, a, act, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	f := &serviceFixture{service: s, store: store, authority: a, activator: act, scope: scope, caller: identity.WithActor(t.Context(), a.caller.Actor), browser: identity.WithActor(t.Context(), a.browser.Actor)}
	raw, _ := json.Marshal(scope)
	f.request, err = s.Request(f.caller, raw)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "confirm" {
		f.request, err = s.Confirm(f.browser, f.request.ID, f.request.RequestDigest)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func activationInput(r lease.Request) lease.ActivationInput {
	key := make([]byte, 32)
	key[0] = 42
	return lease.ActivationInput{RequestID: r.ID, RequestDigest: r.RequestDigest, OperationID: identity.New(), Key: key}
}
func (f *serviceFixture) activate(t *testing.T) {
	t.Helper()
	var err error
	f.active, err = f.service.Activate(f.browser, activationInput(f.request))
	if err != nil {
		t.Fatal(err)
	}
}
func (f *serviceFixture) admit() (*lease.Admission, error) {
	r := audit.NewInvocation(f.caller, "alice")
	r.ToolID = f.scope.Tools[0].ToolID
	r.Tool = "files.search"
	r.UpstreamID = f.scope.ConnectorID
	r.ArgsSHA256 = audit.HashArgs(json.RawMessage(`{}`))
	return f.service.Admit(f.caller, f.scope.CredentialID, r.ToolID, f.scope.Tools[0].DefinitionDigest, []byte(`{}`), r)
}

// The runtime role cannot rewrite events, change the schema or remove rows.
// Constraint and guard behavior shared with SQLite is in storetest.
func TestPostgresPrivileges(t *testing.T) {
	f := testDatabase(t)
	store := f.store(t)
	service := newService(t, store, nil, "none")
	service.activate(t)
	a, err := service.admit()
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Run(func(context.Context) error { return nil })
	root := vaultRootFixture(t, "alice")
	if err := withVault(t, store, "alice", func(tx vault.Tx) error {
		if err := tx.PutVaultRoot(root, ""); err != nil {
			return err
		}
		return tx.PutCredentialRecord(credentialFixture(t, root), nil)
	}); err != nil {
		t.Fatal(err)
	}
	runtime := f.runtime(t)
	for _, sql := range []string{"UPDATE mcpwarden_security.invocation_events SET metadata=metadata", "DELETE FROM mcpwarden_security.security_events",
		"TRUNCATE mcpwarden_security.leases", "ALTER TABLE mcpwarden_security.owners ADD COLUMN forbidden text",
		"INSERT INTO mcpwarden_security.schema_migrations VALUES (2,'invalid',clock_timestamp())",
		"UPDATE mcpwarden_security.credential_versions SET envelope=envelope", "DELETE FROM mcpwarden_security.credential_epochs",
		"DELETE FROM mcpwarden_security.credential_heads", "UPDATE mcpwarden_security.vault_wrapper_sets SET passphrase=passphrase",
		"TRUNCATE mcpwarden_security.vault_roots"} {
		_, err := runtime.Exec(t.Context(), sql)
		requireCode(t, err, "42501")
	}
}

type dropCommitReply struct {
	net.Conn
	armed atomic.Bool
	drop  atomic.Bool
}

func (c *dropCommitReply) Write(p []byte) (int, error) {
	if c.armed.Load() && bytes.Contains(bytes.ToLower(p), []byte("commit\x00")) {
		c.drop.Store(true)
	}
	return c.Conn.Write(p)
}
func (c *dropCommitReply) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.drop.Load() && n > 0 {
		_ = c.Conn.Close()
		return 0, io.ErrUnexpectedEOF
	}
	return n, err
}
func TestPostgresAmbiguousActivationCommit(t *testing.T) {
	f := testDatabase(t)
	config, err := pgx.ParseConfig(f.runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	var wire *dropCommitReply
	config.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		wire = &dropCommitReply{Conn: conn}
		return wire, nil
	}
	store, err := open(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	service := newService(t, store, nil, "none")
	wire.armed.Store(true)
	if _, err := service.service.Activate(service.browser, activationInput(service.request)); err != lease.ErrStorage {
		t.Fatalf("ambiguous activation succeeded: %v", err)
	}
	var count int
	if err := f.admin.QueryRow(t.Context(), "SELECT count(*) FROM mcpwarden_security.leases").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("fixture did not commit before losing reply")
	}
	if service.activator.m.destroyed.Load() != 1 {
		t.Fatal("ambiguous commit published key material")
	}
	if _, err := service.admit(); err != lease.ErrLocked {
		t.Fatal("ambiguous commit retained execution")
	}
}

func TestPostgresExclusiveExecutorAndLoss(t *testing.T) {
	f := testDatabase(t)
	store := f.store(t)
	service := newService(t, store, nil, "none")
	service.activate(t)
	other := f.store(t)
	if err := other.Start(t.Context(), identity.New()); err != lease.ErrLocked {
		t.Fatal("second executor acquired ownership")
	}
	if err := Migrate(t.Context(), f.admin, f.role); err != lease.ErrLocked {
		t.Fatal("migration ran during execution")
	}
	var killed bool
	if err := f.admin.QueryRow(t.Context(), "SELECT pg_terminate_backend($1)", int32(store.conn.PgConn().PID())).Scan(&killed); err != nil || !killed {
		t.Fatal("failed to terminate fixture connection")
	}
	select {
	case <-store.Lost():
	case <-time.After(4 * time.Second):
		t.Fatal("lost session lock not detected")
	}
	if _, err := service.admit(); err != lease.ErrLocked {
		t.Fatal("lost lock admitted")
	}
}

func TestPostgresSnapshotRestartLocksExecution(t *testing.T) {
	f := testDatabase(t)
	store := f.store(t)
	service := newService(t, store, nil, "none")
	service.activate(t)
	service.service.Close()
	_ = store.Close(context.Background())
	_ = f.admin.Close(context.Background())
	name := f.database + "_restore"
	if _, err := f.master.Exec(t.Context(), "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE "+pgx.Identifier{f.database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := f.master.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		if err != nil {
			t.Error("restored fixture cleanup failed")
		}
	})
	u, _ := url.Parse(f.runtimeDSN)
	u.Path = "/" + name
	restored, err := Open(t.Context(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close(context.Background()) })
	next, err := lease.New(t.Context(), restored, service.authority, &activator{}, lease.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	service.service = next
	service.store = restored
	if _, err := service.admit(); err != lease.ErrRequired {
		t.Fatal("restored database recreated live authority")
	}
	if err := restored.WithOwner(t.Context(), "alice", func(tx lease.Tx) error {
		l, err := tx.Lease(service.active.ID)
		if err != nil {
			return err
		}
		if l.State != "suspended" || l.ScopeDigest != service.active.ScopeDigest || !l.ExpiresAt.Equal(service.active.ExpiresAt) {
			t.Fatal("restore lost identity or extended deadline")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSchemaDrift(t *testing.T) {
	t.Run("powerful membership", func(t *testing.T) {
		f := testDatabase(t)
		powerful := f.role + "_elevated"
		if _, err := f.master.Exec(t.Context(), "CREATE ROLE "+pgx.Identifier{powerful}.Sanitize()+" NOLOGIN CREATEROLE"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := f.master.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{powerful}.Sanitize()); err != nil {
				t.Error("role fixture cleanup failed")
			}
		})
		if _, err := f.master.Exec(t.Context(), "GRANT "+pgx.Identifier{powerful}.Sanitize()+" TO "+pgx.Identifier{f.role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(t.Context(), f.admin, f.role); err != ErrMigration {
			t.Fatal("migration accepted SET ROLE escalation")
		}
		if _, err := Open(t.Context(), f.runtimeDSN); err != lease.ErrStorage {
			t.Fatal("runtime accepted SET ROLE escalation")
		}
	})
	t.Run("checksum", func(t *testing.T) {
		f := testDatabase(t)
		if _, err := f.admin.Exec(t.Context(), "UPDATE mcpwarden_security.schema_migrations SET sha256='changed'"); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(t.Context(), f.admin, f.role); err != ErrMigration {
			t.Fatal("migration checksum drift accepted")
		}
		if _, err := Open(t.Context(), f.runtimeDSN); err != lease.ErrStorage {
			t.Fatal("executor accepted schema drift")
		}
	})
}
