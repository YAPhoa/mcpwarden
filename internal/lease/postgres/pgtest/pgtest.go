// Package pgtest creates isolated scratch databases on the local PostgreSQL
// test fixture for packages outside internal/lease/postgres. It never touches
// application data: each call makes a random database and restricted runtime
// role, migrates it, and drops both on cleanup.
package pgtest

import (
	"context"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
)

type Database struct {
	// Admin owns the scratch schema. RuntimeDSN logs in as the restricted role.
	Admin      *pgx.Conn
	RuntimeDSN string
}

// New skips the test unless MCPWARDEN_TEST_DATABASE_URL names the loopback
// mcpwarden_security_test fixture described in docs/security/lease-storage.md.
func New(t testing.TB) *Database {
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
	ctx := context.Background()
	master, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	name := "mcpwarden_owner_test_" + strings.ReplaceAll(identity.New(), "-", "")
	role := "mcpw_rt_" + strings.ReplaceAll(identity.New(), "-", "")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := master.Exec(cleanup, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("scratch database cleanup failed")
		}
		if _, err := master.Exec(cleanup, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize()); err != nil {
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
	scratch := config.Copy()
	scratch.Database = name
	admin, err := pgx.ConnectConfig(ctx, scratch)
	if err != nil {
		t.Fatal("scratch database connection failed")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	if err = postgres.Migrate(ctx, admin, role); err != nil {
		t.Fatal(err)
	}
	runtime := url.URL{Scheme: "postgres", User: url.UserPassword(role, "test-only-password"), Host: net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port))), Path: "/" + name, RawQuery: "sslmode=disable"}
	return &Database{Admin: admin, RuntimeDSN: runtime.String()}
}
