// This deployment command creates or verifies the PostgreSQL schema with a
// migration role and grants the runtime role its privileges.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
)

func main() {
	role := flag.String("runtime-role", "", "existing, unprivileged PostgreSQL runtime role")
	flag.Parse()
	if *role == "" || os.Getenv("MCPWARDEN_MIGRATION_DATABASE_URL") == "" {
		fmt.Fprintln(os.Stderr, "Set MCPWARDEN_MIGRATION_DATABASE_URL and pass -runtime-role.")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, os.Getenv("MCPWARDEN_MIGRATION_DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Database connection failed.")
		os.Exit(1)
	}
	defer conn.Close(context.Background())
	if err := postgres.Migrate(ctx, conn, *role); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Schema v%d verified (leases, vault ciphertext, catalog and history).\n", postgres.SchemaVersion)
}
