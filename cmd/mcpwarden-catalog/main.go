// Command mcpwarden-catalog moves the gateway catalog and tool-call history
// between the encrypted file and PostgreSQL. Stop every gateway first; each
// step holds the executor lock and the exclusive catalog lock. Output is a
// manifest of counts, IDs and digests, never secrets.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/pgcatalog"
	"github.com/yaphoa/mcpwarden/internal/config"
)

const usage = `Usage: mcpwarden-catalog -config config.yaml <status|import|cutover|rollback|abort>

  status    show which store is authoritative and the recorded manifests
  import    copy the file catalog and history into PostgreSQL and verify them
            (resumable; the file stays authoritative)
  cutover   re-verify the import and make PostgreSQL authoritative
  rollback  export the PostgreSQL catalog and history back to the files,
            keeping revocations and new history (resumable)
  abort     discard an import that was never cut over

Set MCPWARDEN_MIGRATION_DATABASE_URL to the migration role. See docs/catalog-migration.md.`

func main() {
	configPath := flag.String("config", "config.yaml", "gateway YAML configuration")
	flag.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*configPath, flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path, command string) error {
	dsn := os.Getenv("MCPWARDEN_MIGRATION_DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("set MCPWARDEN_MIGRATION_DATABASE_URL")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.Managed == nil {
		return fmt.Errorf("the configuration has no managed_upstreams catalog")
	}
	src := pgcatalog.Sources{CatalogPath: cfg.Managed.Path, CatalogKey: cfg.Managed.Key, HistoryPath: cfg.Audit.Path}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("database connection failed")
	}
	defer conn.Close(context.Background())
	var out any
	switch command {
	case "status":
		st, ok, err := pgcatalog.Status(ctx, conn)
		if err != nil {
			return err
		}
		if !ok {
			out = map[string]string{"state": "file", "detail": "no import has started"}
			break
		}
		out = map[string]any{"state": st.State, "import_id": st.ImportID, "rollback_id": st.RollbackID, "history_lines_imported": st.HistoryLines,
			"changed_at": st.ChangedAt, "manifest": json.RawMessage(orNull(st.Manifest)), "rollback_manifest": json.RawMessage(orNull(st.RollbackManifest))}
	case "import":
		out, err = pgcatalog.Import(ctx, conn, src, pgcatalog.Options{})
	case "cutover":
		out, err = pgcatalog.Cutover(ctx, conn, src)
	case "rollback":
		out, err = pgcatalog.Rollback(ctx, conn, src)
	case "abort":
		err = pgcatalog.Abort(ctx, conn, src)
		out = map[string]string{"state": "file", "detail": "import discarded; the protected snapshot directory was kept"}
	default:
		return fmt.Errorf("unknown command %q\n%s", command, usage)
	}
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func orNull(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte("null")
	}
	return raw
}
