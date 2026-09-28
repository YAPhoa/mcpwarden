package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/catalog/dbcatalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/custody"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
	"github.com/yaphoa/mcpwarden/internal/lease/sqlite"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

// errCatalogFailed stops the gateway when a catalog or history commit has an
// unknown outcome or the database session is lost. It never falls back to
// the file catalog; restart after the database is healthy.
var errCatalogFailed = errors.New("catalog storage failed; the gateway stopped without falling back to the file catalog")

// storageDB is what the gateway needs from a store: the lease executor,
// custody, the catalog and indexed history.
type storageDB interface {
	lease.Store
	catalogdb.Store
	Complete(context.Context, audit.Record) error
	LoadCustody(context.Context) (custody.Snapshot, error)
	Close(context.Context) error
}

var (
	_ storageDB = (*postgres.Store)(nil)
	_ storageDB = (*sqlite.Store)(nil)
)

// storageBackend is the database catalog, its indexed history and the lease
// service that coordinates every catalog change. accounts is set in accounts
// mode; the owner security routes are registered only with owner_security.
type storageBackend struct {
	repo     *dbcatalog.Repository
	history  *dbcatalog.History
	accounts *accountAuth
	security *securityAPI
}

// openDatabase opens the configured store. Errors carry no driver text.
func openDatabase(ctx context.Context, s *config.Storage, logger *slog.Logger) (storageDB, error) {
	switch s.Driver {
	case "postgres":
		db, err := postgres.Open(ctx, s.DatabaseURL)
		if err != nil {
			return nil, errors.New("PostgreSQL storage unavailable")
		}
		return db, nil
	case "sqlite":
		db, err := sqlite.Open(ctx, s.Path, sqlite.Options{Warn: func(m string) { logger.Warn(m) }})
		if err != nil {
			return nil, err
		}
		return db, nil
	}
	return nil, errors.New("unknown storage driver")
}

// openStorage starts the executor (which takes the executor lock and
// suspends earlier leases), then loads the committed catalog. Any failure
// stops startup.
func openStorage(ctx context.Context, cfg config.Config, pol *policy.Policy, logger *slog.Logger, fail context.CancelCauseFunc) (*storageBackend, error) {
	db, err := openDatabase(ctx, cfg.Storage, logger)
	if err != nil {
		return nil, err
	}
	stopped := func() {
		logger.Error("catalog storage failed; stopping")
		fail(errCatalogFailed)
	}
	repo, err := dbcatalog.New(cfg.Storage.Key, db, stopped)
	if err != nil {
		closeStore(db)
		return nil, err
	}
	var accounts *accountAuth
	if cfg.Accounts != nil {
		accounts = newAccountAuth(repo, cfg)
	}
	security, err := startSecurity(ctx, cfg, db, repo, pol, accounts, logger)
	if err != nil {
		return nil, err
	}
	if err := repo.Load(ctx); err != nil {
		security.close()
		if errors.Is(err, catalogdb.ErrNotActive) {
			return nil, err
		}
		return nil, errors.New("catalog could not be loaded from storage")
	}
	repo.Attach(security.service)
	if err := repo.EndStaleSessions(); err != nil {
		security.close()
		return nil, errors.New("catalog could not end stale MCP sessions")
	}
	go func() {
		select {
		case <-db.Lost():
			stopped()
		case <-ctx.Done():
		}
	}()
	return &storageBackend{repo: repo, history: dbcatalog.NewHistory(db), accounts: accounts, security: security}, nil
}

func (b *storageBackend) close() { b.security.close() }
