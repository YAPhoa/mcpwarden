package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/catalog/pgcatalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

// errCatalogFailed stops the gateway when a catalog or history commit has an
// unknown outcome or the database session is lost. It never falls back to
// the file catalog; restart after the database is healthy.
var errCatalogFailed = errors.New("PostgreSQL catalog storage failed; the gateway stopped without falling back to the file catalog")

// pgBackend is the PostgreSQL catalog, its indexed history and the lease
// service that coordinates every catalog change.
type pgBackend struct {
	repo     *pgcatalog.Repository
	history  *pgcatalog.History
	accounts *accountAuth
	security *securityAPI
}

// openPostgresCatalog starts the executor (which takes the executor lock and
// suspends earlier leases), loads the committed catalog and verifies that
// PostgreSQL is the active catalog. Any failure stops startup.
func openPostgresCatalog(ctx context.Context, cfg config.Config, pol *policy.Policy, logger *slog.Logger, fail context.CancelCauseFunc) (*pgBackend, error) {
	if _, err := cfg.OwnerSecurity.ProxyPrefixes(); err != nil {
		return nil, err
	}
	db, err := postgres.Open(ctx, cfg.OwnerSecurity.DatabaseURL)
	if err != nil {
		return nil, errors.New("PostgreSQL catalog storage unavailable")
	}
	stopped := func() {
		logger.Error("catalog storage failed; stopping")
		fail(errCatalogFailed)
	}
	repo, err := pgcatalog.New(cfg.Managed.Key, db, stopped)
	if err != nil {
		return nil, err
	}
	accounts := newAccountAuth(repo, cfg)
	security, err := startSecurity(ctx, cfg, db, repo, pol, accounts, logger)
	if err != nil {
		return nil, err
	}
	if err := repo.Load(ctx); err != nil {
		security.close()
		if errors.Is(err, pgcatalog.ErrNotActive) {
			return nil, err
		}
		return nil, errors.New("PostgreSQL catalog could not be loaded")
	}
	repo.Attach(security.service)
	go func() {
		select {
		case <-db.Lost():
			stopped()
		case <-ctx.Done():
		}
	}()
	return &pgBackend{repo: repo, history: pgcatalog.NewHistory(db), accounts: accounts, security: security}, nil
}

func (b *pgBackend) close() { b.security.close() }

// fileAuthority refuses a file-backed gateway while PostgreSQL holds, or is
// taking or returning, catalog authority. The marker beside the catalog file
// enforces the same rule without a database.
func fileAuthority(ctx context.Context, db *postgres.Store) error {
	var state string
	err := db.Run(ctx, func(ctx context.Context, tx catalogdb.DB) error {
		st, ok, err := catalogdb.ReadState(ctx, tx, false)
		if ok {
			state = st.State
		}
		return err
	})
	if err != nil {
		return errors.New("catalog state could not be read")
	}
	if state != "" && state != "rolled_back" {
		return errors.New("the PostgreSQL catalog is " + state + "; set managed_upstreams.backend to postgres or complete the rollback")
	}
	return nil
}
