package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// Owner transactions expose their pgx transaction to catalog writes so those
// writes commit together with lease changes and security events.
func (x *ownerTx) CatalogOwner() string            { return x.owner }
func (x *ownerTx) CatalogContext() context.Context { return x.ctx }
func (x *ownerTx) CatalogDB() catalogdb.DB         { return x.tx }

var _ catalogdb.OwnerTx = (*ownerTx)(nil)

// Run executes fn in one short transaction on the executor session, after
// Start. Tool-call history writes use it; owner security changes must use
// WithOwner instead so they take the owner lock.
func (s *Store) Run(ctx context.Context, fn func(context.Context, catalogdb.DB) error) error {
	return s.run(ctx, ownerDeadline, fn)
}

// Load is Run with the startup deadline, for the catalog load.
func (s *Store) Load(ctx context.Context, fn func(context.Context, catalogdb.DB) error) error {
	return s.run(ctx, loadDeadline, fn)
}

func (s *Store) run(ctx context.Context, deadline time.Duration, fn func(context.Context, catalogdb.DB) error) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if !s.started {
		return lease.ErrLocked
	}
	return s.transaction(ctx, deadline, func(ctx context.Context, tx pgx.Tx) error { return fn(ctx, tx) })
}
