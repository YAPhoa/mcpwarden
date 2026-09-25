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

// Run executes fn in one transaction on the executor session, after Start.
// Catalog loading and tool-call history use it; owner security changes must use
// WithOwner instead so they take the owner lock.
func (s *Store) Run(ctx context.Context, fn func(context.Context, catalogdb.DB) error) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if !s.started {
		return lease.ErrLocked
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.transaction(ctx, func(tx pgx.Tx) error { return fn(ctx, tx) })
}
