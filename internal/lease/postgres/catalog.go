package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// Owner transactions write catalog rows in their pgx transaction, so those
// writes commit together with lease changes and security events.
func (x *ownerTx) CatalogOwner() string      { return x.owner }
func (x *ownerTx) CatalogRows() catalogdb.Tx { return catalogRows{x} }

var (
	_ catalogdb.OwnerTx = (*ownerTx)(nil)
	_ catalogdb.Store   = (*Store)(nil)
)

type catalogRows struct{ x *ownerTx }

func (c catalogRows) PutAccount(a catalogdb.Account) error { return PutAccount(c.x.ctx, c.x.tx, a) }
func (c catalogRows) PutAccess(a catalogdb.Access) error   { return PutAccess(c.x.ctx, c.x.tx, a) }
func (c catalogRows) ActiveAccess(owner string, kinds []string, now time.Time) (int, error) {
	return ActiveAccess(c.x.ctx, c.x.tx, owner, kinds, now)
}
func (c catalogRows) PutConnector(k catalogdb.Connector) error {
	return PutConnector(c.x.ctx, c.x.tx, k)
}
func (c catalogRows) PutDiscovery(d catalogdb.Discovery) error {
	return PutDiscovery(c.x.ctx, c.x.tx, d)
}
func (c catalogRows) DeleteDiscovery(owner, provider string) error {
	return DeleteDiscovery(c.x.ctx, c.x.tx, owner, provider)
}
func (c catalogRows) PutVisibility(v catalogdb.Visibility) error {
	return PutVisibility(c.x.ctx, c.x.tx, v)
}
func (c catalogRows) DeleteVisibility(owner, provider string) error {
	return DeleteVisibility(c.x.ctx, c.x.tx, owner, provider)
}

// LoadCatalog reads every catalog row in one transaction under the startup
// deadline.
func (s *Store) LoadCatalog(ctx context.Context) (catalogdb.Rows, error) {
	var rows catalogdb.Rows
	err := s.run(ctx, loadDeadline, func(ctx context.Context, db DB) error {
		var err error
		rows, err = Load(ctx, db)
		return err
	})
	return rows, err
}

// InsertHistory commits one event in its own short transaction on the
// executor session, so a successful admission is durable before dispatch.
func (s *Store) InsertHistory(ctx context.Context, row catalogdb.HistoryRow) error {
	return s.run(ctx, ownerDeadline, func(ctx context.Context, db DB) error { return InsertHistory(ctx, db, row) })
}

// QueryHistory reads one page on the history session.
func (s *Store) QueryHistory(ctx context.Context, q catalogdb.HistoryQuery) (catalogdb.HistoryResult, error) {
	var out catalogdb.HistoryResult
	err := s.ReadHistory(ctx, func(ctx context.Context, db DB) error {
		var err error
		out, err = QueryHistory(ctx, db, q)
		return err
	})
	return out, err
}

func (s *Store) run(ctx context.Context, deadline time.Duration, fn func(context.Context, DB) error) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if !s.started {
		return lease.ErrLocked
	}
	return s.transaction(ctx, deadline, func(ctx context.Context, tx pgx.Tx) error { return fn(ctx, tx) })
}
