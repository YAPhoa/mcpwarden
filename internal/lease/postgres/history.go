package postgres

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// historyDeadline bounds one history page; the session's statement_timeout
// matches it.
const historyDeadline = 5 * time.Second

// reader is the read-only session that serves history pages, so a slow page
// never holds the executor gate. A pgx.Conn is not safe for concurrent use,
// so pages take turns. After an error the session is closed, and the next
// page reopens it, at most once a second. A failed page never fails the store.
type reader struct {
	config *pgx.ConnConfig
	mu     sync.Mutex
	conn   *pgx.Conn
	opened time.Time
	closed bool
}

func newReader(config *pgx.ConnConfig) *reader {
	c := config.Copy()
	c.RuntimeParams["application_name"] = "mcpwarden-history"
	c.RuntimeParams["default_transaction_read_only"] = "on"
	c.RuntimeParams["statement_timeout"] = "5000"
	return &reader{config: c}
}

// ReadHistory runs fn in one REPEATABLE READ, read-only transaction on the
// history session, so a page's rows, count and timings share one snapshot.
func (s *Store) ReadHistory(ctx context.Context, fn func(context.Context, catalogdb.DB) error) error {
	select {
	case <-s.lost:
		return lease.ErrLocked
	default:
	}
	return s.reader.read(ctx, fn)
}

func (r *reader) read(ctx context.Context, fn func(context.Context, catalogdb.DB) error) error {
	ctx, cancel := context.WithTimeout(ctx, historyDeadline)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return lease.ErrLocked
	}
	if r.conn == nil {
		if time.Since(r.opened) < time.Second {
			return catalogdb.ErrStorage
		}
		r.opened = time.Now()
		conn, err := pgx.ConnectConfig(ctx, r.config)
		if err != nil {
			return catalogdb.ErrStorage
		}
		r.conn = conn
	}
	err := pgx.BeginTxFunc(ctx, r.conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		return fn(ctx, tx)
	})
	if err != nil {
		r.drop()
		return catalogdb.ErrStorage
	}
	return nil
}

// drop closes the session; r.mu must be held.
func (r *reader) drop() {
	if r.conn == nil {
		return
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = r.conn.Close(closeCtx)
	r.conn = nil
}

func (r *reader) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.drop()
}
