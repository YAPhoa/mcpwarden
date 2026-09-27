package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// historyDeadline bounds one history page; the session's statement_timeout
// matches it. historyWait bounds the wait for the session, so three full pages
// can queue ahead of a page before it gives up.
const (
	historyDeadline = 5 * time.Second
	historyWait     = 3 * historyDeadline
)

// reader is the read-only session that serves history pages, so a slow page
// never holds the executor gate. A pgx.Conn is not safe for concurrent use,
// so pages take turns; waiting for a turn and running a page are bounded
// separately. A session that is gone is closed and the next page reopens it,
// at most once a second. A failed page never fails the store.
type reader struct {
	config *pgx.ConnConfig
	turn   chan struct{} // holds one token; taking it is taking the session
	wait   time.Duration
	limit  time.Duration
	now    func() time.Time
	conn   *pgx.Conn
	opened time.Time
	closed bool
}

func newReader(config *pgx.ConnConfig) *reader {
	c := config.Copy()
	c.RuntimeParams["application_name"] = "mcpwarden-history"
	c.RuntimeParams["default_transaction_read_only"] = "on"
	c.RuntimeParams["statement_timeout"] = "5000"
	r := &reader{config: c, turn: make(chan struct{}, 1), wait: historyWait, limit: historyDeadline, now: time.Now}
	r.turn <- struct{}{}
	return r
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
	// Waiting for the session has its own bound, so queued pages do not share
	// one deadline; each page gets the full limit once it runs. A page that
	// gives up waiting leaves the session alone.
	wait, stop := context.WithTimeout(ctx, r.wait)
	select {
	case <-r.turn:
		stop()
	case <-wait.Done():
		stop()
		return catalogdb.ErrStorage
	}
	defer func() { r.turn <- struct{}{} }()
	if r.closed {
		return lease.ErrLocked
	}
	// pgx may close a session for a context that is already done, so a page
	// whose caller gave up while it waited sends nothing.
	if ctx.Err() != nil {
		return catalogdb.ErrStorage
	}
	ctx, cancel := context.WithTimeout(ctx, r.limit)
	defer cancel()
	for attempt := 0; ; attempt++ {
		reused := r.conn != nil
		if !reused {
			if r.now().Sub(r.opened) < time.Second {
				return catalogdb.ErrStorage
			}
			r.opened = r.now()
			conn, err := pgx.ConnectConfig(ctx, r.config)
			if err != nil {
				return catalogdb.ErrStorage
			}
			r.conn = conn
		}
		err := pgx.BeginTxFunc(ctx, r.conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
			return fn(ctx, tx)
		})
		if err == nil {
			return nil
		}
		// Close only a session that is actually gone; a page that failed on a
		// healthy session leaves it for the next page. pgx closes a session
		// whose statement context ends mid-query, so a timed-out page is
		// covered too.
		if !r.conn.IsClosed() {
			return catalogdb.ErrStorage
		}
		r.drop()
		// A reused session that had died while idle is replaced once, without
		// the reopen limit, when the page has time left. Pages are read-only,
		// so running one again has no effect beyond its result.
		if !reused || attempt > 0 || ctx.Err() != nil {
			return catalogdb.ErrStorage
		}
		r.opened = time.Time{}
	}
}

// drop closes the session; the caller holds the turn.
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
	<-r.turn
	defer func() { r.turn <- struct{}{} }()
	r.closed = true
	r.drop()
}
