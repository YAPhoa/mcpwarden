// Package sqlite is the SQLite store: lease metadata, vault ciphertext,
// custody, the catalog and tool-call history in one local file. It mirrors
// the PostgreSQL store's behavior (docs/storage.md): one executor session
// serialized by a gate, detached statement deadlines, poisoning after a
// statement error, a per-family error mapping, and fail closed on session
// loss. Unlike PostgreSQL it cannot keep its own process from changing the
// file, so triggers catch bugs, not attackers.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
	_ "modernc.org/sqlite"
)

// ErrInUse is returned by Open when another mcpwarden process holds the
// database.
var ErrInUse = fmt.Errorf("%w: database in use by another mcpwarden process (a gateway, or --stdio clients); stop it, or give this gateway its own storage.path", lease.ErrLocked)

// Store deadlines. A statement that reaches one is a real stall, so the store
// fails. The executor's busy timeout is below the owner deadline: SQLite's
// busy wait ignores context deadlines, so it alone bounds BEGIN IMMEDIATE.
const (
	ownerDeadline = 5 * time.Second
	loadDeadline  = 30 * time.Second
	busyTimeout   = 2000
)

// lockWait bounds the wait for the lock file at Open: a stdio client may hold
// it briefly to create or migrate the database.
var lockWait = 30 * time.Second

type Options struct {
	// Warn receives startup warnings, such as an unrecognized filesystem.
	Warn func(string)
}

type Store struct {
	db       *sql.DB // the executor pool: exactly one connection
	conn     *sql.Conn
	reads    *sql.DB // history pages
	lock     *lockFile
	path     string
	lockPath string
	file     os.FileInfo
	lockInfo os.FileInfo

	gate    chan struct{}
	lost    chan struct{}
	once    sync.Once
	started bool // gate protected
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	now     func() time.Time
}

func dsn(path string, pragmas ...string) string {
	q := url.Values{}
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	return path + "?" + q.Encode()
}

// Open takes the lock file exclusively, creates or migrates the database,
// verifies its pragmas and identity, and opens the history read pool. It
// never adopts a file that is not an mcpwarden database. Errors carry no
// driver text.
func Open(ctx context.Context, path string, opt Options) (*Store, error) {
	abs, err := checkPath(path, opt.Warn)
	if err != nil {
		return nil, err
	}
	s := &Store{path: abs, lockPath: abs + ".lock", gate: make(chan struct{}, 1), lost: make(chan struct{}), done: make(chan struct{}),
		now: func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }}
	ok := false
	defer func() {
		if !ok {
			s.closeAll()
		}
	}()
	if s.lock, err = openLock(s.lockPath); err != nil {
		return nil, errors.New("storage lock file could not be opened")
	}
	if err := s.takeLock(ctx); err != nil {
		return nil, err
	}
	if s.lockInfo, err = s.lock.stat(); err != nil || !sameFile(s.lockPath, s.lockInfo) || safeFile(s.lockInfo) != nil {
		return nil, errors.New("storage lock file is not a private regular file")
	}
	if s.file, err = prepareFile(abs); err != nil {
		return nil, err
	}
	s.db, err = sql.Open("sqlite", dsn(abs, "busy_timeout("+strconv.Itoa(busyTimeout)+")", "foreign_keys(1)", "journal_mode(WAL)",
		"synchronous(FULL)", "trusted_schema(0)")+"&_txlock=immediate")
	if err != nil {
		return nil, errors.New("storage database could not be opened")
	}
	s.db.SetMaxOpenConns(1)
	s.db.SetMaxIdleConns(1)
	s.db.SetConnMaxLifetime(0)
	s.db.SetConnMaxIdleTime(0)
	openCtx, cancel := context.WithTimeout(ctx, loadDeadline)
	defer cancel()
	if s.conn, err = s.db.Conn(openCtx); err != nil {
		return nil, errors.New("storage database could not be opened")
	}
	if err := checkPragmas(openCtx, s.conn, busyTimeout, false); err != nil {
		return nil, err
	}
	if err := migrate(openCtx, s.conn); err != nil {
		if errors.Is(err, ErrMigration) || errors.Is(err, ErrNewer) || errors.Is(err, ErrForeign) {
			return nil, err
		}
		return nil, errors.New("storage database could not be migrated")
	}
	if !sameFile(abs, s.file) {
		return nil, errors.New("storage database was replaced while opening")
	}
	if info, err := os.Lstat(abs); err != nil || safeFile(info) != nil {
		return nil, errors.New("storage database must not be accessible to group or other users (chmod 600)")
	}
	s.reads, err = sql.Open("sqlite", dsn(abs, "busy_timeout(5000)", "foreign_keys(1)", "query_only(1)", "trusted_schema(0)"))
	if err != nil {
		return nil, errors.New("storage database could not be opened")
	}
	s.reads.SetMaxOpenConns(2)
	s.reads.SetMaxIdleConns(2)
	read, err := s.reads.Conn(openCtx)
	if err != nil {
		return nil, errors.New("storage database could not be opened")
	}
	err = checkPragmas(openCtx, read, 5000, true)
	read.Close()
	if err != nil {
		return nil, err
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.gate <- struct{}{}
	ok = true
	go s.heartbeat()
	return s, nil
}

// takeLock retries the exclusive lock until lockWait passes.
func (s *Store) takeLock(ctx context.Context) error {
	deadline := time.Now().Add(lockWait)
	for {
		err := s.lock.try(true)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errBusy) {
			return errors.New("storage lock file could not be locked")
		}
		if time.Now().After(deadline) {
			return ErrInUse
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// checkPragmas refuses to run with any durability or safety setting other
// than the one the store requires.
func checkPragmas(ctx context.Context, c *sql.Conn, busy int, readOnly bool) error {
	var journal string
	var synchronous, fk, trusted, timeout, queryOnly int
	for _, p := range []struct {
		sql  string
		dest any
	}{{"PRAGMA journal_mode", &journal}, {"PRAGMA synchronous", &synchronous}, {"PRAGMA foreign_keys", &fk},
		{"PRAGMA trusted_schema", &trusted}, {"PRAGMA busy_timeout", &timeout}, {"PRAGMA query_only", &queryOnly}} {
		if err := c.QueryRowContext(ctx, p.sql).Scan(p.dest); err != nil {
			return errors.New("storage database settings could not be read")
		}
	}
	want := 0
	if readOnly {
		want = 1
	}
	if journal != "wal" || !readOnly && synchronous != 2 || fk != 1 || trusted != 0 || timeout != busy || queryOnly != want {
		return errors.New("storage database settings could not be applied (WAL, synchronous FULL, foreign keys, untrusted schema)")
	}
	return nil
}

func (s *Store) closeAll() {
	if s.reads != nil {
		s.reads.Close()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
	if s.lock != nil {
		s.lock.close()
	}
}

func (s *Store) Lost() <-chan struct{} { return s.lost }
func (s *Store) fail()                 { s.once.Do(func() { close(s.lost); s.cancel() }) }

func (s *Store) acquire(ctx context.Context) error {
	select {
	case <-s.lost:
		return lease.ErrLocked
	default:
	}
	// A caller that has already gone gets its context error and no side
	// effect, even when the gate happens to be free.
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.lost:
		return lease.ErrLocked
	case <-s.gate:
		return nil
	}
}
func (s *Store) release() { s.gate <- struct{}{} }

// Close stops the heartbeat, waits for the executor, and closes every
// connection, which checkpoints the WAL, then releases the lock file.
func (s *Store) Close(ctx context.Context) error {
	s.fail()
	<-s.done
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	defer s.release()
	var failed bool
	if err := s.reads.Close(); err != nil {
		failed = true
	}
	if err := s.conn.Close(); err != nil {
		failed = true
	}
	if err := s.db.Close(); err != nil {
		failed = true
	}
	if err := s.lock.close(); err != nil {
		failed = true
	}
	if failed {
		return lease.ErrStorage
	}
	return nil
}

func (s *Store) Start(ctx context.Context, boot string) error {
	if !identity.Valid(boot) {
		return lease.ErrDenied
	}
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if s.started {
		return lease.ErrLocked
	}
	err := s.transaction(ctx, ownerDeadline, func(t *tx) error {
		_, _, err := s.quiesce(t, boot)
		return err
	})
	if err != nil {
		s.fail()
		return lease.ErrStorage
	}
	s.started = true
	return nil
}

// quiesce marks every pending or approved request stale and suspends every
// active lease, recording one security event each under boot.
func (s *Store) quiesce(t *tx, boot string) (stale, suspended int, err error) {
	now := s.now()
	var events []lease.Event
	err = t.query("UPDATE requests SET state='stale' WHERE state IN ('pending','approved') RETURNING owner_id, request_id", nil, func(r *sql.Rows) error {
		var owner, id string
		if err := r.Scan(&owner, &id); err != nil {
			return err
		}
		events = append(events, lease.Event{ID: identity.New(), OwnerID: owner, Type: "request.stale", At: now, BootID: boot, RequestID: id})
		return nil
	})
	if err != nil {
		return 0, 0, lease.ErrStorage
	}
	stale = len(events)
	err = t.query("UPDATE leases SET state='suspended', ended_at=$1 WHERE state='active' RETURNING owner_id, request_id, lease_id", []any{micros(now)}, func(r *sql.Rows) error {
		var owner, request, id string
		if err := r.Scan(&owner, &request, &id); err != nil {
			return err
		}
		events = append(events, lease.Event{ID: identity.New(), OwnerID: owner, Type: "lease.suspended", At: now, BootID: boot, RequestID: request, LeaseID: id})
		return nil
	})
	if err != nil {
		return 0, 0, lease.ErrStorage
	}
	suspended = len(events) - stale
	for _, event := range events {
		x := &ownerTx{t: t, owner: event.OwnerID, now: now}
		if err := x.Event(event); err != nil {
			return 0, 0, err
		}
	}
	return stale, suspended, nil
}

// transaction runs fn in one IMMEDIATE transaction on the executor
// connection. Statements use a store context detached from the caller, so a
// client that disconnects never interrupts a statement. The caller's context
// is checked before COMMIT instead: a caller that has gone gets its context
// error wrapped in lease.ErrRolledBack, and nothing is committed. The store
// context is tested before any error mapping, because a statement stopped by
// it returns the context error, and database/sql may already have rolled the
// transaction back.
func (s *Store) transaction(caller context.Context, deadline time.Duration, fn func(*tx) error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(caller), deadline)
	defer cancel()
	sqlTx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		s.fail()
		return lease.ErrStorage
	}
	t := &tx{ctx: ctx, tx: sqlTx}
	rollback := func() {
		if err := sqlTx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			s.fail()
		}
	}
	if err := fn(t); err != nil {
		rollback()
		if ctx.Err() != nil || fatal(t.err) || errors.Is(err, lease.ErrStorage) {
			s.fail()
			return lease.ErrStorage
		}
		return err
	}
	if t.err != nil || ctx.Err() != nil {
		// A callback that returns nil on a poisoned transaction is a bug:
		// on PostgreSQL its COMMIT would fail.
		rollback()
		s.fail()
		return lease.ErrStorage
	}
	if err := caller.Err(); err != nil {
		rollback()
		return fmt.Errorf("%w: %w", lease.ErrRolledBack, err)
	}
	if err := sqlTx.Commit(); err != nil {
		// A COMMIT refused by a deferred constraint leaves SQLite's
		// transaction open, holding the write lock until Close. End it now.
		end, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _ = s.conn.ExecContext(end, "ROLLBACK")
		cancel()
		s.fail()
		return lease.ErrStorage
	}
	return nil
}

func (s *Store) WithOwner(ctx context.Context, owner string, fn func(lease.Tx) error) error {
	if owner == "" || len(owner) > 512 {
		return lease.ErrDenied
	}
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if !s.started {
		return lease.ErrLocked
	}
	return s.transaction(ctx, ownerDeadline, func(t *tx) error {
		// BEGIN IMMEDIATE already holds the database write lock, so Now is
		// sampled after the lock, as lease.Tx requires.
		if _, err := t.exec("INSERT INTO owners(owner_id) VALUES ($1) ON CONFLICT(owner_id) DO NOTHING", owner); err != nil {
			return lease.ErrStorage
		}
		return fn(&ownerTx{t: t, owner: owner, now: s.now()})
	})
}

// run executes fn in one short transaction on the executor, after Start.
func (s *Store) run(ctx context.Context, deadline time.Duration, fn func(*tx) error) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if !s.started {
		return lease.ErrLocked
	}
	return s.transaction(ctx, deadline, fn)
}

// heartbeat checks every second that the database and lock paths still name
// the files that were opened, whatever the gate is doing: a busy executor
// hands the gate from one waiter to the next and could otherwise keep
// serving beside a second process. It then pings the session if the gate is
// idle; a busy gate skips the ping, since its holder is bounded by its own
// store deadline.
func (s *Store) heartbeat() {
	defer close(s.done)
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-timer.C:
			if !s.sameFiles() {
				s.fail()
				continue
			}
			select {
			case <-s.gate:
			default:
				continue
			}
			if s.started && !s.alive() && s.ctx.Err() == nil {
				s.fail()
			}
			s.release()
		}
	}
}

func (s *Store) sameFiles() bool {
	return sameFile(s.path, s.file) && sameFile(s.lockPath, s.lockInfo)
}

// alive pings the session; the caller holds the gate.
func (s *Store) alive() bool {
	if !s.sameFiles() {
		return false
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	var one int
	return s.conn.QueryRowContext(ctx, "SELECT 1").Scan(&one) == nil && one == 1
}

var _ lease.Store = (*Store)(nil)
