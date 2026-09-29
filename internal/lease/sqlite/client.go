package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// ErrClientBusy is returned by OpenClient when it could not start serving
// within its wait.
var ErrClientBusy = fmt.Errorf("%w: database in use by a gateway, or needs a migration while other mcpwarden clients use it; connect over HTTP, or close the other clients", lease.ErrLocked)

// clientWait bounds OpenClient's lock loop. clientBusyTimeout is the busy
// wait of each history write: clients share the file only with each other.
var clientWait = 10 * time.Second

const (
	clientBusyTimeout = 5000
	clientDeadline    = 5 * time.Second
)

// convertHook runs in the gap of the exclusive-to-shared conversion, where
// another process can take the lock. Tests only.
var convertHook func()

// Client is a --stdio process's view of the database. It holds the lock file
// shared for its whole life, so any number of clients can use the file
// together and a gateway cannot; it holds it exclusively only to create or
// migrate the database. It reads one owner's catalog rows and writes nothing
// but history.
type Client struct {
	db       *sql.DB // exactly one connection
	lock     *lockFile
	path     string
	lockPath string
	file     os.FileInfo
	lockInfo os.FileInfo

	mu   sync.Mutex
	lost chan struct{}
	once sync.Once
}

var _ catalogdb.Client = (*Client)(nil)

type dbState int

const (
	dbReady dbState = iota
	dbCreate
	dbMigrate
)

// OpenClient takes the lock file shared and checks that the database is at
// this build's schema, creating or migrating it only while it can hold the
// lock exclusively. It gives up after clientWait with ErrClientBusy. A
// newer, foreign or unknown database is refused at once, as the gateway
// refuses it.
func OpenClient(ctx context.Context, path string, opt Options) (*Client, error) {
	abs, err := checkPath(path, opt.Warn)
	if err != nil {
		return nil, err
	}
	c := &Client{path: abs, lockPath: abs + ".lock", lost: make(chan struct{})}
	ok := false
	defer func() {
		if !ok {
			c.closeAll()
		}
	}()
	if c.lock, err = openLock(c.lockPath); err != nil {
		return nil, errors.New("storage lock file could not be opened")
	}
	deadline := time.Now().Add(clientWait)
	for {
		ready, err := c.attempt(ctx)
		if err != nil {
			return nil, err
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			return nil, ErrClientBusy
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50*time.Millisecond + rand.N(50*time.Millisecond)):
		}
	}
	if c.lockInfo, err = c.lock.stat(); err != nil || !sameFile(c.lockPath, c.lockInfo) || safeFile(c.lockInfo) != nil {
		return nil, errors.New("storage lock file is not a private regular file")
	}
	if c.file, err = os.Lstat(abs); err != nil {
		return nil, errors.New("storage database could not be read")
	}
	if err := safeFile(c.file); err != nil {
		return nil, err
	}
	ok = true
	return c, nil
}

// attempt is one pass of the lock loop. It reports true when the client
// holds the lock shared on a database at this build's schema; false means
// the lock was not free and the caller waits and tries again.
func (c *Client) attempt(ctx context.Context) (bool, error) {
	if err := c.lock.try(false); err != nil {
		if errors.Is(err, errBusy) {
			return false, nil
		}
		return false, errors.New("storage lock file could not be locked")
	}
	state, err := c.inspect(ctx)
	if err != nil || state == dbReady {
		if err != nil {
			_ = c.lock.unlock()
		}
		return err == nil, err
	}
	// Creating or migrating needs every other client gone.
	if err := c.lock.unlock(); err != nil {
		return false, errors.New("storage lock file could not be unlocked")
	}
	if err := c.lock.try(true); err != nil {
		if errors.Is(err, errBusy) {
			return false, nil
		}
		return false, errors.New("storage lock file could not be locked")
	}
	if state, err = c.inspect(ctx); err == nil && state != dbReady {
		err = c.create(ctx)
	}
	// The conversion is not atomic on either platform, so it is done in two
	// steps; another process may take the lock in between.
	if uerr := c.lock.unlock(); err != nil || uerr != nil {
		if err == nil {
			err = errors.New("storage lock file could not be unlocked")
		}
		return false, err
	}
	if convertHook != nil {
		convertHook()
	}
	if err := c.lock.try(false); err != nil {
		if errors.Is(err, errBusy) {
			return false, nil
		}
		return false, errors.New("storage lock file could not be locked")
	}
	if state, err = c.inspect(ctx); err != nil || state != dbReady {
		_ = c.lock.unlock()
		return false, err
	}
	return true, nil
}

// inspect reports what the database needs without creating it. The caller
// holds the lock.
func (c *Client) inspect(ctx context.Context) (dbState, error) {
	info, err := os.Lstat(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return dbCreate, nil
	}
	if err != nil {
		return 0, errors.New("storage database could not be read")
	}
	if err := safeFile(info); err != nil {
		return 0, err
	}
	if info.Size() == 0 {
		return dbCreate, nil
	}
	conn, err := c.conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	n, err := ledger(ctx, conn)
	switch {
	case errors.Is(err, ErrMigration), errors.Is(err, ErrNewer), errors.Is(err, ErrForeign), errors.Is(err, ErrSchemaReset):
		return 0, err
	case err != nil:
		return 0, errors.New("storage database could not be read")
	case n == 0:
		return dbCreate, nil
	case n < len(migrations):
		return dbMigrate, nil
	}
	return dbReady, nil
}

// create creates or migrates the database. The caller holds the lock
// exclusively.
func (c *Client) create(ctx context.Context) error {
	if _, err := prepareFile(c.path); err != nil {
		return err
	}
	conn, err := c.conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := migrate(ctx, conn); err != nil {
		if errors.Is(err, ErrMigration) || errors.Is(err, ErrNewer) || errors.Is(err, ErrForeign) || errors.Is(err, ErrSchemaReset) {
			return err
		}
		return errors.New("storage database could not be migrated")
	}
	return nil
}

// conn opens the pool on first use and returns its connection with the
// client settings verified. The file exists: the driver never creates it.
func (c *Client) conn(ctx context.Context) (*sql.Conn, error) {
	if c.db == nil {
		db, err := sql.Open("sqlite", dsn(c.path, "busy_timeout("+strconv.Itoa(clientBusyTimeout)+")", "foreign_keys(1)", "journal_mode(WAL)",
			"synchronous(FULL)", "trusted_schema(0)")+"&_txlock=immediate")
		if err != nil {
			return nil, errors.New("storage database could not be opened")
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(0)
		db.SetConnMaxIdleTime(0)
		c.db = db
	}
	ctx, cancel := context.WithTimeout(ctx, clientDeadline)
	defer cancel()
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return nil, errors.New("storage database could not be opened")
	}
	if err := checkPragmas(ctx, conn, clientBusyTimeout, false); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Lost is closed when the client stops trusting the database: a file was
// replaced, or a commit outcome is unknown.
func (c *Client) Lost() <-chan struct{} { return c.lost }
func (c *Client) fail()                 { c.once.Do(func() { close(c.lost) }) }

func (c *Client) usable() bool {
	select {
	case <-c.lost:
		return false
	default:
	}
	if !sameFile(c.path, c.file) || !sameFile(c.lockPath, c.lockInfo) {
		c.fail()
		return false
	}
	return true
}

// transaction runs fn in one IMMEDIATE transaction, waiting at most the busy
// timeout for another client's write. A commit failure stops the client.
func (c *Client) transaction(ctx context.Context, fn func(*tx) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.usable() {
		return lease.ErrLocked
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), clientDeadline+time.Duration(clientBusyTimeout)*time.Millisecond)
	defer cancel()
	conn, err := c.conn(ctx)
	if err != nil {
		return catalogdb.ErrStorage
	}
	defer conn.Close()
	sqlTx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return catalogdb.ErrStorage
	}
	t := &tx{ctx: ctx, tx: sqlTx}
	if err := fn(t); err != nil || t.err != nil {
		_ = sqlTx.Rollback()
		if err == nil || fatal(t.err) {
			return catalogdb.ErrStorage
		}
		return err
	}
	if err := sqlTx.Commit(); err != nil {
		end, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _ = conn.ExecContext(end, "ROLLBACK")
		cancel()
		c.fail()
		return catalogdb.ErrStorage
	}
	return nil
}

// LoadOwner reads one owner's catalog rows in one transaction.
func (c *Client) LoadOwner(ctx context.Context, owner string) (catalogdb.Rows, error) {
	if owner == "" {
		return catalogdb.Rows{}, lease.ErrDenied
	}
	var out catalogdb.Rows
	err := c.transaction(ctx, func(t *tx) error {
		var err error
		out, err = loadRows(t, owner)
		return err
	})
	if err != nil {
		return catalogdb.Rows{}, err
	}
	return out, nil
}

// InsertHistory stores one event in its own IMMEDIATE transaction, after
// checking that the database and lock paths still name the files it opened.
// A write that cannot get the database within the busy timeout fails, as any
// failed admission write does.
func (c *Client) InsertHistory(ctx context.Context, h catalogdb.HistoryRow) error {
	return c.transaction(ctx, func(t *tx) error { return insertHistory(t, h) })
}

func (c *Client) closeAll() {
	if c.db != nil {
		c.db.Close()
	}
	if c.lock != nil {
		c.lock.close()
	}
}

// Close closes the connection, which checkpoints the WAL when it is the
// last one, then releases the lock file.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail()
	var failed bool
	if c.db != nil && c.db.Close() != nil {
		failed = true
	}
	if c.lock != nil && c.lock.close() != nil {
		failed = true
	}
	c.db, c.lock = nil, nil
	if failed {
		return lease.ErrStorage
	}
	return nil
}
