package postgres

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// Store owns one dedicated PostgreSQL session. It never reconnects after losing
// executor ownership. A new process must explicitly acquire ownership and boot
// locked. The first adapter serializes short database transactions on this
// session; provider I/O must happen after WithOwner returns.
type Store struct {
	conn    *pgx.Conn
	gate    chan struct{}
	lost    chan struct{}
	once    sync.Once
	started bool // gate protected
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
}

// Open rejects powerful runtime roles and incompatible schemas. dsn is secret
// input: neither it nor driver errors containing connection fields are returned.
func Open(ctx context.Context, dsn string) (*Store, error) {
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, lease.ErrStorage
	}
	return open(ctx, config)
}

func open(ctx context.Context, config *pgx.ConnConfig) (*Store, error) {
	config.ConnectTimeout = 5 * time.Second
	config.RuntimeParams["application_name"] = "mcpwarden-security"
	config.RuntimeParams["statement_timeout"] = "3000"
	config.RuntimeParams["lock_timeout"] = "2000"
	config.RuntimeParams["idle_in_transaction_session_timeout"] = "5000"
	config.RuntimeParams["synchronous_commit"] = "on"
	config.RuntimeParams["search_path"] = "pg_catalog"
	config.RuntimeParams["timezone"] = "UTC"
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, lease.ErrStorage
	}
	ok := false
	defer func() {
		if !ok {
			closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = conn.Close(closeCtx)
		}
	}()
	var safe bool
	err = conn.QueryRow(ctx, `SELECT NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
        AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE `+unsafeRole+` AND pg_has_role(current_user,oid,'MEMBER'))
        AND NOT pg_has_role(current_user,n.nspowner,'MEMBER')
        AND NOT has_schema_privilege(current_user,n.oid,'CREATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.invocation_events','UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.security_events','UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.schema_migrations','INSERT,UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.vault_wrapper_sets','UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.credential_versions','UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.credential_heads','DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.credential_epochs','DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.vault_roots','DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.approval_policies','DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.catalog_state','INSERT,UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.catalog_legacy_tombstones','INSERT,UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.catalog_accounts','DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.catalog_access','DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.catalog_connectors','DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,'mcpwarden_security.history_events','UPDATE,DELETE,TRUNCATE')
        FROM pg_roles r,pg_namespace n WHERE r.rolname=current_user AND n.nspname='mcpwarden_security'`).Scan(&safe)
	if err != nil || !safe {
		return nil, lease.ErrStorage
	}
	count, err := appliedMigrations(ctx, conn)
	if err != nil || count != SchemaVersion {
		return nil, lease.ErrStorage
	}
	s := &Store{conn: conn, gate: make(chan struct{}, 1), lost: make(chan struct{}), done: make(chan struct{})}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.gate <- struct{}{}
	ok = true
	go s.heartbeat()
	return s, nil
}
func (s *Store) Lost() <-chan struct{} { return s.lost }
func (s *Store) fail()                 { s.once.Do(func() { close(s.lost); s.cancel() }) }
func (s *Store) acquire(ctx context.Context) error {
	select {
	case <-s.lost:
		return lease.ErrLocked
	default:
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

func (s *Store) Close(ctx context.Context) error {
	s.fail()
	<-s.done
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	defer s.release()
	if err := s.conn.Close(ctx); err != nil {
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
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var locked bool
	if err := s.conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", executorLock).Scan(&locked); err != nil {
		s.fail()
		return lease.ErrStorage
	}
	if !locked {
		return lease.ErrLocked
	}
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		_, _, err := Quiesce(ctx, tx, boot)
		return err
	})
	if err != nil {
		s.fail()
		return lease.ErrStorage
	}
	s.started = true
	return nil
}

// Quiesce marks every pending or approved request stale and suspends every
// active lease, recording one security event each under boot. Startup and
// catalog rollback both use it while holding the executor lock.
func Quiesce(ctx context.Context, tx pgx.Tx, boot string) (stale, suspended int, err error) {
	if !identity.Valid(boot) {
		return 0, 0, lease.ErrDenied
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return 0, 0, lease.ErrStorage
	}
	rows, err := tx.Query(ctx, "UPDATE mcpwarden_security.requests SET state='stale' WHERE state IN ('pending','approved') RETURNING owner_id,request_id::text")
	if err != nil {
		return 0, 0, lease.ErrStorage
	}
	var events []lease.Event
	for rows.Next() {
		var owner, id string
		if err := rows.Scan(&owner, &id); err != nil {
			rows.Close()
			return 0, 0, lease.ErrStorage
		}
		events = append(events, lease.Event{ID: identity.New(), OwnerID: owner, Type: "request.stale", At: now, BootID: boot, RequestID: id})
	}
	rows.Close()
	if rows.Err() != nil {
		return 0, 0, lease.ErrStorage
	}
	stale = len(events)
	rows, err = tx.Query(ctx, "UPDATE mcpwarden_security.leases SET state='suspended',ended_at=$1 WHERE state='active' RETURNING owner_id,request_id::text,lease_id::text", now)
	if err != nil {
		return 0, 0, lease.ErrStorage
	}
	for rows.Next() {
		var owner, request, id string
		if err := rows.Scan(&owner, &request, &id); err != nil {
			rows.Close()
			return 0, 0, lease.ErrStorage
		}
		events = append(events, lease.Event{ID: identity.New(), OwnerID: owner, Type: "lease.suspended", At: now, BootID: boot, RequestID: request, LeaseID: id})
	}
	rows.Close()
	if rows.Err() != nil {
		return 0, 0, lease.ErrStorage
	}
	suspended = len(events) - stale
	for _, event := range events {
		x := &ownerTx{ctx: ctx, tx: tx, owner: event.OwnerID, now: now}
		if err := x.Event(event); err != nil {
			return 0, 0, err
		}
	}
	return stale, suspended, nil
}

func (s *Store) transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		s.fail()
		return lease.ErrStorage
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			s.fail()
		}
	}()
	if err = fn(tx); err != nil {
		if errors.Is(err, lease.ErrStorage) {
			s.fail()
		}
		return err
	}
	if err = tx.Commit(ctx); err != nil {
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
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO mcpwarden_security.owners(owner_id) VALUES ($1) ON CONFLICT DO NOTHING", owner); err != nil {
			return lease.ErrStorage
		}
		var lockedOwner string
		if err := tx.QueryRow(ctx, "SELECT owner_id FROM mcpwarden_security.owners WHERE owner_id=$1 FOR UPDATE", owner).Scan(&lockedOwner); err != nil {
			return lease.ErrStorage
		}
		var now time.Time
		// now()/transaction_timestamp() would use the timestamp before waiting.
		if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return lease.ErrStorage
		}
		return fn(&ownerTx{ctx: ctx, tx: tx, owner: owner, now: now})
	})
}

func (s *Store) heartbeat() {
	defer close(s.done)
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
			if err := s.acquire(ctx); err == nil {
				if s.started && s.conn.Ping(ctx) != nil {
					s.fail()
				}
				s.release()
			} else if errors.Is(err, context.DeadlineExceeded) {
				s.fail()
			}
			cancel()
		}
	}
}

var _ lease.Store = (*Store)(nil)
