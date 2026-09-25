// Package catalogdb holds the PostgreSQL row layer for the gateway catalog and
// indexed history (schema 004). It never sees plaintext secrets: callers pass
// sealed payloads and digests. The runtime reaches it only through an owner
// transaction or the store's gated session; operator tooling uses it on its
// own migration connection.
package catalogdb

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is satisfied by pgx.Tx and *pgx.Conn.
type DB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// OwnerTx is implemented by the lease store's owner transaction. Catalog writes
// made through it commit or roll back with that transaction's lease changes
// and security events.
type OwnerTx interface {
	CatalogOwner() string
	CatalogContext() context.Context
	CatalogDB() DB
}

var (
	ErrConflict = errors.New("catalog row conflict")
	ErrStorage  = errors.New("catalog storage failed")
)

type Account struct {
	OwnerID, Username    string
	CreatedAt, UpdatedAt time.Time
	Sealed               []byte
}

type Access struct {
	ID, OwnerID, PublicID, Kind, Role string
	SecretDigest                      []byte
	CreatedAt, UpdatedAt, LastUsedAt  time.Time
	ExpiresAt, EndedAt                time.Time
	RevokedAt, DeletedAt              time.Time
	Sealed                            []byte
}

// Connector is a live connector, or a credential-free tombstone when DeletedAt
// is set: Name and GrantID are then empty and Sealed holds only the lifecycle.
type Connector struct {
	ID, OwnerID, Name, AuthType, GrantID string
	GrantRevision                        int64
	CreatedAt, UpdatedAt, DeletedAt      time.Time
	Sealed                               []byte
}

// Tombstone is a file-catalog connector tombstone, which never had an owner.
// Sealed holds only its lifecycle, at full precision.
type Tombstone struct {
	ConnectorID string
	DeletedAt   time.Time
	Sealed      []byte
}

type Discovery struct {
	OwnerID, Provider string
	UpdatedAt         time.Time
	Sealed            []byte
}

type Visibility struct {
	OwnerID, Provider, Mode string
	Disabled                bool
	CreatedAt, UpdatedAt    time.Time
	Sealed                  []byte
}

type Rows struct {
	Accounts   []Account
	Access     []Access
	Connectors []Connector
	Tombstones []Tombstone
	Discovery  []Discovery
	Visibility []Visibility
}

func ts(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func text(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type nullTime struct{ t *time.Time }

func (n nullTime) value() time.Time {
	if n.t == nil {
		return time.Time{}
	}
	return n.t.UTC()
}

func one(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// classify maps constraint failures to ErrConflict. Other errors never carry
// driver text, which can include connection details or values.
func classify(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23514" || pg.Code == "23503") {
		return ErrConflict
	}
	return ErrStorage
}

func EnsureOwner(ctx context.Context, db DB, owner string) error {
	if _, err := db.Exec(ctx, "INSERT INTO mcpwarden_security.owners(owner_id) VALUES ($1) ON CONFLICT DO NOTHING", owner); err != nil {
		return classify(err)
	}
	return nil
}

// PutAccount inserts or updates an account. The username never changes.
func PutAccount(ctx context.Context, db DB, a Account) error {
	return one(db.Exec(ctx, `INSERT INTO mcpwarden_security.catalog_accounts(owner_id,username,created_at,updated_at,sealed)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (owner_id) DO UPDATE SET updated_at=excluded.updated_at,sealed=excluded.sealed
        WHERE catalog_accounts.username=excluded.username`,
		a.OwnerID, a.Username, ts(a.CreatedAt), ts(a.UpdatedAt), a.Sealed))
}

// PutAccess inserts or updates an access record. Owner, kind, verifier digest
// and public ID are immutable.
func PutAccess(ctx context.Context, db DB, a Access) error {
	return one(db.Exec(ctx, `INSERT INTO mcpwarden_security.catalog_access
        (access_id,owner_id,public_id,secret_digest,kind,role,created_at,updated_at,last_used_at,expires_at,ended_at,revoked_at,deleted_at,sealed)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        ON CONFLICT (access_id) DO UPDATE SET role=excluded.role,created_at=excluded.created_at,updated_at=excluded.updated_at,
        last_used_at=excluded.last_used_at,expires_at=excluded.expires_at,ended_at=excluded.ended_at,revoked_at=excluded.revoked_at,
        deleted_at=excluded.deleted_at,sealed=excluded.sealed
        WHERE catalog_access.owner_id=excluded.owner_id AND catalog_access.kind=excluded.kind
        AND catalog_access.secret_digest=excluded.secret_digest AND catalog_access.public_id IS NOT DISTINCT FROM excluded.public_id`,
		a.ID, a.OwnerID, text(a.PublicID), a.SecretDigest, a.Kind, a.Role, ts(a.CreatedAt), ts(a.UpdatedAt), ts(a.LastUsedAt),
		ts(a.ExpiresAt), ts(a.EndedAt), ts(a.RevokedAt), ts(a.DeletedAt), a.Sealed))
}

// ActiveAccess counts an owner's active records of the given kinds at now,
// matching catalog.AccessRecord.Active. The owner row lock serializes it with
// the insert that follows.
func ActiveAccess(ctx context.Context, db DB, owner string, kinds []string, now time.Time) (int, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM mcpwarden_security.catalog_access WHERE owner_id=$1 AND kind=ANY($2)
        AND ended_at IS NULL AND revoked_at IS NULL AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > $3)`, owner, kinds, now).Scan(&n)
	if err != nil {
		return 0, ErrStorage
	}
	return n, nil
}

// PutConnector inserts or updates a connector. With checkGrant, the update
// applies only while the stored grant ID still equals expectedGrant.
func PutConnector(ctx context.Context, db DB, c Connector, checkGrant bool, expectedGrant string) error {
	return one(db.Exec(ctx, `INSERT INTO mcpwarden_security.catalog_connectors
        (connector_id,owner_id,name,auth_type,grant_id,grant_revision,created_at,updated_at,deleted_at,sealed)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (connector_id) DO UPDATE SET name=excluded.name,auth_type=excluded.auth_type,grant_id=excluded.grant_id,
        grant_revision=excluded.grant_revision,created_at=excluded.created_at,updated_at=excluded.updated_at,
        deleted_at=excluded.deleted_at,sealed=excluded.sealed
        WHERE catalog_connectors.owner_id=excluded.owner_id AND catalog_connectors.deleted_at IS NULL
        AND (NOT $11 OR catalog_connectors.grant_id IS NOT DISTINCT FROM $12)`,
		c.ID, c.OwnerID, text(c.Name), c.AuthType, text(c.GrantID), c.GrantRevision, ts(c.CreatedAt), ts(c.UpdatedAt), ts(c.DeletedAt), c.Sealed,
		checkGrant, text(expectedGrant)))
}

func PutTombstone(ctx context.Context, db DB, t Tombstone) error {
	return one(db.Exec(ctx, `INSERT INTO mcpwarden_security.catalog_legacy_tombstones(connector_id,deleted_at,sealed) VALUES ($1,$2,$3)`,
		t.ConnectorID, t.DeletedAt, t.Sealed))
}

func PutDiscovery(ctx context.Context, db DB, d Discovery) error {
	return one(db.Exec(ctx, `INSERT INTO mcpwarden_security.catalog_discovery(owner_id,provider,updated_at,sealed) VALUES ($1,$2,$3,$4)
        ON CONFLICT (owner_id,provider) DO UPDATE SET updated_at=excluded.updated_at,sealed=excluded.sealed`,
		d.OwnerID, d.Provider, ts(d.UpdatedAt), d.Sealed))
}

func DeleteDiscovery(ctx context.Context, db DB, owner, provider string) error {
	if _, err := db.Exec(ctx, `DELETE FROM mcpwarden_security.catalog_discovery WHERE owner_id=$1 AND provider=$2`, owner, provider); err != nil {
		return classify(err)
	}
	return nil
}

func PutVisibility(ctx context.Context, db DB, v Visibility) error {
	return one(db.Exec(ctx, `INSERT INTO mcpwarden_security.catalog_visibility(owner_id,provider,mode,disabled,created_at,updated_at,sealed)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (owner_id,provider) DO UPDATE SET mode=excluded.mode,disabled=excluded.disabled,created_at=excluded.created_at,
        updated_at=excluded.updated_at,sealed=excluded.sealed`,
		v.OwnerID, v.Provider, v.Mode, v.Disabled, ts(v.CreatedAt), ts(v.UpdatedAt), v.Sealed))
}

func DeleteVisibility(ctx context.Context, db DB, owner, provider string) error {
	if _, err := db.Exec(ctx, `DELETE FROM mcpwarden_security.catalog_visibility WHERE owner_id=$1 AND provider=$2`, owner, provider); err != nil {
		return classify(err)
	}
	return nil
}

// Load reads every catalog row. Call it inside one transaction so the rows form
// a coherent snapshot.
func Load(ctx context.Context, db DB) (Rows, error) {
	var out Rows
	if err := each(ctx, db, `SELECT owner_id,username,created_at,updated_at,sealed FROM mcpwarden_security.catalog_accounts ORDER BY owner_id`, func(r pgx.Rows) error {
		var a Account
		var c, u nullTime
		if err := r.Scan(&a.OwnerID, &a.Username, &c.t, &u.t, &a.Sealed); err != nil {
			return ErrStorage
		}
		a.CreatedAt, a.UpdatedAt = c.value(), u.value()
		out.Accounts = append(out.Accounts, a)
		return nil
	}); err != nil {
		return Rows{}, err
	}
	if err := each(ctx, db, `SELECT access_id,owner_id,coalesce(public_id,''),secret_digest,kind,role,created_at,updated_at,last_used_at,
        expires_at,ended_at,revoked_at,deleted_at,sealed FROM mcpwarden_security.catalog_access ORDER BY access_id`, func(r pgx.Rows) error {
		var a Access
		var c, u, l, x, e, rv, d nullTime
		if err := r.Scan(&a.ID, &a.OwnerID, &a.PublicID, &a.SecretDigest, &a.Kind, &a.Role, &c.t, &u.t, &l.t, &x.t, &e.t, &rv.t, &d.t, &a.Sealed); err != nil {
			return ErrStorage
		}
		a.CreatedAt, a.UpdatedAt, a.LastUsedAt, a.ExpiresAt, a.EndedAt, a.RevokedAt, a.DeletedAt = c.value(), u.value(), l.value(), x.value(), e.value(), rv.value(), d.value()
		out.Access = append(out.Access, a)
		return nil
	}); err != nil {
		return Rows{}, err
	}
	if err := each(ctx, db, `SELECT connector_id::text,owner_id,coalesce(name,''),auth_type,coalesce(grant_id,''),grant_revision,created_at,updated_at,deleted_at,sealed
        FROM mcpwarden_security.catalog_connectors ORDER BY connector_id`, func(r pgx.Rows) error {
		var k Connector
		var c, u, d nullTime
		if err := r.Scan(&k.ID, &k.OwnerID, &k.Name, &k.AuthType, &k.GrantID, &k.GrantRevision, &c.t, &u.t, &d.t, &k.Sealed); err != nil {
			return ErrStorage
		}
		k.CreatedAt, k.UpdatedAt, k.DeletedAt = c.value(), u.value(), d.value()
		out.Connectors = append(out.Connectors, k)
		return nil
	}); err != nil {
		return Rows{}, err
	}
	if err := each(ctx, db, `SELECT connector_id::text,deleted_at,sealed FROM mcpwarden_security.catalog_legacy_tombstones ORDER BY connector_id`, func(r pgx.Rows) error {
		var t Tombstone
		if err := r.Scan(&t.ConnectorID, &t.DeletedAt, &t.Sealed); err != nil {
			return ErrStorage
		}
		t.DeletedAt = t.DeletedAt.UTC()
		out.Tombstones = append(out.Tombstones, t)
		return nil
	}); err != nil {
		return Rows{}, err
	}
	if err := each(ctx, db, `SELECT owner_id,provider,updated_at,sealed FROM mcpwarden_security.catalog_discovery ORDER BY owner_id,provider`, func(r pgx.Rows) error {
		var d Discovery
		var u nullTime
		if err := r.Scan(&d.OwnerID, &d.Provider, &u.t, &d.Sealed); err != nil {
			return ErrStorage
		}
		d.UpdatedAt = u.value()
		out.Discovery = append(out.Discovery, d)
		return nil
	}); err != nil {
		return Rows{}, err
	}
	if err := each(ctx, db, `SELECT owner_id,provider,mode,disabled,created_at,updated_at,sealed FROM mcpwarden_security.catalog_visibility ORDER BY owner_id,provider`, func(r pgx.Rows) error {
		var v Visibility
		var c, u nullTime
		if err := r.Scan(&v.OwnerID, &v.Provider, &v.Mode, &v.Disabled, &c.t, &u.t, &v.Sealed); err != nil {
			return ErrStorage
		}
		v.CreatedAt, v.UpdatedAt = c.value(), u.value()
		out.Visibility = append(out.Visibility, v)
		return nil
	}); err != nil {
		return Rows{}, err
	}
	return out, nil
}

func each(ctx context.Context, db DB, sql string, scan func(pgx.Rows) error, args ...any) error {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	if rows.Err() != nil {
		return ErrStorage
	}
	return nil
}
