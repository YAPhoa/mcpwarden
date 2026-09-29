package sqlite

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
)

// Owner transactions write catalog rows in the same transaction as lease
// changes and security events.
func (x *ownerTx) CatalogOwner() string      { return x.owner }
func (x *ownerTx) CatalogRows() catalogdb.Tx { return catalogRows{x.t} }

var (
	_ catalogdb.OwnerTx = (*ownerTx)(nil)
	_ catalogdb.Store   = (*Store)(nil)
)

type catalogRows struct{ t *tx }

// one requires exactly one changed row: an upsert whose update condition
// fails changes nothing and is a conflict.
func one(n int64, err error) error {
	if err != nil {
		return catalogError(err)
	}
	if n != 1 {
		return catalogdb.ErrConflict
	}
	return nil
}

// PutAccount inserts or updates an account. The username never changes.
func (c catalogRows) PutAccount(a catalogdb.Account) error {
	return one(c.t.exec(`INSERT INTO catalog_accounts(owner_id,username,created_at,updated_at,sealed) VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (owner_id) DO UPDATE SET updated_at=excluded.updated_at,sealed=excluded.sealed
        WHERE catalog_accounts.username=excluded.username`,
		a.OwnerID, a.Username, optMicros(a.CreatedAt), optMicros(a.UpdatedAt), a.Sealed))
}

func (c catalogRows) PutAccess(a catalogdb.Access) error {
	return one(c.t.exec(`INSERT INTO catalog_access
        (access_id,owner_id,public_id,secret_digest,kind,role,created_at,updated_at,last_used_at,expires_at,ended_at,revoked_at,deleted_at,sealed)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        ON CONFLICT (access_id) DO UPDATE SET role=excluded.role,created_at=excluded.created_at,updated_at=excluded.updated_at,
        last_used_at=excluded.last_used_at,expires_at=excluded.expires_at,ended_at=excluded.ended_at,revoked_at=excluded.revoked_at,
        deleted_at=excluded.deleted_at,sealed=excluded.sealed
        WHERE catalog_access.owner_id=excluded.owner_id AND catalog_access.kind=excluded.kind
        AND catalog_access.secret_digest=excluded.secret_digest AND catalog_access.public_id IS excluded.public_id`,
		a.ID, a.OwnerID, optText(a.PublicID), a.SecretDigest, a.Kind, a.Role, optMicros(a.CreatedAt), optMicros(a.UpdatedAt), optMicros(a.LastUsedAt),
		optMicros(a.ExpiresAt), optMicros(a.EndedAt), optMicros(a.RevokedAt), optMicros(a.DeletedAt), a.Sealed))
}

func (c catalogRows) ActiveAccess(owner string, kinds []string, now time.Time) (int, error) {
	if len(kinds) == 0 {
		return 0, nil
	}
	args := []any{owner, micros(now)}
	marks := make([]string, len(kinds))
	for i, k := range kinds {
		args = append(args, k)
		marks[i] = "$" + strconv.Itoa(i+3)
	}
	var n int
	err := c.t.queryRow(`SELECT count(*) FROM catalog_access WHERE owner_id=$1 AND kind IN (`+strings.Join(marks, ",")+`)
        AND ended_at IS NULL AND revoked_at IS NULL AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > $2)`, args, &n)
	if err != nil {
		return 0, catalogdb.ErrStorage
	}
	return n, nil
}

func (c catalogRows) PutConnector(k catalogdb.Connector) error {
	return one(c.t.exec(`INSERT INTO catalog_connectors(connector_id,owner_id,name,auth_type,created_at,updated_at,deleted_at,sealed)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (connector_id) DO UPDATE SET name=excluded.name,auth_type=excluded.auth_type,created_at=excluded.created_at,
        updated_at=excluded.updated_at,deleted_at=excluded.deleted_at,sealed=excluded.sealed
        WHERE catalog_connectors.owner_id=excluded.owner_id AND catalog_connectors.deleted_at IS NULL`,
		k.ID, k.OwnerID, optText(k.Name), k.AuthType, optMicros(k.CreatedAt), optMicros(k.UpdatedAt), optMicros(k.DeletedAt), k.Sealed))
}

func (c catalogRows) PutDiscovery(d catalogdb.Discovery) error {
	return one(c.t.exec(`INSERT INTO catalog_discovery(owner_id,provider,updated_at,sealed) VALUES ($1,$2,$3,$4)
        ON CONFLICT (owner_id,provider) DO UPDATE SET updated_at=excluded.updated_at,sealed=excluded.sealed`,
		d.OwnerID, d.Provider, optMicros(d.UpdatedAt), d.Sealed))
}

func (c catalogRows) DeleteDiscovery(owner, provider string) error {
	_, err := c.t.exec(`DELETE FROM catalog_discovery WHERE owner_id=$1 AND provider=$2`, owner, provider)
	return catalogError(err)
}

func (c catalogRows) PutVisibility(v catalogdb.Visibility) error {
	return one(c.t.exec(`INSERT INTO catalog_visibility(owner_id,provider,mode,disabled,created_at,updated_at,sealed)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (owner_id,provider) DO UPDATE SET mode=excluded.mode,disabled=excluded.disabled,created_at=excluded.created_at,
        updated_at=excluded.updated_at,sealed=excluded.sealed`,
		v.OwnerID, v.Provider, v.Mode, v.Disabled, optMicros(v.CreatedAt), optMicros(v.UpdatedAt), v.Sealed))
}

func (c catalogRows) DeleteVisibility(owner, provider string) error {
	_, err := c.t.exec(`DELETE FROM catalog_visibility WHERE owner_id=$1 AND provider=$2`, owner, provider)
	return catalogError(err)
}

// LoadCatalog reads every catalog row in one transaction under the startup
// deadline.
func (s *Store) LoadCatalog(ctx context.Context) (catalogdb.Rows, error) {
	var out catalogdb.Rows
	err := s.run(ctx, loadDeadline, func(t *tx) error {
		var err error
		out, err = loadRows(t, "")
		return err
	})
	if err != nil {
		return catalogdb.Rows{}, err
	}
	return out, nil
}

// loadRows reads every catalog row, or one owner's when owner is set.
func loadRows(t *tx, owner string) (catalogdb.Rows, error) {
	var out catalogdb.Rows
	where, args := "", []any(nil)
	if owner != "" {
		where, args = " WHERE owner_id=$1", []any{owner}
	}
	steps := []struct {
		sql  string
		scan func(*sql.Rows) error
	}{
		{`SELECT owner_id,username,created_at,updated_at,sealed FROM catalog_accounts` + where + ` ORDER BY owner_id`, func(r *sql.Rows) error {
			var a catalogdb.Account
			var c, u sql.NullInt64
			if err := r.Scan(&a.OwnerID, &a.Username, &c, &u, &a.Sealed); err != nil {
				return err
			}
			a.CreatedAt, a.UpdatedAt = fromOptMicros(c), fromOptMicros(u)
			out.Accounts = append(out.Accounts, a)
			return nil
		}},
		{`SELECT access_id,owner_id,coalesce(public_id,''),secret_digest,kind,role,created_at,updated_at,last_used_at,
            expires_at,ended_at,revoked_at,deleted_at,sealed FROM catalog_access` + where + ` ORDER BY access_id`, func(r *sql.Rows) error {
			var a catalogdb.Access
			var c, u, l, x, e, rv, d sql.NullInt64
			if err := r.Scan(&a.ID, &a.OwnerID, &a.PublicID, &a.SecretDigest, &a.Kind, &a.Role, &c, &u, &l, &x, &e, &rv, &d, &a.Sealed); err != nil {
				return err
			}
			a.CreatedAt, a.UpdatedAt, a.LastUsedAt, a.ExpiresAt = fromOptMicros(c), fromOptMicros(u), fromOptMicros(l), fromOptMicros(x)
			a.EndedAt, a.RevokedAt, a.DeletedAt = fromOptMicros(e), fromOptMicros(rv), fromOptMicros(d)
			out.Access = append(out.Access, a)
			return nil
		}},
		{`SELECT connector_id,owner_id,coalesce(name,''),auth_type,created_at,updated_at,deleted_at,sealed FROM catalog_connectors` + where + ` ORDER BY connector_id`, func(r *sql.Rows) error {
			var k catalogdb.Connector
			var c, u, d sql.NullInt64
			if err := r.Scan(&k.ID, &k.OwnerID, &k.Name, &k.AuthType, &c, &u, &d, &k.Sealed); err != nil {
				return err
			}
			k.CreatedAt, k.UpdatedAt, k.DeletedAt = fromOptMicros(c), fromOptMicros(u), fromOptMicros(d)
			out.Connectors = append(out.Connectors, k)
			return nil
		}},
		{`SELECT owner_id,provider,updated_at,sealed FROM catalog_discovery` + where + ` ORDER BY owner_id,provider`, func(r *sql.Rows) error {
			var d catalogdb.Discovery
			var u sql.NullInt64
			if err := r.Scan(&d.OwnerID, &d.Provider, &u, &d.Sealed); err != nil {
				return err
			}
			d.UpdatedAt = fromOptMicros(u)
			out.Discovery = append(out.Discovery, d)
			return nil
		}},
		{`SELECT owner_id,provider,mode,disabled,created_at,updated_at,sealed FROM catalog_visibility` + where + ` ORDER BY owner_id,provider`, func(r *sql.Rows) error {
			var v catalogdb.Visibility
			var c, u sql.NullInt64
			if err := r.Scan(&v.OwnerID, &v.Provider, &v.Mode, &v.Disabled, &c, &u, &v.Sealed); err != nil {
				return err
			}
			v.CreatedAt, v.UpdatedAt = fromOptMicros(c), fromOptMicros(u)
			out.Visibility = append(out.Visibility, v)
			return nil
		}},
	}
	for _, step := range steps {
		if err := t.query(step.sql, args, step.scan); err != nil {
			return catalogdb.Rows{}, catalogdb.ErrStorage
		}
	}
	return out, nil
}
