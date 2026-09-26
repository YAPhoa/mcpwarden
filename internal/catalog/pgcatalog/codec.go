package pgcatalog

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
)

// state is the decoded catalog. Payloads are authoritative; plain columns
// must agree with them or the load fails.
type state struct {
	accounts   map[string]catalog.Account      // by username
	access     map[string]catalog.AccessRecord // by ID
	entries    map[string]catalog.Entry        // by connector ID
	grants     map[string]int64                // connector ID: OAuth grant revision
	tombstones map[string]tombstone            // connector ID
	legacy     map[string]catalog.Lifecycle    // file tombstones without an owner
	discovery  map[catalog.ProviderKey]catalog.Discovery
	visibility map[catalog.ProviderKey]catalog.Visibility
	revisions  map[catalog.ProviderKey]int64 // provider security revision
}

// visibilityRecord is the sealed visibility payload. Revision counts changes to
// a provider's availability and visible tools; access scopes bind it as the
// connector security revision. The file catalog keeps no counter, so an import
// starts at zero and a rollback export drops it.
type visibilityRecord struct {
	catalog.Visibility
	Revision int64 `json:"security_revision,omitempty"`
}

type tombstone struct {
	owner string
	life  catalog.Lifecycle
}

func newState() *state {
	return &state{accounts: map[string]catalog.Account{}, access: map[string]catalog.AccessRecord{}, entries: map[string]catalog.Entry{},
		grants: map[string]int64{}, tombstones: map[string]tombstone{}, legacy: map[string]catalog.Lifecycle{},
		discovery: map[catalog.ProviderKey]catalog.Discovery{}, visibility: map[catalog.ProviderKey]catalog.Visibility{}, revisions: map[catalog.ProviderKey]int64{}}
}

// sameTime compares a payload time with its column, which PostgreSQL keeps at
// microsecond precision.
func sameTime(payload, column time.Time) bool {
	if payload.IsZero() || column.IsZero() {
		return payload.IsZero() && column.IsZero()
	}
	return payload.Truncate(time.Microsecond).Equal(column.Truncate(time.Microsecond))
}

// storedEntry catches the fields an older build sealed into a connector:
// header values and upstream OAuth settings. Such a catalog is refused.
type storedEntry struct {
	catalog.Entry
	Headers map[string]string `json:"headers"`
	OAuth   json.RawMessage   `json:"oauth"`
}

func (e *storedEntry) old() bool {
	old := len(e.Headers) > 0 || len(e.OAuth) > 0 && string(e.OAuth) != "null"
	clear(e.Headers)
	e.Headers, e.OAuth = nil, nil
	return old
}

func (s *sealer) decode(rows catalogdb.Rows) (*state, error) {
	st := newState()
	bad := func(kind string) error { return fmt.Errorf("stored %s does not match its sealed record", kind) }
	for _, row := range rows.Accounts {
		var a catalog.Account
		if err := s.open(accountAAD(row.OwnerID), row.Sealed, &a); err != nil {
			return nil, err
		}
		if a.ID != row.OwnerID || a.Username != row.Username || !sameTime(a.CreatedAt, row.CreatedAt) || !sameTime(a.UpdatedAt, row.UpdatedAt) || a.ClientTokenHash != "" {
			return nil, bad("account")
		}
		if _, dup := st.accounts[a.Username]; dup {
			return nil, bad("account")
		}
		st.accounts[a.Username] = a
	}
	for _, row := range rows.Access {
		var r catalog.AccessRecord
		if err := s.open(accessAAD(row.ID), row.Sealed, &r); err != nil {
			return nil, err
		}
		if r.ID != row.ID || r.Owner != row.OwnerID || r.PublicID != row.PublicID || r.Kind != row.Kind || r.Role != row.Role ||
			!hmac.Equal(s.digest(r.SecretHash), row.SecretDigest) || !sameTime(r.CreatedAt, row.CreatedAt) || !sameTime(r.UpdatedAt, row.UpdatedAt) ||
			!sameTime(r.LastUsedAt, row.LastUsedAt) || !sameTime(r.ExpiresAt, row.ExpiresAt) || !sameTime(r.EndedAt, row.EndedAt) ||
			!sameTime(r.RevokedAt, row.RevokedAt) || !sameTime(r.DeletedAt, row.DeletedAt) {
			return nil, bad("access record")
		}
		st.access[r.ID] = r
	}
	for _, row := range rows.Connectors {
		if !row.DeletedAt.IsZero() {
			var life catalog.Lifecycle
			if err := s.open(connectorAAD(row.ID), row.Sealed, &life); err != nil {
				return nil, err
			}
			if row.Name != "" || row.GrantID != "" || !sameTime(life.DeletedAt, row.DeletedAt) || !sameTime(life.CreatedAt, row.CreatedAt) || !sameTime(life.UpdatedAt, row.UpdatedAt) {
				return nil, bad("connector tombstone")
			}
			st.tombstones[row.ID] = tombstone{owner: row.OwnerID, life: life}
			continue
		}
		var stored storedEntry
		if err := s.open(connectorAAD(row.ID), row.Sealed, &stored); err != nil {
			return nil, err
		}
		if stored.old() || row.GrantID != "" {
			return nil, fmt.Errorf("stored connector was %w", catalog.ErrOldFormat)
		}
		e := stored.Entry
		if e.ID != row.ID || e.Owner != row.OwnerID || e.Name != row.Name || e.AuthType != row.AuthType ||
			!sameTime(e.CreatedAt, row.CreatedAt) || !sameTime(e.UpdatedAt, row.UpdatedAt) || !e.DeletedAt.IsZero() {
			return nil, bad("connector")
		}
		if err := catalog.Validate(e); err != nil {
			return nil, bad("connector")
		}
		st.entries[e.ID] = e
		st.grants[e.ID] = row.GrantRevision
	}
	for _, row := range rows.Tombstones {
		var life catalog.Lifecycle
		if err := s.open("tombstone/"+row.ConnectorID, row.Sealed, &life); err != nil {
			return nil, err
		}
		if !sameTime(life.DeletedAt, row.DeletedAt) {
			return nil, bad("connector tombstone")
		}
		if _, dup := st.tombstones[row.ConnectorID]; dup {
			return nil, bad("connector tombstone")
		}
		st.legacy[row.ConnectorID] = life
	}
	for _, row := range rows.Discovery {
		var d catalog.Discovery
		if err := s.open(discoveryAAD(row.OwnerID, row.Provider), row.Sealed, &d); err != nil {
			return nil, err
		}
		if !sameTime(d.UpdatedAt, row.UpdatedAt) {
			return nil, bad("discovery")
		}
		st.discovery[catalog.ProviderKey{Owner: row.OwnerID, Provider: row.Provider}] = d
	}
	for _, row := range rows.Visibility {
		var v visibilityRecord
		if err := s.open(visibilityAAD(row.OwnerID, row.Provider), row.Sealed, &v); err != nil {
			return nil, err
		}
		if v.Mode != row.Mode || v.Disabled != row.Disabled || !sameTime(v.CreatedAt, row.CreatedAt) || !sameTime(v.UpdatedAt, row.UpdatedAt) || v.Revision < 0 {
			return nil, bad("visibility")
		}
		k := catalog.ProviderKey{Owner: row.OwnerID, Provider: row.Provider}
		st.visibility[k] = v.Visibility
		if v.Revision > 0 {
			st.revisions[k] = v.Revision
		}
	}
	return st, nil
}

// snapshot converts the decoded state to the file catalog's shape. Tombstones
// with an owner lose it, since the file never recorded one.
func (st *state) snapshot() catalog.Snapshot {
	snap := catalog.Snapshot{Deleted: map[string]catalog.Lifecycle{}, Discovery: map[catalog.ProviderKey]catalog.Discovery{}, Visibility: map[catalog.ProviderKey]catalog.Visibility{}}
	for _, a := range st.accounts {
		snap.Accounts = append(snap.Accounts, a)
	}
	for _, r := range st.access {
		snap.Access = append(snap.Access, r)
	}
	for _, e := range st.entries {
		snap.Entries = append(snap.Entries, e)
	}
	for id, l := range st.legacy {
		snap.Deleted[id] = l
	}
	for id, t := range st.tombstones {
		snap.Deleted[id] = t.life
	}
	for k, d := range st.discovery {
		snap.Discovery[k] = d
	}
	for k, v := range st.visibility {
		snap.Visibility[k] = v
	}
	return snap
}

// Row builders. Each seals the full record bound to its row identity.

func (s *sealer) accountRow(a catalog.Account) (catalogdb.Account, error) {
	sealed, err := s.seal(accountAAD(a.ID), a)
	return catalogdb.Account{OwnerID: a.ID, Username: a.Username, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, Sealed: sealed}, err
}

func (s *sealer) accessRow(r catalog.AccessRecord) (catalogdb.Access, error) {
	sealed, err := s.seal(accessAAD(r.ID), r)
	return catalogdb.Access{ID: r.ID, OwnerID: r.Owner, PublicID: r.PublicID, Kind: r.Kind, Role: r.Role, SecretDigest: s.digest(r.SecretHash),
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastUsedAt: r.LastUsedAt, ExpiresAt: r.ExpiresAt, EndedAt: r.EndedAt,
		RevokedAt: r.RevokedAt, DeletedAt: r.DeletedAt, Sealed: sealed}, err
}

func (s *sealer) connectorRow(e catalog.Entry, revision int64) (catalogdb.Connector, error) {
	sealed, err := s.seal(connectorAAD(e.ID), e)
	return catalogdb.Connector{ID: e.ID, OwnerID: e.Owner, Name: e.Name, AuthType: e.AuthType, GrantRevision: revision,
		CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, Sealed: sealed}, err
}

func (s *sealer) tombstoneRow(id, owner string, life catalog.Lifecycle) (catalogdb.Connector, error) {
	sealed, err := s.seal(connectorAAD(id), life)
	return catalogdb.Connector{ID: id, OwnerID: owner, AuthType: "", CreatedAt: life.CreatedAt, UpdatedAt: life.UpdatedAt, DeletedAt: life.DeletedAt, Sealed: sealed}, err
}

func (s *sealer) legacyTombstoneRow(id string, life catalog.Lifecycle) (catalogdb.Tombstone, error) {
	if !identity.Valid(id) || life.DeletedAt.IsZero() {
		return catalogdb.Tombstone{}, fmt.Errorf("invalid stored connector tombstone")
	}
	sealed, err := s.seal("tombstone/"+id, life)
	return catalogdb.Tombstone{ConnectorID: id, DeletedAt: life.DeletedAt, Sealed: sealed}, err
}

func (s *sealer) discoveryRow(k catalog.ProviderKey, d catalog.Discovery) (catalogdb.Discovery, error) {
	sealed, err := s.seal(discoveryAAD(k.Owner, k.Provider), d)
	return catalogdb.Discovery{OwnerID: k.Owner, Provider: k.Provider, UpdatedAt: d.UpdatedAt, Sealed: sealed}, err
}

func (s *sealer) visibilityRow(k catalog.ProviderKey, v catalog.Visibility, revision int64) (catalogdb.Visibility, error) {
	sealed, err := s.seal(visibilityAAD(k.Owner, k.Provider), visibilityRecord{Visibility: v, Revision: revision})
	return catalogdb.Visibility{OwnerID: k.Owner, Provider: k.Provider, Mode: v.Mode, Disabled: v.Disabled, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, Sealed: sealed}, err
}

// sameSnapshot compares every field, secrets included, without exposing them.
func sameSnapshot(a, b catalog.Snapshot) (bool, error) {
	x, err := a.Canonical()
	if err != nil {
		return false, err
	}
	defer clear(x)
	y, err := b.Canonical()
	if err != nil {
		return false, err
	}
	defer clear(y)
	return bytes.Equal(x, y), nil
}
