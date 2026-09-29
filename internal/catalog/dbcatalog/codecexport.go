package dbcatalog

import (
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
)

// Codec gives the PostgreSQL catalog import and rollback (pgcatalog) the same
// sealing and verification the runtime repository uses. It goes away with
// them.
type Codec struct{ s *sealer }

func NewCodec(encodedKey string) (*Codec, error) {
	s, err := newSealer(encodedKey)
	if err != nil {
		return nil, err
	}
	return &Codec{s: s}, nil
}

// Decoded is a verified catalog in the file catalog's shape, with the counts
// of what that shape cannot hold.
type Decoded struct {
	Snapshot   catalog.Snapshot
	Tombstones int // connector tombstones with an owner
	Revisions  int // provider security revisions
}

// Decode verifies every row against its sealed record.
func (c *Codec) Decode(rows catalogdb.Rows) (Decoded, error) {
	st, err := c.s.decode(rows)
	if err != nil {
		return Decoded{}, err
	}
	return Decoded{Snapshot: st.snapshot(), Tombstones: len(st.tombstones), Revisions: len(st.revisions)}, nil
}

func (c *Codec) AccountRow(a catalog.Account) (catalogdb.Account, error) { return c.s.accountRow(a) }
func (c *Codec) AccessRow(r catalog.AccessRecord) (catalogdb.Access, error) {
	return c.s.accessRow(r)
}
func (c *Codec) ConnectorRow(e catalog.Entry) (catalogdb.Connector, error) {
	return c.s.connectorRow(e, 0)
}
func (c *Codec) LegacyTombstoneRow(id string, life catalog.Lifecycle) (catalogdb.Tombstone, error) {
	return c.s.legacyTombstoneRow(id, life)
}
func (c *Codec) DiscoveryRow(k catalog.ProviderKey, d catalog.Discovery) (catalogdb.Discovery, error) {
	return c.s.discoveryRow(k, d)
}
func (c *Codec) VisibilityRow(k catalog.ProviderKey, v catalog.Visibility) (catalogdb.Visibility, error) {
	return c.s.visibilityRow(k, v, 0)
}

// MAC is the verifier-digest key, for the keyed snapshot digest.
func (c *Codec) MAC() []byte { return c.s.mac }

// SameSnapshot compares every field, secrets included, without exposing them.
func SameSnapshot(a, b catalog.Snapshot) (bool, error) { return sameSnapshot(a, b) }

// HistoryRow derives the indexed columns of a normalized record.
func HistoryRow(r audit.Record, raw string) catalogdb.HistoryRow { return historyRow(r, raw) }
