package dbcatalog

import (
	"context"
	"errors"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
)

// ErrReadOnly is every catalog change a --stdio process is asked for.
var ErrReadOnly = errors.New("stdio cannot change the catalog; use the panel")

// NewSnapshot is the read-only repository a --stdio process serves: one
// owner's visibility, discovery and no-auth connectors, loaded once through
// the client. Credentialed connectors are not loaded, since their
// credentials live in the owner vault, which only the gateway opens.
// Discovery updates stay in memory; every other change returns ErrReadOnly.
func NewSnapshot(ctx context.Context, encodedKey string, client catalogdb.Client, owner string) (*Repository, error) {
	s, err := newSealer(encodedKey)
	if err != nil {
		return nil, err
	}
	rows, err := client.LoadOwner(ctx, owner)
	if err != nil {
		return nil, err
	}
	// Accounts and access records are for HTTP sign-in; stdio has none.
	rows.Accounts, rows.Access = nil, nil
	st, err := s.decode(rows)
	if err != nil {
		return nil, err
	}
	for id, e := range st.entries {
		if e.Owner != owner {
			return nil, errors.New("stored connector belongs to another owner")
		}
		if e.Credentialed() {
			k := catalog.ProviderKey{Owner: owner, Provider: e.Name}
			delete(st.entries, id)
			delete(st.discovery, k)
			delete(st.visibility, k)
			delete(st.revisions, k)
		}
	}
	r := &Repository{seal: s, snapshot: true, st: st, now: func() time.Time { return time.Now().UTC() }}
	if l, ok := client.(interface{ Lost() <-chan struct{} }); ok {
		r.lost = l.Lost()
	}
	return r, nil
}
