// Package catalogdb holds the backend-neutral row types and interfaces for the
// gateway catalog and indexed history. It never sees plaintext secrets:
// callers pass sealed payloads and digests. Each store (PostgreSQL, SQLite)
// implements the interfaces with its own SQL.
package catalogdb

import (
	"context"
	"errors"
	"time"
)

var (
	ErrConflict = errors.New("catalog row conflict")
	ErrStorage  = errors.New("catalog storage failed")
)

// Tx writes catalog rows inside lease.Store.WithOwner, so they commit or roll
// back with that transaction's lease changes and security events. A
// constraint failure returns ErrConflict; any other failure ErrStorage.
type Tx interface {
	PutAccount(Account) error
	// PutAccess inserts or updates an access record. Owner, kind, verifier
	// digest and public ID are immutable.
	PutAccess(Access) error
	// ActiveAccess counts an owner's active records of the given kinds at
	// now, matching catalog.AccessRecord.Active. The owner lock serializes it
	// with the insert that follows.
	ActiveAccess(owner string, kinds []string, now time.Time) (int, error)
	// PutConnector inserts or updates a connector. An update never changes
	// the owner and never revives a tombstone.
	PutConnector(Connector) error
	PutDiscovery(Discovery) error
	DeleteDiscovery(owner, provider string) error
	PutVisibility(Visibility) error
	DeleteVisibility(owner, provider string) error
}

// OwnerTx is implemented by each lease store's owner transaction.
type OwnerTx interface {
	CatalogOwner() string
	CatalogRows() Tx
}

// Store is executor-session access outside owner transactions, plus the
// separate history reader.
type Store interface {
	// LoadCatalog reads every catalog row in one transaction under the
	// startup deadline.
	LoadCatalog(context.Context) (Rows, error)
	// InsertHistory commits one event on the executor session, keeping the
	// tool list and the open admissions in the same transaction.
	InsertHistory(context.Context, HistoryRow) error
	// QueryHistory reads one page on the read connection, in one snapshot.
	QueryHistory(context.Context, HistoryQuery) (HistoryResult, error)
	Lost() <-chan struct{}
}

// Client is the --stdio side (SQLite only): a process that shares the
// database with other clients under a shared lock, never with a gateway. It
// has no owner transactions and writes nothing but history.
type Client interface {
	// LoadOwner reads one owner's catalog rows in one transaction.
	LoadOwner(ctx context.Context, owner string) (Rows, error)
	// InsertHistory commits one event, keeping the tool list and the open
	// admissions in the same transaction.
	InsertHistory(context.Context, HistoryRow) error
}

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
// is set: Name is then empty and Sealed holds only the lifecycle.
type Connector struct {
	ID, OwnerID, Name, AuthType     string
	CreatedAt, UpdatedAt, DeletedAt time.Time
	Sealed                          []byte
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
	Discovery  []Discovery
	Visibility []Visibility
}
