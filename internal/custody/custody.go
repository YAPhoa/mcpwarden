// Package custody holds the owner-security metadata that the lease engine reads
// synchronously: approval policy, current credential heads and the catalog view
// of callers and tools. It never holds a vault root, CEK or plaintext credential.
package custody

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

// DefaultMode applies until an owner saves a policy. Revision 1 is implicit;
// the first stored change is revision 2.
const DefaultMode = "confirm"

var (
	ErrInvalid  = errors.New("invalid approval policy")
	ErrConflict = errors.New("approval policy changed; reload before saving")
)

type Policy struct {
	OwnerID   string    `json:"owner_id"`
	Mode      string    `json:"mode"`
	Revision  string    `json:"revision"`
	ChangedAt time.Time `json:"changed_at,omitzero"`
	ChangedBy string    `json:"changed_by,omitempty"`
}

func Default(owner string) Policy {
	return Policy{OwnerID: owner, Mode: DefaultMode, Revision: "1"}
}

func (p Policy) Valid() bool {
	_, ok := vault.Version(p.Revision)
	stored := p.Revision != "1"
	return p.OwnerID != "" && len(p.OwnerID) <= 512 && ok && (p.Mode == "none" || p.Mode == "confirm") &&
		stored == !p.ChangedAt.IsZero() && stored == identity.Valid(p.ChangedBy)
}

// Tx is implemented by the PostgreSQL owner transaction. Policy writes belong
// inside lease.Service.ChangeAtomic so that a change stales pending requests and
// revokes live leases in the same transaction.
type Tx interface {
	ApprovalPolicy() (Policy, error)
	PutApprovalPolicy(p Policy, expected string) error
	SecurityEvents(limit int) ([]lease.Event, error)
	RecentLeases(since time.Time, limit int) ([]lease.Lease, error) // ended windows, newest first
}

// Snapshot is the committed custody state loaded once at startup, before any
// owner route or admission can run.
type Snapshot struct {
	Credentials []vault.Record
	Policies    []Policy
}

// Head is public metadata for the current version of one credential.
type Head struct {
	OwnerID, CredentialID, ConnectorID string
	Epoch, Revision, DestinationDigest string
	Deleted                            bool
}

// Index serves committed heads and policies without I/O. Updates are prepared
// inside a transaction and published only after commit, under the owner gate.
type Index struct {
	mu       sync.RWMutex
	heads    map[[2]string]Head
	policies map[string]Policy
}

func NewIndex() *Index {
	return &Index{heads: map[[2]string]Head{}, policies: map[string]Policy{}}
}

func (x *Index) PrepareCredential(r vault.Record) (func() error, error) {
	deleted := !r.DeletedAt.IsZero()
	live := r
	live.DeletedAt = time.Time{}
	n, err := live.Normalize()
	if err != nil {
		return nil, err
	}
	digest, err := n.Destination.Digest()
	if err != nil {
		return nil, vault.ErrInvalid
	}
	h := Head{OwnerID: n.OwnerID, CredentialID: n.CredentialID, ConnectorID: n.ConnectorID, Epoch: n.Epoch, Revision: n.Revision, DestinationDigest: digest, Deleted: deleted}
	return func() error {
		x.mu.Lock()
		defer x.mu.Unlock()
		x.heads[[2]string{h.OwnerID, h.CredentialID}] = h
		return nil
	}, nil
}

func (x *Index) PreparePolicy(p Policy) (func() error, error) {
	if !p.Valid() {
		return nil, ErrInvalid
	}
	return func() error {
		x.mu.Lock()
		defer x.mu.Unlock()
		x.policies[p.OwnerID] = p
		return nil
	}, nil
}

func (x *Index) Credential(owner, id string) (Head, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	h, ok := x.heads[[2]string{owner, id}]
	return h, ok
}

// ConnectorCredential returns the connector's head, including a tombstone.
// Storage keeps at most one credential per owner and connector.
func (x *Index) ConnectorCredential(owner, connectorID string) (Head, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	for key, h := range x.heads {
		if key[0] == owner && h.ConnectorID == connectorID {
			return h, true
		}
	}
	return Head{}, false
}

// Credentials lists the owner's heads, including tombstones, by credential ID.
func (x *Index) Credentials(owner string) []Head {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := []Head{}
	for key, h := range x.heads {
		if key[0] == owner {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CredentialID < out[j].CredentialID })
	return out
}

func (x *Index) Policy(owner string) Policy {
	x.mu.RLock()
	defer x.mu.RUnlock()
	if p, ok := x.policies[owner]; ok {
		return p
	}
	return Default(owner)
}

// Load validates the whole snapshot before publishing any of it. Execution must
// remain unavailable until Load succeeds; a failure leaves both targets empty.
func (x *Index) Load(s Snapshot, cache *vault.Cache) error {
	var publish []func() error
	for _, r := range s.Credentials {
		index, err := x.PrepareCredential(r)
		if err != nil {
			return err
		}
		ciphertext, err := cache.Prepare(r)
		if err != nil {
			return err
		}
		publish = append(publish, index, ciphertext)
	}
	for _, p := range s.Policies {
		fn, err := x.PreparePolicy(p)
		if err != nil {
			return err
		}
		publish = append(publish, fn)
	}
	for _, fn := range publish {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}
