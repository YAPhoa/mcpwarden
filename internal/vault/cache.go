package vault

import (
	"slices"
	"sync"
	"time"

	"github.com/yaphoa/mcpwarden/internal/secret"
)

// Cache supplies ciphertext to the activator without I/O inside an owner
// transaction. Prepare returns a publication callback for ChangeAtomic. Startup
// may also populate it from committed records while all execution is locked.
// Catalog authority and this cache must be published under the same owner gate.
type Cache struct {
	mu      sync.RWMutex
	records map[[2]string]secret.Record
}

func clone(r secret.Record) secret.Record {
	r.Envelope = slices.Clone(r.Envelope)
	r.Destination.HeaderNames = slices.Clone(r.Destination.HeaderNames)
	r.Destination.PrivatePrefixes = slices.Clone(r.Destination.PrivatePrefixes)
	return r
}

func (c *Cache) Prepare(r Record) (func() error, error) {
	deleted := !r.DeletedAt.IsZero()
	// Normalize validates tombstones with their retained current ciphertext too.
	copy := r
	copy.DeletedAt = time.Time{}
	value, err := copy.SecretRecord()
	if err != nil {
		return nil, err
	}
	key := [2]string{r.OwnerID, r.CredentialID}
	return func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if deleted {
			delete(c.records, key)
		} else {
			if c.records == nil {
				c.records = make(map[[2]string]secret.Record)
			}
			c.records[key] = value
		}
		return nil
	}, nil
}

func (c *Cache) Current(owner, id string) (secret.Record, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.records[[2]string{owner, id}]
	return clone(r), ok
}
