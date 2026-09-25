package catalog

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

// ProviderKey names per-provider settings. The file keys them by an owner hash,
// so a snapshot resolves them back to owners it knows.
type ProviderKey struct{ Owner, Provider string }

// Snapshot is a complete decrypted catalog. It carries secrets: callers must
// never log or serialize it outside an encrypted store.
type Snapshot struct {
	Accounts   []Account
	Access     []AccessRecord
	Entries    []Entry
	Deleted    map[string]Lifecycle
	Discovery  map[ProviderKey]Discovery
	Visibility map[ProviderKey]Visibility
	// Rollback is the ID of the PostgreSQL rollback that wrote this file.
	Rollback string
}

// Normalized counts the changes ReadSnapshot applies exactly as Open would on
// the next start of a file gateway.
type Normalized struct {
	EndedMCPSessions int `json:"ended_mcp_sessions"`
}

var ErrNeedsFileMigration = errors.New("catalog file predates the current format; start the file gateway once, stop it, then retry")

// ReadSnapshot decodes a catalog file without writing it. It refuses files that
// Open would still migrate (missing connector or public IDs, legacy client
// tokens) and provider settings whose owner it cannot resolve, rather than
// guessing. MCP sessions still open are ended as Open ends them at startup.
func ReadSnapshot(path, encodedKey string, now time.Time) (Snapshot, Normalized, error) {
	var n Normalized
	aead, err := newAEAD(encodedKey)
	if err != nil {
		return Snapshot{}, n, err
	}
	state, exists, err := readDisk(path, aead)
	if err != nil {
		return Snapshot{}, n, err
	}
	if !exists {
		return Snapshot{}, n, fmt.Errorf("catalog file not found")
	}
	snap := Snapshot{Deleted: map[string]Lifecycle{}, Discovery: map[ProviderKey]Discovery{}, Visibility: map[ProviderKey]Visibility{}, Rollback: state.Rollback}
	for id, l := range state.Deleted {
		snap.Deleted[id] = l
	}
	owners := map[string]bool{"local": true}
	usernames := map[string]bool{}
	for username, a := range state.Accounts {
		if a.Username != username || a.ID == "" || usernames[a.Username] {
			return Snapshot{}, n, fmt.Errorf("invalid stored account")
		}
		if a.ClientTokenHash != "" {
			return Snapshot{}, n, ErrNeedsFileMigration
		}
		usernames[a.Username] = true
		owners[a.ID] = true
		snap.Accounts = append(snap.Accounts, a)
	}
	publicIDs, hashes := map[string]bool{}, map[string]bool{}
	for id, r := range state.Access {
		if r.ID != id || r.Owner == "" || r.SecretHash == "" || hashes[r.SecretHash] {
			return Snapshot{}, n, fmt.Errorf("invalid stored access record")
		}
		if r.Kind == "api_key" && r.PublicID == "" {
			return Snapshot{}, n, ErrNeedsFileMigration
		}
		if r.PublicID != "" {
			if !identity.ValidPublicID(r.PublicID) || publicIDs[r.PublicID] {
				return Snapshot{}, n, fmt.Errorf("invalid or duplicate stored access public ID")
			}
			publicIDs[r.PublicID] = true
		}
		hashes[r.SecretHash] = true
		if r.Kind == "mcp" && r.EndedAt.IsZero() {
			r.EndedAt = now
			r.UpdatedAt = now
			n.EndedMCPSessions++
		}
		owners[r.Owner] = true
		snap.Access = append(snap.Access, r)
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, e := range state.Entries {
		if e.ID == "" {
			return Snapshot{}, n, ErrNeedsFileMigration
		}
		if ids[e.ID] || names[keyFor(e.Owner, e.Name)] {
			return Snapshot{}, n, fmt.Errorf("duplicate stored upstream")
		}
		if err := Validate(e); err != nil {
			return Snapshot{}, n, fmt.Errorf("stored upstream %s: %w", e.Name, err)
		}
		if _, deleted := snap.Deleted[e.ID]; deleted {
			return Snapshot{}, n, fmt.Errorf("stored upstream is also a tombstone")
		}
		ids[e.ID], names[keyFor(e.Owner, e.Name)] = true, true
		owners[e.Owner] = true
		snap.Entries = append(snap.Entries, e)
	}
	byHash := map[string]string{}
	for owner := range owners {
		byHash[fmt.Sprintf("%x", sha256.Sum256([]byte(owner)))] = owner
	}
	resolve := func(key string) (ProviderKey, error) {
		if len(key) < 66 || key[64] != '/' {
			return ProviderKey{}, fmt.Errorf("invalid stored provider key")
		}
		owner, ok := byHash[key[:64]]
		if !ok {
			return ProviderKey{}, fmt.Errorf("provider settings belong to an owner with no account, key or connection")
		}
		return ProviderKey{Owner: owner, Provider: key[65:]}, nil
	}
	for key, d := range state.Discovery {
		k, err := resolve(key)
		if err != nil {
			return Snapshot{}, n, err
		}
		snap.Discovery[k] = d
	}
	for key, v := range state.Visibility {
		if v.Mode != "all" && v.Mode != "selected" {
			return Snapshot{}, n, fmt.Errorf("invalid stored tool visibility")
		}
		k, err := resolve(key)
		if err != nil {
			return Snapshot{}, n, err
		}
		snap.Visibility[k] = v
	}
	snap.sort()
	return snap, n, nil
}

func (s *Snapshot) sort() {
	sort.Slice(s.Accounts, func(i, j int) bool { return s.Accounts[i].Username < s.Accounts[j].Username })
	sort.Slice(s.Access, func(i, j int) bool { return s.Access[i].ID < s.Access[j].ID })
	sort.Slice(s.Entries, func(i, j int) bool { return s.Entries[i].ID < s.Entries[j].ID })
}

// Canonical returns a stable encoding used to compare two snapshots field by
// field. It contains secrets and must only be hashed or compared in memory.
func (s Snapshot) Canonical() ([]byte, error) {
	s.sort()
	type provider struct {
		Owner      string      `json:"owner"`
		Provider   string      `json:"provider"`
		Discovery  *Discovery  `json:"discovery,omitempty"`
		Visibility *Visibility `json:"visibility,omitempty"`
	}
	merged := map[ProviderKey]*provider{}
	for k, d := range s.Discovery {
		d := d
		merged[k] = &provider{Owner: k.Owner, Provider: k.Provider, Discovery: &d}
	}
	for k, v := range s.Visibility {
		v := v
		if p := merged[k]; p != nil {
			p.Visibility = &v
		} else {
			merged[k] = &provider{Owner: k.Owner, Provider: k.Provider, Visibility: &v}
		}
	}
	providers := make([]*provider, 0, len(merged))
	for _, p := range merged {
		providers = append(providers, p)
	}
	sort.Slice(providers, func(i, j int) bool {
		if providers[i].Owner == providers[j].Owner {
			return providers[i].Provider < providers[j].Provider
		}
		return providers[i].Owner < providers[j].Owner
	})
	return jsoncodec.Marshal(struct {
		Accounts  []Account            `json:"accounts"`
		Access    []AccessRecord       `json:"access"`
		Entries   []Entry              `json:"entries"`
		Deleted   map[string]Lifecycle `json:"deleted"`
		Providers []*provider          `json:"providers"`
	}{s.Accounts, s.Access, s.Entries, s.Deleted, providers})
}

// WriteSnapshot writes a complete catalog file for a PostgreSQL rollback. It
// replaces path atomically and syncs the directory before returning.
func WriteSnapshot(path, encodedKey string, snap Snapshot) error {
	aead, err := newAEAD(encodedKey)
	if err != nil {
		return err
	}
	state := diskState{Access: map[string]AccessRecord{}, Deleted: map[string]Lifecycle{}, Accounts: map[string]Account{}, Entries: []Entry{},
		Discovery: map[string]Discovery{}, Visibility: map[string]Visibility{}, Rollback: snap.Rollback}
	for _, a := range snap.Accounts {
		state.Accounts[a.Username] = a
	}
	for _, r := range snap.Access {
		state.Access[r.ID] = r
	}
	state.Entries = append(state.Entries, snap.Entries...)
	sort.Slice(state.Entries, func(i, j int) bool {
		if state.Entries[i].Owner == state.Entries[j].Owner {
			return state.Entries[i].Name < state.Entries[j].Name
		}
		return state.Entries[i].Owner < state.Entries[j].Owner
	})
	for id, l := range snap.Deleted {
		state.Deleted[id] = l
	}
	for k, d := range snap.Discovery {
		state.Discovery[keyFor(k.Owner, k.Provider)] = d
	}
	for k, v := range snap.Visibility {
		state.Visibility[keyFor(k.Owner, k.Provider)] = v
	}
	plain, err := jsoncodec.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode managed upstreams failed")
	}
	defer clear(plain)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("create credential nonce: %w", err)
	}
	if err := writeEncrypted(path, aead.Seal(nonce, nonce, plain, nil)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
