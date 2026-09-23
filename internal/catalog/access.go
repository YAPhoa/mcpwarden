package catalog

import (
	"crypto/subtle"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

// Lifecycle records real creation/change/use/revocation times. Legacy creation
// times remain unknown rather than inventing historical timestamps.
const MaxAPIKeys = 10
const MaxLoginSessions = 10
const MaxMCPSessions = 10

type Lifecycle struct {
	EndedAt    time.Time `json:"ended_at,omitzero"`
	CreatedAt  time.Time `json:"created_at,omitzero"`
	UpdatedAt  time.Time `json:"updated_at,omitzero"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	RevokedAt  time.Time `json:"revoked_at,omitzero"`
	DeletedAt  time.Time `json:"deleted_at,omitzero"`
}

func (l *Lifecycle) touch() {
	now := time.Now().UTC()
	if l.CreatedAt.IsZero() {
		l.CreatedAt = now
	}
	l.UpdatedAt = now
}

type AccessRecord struct {
	Device   string `json:"device,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	Lifecycle
	ID         string    `json:"id"`
	PublicID   string    `json:"public_id,omitempty"`
	Owner      string    `json:"owner"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"` // api_key, browser, oauth
	Role       string    `json:"role"` // admin or client
	SecretHash string    `json:"secret_hash,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
}

func (r AccessRecord) Active() bool {
	return r.EndedAt.IsZero() && r.RevokedAt.IsZero() && r.DeletedAt.IsZero() && (r.ExpiresAt.IsZero() || r.ExpiresAt.After(time.Now()))
}
func (s *Store) AddAccess(r AccessRecord) error {
	if r.Owner == "" || r.SecretHash == "" || len(strings.TrimSpace(r.Name)) == 0 || len(r.Name) > 100 || (r.Role != "admin" && r.Role != "client") || (r.Kind != "api_key" && r.Kind != "browser" && r.Kind != "oauth" && r.Kind != "mcp") {
		return fmt.Errorf("invalid access credential")
	}
	if r.ID == "" {
		r.ID = identity.New()
	}
	if r.Kind == "api_key" && r.PublicID == "" {
		r.PublicID = identity.NewPublicID()
	}
	if r.PublicID != "" && !identity.ValidPublicID(r.PublicID) {
		return fmt.Errorf("invalid access public ID")
	}
	r.touch()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.access[r.ID]; exists {
		return fmt.Errorf("credential already exists")
	}
	for _, old := range s.access {
		if old.SecretHash == r.SecretHash || r.PublicID != "" && old.PublicID == r.PublicID {
			return fmt.Errorf("credential already exists")
		}
	}
	if err := s.accessLimit(r.Owner, r.Kind); err != nil {
		return err
	}
	s.access[r.ID] = r
	if err := s.save(); err != nil {
		delete(s.access, r.ID)
		return err
	}
	return nil
}
func (s *Store) AccessList(owner string) []AccessRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []AccessRecord{}
	for _, r := range s.access {
		if r.Owner == owner {
			r.SecretHash = ""
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (s *Store) AccessByID(owner, id string) (AccessRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.access[id]
	r.SecretHash = ""
	if !ok || r.Owner != owner {
		return AccessRecord{}, false
	}
	return r, true
}
func (s *Store) AuthenticateAccess(hash, kind string) (AccessRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.access {
		if subtle.ConstantTimeCompare([]byte(r.SecretHash), []byte(hash)) != 1 || r.Kind != kind || !r.Active() {
			continue
		}
		if time.Since(r.LastUsedAt) >= time.Minute {
			old := r
			r.LastUsedAt = time.Now().UTC()
			s.access[id] = r
			if err := s.save(); err != nil {
				s.access[id] = old
				return AccessRecord{}, false
			}
		}
		r.SecretHash = ""
		return r, true
	}
	return AccessRecord{}, false
}
func (s *Store) RevokeAccess(owner, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.access[id]
	if !ok || r.Owner != owner {
		return fmt.Errorf("credential not found")
	}
	if !r.RevokedAt.IsZero() {
		return nil
	}
	old := r
	r.RevokedAt = time.Now().UTC()
	r.UpdatedAt = r.RevokedAt
	s.access[id] = r
	if err := s.save(); err != nil {
		s.access[id] = old
		return err
	}
	return nil
}

// ObserveOAuth registers only tokens already validated by the external issuer.
// Revoked hashes remain blocked if the issuer still considers the token active.
func (s *Store) ObserveOAuth(owner, hash, role string, expires time.Time, device ...string) (AccessRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.access {
		if r.Kind != "oauth" || r.SecretHash != hash {
			continue
		}
		if r.Owner != owner || !r.Active() {
			return AccessRecord{}, fmt.Errorf("OAuth access revoked")
		}
		old := r
		r.Role = role
		r.ExpiresAt = expires
		if time.Since(r.LastUsedAt) >= time.Minute || r.Role != old.Role {
			r.LastUsedAt = time.Now().UTC()
			r.UpdatedAt = r.LastUsedAt
			s.access[id] = r
			if err := s.save(); err != nil {
				s.access[id] = old
				return AccessRecord{}, err
			}
		}
		r.SecretHash = ""
		return r, nil
	}
	if err := s.accessLimit(owner, "oauth"); err != nil {
		return AccessRecord{}, err
	}
	r := AccessRecord{ID: identity.New(), Owner: owner, Name: "OAuth access", Kind: "oauth", Role: role, SecretHash: hash, ExpiresAt: expires}
	if len(device) > 0 {
		r.Device = device[0]
		if len(r.Device) > 300 {
			r.Device = r.Device[:300]
		}
	}
	r.touch()
	r.LastUsedAt = r.CreatedAt
	s.access[r.ID] = r
	if err := s.save(); err != nil {
		delete(s.access, r.ID)
		return AccessRecord{}, err
	}
	r.SecretHash = ""
	return r, nil
}

func (s *Store) accessLimit(owner, kind string) error {
	count := 0
	limit := MaxLoginSessions
	if kind == "api_key" {
		limit = MaxAPIKeys
	}
	if kind == "mcp" {
		limit = MaxMCPSessions
	}
	for _, r := range s.access {
		same := r.Kind == kind
		if kind == "browser" || kind == "oauth" {
			same = r.Kind == "browser" || r.Kind == "oauth"
		}
		if r.Owner == owner && same && r.Active() {
			count++
		}
	}
	if count >= limit {
		return fmt.Errorf("active %s limit reached (%d)", kind, limit)
	}
	return nil
}
func (s *Store) UpdateAccess(owner, id, name string, end bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.access[id]
	if !ok || r.Owner != owner {
		return fmt.Errorf("session not found")
	}
	old := r
	if name != "" {
		if len(name) > 100 {
			return fmt.Errorf("name too long")
		}
		r.Name = name
	}
	if end {
		r.EndedAt = time.Now().UTC()
	}
	r.UpdatedAt = time.Now().UTC()
	s.access[id] = r
	if err := s.save(); err != nil {
		s.access[id] = old
		return err
	}
	return nil
}
func (s *Store) TouchAccess(owner, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.access[id]
	if !ok || r.Owner != owner || !r.Active() {
		return fmt.Errorf("access revoked or expired")
	}
	if time.Since(r.LastUsedAt) < time.Minute {
		return nil
	}
	old := r
	r.LastUsedAt = time.Now().UTC()
	s.access[id] = r
	if err := s.save(); err != nil {
		s.access[id] = old
		return err
	}
	return nil
}
func (s *Store) AccountOwner(owner string) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts {
		if a.ID == owner {
			return Account{ID: a.ID, Username: a.Username}, true
		}
	}
	return Account{}, false
}
