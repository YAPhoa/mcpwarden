package catalog

import (
	"time"
)

// Hard limits on an owner's active credentials of each kind.
const (
	MaxAPIKeys       = 10
	MaxLoginSessions = 10
	MaxMCPSessions   = 10
)

// Lifecycle records real creation, change, use and revocation times.
type Lifecycle struct {
	EndedAt    time.Time `json:"ended_at,omitzero"`
	CreatedAt  time.Time `json:"created_at,omitzero"`
	UpdatedAt  time.Time `json:"updated_at,omitzero"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	RevokedAt  time.Time `json:"revoked_at,omitzero"`
	DeletedAt  time.Time `json:"deleted_at,omitzero"`
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
