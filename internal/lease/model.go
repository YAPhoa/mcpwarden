package lease

import (
	"context"
	"errors"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

var (
	ErrDenied   = errors.New("access window denied")
	ErrNotFound = errors.New("access window not found")
	ErrStale    = errors.New("access window expired or stale")
	ErrRequired = errors.New("access window required")
	ErrBusy     = errors.New("caller concurrency limit reached")
	ErrStorage  = errors.New("security storage unavailable; execution locked")
	ErrLocked   = errors.New("execution is locked")
	ErrLimit    = errors.New("access request limit reached")
	ErrKey      = errors.New("credential activation failed")
	// ErrRolledBack wraps the caller's context error when a transaction was
	// abandoned before COMMIT: nothing was committed. A failed ROLLBACK still
	// fails the store, which Lost reports.
	ErrRolledBack = errors.New("transaction rolled back before commit")
)

// Binding is immutable after creation. The store must reject substitutions,
// including changes to the mode, revision, duration, challenge or scope digest.
type Binding struct {
	ID                     string    `json:"id"`
	BootID                 string    `json:"boot_id"`
	Scope                  Scope     `json:"scope"`
	ScopeDigest            string    `json:"scope_digest"`
	RequestDigest          string    `json:"request_digest"`
	Nonce                  string    `json:"nonce"`
	Mode                   string    `json:"mode"`
	VerificationMethod     string    `json:"verification_method"`
	ApprovalPolicyRevision string    `json:"approval_policy_revision"`
	CreatedAt              time.Time `json:"created_at"`
	ExpiresAt              time.Time `json:"expires_at"`
}

// Valid authenticates the durable request's structure and immutable digest.
// It validates metadata, not a browser identity or possession of a credential key.
func (b Binding) Valid() bool {
	if !validID(b.ID) || !validID(b.BootID) || !validDigest(b.Nonce) || !validVersion(b.ApprovalPolicyRevision) || (b.Mode != "none" && b.Mode != "confirm") || b.VerificationMethod != "none" || b.CreatedAt.IsZero() || !b.ExpiresAt.After(b.CreatedAt) || b.ExpiresAt.Sub(b.CreatedAt) > 5*time.Minute {
		return false
	}
	raw, err := json.Marshal(b.Scope)
	if err != nil {
		return false
	}
	_, hash, err := ParseScope(raw)
	if err != nil || hash != b.ScopeDigest {
		return false
	}
	want := b.RequestDigest
	b.RequestDigest = ""
	raw, err = json.Marshal(b)
	if err != nil {
		return false
	}
	raw, err = canonical(raw, MaxScopeBytes+4096)
	return err == nil && digest(raw) == want
}

type Request struct {
	Binding
	State               string    `json:"state"`
	DecidedAt           time.Time `json:"decided_at,omitzero"`
	ActivationDeadline  time.Time `json:"activation_deadline,omitzero"`
	ApproverID          string    `json:"approver_id,omitempty"`
	AuthorizationSource string    `json:"authorization_source,omitempty"`
	LeaseID             string    `json:"lease_id,omitempty"`
}

type Lease struct {
	ID                string    `json:"id"`
	OwnerID           string    `json:"owner_id"`
	RequestID         string    `json:"request_id"`
	CallerID          string    `json:"caller_id"`
	CredentialID      string    `json:"credential_id"`
	Epoch             string    `json:"epoch"`
	BootID            string    `json:"boot_id"`
	ScopeDigest       string    `json:"scope_digest"`
	State             string    `json:"state"`
	ActivatedAt       time.Time `json:"activated_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	EndedAt           time.Time `json:"ended_at,omitzero"`
	MaxCalls          *int64    `json:"max_calls"`
	AdmittedCalls     int64     `json:"admitted_calls"`
	ActivationActorID string    `json:"activation_actor_id"`
	OperationID       string    `json:"operation_id"`
}

// Event is an allowlisted metadata record; it cannot carry key bytes, arbitrary
// arguments, provider errors or generic logging attributes.
type Event struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Type      string    `json:"type"`
	At        time.Time `json:"at"`
	BootID    string    `json:"boot_id"`
	ActorID   string    `json:"actor_id,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	LeaseID   string    `json:"lease_id,omitempty"`
	Source    string    `json:"source,omitempty"`
	// Owner-route events identify the changed record by public version metadata
	// and an allowlisted reason code, never by payload, key or provider error.
	CredentialID string `json:"credential_id,omitempty"`
	Epoch        string `json:"epoch,omitempty"`
	Revision     string `json:"revision,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Reason       string `json:"reason,omitempty"`
	// Catalog events name the changed account, access record or connector.
	SubjectID string `json:"subject_id,omitempty"`
}

// Store implementations must commit all Tx writes together, then return success.
// No callback may be retried automatically. On an ambiguous commit, return an
// error and close Lost; never publish activation or permit dispatch. Start holds
// exclusive executor ownership and suspends prior boots before admitting work.
type Store interface {
	Start(context.Context, string) error
	// WithOwner runs fn in one owner transaction. When the caller's context
	// ends before fn runs, it returns the bare context error and nothing ran;
	// when it ends after fn but before COMMIT, it returns that error wrapped
	// in ErrRolledBack and nothing is committed. The catalog relies on both.
	WithOwner(context.Context, string, func(Tx) error) error
	Lost() <-chan struct{}
}

type Tx interface {
	// Now is the actual UTC clock sampled AFTER acquiring the owner row lock.
	Now() time.Time
	Request(string) (Request, error)
	Requests() ([]Request, error) // live requests and creations in the last minute
	PutRequest(Request) error
	Lease(string) (Lease, error)
	Leases() ([]Lease, error) // active leases for this owner
	PutLease(Lease) error
	Event(Event) error
	Admission(audit.Record) error
}

type Caller struct {
	identity.Actor
	Active      bool
	ExpiresAt   time.Time
	Interactive bool // set only for an authenticated local-account browser session
}

type Tool struct {
	ID, DefinitionDigest string
	Allowed, Visible     bool
}
type Credential struct {
	ID, ConnectorID, Epoch, Revision, DestinationDigest                             string
	PolicyRevision, ConnectorSecurityRevision, ApprovalPolicyRevision, ApprovalMode string
	Enabled                                                                         bool
	Tools                                                                           map[string]Tool
}

// Authority supplies a coherent, current metadata snapshot. Its security writes
// MUST use Service.Change under the same owner coordinator; it cannot perform
// network calls, secret resolution, or interactive approval in these callbacks.
type Authority interface {
	Caller(owner, accessID string) (Caller, bool)
	Credential(owner, credentialID string) (Credential, bool)
}

// Material is deliberately opaque and non-serializable. A reviewed runtime may
// add constrained transport operations, but no API should return key bytes.
type Material interface{ Destroy() }
type Activator interface {
	// Stage must authenticate the CURRENT encrypted record against reconstructed
	// expected AAD. It performs local bounded crypto only, never provider I/O.
	// Returned material owns its buffers; the service clears the supplied key.
	Stage(context.Context, string, Credential, []byte) (Material, error)
}

type ActivationInput struct {
	RequestID, RequestDigest, OperationID string
	Key                                   []byte `json:"-"`
}

func (ActivationInput) String() string   { return "[credential activation]" }
func (ActivationInput) GoString() string { return "[credential activation]" }

// Clock keeps wall and monotonic measurements distinct. Serializing time.Time
// would lose the monotonic component; store only the wall deadline durably.
type Clock interface {
	Wall() time.Time
	Mono() time.Duration
}
type realClock struct{ start time.Time }

func (c realClock) Wall() time.Time     { return time.Now().UTC() }
func (c realClock) Mono() time.Duration { return time.Since(c.start) }

type Options struct {
	RequestTTL, ActivationTTL, MaxTTL, ClockTolerance time.Duration
	MaxConcurrent, MaxPending, RequestsPerMinute      int
	Clock                                             Clock
}

func DefaultOptions() Options {
	return Options{RequestTTL: 5 * time.Minute, ActivationTTL: time.Minute, MaxTTL: time.Hour,
		ClockTolerance: 5 * time.Second, MaxConcurrent: 4, MaxPending: 32, RequestsPerMinute: 64}
}
