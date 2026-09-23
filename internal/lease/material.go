package lease

import (
	"context"
	"crypto/sha256"
	"reflect"
	"sort"
	"sync"

	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

type useKey struct{}
type materialUse struct {
	material      Material
	ctx           context.Context // SDK-detached contexts must still observe this lifetime.
	phase         string
	argumentsHash [32]byte
	check         func() error
	mu            sync.Mutex
	claimed       bool
}

func withUse(ctx context.Context, material Material, phase string, hash [32]byte, check func() error) context.Context {
	return context.WithValue(ctx, useKey{}, &materialUse{material: material, ctx: ctx, phase: phase, argumentsHash: hash, check: check})
}

// CheckUse checks the original callback lifetime, both clocks, current caller,
// policy, epoch and material revision. A transport may only use the returned
// phase to allow its finite maintenance RPCs or the single admitted tool call.
func CheckUse(ctx context.Context, material Material) (string, error) {
	u, ok := ctx.Value(useKey{}).(*materialUse)
	if !ok || material == nil || !reflect.TypeOf(material).Comparable() || u.material != material {
		return "", ErrDenied
	}
	if ctx.Err() != nil || u.ctx.Err() != nil {
		return "", ErrStale
	}
	if err := u.check(); err != nil {
		return "", err
	}
	return u.phase, nil
}

// ClaimCall prevents SDK/HTTP retries from forwarding tools/call twice through
// one admission. Failed/ambiguous network attempts are never refunded.
func ClaimCall(ctx context.Context, material Material, arguments []byte) error {
	phase, err := CheckUse(ctx, material)
	if err != nil {
		return err
	}
	if phase != "call" {
		return ErrDenied
	}
	argumentsHash, err := argumentBinding(arguments)
	if err != nil {
		return ErrDenied
	}
	u := ctx.Value(useKey{}).(*materialUse)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.claimed || u.argumentsHash != argumentsHash {
		return ErrDenied
	}
	u.claimed = true
	return nil
}

// This ephemeral dispatch binding preserves exact JSON number tokens. Legacy
// audit.HashArgs intentionally retains float64 compatibility and is unsuitable
// for binding wire arguments: large distinct integers can share its audit hash.
// This is neither the persisted audit hash nor the RFC 8785 approval scope hash.
func argumentBinding(raw []byte) ([32]byte, error) {
	if json.Validate(raw, MaxArgumentBytes, 64) != nil {
		return [32]byte{}, ErrDenied
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return [32]byte{}, ErrDenied
	}
	if _, ok := value.(map[string]any); !ok {
		return [32]byte{}, ErrDenied
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, ErrDenied
	}
	defer clear(encoded)
	return sha256.Sum256(encoded), nil
}

func (s *Service) useCheck(ctx context.Context, o *ownerState, rt *runtimeLease, r Request) func() error {
	return func() error {
		o.mu.Lock()
		defer o.mu.Unlock()
		if ctx.Err() != nil {
			return ErrStale
		}
		if s.stopped() || o.blocked || s.uncertain(o) {
			block(o)
			return ErrLocked
		}
		if !s.live(rt, s.opts.Clock.Wall()) {
			return ErrStale
		}
		k, _, err := s.current(r.Scope, s.opts.Clock.Wall())
		if err != nil || k.Revision != rt.revision || r.Mode != k.ApprovalMode || r.ApprovalPolicyRevision != k.ApprovalPolicyRevision {
			return ErrStale
		}
		return nil
	}
}

// Prepare lends material for bounded connection setup before final admission.
// It requires one live tool-use lease covering the entire proposed call, counts
// against caller concurrency, and consumes no call budget. It cannot send a tool
// call. The returned lease ID is metadata, not a credential or reusable permit.
// Call AdmitPrepared immediately afterward; it repeats authorization and commits
// the budget/admission before any tool side effect. No owner gate spans I/O.
func (s *Service) Prepare(ctx context.Context, credentialID, toolID, definition string, args []byte, fn func(context.Context, Material) error) (string, error) {
	a, ok := identity.ActorFrom(ctx)
	if !ok || fn == nil {
		return "", ErrDenied
	}
	var permit *Admission
	var selected string
	err := s.transition(ctx, a.Owner, func(tx Tx, o *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), false)
		if err != nil || actor.Kind != "api_key" {
			return ErrDenied
		}
		if o.inflight[actor.AccessID] >= s.opts.MaxConcurrent {
			return ErrBusy
		}
		leases, err := tx.Leases()
		if err != nil {
			return err
		}
		sort.Slice(leases, func(i, j int) bool {
			if leases[i].ExpiresAt.Equal(leases[j].ExpiresAt) {
				return leases[i].ID < leases[j].ID
			}
			return leases[i].ExpiresAt.Before(leases[j].ExpiresAt)
		})
		for _, l := range leases {
			rt := o.live[l.ID]
			if l.CallerID != actor.AccessID || l.CredentialID != credentialID || l.State != "active" || l.MaxCalls != nil && l.AdmittedCalls >= *l.MaxCalls || !s.live(rt, tx.Now()) {
				continue
			}
			r, err := tx.Request(l.RequestID)
			if err != nil {
				return err
			}
			k, _, err := s.current(r.Scope, tx.Now())
			if err != nil || rt.revision != k.Revision || r.Mode != k.ApprovalMode || r.ApprovalPolicyRevision != k.ApprovalPolicyRevision || !r.Scope.Matches(toolID, definition, args) {
				continue
			}
			selected = l.ID
			callCtx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(rt.ctx, cancel)
			permit = &Admission{material: rt.material}
			permit.start = s.useCheck(callCtx, o, rt, r)
			permit.ctx = withUse(callCtx, rt.material, "prepare", [32]byte{}, permit.start)
			reserved := false
			permit.done = func() {
				stop()
				cancel()
				o.mu.Lock()
				defer o.mu.Unlock()
				if !reserved {
					return
				}
				reserved = false
				rt.inflight--
				o.inflight[actor.AccessID]--
				if rt.ended && rt.inflight == 0 && rt.material != nil {
					rt.material.Destroy()
					rt.material = nil
				}
			}
			o.publish = append(o.publish, func() error {
				if !s.live(rt, s.opts.Clock.Wall()) || callCtx.Err() != nil {
					return ErrStale
				}
				rt.inflight++
				o.inflight[actor.AccessID]++
				reserved = true
				return nil
			})
			return nil
		}
		return ErrRequired
	})
	if err != nil {
		if permit != nil {
			permit.done()
		}
		return "", err
	}
	if err := permit.RunWithMaterial(fn); err != nil {
		return "", err
	}
	return selected, nil
}
