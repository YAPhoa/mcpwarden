package lease

import (
	"context"
	"errors"
	"fmt"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

// errSetupEnded refuses to save a discovery whose setup window is no longer
// active and current. The owner transaction returns it before COMMIT, so the
// catalog change is rolled back.
var errSetupEnded = fmt.Errorf("%w: %w", ErrRolledBack, ErrStale)

// Setup runs one connector discovery ("Connect and inspect") under a live
// setup_discovery window. Only the owner's browser session that requested and
// activated the window may run it, and only once. The material is lent in
// phase "setup", in which a credential transport forwards only connection
// setup and tools/list; no tool call is ever admitted.
//
// discover talks to the upstream. save commits the result through CatalogSetup,
// which ends the window in the same transaction and refuses the save if the
// window ended or changed meanwhile. When discover or save fails,
// the window is revoked. Either way, the window ends after this one run.
func (s *Service) Setup(ctx context.Context, leaseID string, discover func(context.Context, Material) error, save func() error) error {
	a, ok := identity.ActorFrom(ctx)
	if !ok || !validID(leaseID) || discover == nil || save == nil {
		return ErrDenied
	}
	var permit *Admission
	err := s.transition(ctx, a.Owner, func(tx Tx, o *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), true)
		if err != nil {
			return err
		}
		l, err := tx.Lease(leaseID)
		if err != nil {
			return err
		}
		r, err := tx.Request(l.RequestID)
		if err != nil {
			return err
		}
		if r.Scope.Purpose != "setup_discovery" || l.CallerID != actor.AccessID || l.ActivationActorID != actor.AccessID {
			return ErrDenied
		}
		rt := o.live[l.ID]
		if l.State != "active" || !s.live(rt, tx.Now()) || rt.setupUsed {
			return ErrStale
		}
		k, _, err := s.current(r.Scope, tx.Now())
		if err != nil || rt.revision != k.Revision || r.Mode != k.ApprovalMode || r.ApprovalPolicyRevision != k.ApprovalPolicyRevision {
			return ErrStale
		}
		if o.inflight[actor.AccessID] >= s.opts.MaxConcurrent {
			return ErrBusy
		}
		callCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(rt.ctx, cancel)
		permit = &Admission{material: rt.material}
		permit.start = s.useCheck(callCtx, o, rt, r)
		permit.ctx = withUse(callCtx, rt.material, "setup", [32]byte{}, permit.start)
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
			if !s.live(rt, s.opts.Clock.Wall()) || rt.setupUsed || callCtx.Err() != nil {
				return ErrStale
			}
			rt.setupUsed = true
			rt.inflight++
			o.inflight[actor.AccessID]++
			reserved = true
			return nil
		})
		return nil
	})
	if err != nil {
		if permit != nil {
			permit.done()
		}
		return err
	}
	err = permit.RunWithMaterial(discover)
	if err == nil {
		err = save()
	}
	if err != nil {
		s.failSetup(ctx, leaseID)
	}
	return err
}

// failSetup revokes a setup window whose discovery did not save. A window that
// already ended is left as it is.
func (s *Service) failSetup(ctx context.Context, leaseID string) {
	ctx = context.WithoutCancel(ctx) // reducing access is never lost to a closed tab
	a, _ := identity.ActorFrom(ctx)
	_ = s.transition(ctx, a.Owner, func(tx Tx, o *ownerState) error {
		l, err := tx.Lease(leaseID)
		if err != nil {
			return err
		}
		return s.revoke(tx, o, a.Owner, l, a.AccessID, "setup_failed")
	})
}

// endSetup ends the setup window named by a CatalogSetup change in the change's
// own transaction. It refuses, rolling the change back, unless the window is
// active, live, current and has run its discovery for this connector.
func (s *Service) endSetup(tx Tx, o *ownerState, e SetupEnd) (string, error) {
	l, err := tx.Lease(e.LeaseID)
	if errors.Is(err, ErrNotFound) {
		return "", errSetupEnded
	}
	if err != nil {
		return "", err
	}
	r, err := tx.Request(l.RequestID)
	if err != nil {
		return "", err
	}
	rt := o.live[l.ID]
	if l.State != "active" || r.Scope.Purpose != "setup_discovery" || r.Scope.ConnectorID != e.ConnectorID || !s.live(rt, tx.Now()) || !rt.setupUsed {
		return "", errSetupEnded
	}
	k, _, err := s.current(r.Scope, tx.Now())
	if err != nil || rt.revision != k.Revision || r.Mode != k.ApprovalMode || r.ApprovalPolicyRevision != k.ApprovalPolicyRevision {
		return "", errSetupEnded
	}
	l.State, l.EndedAt = "revoked", tx.Now()
	if err := tx.PutLease(l); err != nil {
		return "", err
	}
	if err := s.event(tx, l.OwnerID, "lease.revoked", l.CallerID, l.RequestID, l.ID, "setup_completed"); err != nil {
		return "", err
	}
	return l.ID, nil
}
