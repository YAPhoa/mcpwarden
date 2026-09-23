package lease

import (
	"context"
	"time"
)

// LeaseView reports durable lease metadata together with this executor's own
// runtime state. A durable active row alone never means execution is possible.
type LeaseView struct {
	Lease
	RuntimeAvailable bool `json:"runtime_available"`
	InFlight         int  `json:"in_flight"`
}

// View is a read-only owner snapshot of live and recent requests plus active
// leases. Reading never activates, renews, expires or repairs durable state.
type View struct {
	Now      time.Time
	BootID   string
	Requests []Request
	Leases   []LeaseView
}

// reported returns the state a caller should see. Pending or approved rows that
// have passed a deadline or belong to an older boot cannot be acted on, even
// before the next mutation persists their terminal state.
func (s *Service) reported(r Request, now time.Time) Request {
	if r.State != "pending" && r.State != "approved" {
		return r
	}
	switch {
	case r.BootID != s.boot:
		r.State = "stale"
	case !now.Before(r.ExpiresAt), r.State == "approved" && !now.Before(r.ActivationDeadline):
		r.State = "expired"
	}
	return r
}

func (s *Service) read(ctx context.Context, owner string, fn func(Tx, *ownerState) error) error {
	if owner == "" || len(owner) > 512 {
		return ErrDenied
	}
	o := s.state(owner)
	o.mu.Lock()
	defer o.mu.Unlock()
	if s.stopped() {
		return ErrLocked
	}
	return s.store.WithOwner(ctx, owner, func(tx Tx) error { return fn(tx, o) })
}

// View returns the owner's live and recent requests and active leases. Callers
// must authorize the owner and filter the result for non-owner viewers.
func (s *Service) View(ctx context.Context, owner string) (View, error) {
	out := View{BootID: s.boot}
	err := s.read(ctx, owner, func(tx Tx, o *ownerState) error {
		out.Now = tx.Now()
		requests, err := tx.Requests()
		if err != nil {
			return err
		}
		for _, r := range requests {
			out.Requests = append(out.Requests, s.reported(r, tx.Now()))
		}
		leases, err := tx.Leases()
		if err != nil {
			return err
		}
		for _, l := range leases {
			v := LeaseView{Lease: l}
			if rt := o.live[l.ID]; rt != nil {
				v.RuntimeAvailable = !o.blocked && s.live(rt, tx.Now())
				v.InFlight = rt.inflight
			}
			out.Leases = append(out.Leases, v)
		}
		return nil
	})
	if err != nil {
		return View{}, err
	}
	return out, nil
}

// LookupRequest reads one owner-scoped request in any state. Another owner's
// request ID is indistinguishable from an unknown ID.
func (s *Service) LookupRequest(ctx context.Context, owner, id string) (Request, error) {
	var out Request
	err := s.read(ctx, owner, func(tx Tx, _ *ownerState) error {
		r, err := tx.Request(id)
		if err != nil {
			return err
		}
		out = s.reported(r, tx.Now())
		return nil
	})
	return out, err
}
