package lease

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOwnerMutationExpiryRollsBackWritesAndRevocation(t *testing.T) {
	h := newHarness(t, "none", nil)
	active := h.activate(t)
	pending := h.request(t)
	h.authority.mu.Lock()
	browser := h.authority.callers[browserID]
	browser.ExpiresAt = h.clock.Wall().Add(time.Second)
	h.authority.callers[browserID] = browser
	h.authority.mu.Unlock()
	before := h.store.snapshot()
	published := false
	err := h.service.ChangeOwnerAtomic(h.browser, func(tx Tx) (func() error, error) {
		if err := tx.Event(Event{Type: "credential.rotated"}); err != nil {
			return nil, err
		}
		h.clock.advance(2 * time.Second)
		return func() error { published = true; return nil }, nil
	})
	after := h.store.snapshot()
	if err != ErrDenied || published || len(after.Events) != len(before.Events) ||
		after.Leases[active.ID].State != "active" || after.Requests[pending.ID].State != "pending" {
		t.Fatalf("expired mutation committed writes, revocation or publication: err=%v, published=%v", err, published)
	}
	admission, err := h.admit(h.caller, `{}`)
	if err != nil {
		t.Fatalf("rolled-back mutation ended the approved agent window: %v", err)
	}
	if err := admission.Run(func(_ context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRevocationWaitsForOwnerCommitAndPublication(t *testing.T) {
	for _, phase := range []string{"commit", "publication"} {
		t.Run(phase, func(t *testing.T) {
			h := newHarness(t, "none", nil)
			entered, resume := make(chan struct{}), make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(resume) })
			pause := func() { close(entered); <-resume }
			if phase == "commit" {
				h.store.beforeCommit = pause
			}
			var published atomic.Bool
			changed := make(chan error, 1)
			go func() {
				changed <- h.service.ChangeOwnerAtomic(h.browser, func(tx Tx) (func() error, error) {
					if err := tx.Event(Event{Type: "credential.rotated"}); err != nil {
						return nil, err
					}
					return func() error {
						if phase == "publication" {
							pause()
						}
						published.Store(true)
						return nil
					}, nil
				})
			}()
			<-entered
			attempted, revoked := make(chan struct{}), make(chan error, 1)
			go func() {
				close(attempted)
				revoked <- h.service.ChangeSessions(t.Context(), "alice", func() error {
					if !published.Load() {
						return ErrStale
					}
					h.authority.mu.Lock()
					defer h.authority.mu.Unlock()
					browser := h.authority.callers[browserID]
					browser.Active = false
					h.authority.callers[browserID] = browser
					return nil
				})
			}()
			<-attempted
			select {
			case err := <-revoked:
				t.Fatalf("session revocation passed the paused %s: %v", phase, err)
			case <-time.After(50 * time.Millisecond):
			}
			release.Do(func() { close(resume) })
			if err := <-changed; err != nil {
				t.Fatal(err)
			}
			if err := <-revoked; err != nil {
				t.Fatal(err)
			}
			if err := h.service.ChangeOwnerAtomic(h.browser, func(Tx) (func() error, error) {
				t.Error("revoked session reached the mutation")
				return nil, nil
			}); err != ErrDenied {
				t.Fatalf("revoked session authorized after commit: %v", err)
			}
		})
	}
}
