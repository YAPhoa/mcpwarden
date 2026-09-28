package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// A caller that has gone gets its context error and commits nothing; the
// executor keeps running.
func testCancelledCallerCommitsNothing(t *testing.T, db Database) {
	s := started(t, db)
	gone, cancel := context.WithCancel(t.Context())
	cancel()
	ran := false
	if err := s.WithOwner(gone, "early", func(lease.Tx) error { ran = true; return nil }); !errors.Is(err, context.Canceled) || ran {
		t.Fatal("an already-cancelled caller ran:", err, ran)
	}
	inside, cancel := context.WithCancel(t.Context())
	err := s.WithOwner(inside, "inside", func(tx lease.Tx) error {
		cancel()
		// Statements keep running on the store context.
		return tx.Event(lease.Event{ID: identity.New(), OwnerID: "inside", Type: "execution.locked", At: tx.Now(), BootID: identity.New()})
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, lease.ErrRolledBack) {
		t.Fatal("cancel inside the callback:", err)
	}
	stillOpen(t, s)
	if n := db.Int(t, "SELECT count(*) FROM owners WHERE owner_id IN ('early','inside')"); n != 0 {
		t.Fatal("a cancelled transaction committed")
	}
	if n := db.Int(t, "SELECT count(*) FROM security_events WHERE owner_id='inside'"); n != 0 {
		t.Fatal("a cancelled event committed")
	}
	if err := s.WithOwner(t.Context(), "after", func(lease.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// A cancelled owner view (a closed browser tab) does not stop the executor,
// and revocation detaches from the request so a closed tab never loses it.
func testCancelledViewAndRevoke(t *testing.T, db Database) {
	s := db.Open(t)
	f := newService(t, s, nil, "none")
	f.activate(t)
	gone, cancel := context.WithCancel(f.browser)
	cancel()
	if _, err := f.service.View(gone, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled view:", err)
	}
	stillOpen(t, s)
	if _, err := f.service.View(f.browser, "alice"); err != nil {
		t.Fatal("the owner was blocked by a cancelled view:", err)
	}
	gone, cancel = context.WithCancel(f.browser)
	cancel()
	if err := f.service.Revoke(gone, f.active.ID); err != nil {
		t.Fatal("revoke with a closed request:", err)
	}
	if state := db.Text(t, "SELECT state FROM leases WHERE lease_id=$1", f.active.ID); state != "revoked" {
		t.Fatal("lease not revoked:", state)
	}
	stillOpen(t, s)
}

// Gate contention is not session loss: a transaction that holds the gate for
// three seconds does not stop the store.
func testLongHolderIsNotSessionLoss(t *testing.T, db Database) {
	s := started(t, db)
	err := s.WithOwner(t.Context(), "alice", func(tx lease.Tx) error {
		time.Sleep(3 * time.Second)
		_, err := tx.Leases()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	stillOpen(t, s)
}
