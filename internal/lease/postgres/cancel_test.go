package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

func stillOpen(t *testing.T, s *Store) {
	t.Helper()
	select {
	case <-s.Lost():
		t.Fatal("the store stopped")
	default:
	}
}

func owners(t *testing.T, c *pgx.Conn, owner string) int {
	t.Helper()
	var n int
	if err := c.QueryRow(t.Context(), "SELECT count(*) FROM mcpwarden_security.owners WHERE owner_id=$1", owner).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A caller that has gone gets its context error and commits nothing; the
// executor keeps running.
func TestCancelledCallerCommitsNothing(t *testing.T) {
	f := testDatabase(t)
	s := f.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
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
		return tx.(*ownerTx).Event(lease.Event{ID: identity.New(), OwnerID: "inside", Type: "execution.locked", At: tx.Now(), BootID: identity.New()})
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancel inside the callback:", err)
	}
	err = s.Run(inside, func(context.Context, catalogdb.DB) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("run with a gone caller:", err)
	}
	stillOpen(t, s)
	admin := f.admin
	if owners(t, admin, "early") != 0 || owners(t, admin, "inside") != 0 {
		t.Fatal("a cancelled transaction committed")
	}
	var events int
	if err := admin.QueryRow(t.Context(), "SELECT count(*) FROM mcpwarden_security.security_events WHERE owner_id='inside'").Scan(&events); err != nil || events != 0 {
		t.Fatal("a cancelled event committed", events, err)
	}
	if err := s.WithOwner(t.Context(), "after", func(lease.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// A cancelled owner view (a closed browser tab) no longer stops the executor,
// and revocation detaches from the request so a closed tab never loses it.
func TestCancelledViewAndRevoke(t *testing.T) {
	f := testDatabase(t)
	s := f.store(t)
	fx := newService(t, s, nil, "none")
	fx.activate(t)
	gone, cancel := context.WithCancel(fx.browser)
	cancel()
	if _, err := fx.service.View(gone, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled view:", err)
	}
	stillOpen(t, s)
	if _, err := fx.service.View(fx.browser, "alice"); err != nil {
		t.Fatal("the owner was blocked by a cancelled view:", err)
	}
	gone, cancel = context.WithCancel(fx.browser)
	cancel()
	if err := fx.service.Revoke(gone, fx.active.ID); err != nil {
		t.Fatal("revoke with a closed request:", err)
	}
	var state string
	if err := f.admin.QueryRow(t.Context(), "SELECT state FROM mcpwarden_security.leases WHERE lease_id=$1", fx.active.ID).Scan(&state); err != nil || state != "revoked" {
		t.Fatal("lease not revoked:", state, err)
	}
	stillOpen(t, s)
}

// Gate contention is not session loss: a transaction that holds the gate for
// three seconds does not close Lost().
func TestLongHolderIsNotSessionLoss(t *testing.T) {
	f := testDatabase(t)
	s := f.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	err := s.Run(t.Context(), func(ctx context.Context, db catalogdb.DB) error {
		time.Sleep(3 * time.Second)
		_, err := db.Exec(ctx, "SELECT 1")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	stillOpen(t, s)
}
