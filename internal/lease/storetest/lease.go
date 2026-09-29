package storetest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

func testDurabilityAndIsolation(t *testing.T, db Database) {
	store := db.Open(t)
	f := newService(t, store, nil, "confirm")
	f.activate(t)
	var admission audit.Record
	for range 25 {
		a, err := f.admit()
		if err != nil {
			t.Fatal(err)
		}
		admission = a.Record
		if err := a.Run(func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Complete(t.Context(), completion(admission)); err != nil {
		t.Fatal(err)
	}
	if calls, events := db.Int(t, "SELECT admitted_calls FROM leases WHERE lease_id=$1", f.active.ID), db.Int(t, "SELECT count(*) FROM invocation_events"); calls != 25 || events != 26 {
		t.Fatal("durable call/event counts disagree:", calls, events)
	}
	if err := store.WithOwner(t.Context(), "bob", func(tx lease.Tx) error {
		if _, err := tx.Request(f.request.ID); err != lease.ErrNotFound {
			t.Error("foreign request exposed")
		}
		if _, err := tx.Lease(f.active.ID); err != lease.ErrNotFound {
			t.Error("foreign lease exposed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Events and leases are never rewritten or deleted.
	for _, sql := range []string{"UPDATE invocation_events SET metadata=metadata", "DELETE FROM security_events", "DELETE FROM invocation_events", "DELETE FROM leases", "DELETE FROM requests"} {
		refused(t, db, sql)
	}
	// A lease's deadline and a request's binding are immutable.
	guarded(t, db, pick(db, "UPDATE leases SET expires_at=expires_at+interval '1 second'", "UPDATE leases SET expires_at=expires_at+1000000"))
	guarded(t, db, pick(db, `UPDATE requests SET binding=jsonb_set(binding,'{mode}','"none"')`, `UPDATE requests SET binding=json_set(binding,'$.mode','none')`))
	// A lease cannot be copied to an owner without its request.
	const columns = "lease_id,request_id,caller_id,credential_id,epoch,boot_id,scope_digest,state,activated_at,expires_at,ended_at,max_calls,admitted_calls,activation_actor_id,operation_id"
	guarded(t, db, "INSERT INTO leases (owner_id,"+columns+") SELECT 'bob',"+columns+" FROM leases WHERE owner_id='alice'")
	if err := f.service.Revoke(f.browser, f.active.ID); err != nil {
		t.Fatal(err)
	}
	guarded(t, db, "UPDATE leases SET state='active',ended_at=NULL")
}

func testAtomicBudget(t *testing.T, db Database) {
	budget := int64(7)
	f := newService(t, db.Open(t), &budget, "none")
	f.activate(t)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			a, err := f.admit()
			if err == nil {
				admitted.Add(1)
				if err := a.Run(func(context.Context) error { return nil }); err != nil {
					t.Error(err)
				}
			} else if err != lease.ErrRequired {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls, events := db.Int(t, "SELECT admitted_calls FROM leases"), db.Int(t, "SELECT count(*) FROM invocation_events"); admitted.Load() != 7 || calls != 7 || events != 7 {
		t.Fatal("budget admission was not atomic:", admitted.Load(), calls, events)
	}
}

// A COMMIT that fails after every statement succeeded admits nothing and
// stops the store.
func testAdmissionCommitFailure(t *testing.T, db Database) {
	store := db.Open(t)
	f := newService(t, store, nil, "none")
	f.activate(t)
	db.FailCommit(t, "invocation_events")
	if _, err := f.admit(); err != lease.ErrStorage {
		t.Fatalf("commit failure admitted work: %v", err)
	}
	if calls, events := db.Int(t, "SELECT admitted_calls FROM leases"), db.Int(t, "SELECT count(*) FROM invocation_events"); calls != 0 || events != 0 {
		t.Fatal("commit failure retained counter/audit")
	}
	stopped(t, store)
}

func testClockAfterOwnerLock(t *testing.T, db Database) {
	store := db.Open(t)
	_ = newService(t, store, nil, "none")
	release := db.HoldOwner(t, "alice")
	result := make(chan time.Time, 1)
	failed := make(chan error, 1)
	go func() {
		failed <- store.WithOwner(t.Context(), "alice", func(tx lease.Tx) error { result <- tx.Now(); return nil })
	}()
	time.Sleep(100 * time.Millisecond)
	released := time.Now().UTC()
	release()
	if err := <-failed; err != nil {
		t.Fatal(err)
	}
	if (<-result).Before(released) {
		t.Fatal("transaction used a timestamp from before the lock wait")
	}
}

// A restarted store suspends every active lease: authority never survives a
// restart, and the suspended lease keeps its identity and deadline.
func testRestartQuiescesLeases(t *testing.T, db Database) {
	store := db.Open(t)
	f := newService(t, store, nil, "none")
	f.activate(t)
	f.service.Close()
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted := db.Open(t)
	next, err := lease.New(t.Context(), restarted, f.authority, &activator{}, lease.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	f.service, f.store = next, restarted
	if _, err := f.admit(); err != lease.ErrRequired {
		t.Fatal("a restart kept live authority:", err)
	}
	if err := restarted.WithOwner(t.Context(), "alice", func(tx lease.Tx) error {
		l, err := tx.Lease(f.active.ID)
		if err != nil {
			return err
		}
		if l.State != "suspended" || l.ScopeDigest != f.active.ScopeDigest || !l.ExpiresAt.Equal(f.active.ExpiresAt) || !l.ActivatedAt.Equal(f.active.ActivatedAt) {
			t.Error("restart lost identity or changed deadline")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := db.Int(t, "SELECT count(*) FROM security_events WHERE event_type='lease.suspended' AND lease_id=$1", f.active.ID); n != 1 {
		t.Fatal("suspension events:", n)
	}
}

func testCompletionBinding(t *testing.T, db Database) {
	store := db.Open(t)
	f := newService(t, store, nil, "none")
	f.activate(t)
	a, err := f.admit()
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Run(func(context.Context) error { return nil })
	completed := completion(a.Record)
	completed.ActorLabel = "substituted snapshot"
	if err := store.Complete(t.Context(), completed); err != lease.ErrDenied {
		t.Fatal("completion changed immutable origin:", err)
	}
	completed.ActorLabel = a.Record.ActorLabel
	if err := store.Complete(t.Context(), completed); err != nil {
		t.Fatal(err)
	}
	stillOpen(t, store)
}

func testDenyApproved(t *testing.T, db Database) {
	f := newService(t, db.Open(t), nil, "confirm")
	if err := f.service.Deny(f.browser, f.request.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Activate(f.browser, activationInput(f.request)); err != lease.ErrStale {
		t.Fatal("denied approval activated:", err)
	}
}

// An upsert of a revoked lease back to active is refused by the database
// even when it reaches the store, and commits nothing.
func testTerminalLeaseStaysTerminal(t *testing.T, db Database) {
	store := db.Open(t)
	f := newService(t, store, nil, "none")
	f.activate(t)
	if err := f.service.Revoke(f.browser, f.active.ID); err != nil {
		t.Fatal(err)
	}
	err := store.WithOwner(t.Context(), "alice", func(tx lease.Tx) error {
		l, err := tx.Lease(f.active.ID)
		if err != nil {
			return err
		}
		l.State, l.EndedAt = "active", time.Time{}
		return tx.PutLease(l)
	})
	if err == nil {
		t.Fatal("a revoked lease was made active again")
	}
	if state := db.Text(t, "SELECT state FROM leases WHERE lease_id=$1", f.active.ID); state != "revoked" {
		t.Fatal("lease state:", state)
	}
}

// Only the canonical lowercase form of an ID names a row, on every store.
func testCanonicalIDs(t *testing.T, db Database) {
	store := db.Open(t)
	f := newService(t, store, nil, "none")
	f.activate(t)
	_, record := vaultWithCredential(t, store)
	if err := store.WithOwner(t.Context(), "alice", func(tx lease.Tx) error {
		if _, err := tx.Request(strings.ToUpper(f.request.ID)); err != lease.ErrNotFound {
			t.Error("uppercase request ID:", err)
		}
		if _, err := tx.Lease(strings.ToUpper(f.active.ID)); err != lease.ErrNotFound {
			t.Error("uppercase lease ID:", err)
		}
		if _, err := tx.(vault.Tx).CredentialRecord(strings.ToUpper(record.CredentialID)); !errors.Is(err, vault.ErrNotFound) {
			t.Error("uppercase credential ID:", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stillOpen(t, store)
}
