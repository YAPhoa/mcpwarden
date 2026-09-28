package storetest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

// detachedNonce inserts revision 2 of credential $2 with the envelope $3
// under a stored nonce that is not the envelope's.
func detachedNonce(db Database) string {
	return pick(db, "INSERT INTO credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope) VALUES($1,$2,1,2,decode('000000000000000000000000','hex'),$3::jsonb)",
		"INSERT INTO credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope,created_at) VALUES($1,$2,1,2,'AAAAAAAAAAAAAAAA',$3,0)")
}

func testVaultCASIsolationAndRetention(t *testing.T, db Database) {
	s := started(t, db)
	root, r := vaultWithCredential(t, s)
	if err := withVault(t, s, "bob", func(tx vault.Tx) error {
		if _, err := tx.VaultRoot(); err != vault.ErrNotFound {
			t.Error("cross-owner root read")
		}
		if _, err := tx.CredentialRecord(r.CredentialID); err != vault.ErrNotFound {
			t.Error("cross-owner credential read")
		}
		return tx.PutVaultRoot(root, "")
	}); err != vault.ErrInvalid {
		t.Fatal("cross-owner write accepted", err)
	}
	root.WrapperRevision = "2"
	if err := withVault(t, s, "alice", func(tx vault.Tx) error { return tx.PutVaultRoot(root, "1") }); err != nil {
		t.Fatal(err)
	}
	if err := withVault(t, s, "alice", func(tx vault.Tx) error { return tx.PutVaultRoot(root, "1") }); err != vault.ErrConflict {
		t.Fatal("stale wrapper write", err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			next := r
			next.Revision = "2"
			next = encryptFixture(t, next)
			err := withVault(t, s, "alice", func(tx vault.Tx) error {
				return tx.PutCredentialRecord(next, &vault.Pointer{Epoch: "1", Revision: "1"})
			})
			if err == nil {
				wins.Add(1)
			} else if err != vault.ErrConflict {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("concurrent stale writers succeeded")
	}
	if err := withVault(t, s, "alice", func(tx vault.Tx) error { var err error; r, err = tx.CredentialRecord(r.CredentialID); return err }); err != nil {
		t.Fatal(err)
	}
	// The nonce registry rejects reuse even when the revision and AAD change.
	next := r
	next.Revision = "3"
	var env secret.Envelope
	_ = json.Unmarshal(next.Envelope, &env)
	env.Revision = "3"
	next.Envelope, _ = json.Marshal(env)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		return tx.PutCredentialRecord(next, &vault.Pointer{Epoch: "1", Revision: "2"})
	}); err != vault.ErrConflict {
		t.Fatal("nonce reuse accepted", err)
	}
	// Rotation advances the epoch, allows a changed destination and keeps
	// the old rows.
	next = r
	next.Epoch = "2"
	next.Revision = "1"
	next.Destination.Endpoint = "https://example.org/mcp"
	wrapFixture(&next)
	next = encryptFixture(t, next)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		return tx.PutCredentialRecord(next, &vault.Pointer{Epoch: "1", Revision: "2"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		return tx.DeleteCredentialRecord(r.CredentialID, vault.Pointer{Epoch: "2", Revision: "1"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		deleted, err := tx.CredentialRecord(r.CredentialID)
		if err != nil {
			return err
		}
		if deleted.DeletedAt.IsZero() {
			t.Error("missing tombstone")
		}
		if _, err = deleted.SecretRecord(); err == nil {
			t.Error("deleted credential usable")
		}
		return tx.PutCredentialRecord(next, &vault.Pointer{Epoch: "2", Revision: "1"})
	}); err != vault.ErrConflict {
		t.Fatal("tombstone resurrected", err)
	}
	if versions, wrappers := db.Int(t, "SELECT count(*) FROM credential_versions"), db.Int(t, "SELECT count(*) FROM vault_wrapper_sets"); versions != 3 || wrappers != 2 {
		t.Fatal("encrypted history lost", versions, wrappers)
	}
	for _, sql := range []string{"UPDATE credential_versions SET envelope=envelope", "DELETE FROM credential_versions", "DELETE FROM credential_epochs", "DELETE FROM credential_heads",
		"UPDATE vault_wrapper_sets SET passphrase=passphrase", "DELETE FROM vault_wrapper_sets", "DELETE FROM vault_roots"} {
		refused(t, db, sql)
	}
	stillOpen(t, s)
}

func testVaultWriteCap(t *testing.T, db Database) {
	s := started(t, db)
	_, r := vaultWithCredential(t, s)
	// Seed the terminal count instead of performing a million encryptions.
	db.Seed(t, "credential_epochs", "UPDATE credential_epochs SET write_count=1048576")
	next := r
	next.Revision = "2"
	next = encryptFixture(t, next)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		return tx.PutCredentialRecord(next, &vault.Pointer{Epoch: "1", Revision: "1"})
	}); err != vault.ErrConflict {
		t.Fatal("epoch write cap bypassed", err)
	}
	guarded(t, db, "UPDATE credential_epochs SET write_count=0")
	if rev := db.Int(t, "SELECT revision FROM credential_heads"); rev != 1 {
		t.Fatal("failed insert advanced pointer")
	}
	// Even direct SQL cannot detach a stored nonce from its envelope.
	guarded(t, db, detachedNonce(db), r.OwnerID, r.CredentialID, string(next.Envelope))
	stillOpen(t, s)
}

func testVaultNonceBindingsAndWrappingKeyCap(t *testing.T, db Database) {
	s := started(t, db)
	root, r := vaultWithCredential(t, s)
	next := r
	next.Revision = "2"
	next = encryptFixture(t, next)
	// This runs below the cap, so only the nonce binding can reject it.
	guarded(t, db, detachedNonce(db), r.OwnerID, r.CredentialID, string(next.Envelope))
	other := credentialFixture(t, root)
	var original, wrap secret.CredentialWrapper
	_ = json.Unmarshal(r.WrappedKey, &original)
	_ = json.Unmarshal(other.WrappedKey, &wrap)
	wrap.Nonce = original.Nonce
	other.WrappedKey, _ = json.Marshal(wrap)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error { return tx.PutCredentialRecord(other, nil) }); err != vault.ErrConflict {
		t.Fatal("wrapping key nonce reused across credentials", err)
	}
	if count := db.Int(t, "SELECT wrap_count FROM vault_roots"); count != 1 {
		t.Fatal("failed nonce collision changed counter", count)
	}
	db.Seed(t, "vault_roots", "UPDATE vault_roots SET wrap_count=1048576")
	other = credentialFixture(t, root)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error { return tx.PutCredentialRecord(other, nil) }); err != vault.ErrConflict {
		t.Fatal("wrapping key cap bypassed", err)
	}
	guarded(t, db, "UPDATE vault_roots SET wrap_count=0")
	stillOpen(t, s)
}

func testVaultCommitFailureDoesNotPublish(t *testing.T, db Database) {
	f := newService(t, db.Open(t), nil, "none")
	f.activate(t)
	db.FailCommit(t, "vault_roots")
	root := vaultRootFixture("alice")
	published := false
	err := f.service.ChangeAtomic(t.Context(), "alice", func(tx lease.Tx) (func() error, error) {
		if err := tx.(vault.Tx).PutVaultRoot(root, ""); err != nil {
			return nil, err
		}
		return func() error { published = true; return nil }, nil
	})
	if err != lease.ErrStorage || published || f.activator.m.destroyed.Load() != 1 {
		t.Fatal("ambiguous/failed commit retained access or published cache", err)
	}
	if _, err := f.admit(); err != lease.ErrLocked {
		t.Fatal("admission allowed after commit uncertainty", err)
	}
	if n := db.Int(t, "SELECT count(*) FROM vault_roots"); n != 0 {
		t.Fatal("rejected transaction retained root")
	}
}

func testVaultMutationCommit(t *testing.T, db Database)   { vaultMutation(t, db, "commit") }
func testVaultMutationRollback(t *testing.T, db Database) { vaultMutation(t, db, "rollback") }
func testVaultMutationPublishFailure(t *testing.T, db Database) {
	vaultMutation(t, db, "publish failure")
}

// vaultMutation checks that an atomic vault change revokes live leases in
// the same commit, and only when it commits.
func vaultMutation(t *testing.T, db Database, outcome string) {
	f := newService(t, db.Open(t), nil, "none")
	f.activate(t)
	root := vaultRootFixture("alice")
	var published bool
	rejected := errors.New("synthetic rejected mutation")
	err := f.service.ChangeAtomic(t.Context(), "alice", func(tx lease.Tx) (func() error, error) {
		if err := tx.(vault.Tx).PutVaultRoot(root, ""); err != nil {
			return nil, err
		}
		if outcome == "rollback" {
			return nil, rejected
		}
		return func() error {
			published = true
			if outcome == "publish failure" {
				return rejected
			}
			return nil
		}, nil
	})
	roots := db.Int(t, "SELECT count(*) FROM vault_roots")
	if outcome == "rollback" {
		if err != rejected || published || roots != 0 || f.activator.m.destroyed.Load() != 0 {
			t.Fatal("rollback changed committed authority")
		}
		a, err := f.admit()
		if err != nil {
			t.Fatal("rollback revoked live lease", err)
		}
		_ = a.Run(func(context.Context) error { return nil })
		return
	}
	if !published || roots != 1 || f.activator.m.destroyed.Load() != 1 {
		t.Fatal("commit did not retire material")
	}
	if outcome == "commit" && err != nil {
		t.Fatal(err)
	}
	if outcome == "publish failure" && err != lease.ErrStorage {
		t.Fatal("publication failure not locked", err)
	}
	if _, err := f.admit(); err == nil {
		t.Fatal("admitted after security mutation")
	}
	if state := db.Text(t, "SELECT state FROM leases WHERE lease_id=$1", f.active.ID); state != "revoked" {
		t.Fatal("revocation not in committed transaction")
	}
}
