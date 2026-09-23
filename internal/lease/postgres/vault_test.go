package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

func randomEncoded(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Opaque wrapping fixtures test storage without giving the server a vault root.
// The credential envelope below is independently authenticated with a test CEK.
func vaultRootFixture(t *testing.T, owner string) vault.Root {
	t.Helper()
	r := vault.Root{OwnerID: owner, RootID: identity.New(), RootVersion: "1", WrapperRevision: "1"}
	for _, method := range []string{"passphrase", "recovery"} {
		var k any = secret.RecoveryKDF{Suite: "HKDF-SHA256", OutputBytes: 32, HKDFInfo: secret.RecoveryInfo}
		if method == "passphrase" {
			k = secret.PassphraseKDF{Suite: "ARGON2ID-HKDF-SHA256", ArgonVersion: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: randomEncoded(16), OutputBytes: 32, HKDFInfo: secret.PassphraseInfo}
		}
		kd, _ := json.Marshal(k)
		w := secret.RootWrapper{Format: "mcpwarden.root-wrap.v1", Algorithm: secret.Algorithm, Purpose: "vault-root", RootContext: secret.RootContext{OwnerID: owner, RootID: r.RootID, RootVersion: "1", WrapperID: identity.New(), Method: method}, KDF: kd, Nonce: randomEncoded(12), Ciphertext: randomEncoded(48)}
		raw, _ := json.Marshal(w)
		if method == "passphrase" {
			r.Passphrase = raw
		} else {
			r.Recovery = raw
		}
	}
	return r
}

func credentialFixture(t *testing.T, root vault.Root) vault.Record {
	t.Helper()
	r := vault.Record{CredentialContext: secret.CredentialContext{OwnerID: root.OwnerID, RootID: root.RootID, RootVersion: root.RootVersion, ConnectorID: identity.New(), CredentialID: identity.New(), Epoch: "1"}, Revision: "1", Destination: secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: "https://example.com/mcp", HeaderNames: []string{"authorization"}, Network: "public"}}
	wrapFixture(&r)
	return encryptFixture(t, r)
}
func wrapFixture(r *vault.Record) {
	r.WrappedKey, _ = json.Marshal(secret.CredentialWrapper{Format: "mcpwarden.credential-wrap.v1", Algorithm: secret.Algorithm, Purpose: "credential-key", CredentialContext: r.CredentialContext, Nonce: randomEncoded(12), Ciphertext: randomEncoded(48)})
}
func encryptFixture(t *testing.T, r vault.Record) vault.Record {
	digest, _ := r.Destination.Digest()
	k := lease.Credential{ID: r.CredentialID, ConnectorID: r.ConnectorID, Epoch: r.Epoch, Revision: r.Revision, DestinationDigest: digest}
	r.Envelope = encryptedFixture(t, r.OwnerID, k, r.Destination, bytes.Repeat([]byte{9}, 32)).Envelope
	return r
}
func withVault(t *testing.T, s *Store, owner string, fn func(vault.Tx) error) error {
	t.Helper()
	return s.WithOwner(t.Context(), owner, func(tx lease.Tx) error { return fn(tx.(vault.Tx)) })
}

func TestVaultRecordsCASIsolationAndRetention(t *testing.T) {
	db := testDatabase(t)
	s := db.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	root := vaultRootFixture(t, "alice")
	r := credentialFixture(t, root)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		if err := tx.PutVaultRoot(root, ""); err != nil {
			return err
		}
		return tx.PutCredentialRecord(r, nil)
	}); err != nil {
		t.Fatal(err)
	}
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
	// The database nonce registry rejects reuse even when revision/AAD changes.
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
	// Rotation advances the epoch, allows a changed destination and retains old rows.
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
	var versions, wrappers int
	if err := db.admin.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM mcpwarden_security.credential_versions),(SELECT count(*) FROM mcpwarden_security.vault_wrapper_sets)").Scan(&versions, &wrappers); err != nil || versions != 3 || wrappers != 2 {
		t.Fatal("encrypted history lost", versions, wrappers, err)
	}
	for _, sql := range []string{"UPDATE mcpwarden_security.credential_versions SET envelope=envelope", "DELETE FROM mcpwarden_security.credential_epochs", "DELETE FROM mcpwarden_security.credential_heads", "UPDATE mcpwarden_security.vault_wrapper_sets SET passphrase=passphrase", "TRUNCATE mcpwarden_security.vault_roots"} {
		_, err := db.runtime(t).Exec(t.Context(), sql)
		requireCode(t, err, "42501")
	}
}

func TestVaultWriteCapAndBindingConstraints(t *testing.T) {
	db := testDatabase(t)
	s := db.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	root := vaultRootFixture(t, "alice")
	r := credentialFixture(t, root)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		if err := tx.PutVaultRoot(root, ""); err != nil {
			return err
		}
		return tx.PutCredentialRecord(r, nil)
	}); err != nil {
		t.Fatal(err)
	}
	// In this disposable scratch database only, seed the terminal count without
	// performing a million encryptions. Restore the guard before exercising it.
	_, err := db.admin.Exec(t.Context(), `ALTER TABLE mcpwarden_security.credential_epochs DISABLE TRIGGER guard_credential_epoch;
        UPDATE mcpwarden_security.credential_epochs SET write_count=1048576;
        ALTER TABLE mcpwarden_security.credential_epochs ENABLE TRIGGER guard_credential_epoch;`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal(err)
	}
	next := r
	next.Revision = "2"
	next = encryptFixture(t, next)
	if err = withVault(t, s, "alice", func(tx vault.Tx) error {
		return tx.PutCredentialRecord(next, &vault.Pointer{Epoch: "1", Revision: "1"})
	}); err != vault.ErrConflict {
		t.Fatal("epoch write cap bypassed", err)
	}
	_, err = db.runtime(t).Exec(t.Context(), "UPDATE mcpwarden_security.credential_epochs SET write_count=0")
	requireCode(t, err, "23514")
	var rev int
	_ = db.admin.QueryRow(t.Context(), "SELECT revision FROM mcpwarden_security.credential_heads").Scan(&rev)
	if rev != 1 {
		t.Fatal("failed insert advanced pointer")
	}
	// Even direct runtime SQL cannot detach a stored nonce from its envelope.
	_, err = db.runtime(t).Exec(t.Context(), `INSERT INTO mcpwarden_security.credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope) VALUES($1,$2,1,2,decode('000000000000000000000000','hex'),$3)`, r.OwnerID, r.CredentialID, []byte(next.Envelope))
	requireCode(t, err, "23514")
}

func TestVaultNonceBindingsAndWrappingKeyCap(t *testing.T) {
	db := testDatabase(t)
	s := db.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	root := vaultRootFixture(t, "alice")
	r := credentialFixture(t, root)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		if err := tx.PutVaultRoot(root, ""); err != nil {
			return err
		}
		return tx.PutCredentialRecord(r, nil)
	}); err != nil {
		t.Fatal(err)
	}
	next := r
	next.Revision = "2"
	next = encryptFixture(t, next)
	// This runs BELOW the cap, so only the wire/column binding can reject it.
	_, err := db.runtime(t).Exec(t.Context(), `INSERT INTO mcpwarden_security.credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope) VALUES($1,$2,1,2,decode('000000000000000000000000','hex'),$3)`, r.OwnerID, r.CredentialID, []byte(next.Envelope))
	requireCode(t, err, "23514")
	other := credentialFixture(t, root)
	var original, wrap secret.CredentialWrapper
	_ = json.Unmarshal(r.WrappedKey, &original)
	_ = json.Unmarshal(other.WrappedKey, &wrap)
	wrap.Nonce = original.Nonce
	other.WrappedKey, _ = json.Marshal(wrap)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error { return tx.PutCredentialRecord(other, nil) }); err != vault.ErrConflict {
		t.Fatal("wrapping key nonce reused across credentials", err)
	}
	var count int
	if err := db.admin.QueryRow(t.Context(), "SELECT wrap_count FROM mcpwarden_security.vault_roots").Scan(&count); err != nil || count != 1 {
		t.Fatal("failed nonce collision changed counter", err)
	}
	_, err = db.admin.Exec(t.Context(), `ALTER TABLE mcpwarden_security.vault_roots DISABLE TRIGGER guard_vault_root;
        UPDATE mcpwarden_security.vault_roots SET wrap_count=1048576;
        ALTER TABLE mcpwarden_security.vault_roots ENABLE TRIGGER guard_vault_root;`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal(err)
	}
	other = credentialFixture(t, root)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error { return tx.PutCredentialRecord(other, nil) }); err != vault.ErrConflict {
		t.Fatal("wrapping key cap bypassed", err)
	}
	_, err = db.runtime(t).Exec(t.Context(), "UPDATE mcpwarden_security.vault_roots SET wrap_count=0")
	requireCode(t, err, "23514")
}

func TestCiphertextCacheOwnsPublishedSnapshot(t *testing.T) {
	root := vaultRootFixture(t, "alice")
	r := credentialFixture(t, root)
	var cache vault.Cache
	publish, err := cache.Prepare(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Envelope[0] = '!'
	r.Destination.HeaderNames[0] = "x-mutated"
	if _, ok := cache.Current("alice", r.CredentialID); ok {
		t.Fatal("snapshot published before commit callback")
	}
	if err := publish(); err != nil {
		t.Fatal(err)
	}
	first, ok := cache.Current("alice", r.CredentialID)
	if !ok || first.Envelope[0] != '{' || first.Destination.HeaderNames[0] != "authorization" {
		t.Fatal("caller changed prepared snapshot")
	}
	first.Envelope[0] = '!'
	first.Destination.HeaderNames[0] = "x-mutated"
	second, ok := cache.Current("alice", r.CredentialID)
	if !ok || second.Envelope[0] != '{' || second.Destination.HeaderNames[0] != "authorization" {
		t.Fatal("reader changed committed snapshot")
	}
	if _, ok := cache.Current("bob", r.CredentialID); ok {
		t.Fatal("cross-owner ciphertext read")
	}
}

func TestAtomicVaultCommitFailureDoesNotPublish(t *testing.T) {
	db := testDatabase(t)
	f := newService(t, db.store(t), nil, "none")
	f.activate(t)
	_, err := db.admin.Exec(t.Context(), `CREATE FUNCTION mcpwarden_security.reject_vault_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit rejection'; END $$;
        CREATE CONSTRAINT TRIGGER reject_vault_commit AFTER INSERT ON mcpwarden_security.vault_roots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.reject_vault_commit();`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal(err)
	}
	root := vaultRootFixture(t, "alice")
	published := false
	err = f.service.ChangeAtomic(t.Context(), "alice", func(tx lease.Tx) (func() error, error) {
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
	var count int
	if err := db.admin.QueryRow(t.Context(), "SELECT count(*) FROM mcpwarden_security.vault_roots").Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected transaction retained root", err)
	}
}

func TestAtomicVaultMutationRevokesOnlyAfterCommit(t *testing.T) {
	for _, outcome := range []string{"commit", "rollback", "publish failure"} {
		t.Run(outcome, func(t *testing.T) {
			db := testDatabase(t)
			f := newService(t, db.store(t), nil, "none")
			f.activate(t)
			root := vaultRootFixture(t, "alice")
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
			var roots int
			_ = db.admin.QueryRow(t.Context(), "SELECT count(*) FROM mcpwarden_security.vault_roots").Scan(&roots)
			if outcome == "rollback" {
				if err != rejected || published || roots != 0 || f.activator.m.destroyed.Load() != 0 {
					t.Fatal("rollback changed committed authority")
				}
				a, err := f.admit()
				if err != nil {
					t.Fatal("rollback revoked live lease", err)
				}
				_ = a.Run(func(context.Context) error { return nil })
			} else {
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
				var state string
				_ = db.admin.QueryRow(t.Context(), "SELECT state FROM mcpwarden_security.leases WHERE lease_id=$1", f.active.ID).Scan(&state)
				if state != "revoked" {
					t.Fatal("revocation not in committed transaction")
				}
			}
		})
	}
}

func TestMigrationV1UpgradeAndRollback(t *testing.T) {
	db := testDatabase(t)
	// Only the newly created, random scratch database is reset to a v1 fixture.
	if _, err := db.admin.Exec(t.Context(), "DROP SCHEMA mcpwarden_security CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.admin.Exec(t.Context(), migration, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if _, err := db.admin.Exec(t.Context(), "INSERT INTO mcpwarden_security.schema_migrations(version,sha256) VALUES(1,$1)", migrationHash()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.admin.Exec(t.Context(), "INSERT INTO mcpwarden_security.owners(owner_id) VALUES('retained-owner'); CREATE TABLE mcpwarden_security.credential_heads(conflict integer)", pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db.admin, db.role); err != ErrMigration {
		t.Fatal("partial migration accepted", err)
	}
	var count int
	var rootPresent bool
	if err := db.admin.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM mcpwarden_security.schema_migrations),to_regclass('mcpwarden_security.vault_roots') IS NOT NULL").Scan(&count, &rootPresent); err != nil || count != 1 || rootPresent {
		t.Fatal("failed migration was not atomic", err)
	}
	if _, err := Open(t.Context(), db.runtimeDSN); err != lease.ErrStorage {
		t.Fatal("old schema allowed runtime startup")
	}
	if _, err := db.admin.Exec(t.Context(), "DROP TABLE mcpwarden_security.credential_heads"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db.admin, db.role); err != nil {
		t.Fatal(err)
	}
	if n, err := appliedMigrations(t.Context(), db.admin); err != nil || n != SchemaVersion {
		t.Fatal("upgrade ledger invalid", n, err)
	}
	if err := db.admin.QueryRow(t.Context(), "SELECT count(*) FROM mcpwarden_security.owners WHERE owner_id='retained-owner'").Scan(&count); err != nil || count != 1 {
		t.Fatal("upgrade lost metadata", err)
	}
	for _, badVersion := range []int{0, SchemaVersion + 1} {
		if _, err := db.admin.Exec(t.Context(), "INSERT INTO mcpwarden_security.schema_migrations(version,sha256) VALUES($1,$2)", badVersion, strconv.Itoa(badVersion)); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(t.Context(), db.admin, db.role); err != ErrMigration {
			t.Fatal("unknown ledger entry accepted")
		}
		if _, err := db.admin.Exec(t.Context(), "DELETE FROM mcpwarden_security.schema_migrations WHERE version=$1", badVersion); err != nil {
			t.Fatal(err)
		}
	}
}
