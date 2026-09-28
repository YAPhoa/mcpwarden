package postgres

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strconv"
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
