package catalog

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

func TestAccessCapsRevocationAndMigration(t *testing.T) {
	path := t.TempDir() + "/store"
	s, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if s.AddAccess(AccessRecord{Owner: "alice", Name: fmt.Sprint(i), Kind: "api_key", Role: "client", SecretHash: fmt.Sprint(i)}) == nil {
				successes.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != MaxAPIKeys {
		t.Fatalf("concurrent mint bypassed cap: %d", successes.Load())
	}
	first := s.AccessList("alice")[0]
	if err := s.RevokeAccess("bob", first.ID); err == nil {
		t.Fatal("cross-user revoke succeeded")
	}
	if err := s.RevokeAccess("alice", first.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAccess(AccessRecord{Owner: "alice", Name: "replacement", Kind: "api_key", Role: "admin", SecretHash: "replacement"}); err != nil {
		t.Fatal("revocation did not free slot", err)
	}
	for i := 0; i < MaxLoginSessions; i++ {
		if err := s.AddAccess(AccessRecord{Owner: "alice", Name: "device", Kind: "browser", Role: "admin", SecretHash: fmt.Sprintf("browser%d", i), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ObserveOAuth("alice", "oauth", "client", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("OAuth bypassed shared session cap")
	}
	for i := 0; i < MaxMCPSessions; i++ {
		if err := s.AddAccess(AccessRecord{Owner: "alice", Name: "app", Kind: "mcp", Role: "client", SecretHash: fmt.Sprintf("mcp%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddAccess(AccessRecord{Owner: "alice", Name: "extra", Kind: "mcp", Role: "client", SecretHash: "extra"}); err == nil {
		t.Fatal("MCP limit bypassed")
	}
	// Existing client hashes migrate with client privileges, never admin access.
	s.accounts["legacy"] = Account{ID: "legacy-owner", Username: "legacy", ClientTokenHash: "legacy-hash"}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	legacy, ok := reopened.AuthenticateAccess("legacy-hash", "api_key")
	if !ok || legacy.Role != "client" {
		t.Fatal("legacy key privileges changed")
	}
	for _, r := range reopened.AccessList("alice") {
		if r.Kind == "mcp" && r.EndedAt.IsZero() {
			t.Fatal("dead MCP session survived restart")
		}
	}
	r, ok := reopened.AuthenticateAccess("replacement", "api_key")
	if !ok || r.CreatedAt.IsZero() || r.LastUsedAt.IsZero() {
		t.Fatal("credential metadata did not persist")
	}
	if err := reopened.RevokeAccess("alice", r.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.AuthenticateAccess("replacement", "api_key"); ok {
		t.Fatal("revoked key authenticated")
	}
}

func TestLegacyPublicIDMigrationPreservesCredentialsAndLifecycle(t *testing.T) {
	path := t.TempDir() + "/store"
	s, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 9, 21, 1, 2, 3, 0, time.UTC)
	old := AccessRecord{ID: identity.New(), Owner: "alice", Name: "Existing key", Kind: "api_key", Role: "client",
		SecretHash: "unchanged-legacy-verifier", ExpiresAt: stamp.AddDate(1, 0, 0),
		Lifecycle: Lifecycle{CreatedAt: stamp, UpdatedAt: stamp, RevokedAt: stamp.Add(time.Hour)}}
	s.access[old.ID] = old
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	var publicID string
	for range 2 {
		reopened, err := Open(path, testKey())
		if err != nil {
			t.Fatal(err)
		}
		got := reopened.access[old.ID]
		if !identity.ValidPublicID(got.PublicID) || publicID != "" && got.PublicID != publicID {
			t.Fatal("public ID was not persisted independently")
		}
		publicID = got.PublicID
		got.PublicID = ""
		if !reflect.DeepEqual(got, old) {
			t.Fatal("migration changed legacy identity, verifier, permissions, or timestamps")
		}
		if other, ok := reopened.AccessByID("bob", old.ID); ok || other != (AccessRecord{}) {
			t.Fatal("cross-owner lookup returned metadata")
		}
	}
}

func TestPublicIDUniquenessAndImmutability(t *testing.T) {
	s, err := Open(t.TempDir()+"/store", testKey())
	if err != nil {
		t.Fatal(err)
	}
	r := AccessRecord{ID: identity.New(), PublicID: identity.NewPublicID(), Owner: "alice", Name: "Key", Kind: "api_key", Role: "admin", SecretHash: "verifier"}
	if err := s.AddAccess(r); err != nil {
		t.Fatal(err)
	}
	duplicate := r
	duplicate.ID, duplicate.Owner, duplicate.SecretHash = identity.New(), "bob", "other-verifier"
	if err := s.AddAccess(duplicate); err == nil {
		t.Fatal("duplicate public ID accepted across owners")
	}
	duplicate.PublicID = "not-a-public-id"
	if err := s.AddAccess(duplicate); err == nil {
		t.Fatal("invalid public ID accepted")
	}
	if err := s.UpdateAccess(r.Owner, r.ID, "Renamed", false); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAccess(r.Owner, r.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := s.AccessByID(r.Owner, r.ID)
	if got.PublicID != r.PublicID || got.Name != "Renamed" || got.SecretHash != "" {
		t.Fatal("public metadata changed or verifier exposed")
	}
}

func TestObservedOAuthRevocationAndExpiry(t *testing.T) {
	s, err := Open(t.TempDir()+"/store", testKey())
	if err != nil {
		t.Fatal(err)
	}
	record, err := s.ObserveOAuth("alice", "validated-hash", "client", time.Now().Add(time.Hour), "Test device")
	if err != nil {
		t.Fatal(err)
	}
	if record.Device != "Test device" || record.LastUsedAt.IsZero() {
		t.Fatal("missing OAuth metadata")
	}
	if err := s.RevokeAccess("alice", record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveOAuth("alice", "validated-hash", "admin", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("revoked OAuth token resurrected")
	}
	if err := s.AddAccess(AccessRecord{Owner: "alice", Name: "expired", Kind: "api_key", Role: "admin", SecretHash: "expired", ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.AuthenticateAccess("expired", "api_key"); ok {
		t.Fatal("expired key accepted")
	}
}
