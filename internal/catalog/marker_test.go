package catalog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

func TestMarkerGatesTheFileBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.enc")
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	store, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddAccount(Account{ID: "account:a", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	// A running file gateway holds the shared lock; a migration cannot start.
	if _, err := Lock(path, true); !errors.Is(err, ErrCatalogBusy) {
		t.Fatal("exclusive lock beside a running gateway", err)
	}
	store.Close()
	unlock, err := Lock(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); err == nil || !strings.Contains(err.Error(), "migration is running") {
		t.Fatal("file backend started during a migration", err)
	}
	unlock()

	importID, rollbackID := identity.New(), identity.New()
	for _, state := range []string{"importing", "active"} {
		if err := WriteMarker(path, Marker{State: state, ImportID: importID}); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, key); err == nil {
			t.Fatal("file backend started with marker", state)
		}
	}
	if err := WriteMarker(path, Marker{State: "rolling_back", ImportID: importID, RollbackID: rollbackID}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); err == nil {
		t.Fatal("file backend started while rolling back")
	}
	// rolled_back admits only the file that rollback wrote.
	if err := WriteMarker(path, Marker{State: "rolled_back", ImportID: importID, RollbackID: rollbackID}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); err == nil || !strings.Contains(err.Error(), "revive") {
		t.Fatal("pre-cutover file started after rollback", err)
	}
	snap, _, err := ReadSnapshot(path, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	snap.Rollback = rollbackID
	if err := WriteSnapshot(path, key, snap); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	// Later saves keep the rollback identity.
	if err := store.AddAccount(Account{ID: "account:b", Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if _, err := Open(path, key); err != nil {
		t.Fatal("rollback identity lost on save", err)
	}
	if err := WriteMarker(path, Marker{State: "active", ImportID: "not-an-id"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadMarker(path); err == nil {
		t.Fatal("invalid marker accepted")
	}
}

func TestReadSnapshotRefusesUnmigratedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.enc")
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	aead, _ := newAEAD(key)
	legacy := diskState{Accounts: map[string]Account{"alice": {ID: "account:a", Username: "alice", ClientTokenHash: "legacy"}}}
	raw, _ := json.Marshal(legacy)
	nonce := make([]byte, aead.NonceSize())
	if err := writeEncrypted(path, aead.Seal(nonce, nonce, raw, nil)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadSnapshot(path, key, time.Now()); !errors.Is(err, ErrNeedsFileMigration) {
		t.Fatal("legacy client token imported without the file migration", err)
	}
}
