package storetest

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/custody"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// withRows runs fn with the catalog rows of one owner transaction.
func withRows(t *testing.T, s Store, owner string, fn func(catalogdb.Tx, time.Time) error) error {
	t.Helper()
	return s.WithOwner(t.Context(), owner, func(tx lease.Tx) error {
		return fn(tx.(catalogdb.OwnerTx).CatalogRows(), tx.Now())
	})
}

func sealed(s string) []byte { return []byte("sealed:" + s) }

// Catalog rows round-trip at microsecond precision, and the immutable parts
// of a row (username, access owner, kind and verifier, connector owner, a
// tombstone) refuse an update without stopping the store.
func testCatalogRows(t *testing.T, db Database) {
	s := started(t, db)
	at := time.Date(2026, 9, 28, 10, 11, 12, 345678000, time.UTC)
	later := at.Add(time.Hour)
	connector, tombstone := identity.New(), identity.New()
	want := catalogdb.Rows{
		Accounts: []catalogdb.Account{{OwnerID: "alice", Username: "alice", CreatedAt: at, UpdatedAt: later, Sealed: sealed("account")}},
		Access: []catalogdb.Access{
			{ID: "access-1", OwnerID: "alice", PublicID: "pub-1", Kind: "api_key", Role: "admin", SecretDigest: bytes.Repeat([]byte{1}, 32), CreatedAt: at, UpdatedAt: at, LastUsedAt: later, ExpiresAt: later, Sealed: sealed("a1")},
			{ID: "access-2", OwnerID: "alice", Kind: "browser", Role: "client", SecretDigest: bytes.Repeat([]byte{2}, 32), CreatedAt: at, RevokedAt: at, Sealed: sealed("a2")},
			{ID: "access-3", OwnerID: "alice", Kind: "api_key", Role: "client", SecretDigest: bytes.Repeat([]byte{3}, 32), CreatedAt: at, ExpiresAt: at, Sealed: sealed("a3")},
		},
		Discovery:  []catalogdb.Discovery{{OwnerID: "alice", Provider: "files", UpdatedAt: at, Sealed: sealed("d")}},
		Visibility: []catalogdb.Visibility{{OwnerID: "alice", Provider: "files", Mode: "selected", Disabled: true, CreatedAt: at, UpdatedAt: later, Sealed: sealed("v")}},
	}
	live := catalogdb.Connector{ID: connector, OwnerID: "alice", Name: "files", AuthType: "headers", CreatedAt: at, UpdatedAt: at, Sealed: sealed("c")}
	gone := catalogdb.Connector{ID: tombstone, OwnerID: "alice", AuthType: "", CreatedAt: at, DeletedAt: later, Sealed: sealed("t")}
	want.Connectors = []catalogdb.Connector{live, gone}
	if connector > tombstone {
		want.Connectors = []catalogdb.Connector{gone, live}
	}
	if err := withRows(t, s, "alice", func(rows catalogdb.Tx, now time.Time) error {
		for _, a := range want.Accounts {
			if err := rows.PutAccount(a); err != nil {
				return err
			}
		}
		for _, a := range want.Access {
			if err := rows.PutAccess(a); err != nil {
				return err
			}
		}
		for _, k := range want.Connectors {
			if err := rows.PutConnector(k); err != nil {
				return err
			}
		}
		for _, provider := range []string{"files", "gone"} {
			if err := rows.PutDiscovery(catalogdb.Discovery{OwnerID: "alice", Provider: provider, UpdatedAt: at, Sealed: sealed("d")}); err != nil {
				return err
			}
			if err := rows.PutVisibility(catalogdb.Visibility{OwnerID: "alice", Provider: provider, Mode: "all", CreatedAt: at, Sealed: sealed("old")}); err != nil {
				return err
			}
		}
		if err := rows.PutVisibility(want.Visibility[0]); err != nil {
			return err
		}
		if err := rows.DeleteDiscovery("alice", "gone"); err != nil {
			return err
		}
		if err := rows.DeleteVisibility("alice", "gone"); err != nil {
			return err
		}
		// access-1 is active; access-2 is revoked and access-3 has expired.
		if n, err := rows.ActiveAccess("alice", []string{"api_key", "browser"}, at.Add(time.Minute)); err != nil || n != 1 {
			t.Error("active access:", n, err)
		}
		if n, err := rows.ActiveAccess("alice", []string{"browser"}, at.Add(time.Minute)); err != nil || n != 0 {
			t.Error("active browser access:", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalize(got), normalize(want)) {
		t.Fatalf("catalog rows changed:\n got %+v\nwant %+v", normalize(got), normalize(want))
	}
	for name, change := range map[string]func(catalogdb.Tx) error{
		"username": func(rows catalogdb.Tx) error {
			a := want.Accounts[0]
			a.Username = "mallory"
			return rows.PutAccount(a)
		},
		"access kind": func(rows catalogdb.Tx) error {
			a := want.Access[0]
			a.Kind = "browser"
			return rows.PutAccess(a)
		},
		"access verifier": func(rows catalogdb.Tx) error {
			a := want.Access[0]
			a.SecretDigest = bytes.Repeat([]byte{9}, 32)
			return rows.PutAccess(a)
		},
		"access public ID": func(rows catalogdb.Tx) error {
			a := want.Access[1]
			a.PublicID = "pub-2"
			return rows.PutAccess(a)
		},
		"revived tombstone": func(rows catalogdb.Tx) error {
			k := gone
			k.Name, k.DeletedAt = "revived", time.Time{}
			return rows.PutConnector(k)
		},
	} {
		if err := withRows(t, s, "alice", func(rows catalogdb.Tx, _ time.Time) error { return change(rows) }); !errors.Is(err, catalogdb.ErrConflict) {
			t.Error(name, "changed:", err)
		}
	}
	// Another owner can neither take a row nor reuse a username.
	for name, change := range map[string]func(catalogdb.Tx) error{
		"connector owner": func(rows catalogdb.Tx) error {
			k := live
			k.OwnerID = "bob"
			return rows.PutConnector(k)
		},
		"access owner": func(rows catalogdb.Tx) error {
			a := want.Access[0]
			a.OwnerID = "bob"
			return rows.PutAccess(a)
		},
		"username reuse": func(rows catalogdb.Tx) error {
			return rows.PutAccount(catalogdb.Account{OwnerID: "bob", Username: "alice", Sealed: sealed("bob")})
		},
		"duplicate connector name": func(rows catalogdb.Tx) error {
			k := live
			k.ID = identity.New()
			k.OwnerID = "alice"
			return rows.PutConnector(k)
		},
	} {
		owner := "bob"
		if name == "duplicate connector name" {
			owner = "alice"
		}
		if err := withRows(t, s, owner, func(rows catalogdb.Tx, _ time.Time) error { return change(rows) }); !errors.Is(err, catalogdb.ErrConflict) {
			t.Error(name, "accepted:", err)
		}
	}
	after, err := s.LoadCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalize(after), normalize(want)) {
		t.Fatal("a refused change left rows behind")
	}
	stillOpen(t, s)
}

// normalize makes rows comparable: times in UTC, empty slices as nil.
func normalize(r catalogdb.Rows) catalogdb.Rows {
	utc := func(t *time.Time) {
		if !t.IsZero() {
			*t = t.UTC()
		}
	}
	for i := range r.Accounts {
		utc(&r.Accounts[i].CreatedAt)
		utc(&r.Accounts[i].UpdatedAt)
	}
	for i := range r.Access {
		a := &r.Access[i]
		for _, p := range []*time.Time{&a.CreatedAt, &a.UpdatedAt, &a.LastUsedAt, &a.ExpiresAt, &a.EndedAt, &a.RevokedAt, &a.DeletedAt} {
			utc(p)
		}
	}
	for i := range r.Connectors {
		k := &r.Connectors[i]
		for _, p := range []*time.Time{&k.CreatedAt, &k.UpdatedAt, &k.DeletedAt} {
			utc(p)
		}
	}
	for i := range r.Discovery {
		utc(&r.Discovery[i].UpdatedAt)
	}
	for i := range r.Visibility {
		utc(&r.Visibility[i].CreatedAt)
		utc(&r.Visibility[i].UpdatedAt)
	}
	return r
}

// Each family maps a refused write to its own conflict error and keeps the
// store running; a lease write the database refuses is a store failure.
func testErrorMapping(t *testing.T, db Database) {
	s := started(t, db)
	row := catalogdb.HistoryRow{OwnerID: "alice", EventID: "e1", SchemaVersion: 2, EventType: "tool.dispatch.completed", InvocationID: "inv-e1", ToolID: "t", Tool: "x", Upstream: "u", Status: "ok", TSNano: 1, HistoryNano: 1, Record: `{"schema_version":2}`}
	if err := s.InsertHistory(t.Context(), row); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertHistory(t.Context(), row); !errors.Is(err, catalogdb.ErrConflict) {
		t.Fatal("duplicate history event:", err)
	}
	stillOpen(t, s)
	boot := identity.New()
	if err := s.WithOwner(t.Context(), "alice", func(tx lease.Tx) error {
		c := tx.(custody.Tx)
		if p, err := c.ApprovalPolicy(); err != nil || p.Revision != "1" {
			t.Error("default policy:", p, err)
		}
		return c.PutApprovalPolicy(custody.Policy{OwnerID: "alice", Mode: "confirm", ChangedBy: identity.New()}, "1")
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithOwner(t.Context(), "alice", func(tx lease.Tx) error {
		return tx.(custody.Tx).PutApprovalPolicy(custody.Policy{OwnerID: "alice", Mode: "none", ChangedBy: identity.New()}, "1")
	}); !errors.Is(err, custody.ErrConflict) {
		t.Fatal("stale policy write:", err)
	}
	snap, err := s.LoadCustody(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Policies) != 1 || snap.Policies[0].OwnerID != "alice" || snap.Policies[0].Mode != "confirm" || snap.Policies[0].Revision != "2" {
		t.Fatal("custody snapshot policy:", snap.Policies)
	}
	stillOpen(t, s)
	event := lease.Event{ID: identity.New(), OwnerID: "alice", Type: "execution.locked", BootID: boot}
	if err := s.WithOwner(t.Context(), "alice", func(tx lease.Tx) error { event.At = tx.Now(); return tx.Event(event) }); err != nil {
		t.Fatal(err)
	}
	if err := s.WithOwner(t.Context(), "alice", func(tx lease.Tx) error { return tx.Event(event) }); err != lease.ErrStorage {
		t.Fatal("duplicate security event:", err)
	}
	stopped(t, s)
}

// After a refused statement nothing else in the transaction runs, and a
// callback that ignores the refusal and returns nil stops the store without
// committing anything.
func testPoisonedTransaction(t *testing.T, db Database) {
	s := started(t, db)
	if err := withRows(t, s, "alice", func(rows catalogdb.Tx, _ time.Time) error {
		return rows.PutAccount(catalogdb.Account{OwnerID: "alice", Username: "taken", Sealed: sealed("a")})
	}); err != nil {
		t.Fatal(err)
	}
	var after error
	err := withRows(t, s, "bob", func(rows catalogdb.Tx, _ time.Time) error {
		if err := rows.PutAccount(catalogdb.Account{OwnerID: "bob", Username: "taken", Sealed: sealed("b")}); !errors.Is(err, catalogdb.ErrConflict) {
			t.Error("username reuse:", err)
		}
		after = rows.PutDiscovery(catalogdb.Discovery{OwnerID: "bob", Provider: "files", Sealed: sealed("d")})
		return nil
	})
	if after == nil {
		t.Error("a statement ran after a refused one")
	}
	if err != lease.ErrStorage {
		t.Fatal("a poisoned transaction was committed:", err)
	}
	stopped(t, s)
	if n := db.Int(t, "SELECT count(*) FROM owners WHERE owner_id='bob'"); n != 0 {
		t.Fatal("a poisoned transaction committed its owner row")
	}
	if n := db.Int(t, "SELECT count(*) FROM catalog_discovery"); n != 0 {
		t.Fatal("a poisoned transaction committed a row")
	}
}

// Catalog statements that run past the store deadline stop the store. A
// catalog error alone does not stop it, so only the deadline rule does: a
// stalled transaction is treated as session loss, and nothing is committed.
func testCatalogStatementPastDeadline(t *testing.T, db Database) {
	s := started(t, db)
	db.SlowWrites(t, "catalog_discovery")
	began := time.Now()
	err := withRows(t, s, "alice", func(rows catalogdb.Tx, now time.Time) error {
		for _, provider := range []string{"a", "b", "c"} {
			if err := rows.PutDiscovery(catalogdb.Discovery{OwnerID: "alice", Provider: provider, UpdatedAt: now, Sealed: sealed("d")}); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		t.Fatal("a statement past the deadline succeeded")
	}
	if took := time.Since(began); took > 20*time.Second {
		t.Fatal("the deadline did not end the statement:", took)
	}
	stopped(t, s)
	if n := db.Int(t, "SELECT count(*) FROM catalog_discovery"); n != 0 {
		t.Fatal("rows committed:", n)
	}
}
