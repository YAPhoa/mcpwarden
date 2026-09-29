package dbcatalog

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
)

type rowsLoader struct{ rows catalogdb.Rows }

func (l rowsLoader) LoadCatalog(context.Context) (catalogdb.Rows, error) { return l.rows, nil }

// A connector sealed by an older build (header values, OAuth settings or a
// grant) is refused at load. An older no-auth connector (empty header map,
// null OAuth) still loads.
func TestOldFormatRefusedOnLoad(t *testing.T) {
	raw := make([]byte, 32)
	rand.Read(raw)
	key := base64.StdEncoding.EncodeToString(raw)
	s, err := newSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	for name, tc := range map[string]struct {
		mutate  func(p map[string]any) (grant bool)
		refused bool
	}{
		"header values": {func(p map[string]any) bool {
			p["headers"] = map[string]string{"Authorization": "Bearer synthetic"}
			return false
		}, true},
		"oauth":         {func(p map[string]any) bool { p["oauth"] = map[string]any{"scopes": []string{"read"}}; return false }, true},
		"grant id":      {func(p map[string]any) bool { return true }, true},
		"empty headers": {func(p map[string]any) bool { p["headers"] = map[string]string{}; p["oauth"] = nil; return false }, false},
	} {
		t.Run(name, func(t *testing.T) {
			id := identity.New()
			p := map[string]any{"id": id, "owner": "alice", "name": "svc", "url": "https://example.test/mcp", "call_timeout": "30s",
				"created_at": at, "updated_at": at}
			row := catalogdb.Connector{ID: id, OwnerID: "alice", Name: "svc", CreatedAt: at, UpdatedAt: at}
			if tc.mutate(p) {
				row.GrantID = "g1"
			}
			if row.Sealed, err = s.seal(connectorAAD(id), p); err != nil {
				t.Fatal(err)
			}
			repo, err := New(key, rowsLoader{catalogdb.Rows{Connectors: []catalogdb.Connector{row}}}, func() {})
			if err != nil {
				t.Fatal(err)
			}
			err = repo.Load(t.Context())
			if tc.refused != errors.Is(err, catalog.ErrOldFormat) || !tc.refused && err != nil {
				t.Fatalf("got %v", err)
			}
			if !tc.refused && len(repo.List("alice")) != 1 {
				t.Fatal("connector not loaded")
			}
		})
	}
}
