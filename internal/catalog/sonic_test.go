package catalog

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

// Exercise the actual encrypted persistence format, including SDK tool custom
// serialization. This codec change must not alter identities, times, or schema
// values, nor require migration of existing encrypted files.
func TestSonicCatalogWireCompatibility(t *testing.T) {
	s, err := Open(t.TempDir()+"/catalog.enc", testKey())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 22, 12, 1, 2, 123456789, time.UTC)
	entry := Entry{ID: identity.New(), Owner: "alice", Name: "remote", URL: "https://example.test/mcp", Headers: map[string]string{"X-Key": "synthetic <&> credential"}, Lifecycle: Lifecycle{CreatedAt: at, UpdatedAt: at}}
	key := keyFor("alice", "remote")
	s.entries[key] = entry
	s.discovery[key] = Discovery{UpdatedAt: at, Tools: []*mcp.Tool{{Name: "echo", Description: "Unicode 😀 <&>", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"n": map[string]any{"type": "integer", "maximum": 9007199254740991}}}, OutputSchema: map[string]any{"type": "object"}}}}
	s.accounts["alice"] = Account{ID: "alice", Username: "alice", Salt: []byte{1, 2, 3}, PasswordHash: []byte{4, 5, 6}, Iterations: 600000, Lifecycle: Lifecycle{CreatedAt: at}}
	id := identity.New()
	s.access[id] = AccessRecord{ID: id, Owner: "alice", Kind: "api_key", Role: "client", Name: "fixture", PublicID: identity.NewPublicID(), SecretHash: "synthetic-verifier", Lifecycle: Lifecycle{CreatedAt: at}}
	state := diskState{Entries: []Entry{entry}, Discovery: s.discovery, Visibility: s.visibility, Accounts: s.accounts, Access: s.access, Deleted: s.deleted}
	want, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := jsoncodec.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Sonic changed the catalog wire format")
	}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, encrypted[:n], encrypted[n:], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if !bytes.Equal(plain, want) {
		t.Fatal("encrypted payload differs from original codec")
	}
	reopened, err := Open(s.path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.entries[key].ID != entry.ID || !reopened.entries[key].CreatedAt.Equal(at) || reopened.access[id].SecretHash != "synthetic-verifier" {
		t.Fatal("catalog roundtrip altered stable data")
	}
}
