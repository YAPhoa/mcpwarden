package catalog

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/secret"
)

func testKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func TestEncryptedStoreAndOwnerIsolation(t *testing.T) {
	path := t.TempDir() + "/connections.enc"
	s, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{Owner: "alice", Name: "github", URL: "https://example.test/mcp", AuthType: "bearer", HeaderNames: []string{"Authorization"}, CallTimeout: "45s"}
	if err := s.Add(entry); err != nil {
		t.Fatal(err)
	}
	if got := s.List("bob"); len(got) != 0 {
		t.Fatalf("bob saw Alice's upstream: %+v", got)
	}
	if err := s.SetDiscovery("alice", "github", []*mcp.Tool{{Name: "echo", Description: "test", InputSchema: map[string]any{"type": "object"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVisibility("alice", "github", Visibility{Mode: "selected", Enabled: []string{"github__echo"}}); err != nil {
		t.Fatal(err)
	}
	if !s.ToolVisible("alice", "github", "github__echo") || s.ToolVisible("alice", "github", "github__other") || !s.ToolVisible("bob", "github", "github__other") {
		t.Fatal("visibility was not isolated by owner")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "Authorization") || strings.Contains(string(data), "echo") {
		t.Fatal("connector or discovery leaked in store file")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("store permissions: %v", info.Mode())
	}
	reopened, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.List("alice"); len(got) != 1 || !slices.Equal(got[0].HeaderNames, entry.HeaderNames) || !got[0].Credentialed() {
		t.Fatalf("reopened entries: %+v", got)
	}
	if got, ok := reopened.Discovery("alice", "github"); !ok || len(got.Tools) != 1 || got.Tools[0].Name != "echo" {
		t.Fatalf("reopened discovery: %+v, %v", got, ok)
	}
	if reopened.ToolVisible("alice", "github", "github__other") {
		t.Fatal("visibility did not persist")
	}
	if _, err := Open(path, base64.StdEncoding.EncodeToString([]byte("different-32-byte-key-value-00000"))); err == nil {
		t.Fatal("wrong key decrypted store")
	}
	if err := reopened.Delete("alice", "github"); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Discovery("alice", "github"); ok {
		t.Fatal("discovery remained after removal")
	}
	if !reopened.ToolVisible("alice", "github", "github__other") {
		t.Fatal("visibility remained after removal")
	}
}

func TestVisibilityRejectsOtherProvider(t *testing.T) {
	s, err := Open(t.TempDir()+"/store", testKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetVisibility("alice", "github", Visibility{Mode: "selected", Enabled: []string{"other__echo"}}); err == nil {
		t.Fatal("accepted another provider's tool")
	}
}

func TestValidateEntry(t *testing.T) {
	base := Entry{Owner: "alice", Name: "github", URL: "https://example.test/mcp", CallTimeout: "30s"}
	for _, tc := range []struct {
		name string
		edit func(*Entry)
	}{
		{"missing owner", func(e *Entry) { e.Owner = "" }},
		{"bad name", func(e *Entry) { e.Name = "bad__name" }},
		{"insecure remote", func(e *Entry) { e.URL = "http://example.test/mcp" }},
		{"query secret", func(e *Entry) { e.URL = "https://example.test/mcp?key=secret" }},
		{"bad duration", func(e *Entry) { e.CallTimeout = "later" }},
		{"header injection", func(e *Entry) { e.AuthType, e.HeaderNames = "headers", []string{"X-Key\r\nEvil: yes"} }},
		{"protocol header", func(e *Entry) { e.AuthType, e.HeaderNames = "headers", []string{"Mcp-Session-Id"} }},
		{"hop-by-hop header", func(e *Entry) { e.AuthType, e.HeaderNames = "api_key", []string{"Connection"} }},
		{"duplicate header", func(e *Entry) { e.AuthType, e.HeaderNames = "headers", []string{"X-Key", "x-key"} }},
		{"oauth", func(e *Entry) { e.AuthType = "oauth" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.edit(&e)
			if err := Validate(e); err == nil {
				t.Fatal("invalid entry accepted")
			}
		})
	}
}

func TestLegacyIDsAndProviderSettings(t *testing.T) {
	path := t.TempDir() + "/store"
	s, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	// Write a legacy encrypted record with no UUID, using the original disk shape.
	e := Entry{Owner: "alice", Name: "drive", URL: "https://example.test/mcp", AuthType: "bearer", HeaderNames: []string{"Authorization"}}
	s.entries[keyFor("alice", "drive")] = e
	if err := s.SetDiscovery("alice", "drive", []*mcp.Tool{{Name: "read"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVisibility("alice", "drive", Visibility{Mode: "selected", Enabled: []string{"drive__read"}}); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	id := migrated.List("alice")[0].ID
	if id == "" {
		t.Fatal("missing migrated ID")
	}
	if err := migrated.SetProviderEnabled("alice", "drive", false); err != nil {
		t.Fatal(err)
	}
	// Tool preference writes must not accidentally re-enable a disabled provider.
	if err := migrated.SetVisibility("alice", "drive", Visibility{Mode: "selected", Enabled: []string{"drive__read"}}); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	got := again.List("alice")[0]
	if got.ID != id || !slices.Equal(got.HeaderNames, e.HeaderNames) {
		t.Fatal("migration lost connection data")
	}
	if d, ok := again.Discovery("alice", "drive"); !ok || len(d.Tools) != 1 {
		t.Fatal("migration lost cached tools")
	}
	if !again.Visibility("alice", "drive").Disabled || again.Visibility("bob", "drive").Disabled {
		t.Fatal("provider setting not persisted or isolated")
	}
	if err := again.SetProviderEnabled("alice", "drive", true); err != nil {
		t.Fatal(err)
	}
	if !again.ToolVisible("alice", "drive", "drive__read") || again.ToolVisible("alice", "drive", "drive__write") {
		t.Fatal("tool preferences lost")
	}
	if err := again.Add(Entry{ID: id, Owner: "bob", Name: "drive", URL: e.URL}); err == nil {
		t.Fatal("duplicate ID accepted")
	}
}

func TestAuthenticationValidationAndPrivateCopies(t *testing.T) {
	base := Entry{Owner: "alice", Name: "remote", URL: "https://example.test/mcp"}
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("X-Key-%d", i)
	}
	cases := []struct {
		kind  string
		names []string
		valid bool
	}{
		{"none", nil, true}, {"", nil, true}, {"none", []string{"X-Key"}, false},
		{"bearer", []string{"Authorization"}, true}, {"bearer", []string{"authorization"}, true},
		{"bearer", nil, false}, {"bearer", []string{"X-Key"}, false}, {"bearer", []string{"Authorization", "X-Key"}, false},
		{"api_key", []string{"X-Key"}, true}, {"api_key", nil, false}, {"api_key", []string{"X-Key", "X-Other"}, false},
		{"headers", []string{"X-Tenant", "Authorization"}, true}, {"headers", nil, false},
		{"headers", many[:32], true}, {"headers", many, false},
		{"oauth", nil, false}, {"other", nil, false},
	}
	for _, tc := range cases {
		e := base
		e.AuthType = tc.kind
		e.HeaderNames = tc.names
		if got := Validate(e) == nil; got != tc.valid {
			t.Errorf("%s %v validation got %v", tc.kind, tc.names, got)
		}
	}
	store, err := Open(t.TempDir()+"/store", testKey())
	if err != nil {
		t.Fatal(err)
	}
	base.AuthType, base.HeaderNames = "headers", []string{"X-Tenant"}
	if err := store.Add(base); err != nil {
		t.Fatal(err)
	}
	copied := store.List("alice")
	copied[0].HeaderNames[0] = "X-Other"
	if store.List("alice")[0].HeaderNames[0] != "X-Tenant" {
		t.Fatal("header names shared through List")
	}
}

// Every header name the catalog accepts must be one the vault destination
// accepts, or a connector could exist that no credential can ever unlock.
func TestCatalogHeaderNamesMatchVaultDestinations(t *testing.T) {
	names := []string{"Authorization", "X-API-Key", "x-tenant", "Api_Key", "X~Key", "Host", "Mcp-Session-Id", "Sec-Fetch-Mode",
		"X-Forwarded-For", "Proxy-Authorization", "Cookie", "Content-Type", "Idempotency-Key", "Authorization-Server", "Accept"}
	for _, name := range names {
		e := Entry{Owner: "alice", Name: "remote", URL: "https://example.test/mcp", AuthType: "api_key", HeaderNames: []string{name}}
		if Validate(e) != nil {
			continue
		}
		d := secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: e.URL, Network: "public", HeaderNames: []string{strings.ToLower(name)}, PrivatePrefixes: []string{}}
		if _, err := d.Digest(); err != nil {
			t.Errorf("catalog accepted %s, vault destination refuses it: %v", name, err)
		}
	}
}

func TestOldFormatRefused(t *testing.T) {
	for name, entry := range map[string]string{
		"header values": `{"id":"` + identity.New() + `","owner":"alice","name":"old","url":"https://example.test/mcp","auth_type":"bearer","headers":{"Authorization":"Bearer synthetic"}}`,
		"oauth":         `{"id":"` + identity.New() + `","owner":"alice","name":"old","url":"https://example.test/mcp","auth_type":"oauth","oauth":{"scopes":["read"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir() + "/store"
			s, err := Open(path, testKey())
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, s.aead.NonceSize())
			sealed := s.aead.Seal(nonce, nonce, []byte(`{"entries":[`+entry+`],"discovery":{},"visibility":{}}`), nil)
			if err := os.WriteFile(path, sealed, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, testKey()); !errors.Is(err, ErrOldFormat) {
				t.Fatalf("old catalog opened: %v", err)
			}
		})
	}
}
