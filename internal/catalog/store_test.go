package catalog

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

func TestEncryptedStoreAndOwnerIsolation(t *testing.T) {
	path := t.TempDir() + "/connections.enc"
	s, err := Open(path, testKey())
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{Owner: "alice", Name: "github", URL: "https://example.test/mcp", Headers: map[string]string{"Authorization": "Bearer fake-personal-token"}, CallTimeout: "45s"}
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
	if strings.Contains(string(data), "fake-personal-token") || strings.Contains(string(data), "echo") {
		t.Fatal("credential or discovery leaked in store file")
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
	if got := reopened.List("alice"); len(got) != 1 || got[0].Headers["Authorization"] != entry.Headers["Authorization"] {
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
		{"header injection", func(e *Entry) { e.Headers = map[string]string{"Authorization": "x\r\nEvil: yes"} }},
		{"protocol header", func(e *Entry) { e.Headers = map[string]string{"Mcp-Session-Id": "fake"} }},
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
	e := Entry{Owner: "alice", Name: "drive", URL: "https://example.test/mcp", Headers: map[string]string{"Authorization": "synthetic-secret"}}
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
	if got.ID != id || got.Headers["Authorization"] != "synthetic-secret" {
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
	cases := []struct {
		kind    string
		headers map[string]string
		oauth   *OAuthSettings
		valid   bool
	}{
		{"none", nil, nil, true}, {"bearer", map[string]string{"Authorization": "Bearer synthetic"}, nil, true},
		{"api_key", map[string]string{"X-Key": "synthetic"}, nil, true}, {"headers", map[string]string{"X-Tenant": "test"}, nil, true},
		{"none", map[string]string{"Authorization": "synthetic"}, nil, false}, {"bearer", nil, nil, false},
		{"oauth", nil, &OAuthSettings{}, true}, {"oauth", nil, &OAuthSettings{ClientID: "id"}, false},
		{"oauth", nil, &OAuthSettings{ClientSecret: "secret"}, false}, {"oauth", map[string]string{"Authorization": "Bearer secret"}, &OAuthSettings{}, false},
	}
	for _, tc := range cases {
		e := base
		e.AuthType = tc.kind
		e.Headers = tc.headers
		e.OAuth = tc.oauth
		if got := Validate(e) == nil; got != tc.valid {
			t.Errorf("%s validation got %v", tc.kind, got)
		}
	}
	store, err := Open(t.TempDir()+"/store", testKey())
	if err != nil {
		t.Fatal(err)
	}
	base.AuthType = "oauth"
	base.OAuth = &OAuthSettings{Scopes: []string{"read"}}
	if err := store.Add(base); err != nil {
		t.Fatal(err)
	}
	copied := store.List("alice")
	copied[0].OAuth.Scopes[0] = "write"
	if store.List("alice")[0].OAuth.Scopes[0] != "read" {
		t.Fatal("OAuth settings shared through List")
	}
}
