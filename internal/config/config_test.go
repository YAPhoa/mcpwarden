package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveAndValidate(t *testing.T) {
	t.Setenv("TEST_REMOTE_TOKEN", "fake-token")
	t.Setenv("TEST_OAUTH_ID", "id")
	t.Setenv("TEST_OAUTH_SECRET", "secret")
	t.Setenv(DefaultKeyEnv, "key")
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"defaults", Config{Upstreams: []Upstream{{Name: "fs", Transport: "stdio", Command: "test"}}}, ""},
		{"duplicate", Config{Upstreams: []Upstream{{Name: "fs", Transport: "stdio", Command: "test"}, {Name: "fs", Transport: "stdio", Command: "test"}}}, "duplicate"},
		{"invalid name", Config{Upstreams: []Upstream{{Name: "bad_name", Transport: "stdio", Command: "test"}}}, "invalid"},
		{"missing env", Config{Upstreams: []Upstream{{Name: "remote", Transport: "http", URL: "https://example.test/mcp", Headers: map[string]string{"Authorization": "Bearer ${MISSING_MCPWARDEN_TEST}"}}}}, "unset"},
		{"nonloopback auth", Config{Listen: "0.0.0.0:8787"}, "downstream_auth"},
		{"invalid duration", Config{Upstreams: []Upstream{{Name: "fs", Transport: "stdio", Command: "test", CallTimeout: "later"}}}, "call_timeout"},
		{"resolved env", Config{Upstreams: []Upstream{{Name: "remote", Transport: "http", URL: "https://example.test/mcp", Headers: map[string]string{"Authorization": "Bearer ${TEST_REMOTE_TOKEN}"}}}}, ""},
		{"oauth", Config{OAuth: &OAuth{Resource: "https://mcp.example.test/mcp", AuthorizationServer: "https://auth.example.test", IntrospectionURL: "https://auth.example.test/introspect", IntrospectionClientIDEnv: "TEST_OAUTH_ID", IntrospectionClientSecretEnv: "TEST_OAUTH_SECRET"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.ResolveAndValidate()
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got error %v, want containing %q", err, tt.want)
			}
			if tt.name == "defaults" && (tt.cfg.Upstreams[0].Timeout != 30*time.Second || tt.cfg.Listen != "127.0.0.1:8787") {
				t.Fatal("defaults not applied")
			}
			if tt.name == "resolved env" && tt.cfg.Upstreams[0].Headers["Authorization"] != "Bearer fake-token" {
				t.Fatal("environment not resolved")
			}
		})
	}
}

func TestAccountsExcludeOAuth(t *testing.T) {
	t.Setenv(DefaultKeyEnv, "key")
	cfg := Config{Accounts: &Accounts{}, OAuth: &OAuth{}}
	if err := cfg.ResolveAndValidate(); err == nil || !strings.Contains(err.Error(), "cannot be combined with oauth") {
		t.Fatal("accounts with oauth accepted:", err)
	}
	cfg = Config{Accounts: &Accounts{}}
	if err := cfg.ResolveAndValidate(); err != nil {
		t.Fatal("accounts on default storage refused:", err)
	}
}

func TestOwnerSecurityRequiresAccounts(t *testing.T) {
	t.Setenv(DefaultKeyEnv, "key")
	for name, tt := range map[string]struct {
		cfg  Config
		want string
	}{
		"operator mode": {Config{OwnerSecurity: &OwnerSecurity{}}, "requires accounts"},
		"accounts":      {Config{Accounts: &Accounts{}, OwnerSecurity: &OwnerSecurity{}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := tt.cfg.ResolveAndValidate()
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got error %v, want containing %q", err, tt.want)
			}
		})
	}
}

// Removed keys fail with their replacement, not the generic unknown-field
// error.
func TestRemovedKeys(t *testing.T) {
	t.Setenv(DefaultKeyEnv, "key")
	for yaml, want := range map[string]string{
		"managed_upstreams:\n  path: catalog.enc\n  key_env: KEY\n":       "managed_upstreams was replaced by storage",
		"managed_upstreams:\n  backend: postgres\n":                       "managed_upstreams was replaced by storage",
		"audit:\n  path: audit.jsonl\n":                                   "audit was removed",
		"accounts: {}\nowner_security:\n  database_url_env: DSN\n":        "replaced by storage.database_url_env",
		"accounts: {}\nowner_security:\n  database_url: postgres://x/y\n": "replaced by storage.database_url_env",
		"accounts: {}\nowner_security:\n  custody_mode: legacy_managed\n": "field custody_mode not found",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want containing %q", yaml, err, want)
		}
	}
}

func TestOwnerSecurityTrustedProxyConfiguration(t *testing.T) {
	for _, raw := range []string{"proxy.example.test", "192.0.2.8", "0.0.0.0/0", "::/0", "192.0.2.8/24", "::ffff:192.0.2.8/128", "not-a-network"} {
		if _, err := (OwnerSecurity{TrustedProxies: []string{raw}}).ProxyPrefixes(); err == nil {
			t.Errorf("unsafe or ambiguous proxy network accepted: %s", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1/32", "::1/128", "192.0.2.0/24", "2001:db8::/64"} {
		if _, err := (OwnerSecurity{TrustedProxies: []string{raw}}).ProxyPrefixes(); err != nil {
			t.Errorf("valid proxy network rejected: %s", raw)
		}
	}
	if _, err := (OwnerSecurity{TrustedProxies: make([]string, 17)}).ProxyPrefixes(); err == nil {
		t.Fatal("unbounded proxy network list accepted")
	}
}

func TestStorage(t *testing.T) {
	t.Setenv("TEST_STORAGE_KEY", "key")
	t.Setenv("TEST_STORAGE_DSN", "postgres://runtime@127.0.0.1/db")
	for name, tt := range map[string]struct {
		cfg  Config
		want string
	}{
		"sqlite":             {Config{Storage: &Storage{Path: "x.db", KeyEnv: "TEST_STORAGE_KEY"}}, ""},
		"sqlite accounts":    {Config{Accounts: &Accounts{}, Storage: &Storage{Driver: "sqlite", Path: "x.db", KeyEnv: "TEST_STORAGE_KEY"}}, ""},
		"postgres":           {Config{Storage: &Storage{Driver: "postgres", DatabaseURLEnv: "TEST_STORAGE_DSN", KeyEnv: "TEST_STORAGE_KEY"}}, ""},
		"sqlite with url":    {Config{Storage: &Storage{Path: "x.db", DatabaseURLEnv: "TEST_STORAGE_DSN", KeyEnv: "TEST_STORAGE_KEY"}}, "only for storage.driver postgres"},
		"postgres no url":    {Config{Storage: &Storage{Driver: "postgres", KeyEnv: "TEST_STORAGE_KEY"}}, "database_url_env is required"},
		"postgres with path": {Config{Storage: &Storage{Driver: "postgres", Path: "x.db", DatabaseURLEnv: "TEST_STORAGE_DSN", KeyEnv: "TEST_STORAGE_KEY"}}, "only for storage.driver sqlite"},
		"postgres unset url": {Config{Storage: &Storage{Driver: "postgres", DatabaseURLEnv: "MISSING_MCPWARDEN_TEST", KeyEnv: "TEST_STORAGE_KEY"}}, "unset"},
		"unknown driver":     {Config{Storage: &Storage{Driver: "mysql", KeyEnv: "TEST_STORAGE_KEY"}}, "sqlite or postgres"},
		"unset key":          {Config{Storage: &Storage{Path: "x.db", KeyEnv: "MISSING_MCPWARDEN_TEST"}}, "unset"},
		"default key unset":  {Config{}, DefaultKeyEnv + " is unset"},
	} {
		t.Run(name, func(t *testing.T) {
			c := tt.cfg
			err := c.ResolveAndValidate()
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got error %v, want containing %q", err, tt.want)
			}
			if tt.want != "" {
				return
			}
			if c.Storage.Key != "key" {
				t.Fatal("storage key not resolved")
			}
			if c.Storage.Driver == "postgres" && c.Storage.DatabaseURL != "postgres://runtime@127.0.0.1/db" {
				t.Fatal("database URL not resolved")
			}
		})
	}
}

// Without a storage section the gateway uses SQLite at the default path with
// the default key variable.
func TestStorageDefaults(t *testing.T) {
	t.Setenv(DefaultKeyEnv, "key")
	var c Config
	if err := c.ResolveAndValidate(); err != nil {
		t.Fatal(err)
	}
	if s := c.Storage; s.Driver != "sqlite" || s.Path != DefaultStoragePath || s.KeyEnv != DefaultKeyEnv || s.Key != "key" {
		t.Fatalf("defaults: %+v", *s)
	}
}

// The shipped examples load with this build's rules.
func TestExamplesLoad(t *testing.T) {
	for _, env := range []string{DefaultKeyEnv, "MCPWARDEN_TOKEN", "MCPWARDEN_INTROSPECTION_CLIENT_ID", "MCPWARDEN_INTROSPECTION_CLIENT_SECRET", "SOME_VAR", "REMOTE_TOKEN"} {
		t.Setenv(env, "synthetic")
	}
	for _, name := range []string{"config.yaml", "compose-config.yaml", "oauth-config.yaml"} {
		if _, err := Load(filepath.Join("..", "..", "examples", name)); err != nil {
			t.Error(name, err)
		}
	}
}
