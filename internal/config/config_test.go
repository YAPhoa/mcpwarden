package config

import (
	"strings"
	"testing"
	"time"
)

func TestResolveAndValidate(t *testing.T) {
	t.Setenv("TEST_REMOTE_TOKEN", "fake-token")
	t.Setenv("TEST_OAUTH_ID", "id")
	t.Setenv("TEST_OAUTH_SECRET", "secret")
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"defaults", Config{Upstreams: []Upstream{{Name: "fs", Transport: "stdio", Command: "test"}}}, ""},
		{"nondurable audit", Config{Audit: Audit{Path: "-"}}, "durable dispatch admission"},
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

func TestAccountsRequireEncryptedStorageAndExcludeOAuth(t *testing.T) {
	for _, cfg := range []Config{
		{Accounts: &Accounts{}},
		{Accounts: &Accounts{}, Managed: &Managed{}, OAuth: &OAuth{}},
	} {
		if err := cfg.ResolveAndValidate(); err == nil {
			t.Fatal("invalid accounts configuration accepted")
		}
	}
}

func TestOwnerSecurityRequiresAccountsAndStorage(t *testing.T) {
	t.Setenv("TEST_STORAGE_KEY", "key")
	t.Setenv("TEST_MANAGED_KEY", "key")
	storage := func() *Storage { return &Storage{Path: "data/mcpwarden.db", KeyEnv: "TEST_STORAGE_KEY"} }
	for name, tt := range map[string]struct {
		cfg  Config
		want string
	}{
		"operator mode": {Config{Storage: storage(), OwnerSecurity: &OwnerSecurity{}}, "requires accounts"},
		"file catalog":  {Config{Accounts: &Accounts{}, Managed: &Managed{Path: "catalog.enc", KeyEnv: "TEST_MANAGED_KEY"}, OwnerSecurity: &OwnerSecurity{}}, "requires the storage section"},
		"old database":  {Config{Accounts: &Accounts{}, Storage: storage(), OwnerSecurity: &OwnerSecurity{DatabaseURLEnv: "TEST_SECURITY_DSN"}}, "replaced by storage.database_url_env"},
		"accounts":      {Config{Accounts: &Accounts{}, Storage: storage(), OwnerSecurity: &OwnerSecurity{}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := tt.cfg.ResolveAndValidate()
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got error %v, want containing %q", err, tt.want)
			}
		})
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
	t.Setenv("TEST_MANAGED_KEY", "key")
	for name, tt := range map[string]struct {
		cfg  Config
		want string
	}{
		"sqlite default":     {Config{Storage: &Storage{Path: "x.db", KeyEnv: "TEST_STORAGE_KEY"}}, ""},
		"sqlite accounts":    {Config{Accounts: &Accounts{}, Storage: &Storage{Driver: "sqlite", Path: "x.db", KeyEnv: "TEST_STORAGE_KEY"}}, ""},
		"postgres":           {Config{Storage: &Storage{Driver: "postgres", DatabaseURLEnv: "TEST_STORAGE_DSN", KeyEnv: "TEST_STORAGE_KEY"}}, ""},
		"sqlite no path":     {Config{Storage: &Storage{KeyEnv: "TEST_STORAGE_KEY"}}, "storage.path is required"},
		"sqlite with url":    {Config{Storage: &Storage{Path: "x.db", DatabaseURLEnv: "TEST_STORAGE_DSN", KeyEnv: "TEST_STORAGE_KEY"}}, "only for storage.driver postgres"},
		"postgres no url":    {Config{Storage: &Storage{Driver: "postgres", KeyEnv: "TEST_STORAGE_KEY"}}, "database_url_env is required"},
		"postgres with path": {Config{Storage: &Storage{Driver: "postgres", Path: "x.db", DatabaseURLEnv: "TEST_STORAGE_DSN", KeyEnv: "TEST_STORAGE_KEY"}}, "only for storage.driver sqlite"},
		"postgres unset url": {Config{Storage: &Storage{Driver: "postgres", DatabaseURLEnv: "MISSING_MCPWARDEN_TEST", KeyEnv: "TEST_STORAGE_KEY"}}, "unset"},
		"unknown driver":     {Config{Storage: &Storage{Driver: "mysql", KeyEnv: "TEST_STORAGE_KEY"}}, "sqlite or postgres"},
		"no key":             {Config{Storage: &Storage{Path: "x.db"}}, "key_env is required"},
		"unset key":          {Config{Storage: &Storage{Path: "x.db", KeyEnv: "MISSING_MCPWARDEN_TEST"}}, "unset"},
		"with audit":         {Config{Storage: &Storage{Path: "x.db", KeyEnv: "TEST_STORAGE_KEY"}, Audit: Audit{Path: "audit.jsonl"}}, "audit.path must be unset"},
		"with managed":       {Config{Storage: &Storage{Path: "x.db", KeyEnv: "TEST_STORAGE_KEY"}, Managed: &Managed{Path: "catalog.enc", KeyEnv: "TEST_MANAGED_KEY"}}, "cannot be combined with storage"},
		"managed backend":    {Config{Accounts: &Accounts{}, Managed: &Managed{Path: "catalog.enc", KeyEnv: "TEST_MANAGED_KEY", Backend: "postgres"}}, "replaced by the storage section"},
		"file mode":          {Config{Accounts: &Accounts{}, Managed: &Managed{Path: "catalog.enc", KeyEnv: "TEST_MANAGED_KEY"}}, ""},
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
			if c.Storage == nil {
				if c.Audit.Path != "./audit.jsonl" {
					t.Fatal("file mode lost its audit default:", c.Audit.Path)
				}
				return
			}
			if c.Audit.Path != "" || c.Storage.Key != "key" {
				t.Fatal("storage resolved:", c.Audit.Path, c.Storage.Key)
			}
			if c.Storage.Driver == "postgres" && c.Storage.DatabaseURL != "postgres://runtime@127.0.0.1/db" {
				t.Fatal("database URL not resolved")
			}
			if name == "sqlite default" && c.Storage.Driver != "sqlite" {
				t.Fatal("default driver:", c.Storage.Driver)
			}
		})
	}
}
