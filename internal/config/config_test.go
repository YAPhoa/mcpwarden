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

func TestOwnerSecurityRequiresAccountsAndDatabaseEnv(t *testing.T) {
	t.Setenv("TEST_MANAGED_KEY", "key")
	t.Setenv("TEST_SECURITY_DSN", "postgres://runtime@127.0.0.1/db")
	managed := &Managed{Path: "catalog.enc", KeyEnv: "TEST_MANAGED_KEY"}
	for name, tt := range map[string]struct {
		cfg  Config
		want string
	}{
		"operator mode":   {Config{OwnerSecurity: &OwnerSecurity{DatabaseURLEnv: "TEST_SECURITY_DSN"}}, "requires accounts"},
		"missing env":     {Config{Accounts: &Accounts{}, Managed: managed, OwnerSecurity: &OwnerSecurity{DatabaseURLEnv: "MISSING_MCPWARDEN_TEST"}}, "unset"},
		"accounts":        {Config{Accounts: &Accounts{}, Managed: managed, OwnerSecurity: &OwnerSecurity{DatabaseURLEnv: "TEST_SECURITY_DSN"}}, ""},
		"client release":  {Config{Accounts: &Accounts{}, Managed: managed, OwnerSecurity: &OwnerSecurity{DatabaseURLEnv: "TEST_SECURITY_DSN", CustodyMode: "client_release"}}, ""},
		"unknown custody": {Config{Accounts: &Accounts{}, Managed: managed, OwnerSecurity: &OwnerSecurity{DatabaseURLEnv: "TEST_SECURITY_DSN", CustodyMode: "server_unlock"}}, "custody_mode"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tt.cfg.ResolveAndValidate()
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got error %v, want containing %q", err, tt.want)
			}
			if tt.want == "" && tt.cfg.OwnerSecurity.DatabaseURL != "postgres://runtime@127.0.0.1/db" {
				t.Fatal("database URL not resolved")
			}
			if tt.want == "" && tt.cfg.ClientRelease() != (name == "client release") {
				t.Fatal("custody mode default or selection is wrong")
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

func TestManagedBackend(t *testing.T) {
	t.Setenv("TEST_MANAGED_KEY", "key")
	t.Setenv("TEST_SECURITY_DSN", "postgres://runtime@127.0.0.1/db")
	for name, tt := range map[string]struct {
		backend string
		owner   bool
		want    string
	}{
		"default":           {"", false, ""},
		"file":              {"file", true, ""},
		"postgres":          {"postgres", true, ""},
		"postgres no owner": {"postgres", false, "requires owner_security"},
		"unknown":           {"sqlite", false, "file or postgres"},
	} {
		t.Run(name, func(t *testing.T) {
			c := Config{Accounts: &Accounts{}, Managed: &Managed{Path: "catalog.enc", KeyEnv: "TEST_MANAGED_KEY", Backend: tt.backend}}
			if tt.owner {
				c.OwnerSecurity = &OwnerSecurity{DatabaseURLEnv: "TEST_SECURITY_DSN"}
			}
			err := c.ResolveAndValidate()
			if tt.want == "" && (err != nil || c.Managed.Backend == "") || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatal(err, c.Managed.Backend)
			}
		})
	}
}
