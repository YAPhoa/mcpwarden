package catalog

import (
	"fmt"
	"strings"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/secret"
)

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

func TestAuthenticationValidation(t *testing.T) {
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

// A credentialed connector's endpoint must be one the vault destination the
// console builds accepts; a no-auth connector keeps the looser URL rule.
func TestCatalogEndpointsMatchVaultDestinations(t *testing.T) {
	for endpoint, want := range map[string]bool{
		"https://example.com/mcp": true, "https://example.com:8443/mcp": true,
		"http://localhost:8080/mcp": true, "http://127.0.0.1:8080/mcp": true, "http://[::1]:8080/mcp": true,
		"https://Example.com/mcp": false, "https://example.com": false, "https://example.com./mcp": false,
		"https://example.com/./mcp": false, "https://example.com/a%2Fb": false, "https://example.com:0443/mcp": false,
		"https://10.0.0.5/mcp": false, "https://[::1]/mcp": false,
	} {
		e := Entry{Owner: "alice", Name: "remote", URL: endpoint, AuthType: "bearer", HeaderNames: []string{"Authorization"}}
		network, prefixes := "public", []string{}
		if strings.HasPrefix(endpoint, "http:") {
			network, prefixes = "private", []string{"127.0.0.0/8", "::1/128"}
			if strings.Contains(endpoint, "127.0.0.1") {
				prefixes = []string{"127.0.0.0/8"}
			} else if strings.Contains(endpoint, "[::1]") {
				prefixes = []string{"::1/128"}
			}
		}
		d := secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: endpoint, HeaderNames: []string{"authorization"}, Network: network, PrivatePrefixes: prefixes, AllowLoopbackHTTP: network == "private"}
		_, derr := d.Digest()
		if got := Validate(e) == nil; got != want || (derr == nil) != want {
			t.Errorf("%s: catalog %v, destination %v, want %v", endpoint, got, derr == nil, want)
		}
		e.AuthType, e.HeaderNames = "none", nil
		if strings.HasPrefix(endpoint, "https://Example") && Validate(e) != nil {
			t.Errorf("no-auth connector refused %s", endpoint)
		}
	}
}
