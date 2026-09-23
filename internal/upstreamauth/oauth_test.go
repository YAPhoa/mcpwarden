package upstreamauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog"
)

func TestOAuthConsentRefreshAndIsolation(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		t.Run(map[bool]string{false: "registered", true: "dynamic"}[dynamic], func(t *testing.T) {
			var endpoint string
			var challenge string
			var refreshes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/mcp":
					if r.Method != http.MethodPost {
						w.WriteHeader(405)
						return
					}
					w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+endpoint+`/.well-known/oauth-protected-resource/mcp"`)
					w.WriteHeader(401)
				case "/.well-known/oauth-protected-resource/mcp":
					json.NewEncoder(w).Encode(map[string]any{"resource": endpoint + "/mcp", "authorization_servers": []string{endpoint}, "scopes_supported": []string{"tools:read"}})
				case "/.well-known/oauth-authorization-server":
					json.NewEncoder(w).Encode(map[string]any{"issuer": endpoint, "authorization_endpoint": endpoint + "/authorize", "token_endpoint": endpoint + "/token", "registration_endpoint": endpoint + "/register", "token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"}, "code_challenge_methods_supported": []string{"S256"}})
				case "/register":
					json.NewEncoder(w).Encode(map[string]any{"client_id": "test-client", "token_endpoint_auth_method": "none"})
				case "/token":
					r.ParseForm()
					if r.Form.Get("grant_type") == "authorization_code" {
						sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
						if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || r.Form.Get("resource") != endpoint+"/mcp" || r.Form.Get("code") != "test-code" {
							http.Error(w, "bad PKCE or resource", 400)
							return
						}
						json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "token_type": "Bearer", "expires_in": 3600})
					} else {
						if r.Form.Get("refresh_token") != "synthetic-refresh" {
							http.Error(w, "invalid_grant", 400)
							return
						}
						refreshes.Add(1)
						json.NewEncoder(w).Encode(map[string]any{"access_token": "rotated-access", "refresh_token": "rotated-refresh", "token_type": "Bearer", "expires_in": 3600})
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			endpoint = server.URL
			key := base64.StdEncoding.EncodeToString(make([]byte, 32))
			path := t.TempDir() + "/encrypted"
			store, err := catalog.Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			settings := &catalog.OAuthSettings{}
			if !dynamic {
				settings.ClientID = "test-client"
				settings.ClientSecret = "synthetic-secret"
				settings.Issuer = endpoint
			}
			if err := store.Add(catalog.Entry{Owner: "alice", Name: "drive", URL: endpoint + "/mcp", AuthType: "oauth", OAuth: settings}); err != nil {
				t.Fatal(err)
			}
			entry := store.List("alice")[0]
			service := New(store)
			started, err := service.Start(context.Background(), entry, "http://localhost:8788/api/upstream-oauth/callback")
			if err != nil {
				t.Fatal(err)
			}
			authURL, _ := url.Parse(started.URL)
			challenge = authURL.Query().Get("code_challenge")
			if challenge == "" || authURL.Query().Get("code_challenge_method") != "S256" {
				t.Fatal("missing PKCE")
			}
			if _, _, err := service.Complete(context.Background(), started.State, "wrong-browser", "test-code", "", ""); err == nil {
				t.Fatal("wrong browser accepted")
			}
			owner, name, err := service.Complete(context.Background(), started.State, started.Binding, "test-code", "", "")
			if err != nil || owner != "alice" || name != "drive" {
				t.Fatal(owner, name, err)
			}
			if _, _, err := service.Complete(context.Background(), started.State, started.Binding, "test-code", "", ""); err == nil {
				t.Fatal("callback replay accepted")
			}
			if len(store.List("bob")) != 0 {
				t.Fatal("grant crossed users")
			}
			reopened, err := catalog.Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			saved := reopened.List("alice")[0]
			grant := *saved.OAuth.Grant
			if grant.Token.AccessToken != "synthetic-access" {
				t.Fatal("grant not saved")
			}
			encrypted, _ := os.ReadFile(path)
			if strings.Contains(string(encrypted), "synthetic-") {
				t.Fatal("secret plaintext in storage")
			}
			grant.Token.Expiry = time.Now().Add(-time.Hour)
			if err := reopened.SaveOAuth("alice", saved.ID, grant.ID, grant); err != nil {
				t.Fatal(err)
			}
			resumed := New(reopened)
			source, err := resumed.Handler(reopened.List("alice")[0]).TokenSource(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			token, err := source.Token()
			if err != nil || token.AccessToken != "rotated-access" {
				t.Fatal("refresh failed", err)
			}
			if refreshes.Load() != 1 || reopened.List("alice")[0].OAuth.Grant.Token.RefreshToken != "rotated-refresh" {
				t.Fatal("rotated token not persisted")
			}
			if err := reopened.Delete("alice", "drive"); err != nil {
				t.Fatal(err)
			}
			if err := reopened.SaveOAuth("alice", saved.ID, grant.ID, grant); err == nil {
				t.Fatal("deleted connection resurrected")
			}
		})
	}
}

func TestOAuthRejectsInsecureDiscoveredEndpoint(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://127.0.0.1/token", nil)
	_, err := (checkedTransport{base: http.DefaultTransport}).RoundTrip(req)
	if err == nil {
		t.Fatal("remote OAuth downgraded to local HTTP")
	}
}
