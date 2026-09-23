package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/config"
)

func TestOAuthResource(t *testing.T) {
	resourceURL := "https://mcp.example.test/mcp"
	issuer := "https://auth.example.test"
	var valid = true
	scope := "mcp:tools"
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/introspect" {
			t.Error("unexpected introspection request")
			w.WriteHeader(400)
			return
		}
		id, secret, ok := req.BasicAuth()
		if !ok || id != "client" || secret != "secret" {
			t.Error("missing introspection credentials")
			w.WriteHeader(401)
			return
		}
		_ = req.ParseForm()
		if req.Form.Get("token") != "access-token" {
			t.Error("unexpected access token")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "aud": func() string {
			if valid {
				return resourceURL
			}
			return "https://other.example.test"
		}(), "exp": time.Now().Add(time.Hour).Unix(), "iss": issuer, "scope": scope, "sub": "user-1"})
	}))
	defer idp.Close()
	r, err := New(config.OAuth{Resource: resourceURL, AuthorizationServer: issuer, IntrospectionURL: idp.URL + "/introspect", ClientID: "client", ClientSecret: "secret", Scopes: []string{"mcp:tools"}})
	if err != nil {
		t.Fatal(err)
	}
	protected := r.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	req := httptest.NewRequest(http.MethodGet, "http://localhost/mcp", nil)
	w := httptest.NewRecorder()
	protected.ServeHTTP(w, req)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), r.MetadataURL()) {
		t.Fatalf("challenge: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	req.Header.Set("Authorization", "Bearer access-token")
	w = httptest.NewRecorder()
	protected.ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("valid token: %d %s", w.Code, w.Body.String())
	}
	api := r.ProtectAPI(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tool-only token reached management API: %d", w.Code)
	}
	scope = "mcp:manage"
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("management token rejected: %d", w.Code)
	}
	scope = "mcp:tools"
	valid = false
	w = httptest.NewRecorder()
	protected.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("wrong audience: %d", w.Code)
	}
	metadata := httptest.NewRecorder()
	r.MetadataHandler().ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "http://localhost/.well-known/oauth-protected-resource", nil))
	if metadata.Code != 200 || !strings.Contains(metadata.Body.String(), resourceURL) || !strings.Contains(metadata.Body.String(), issuer) {
		t.Fatalf("metadata: %d %s", metadata.Code, metadata.Body.String())
	}
}
