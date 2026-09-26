package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

func TestAccountsWorkspaceIsolationAndClientTokens(t *testing.T) {
	path := t.TempDir() + "/accounts.enc"
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	store, err := catalog.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Accounts: &config.Accounts{AllowRegistration: true}, DownstreamAuth: &config.Auth{}, Token: "test-operator"}
	accounts := newAccountAuth(store, cfg)
	pol, _ := policy.New(config.Policy{Default: "allow"})
	auditLog, err := audit.Open(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs := newRuntimes(ctx, cfg, pol, auditLog, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer rs.close()
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", originOnly(http.HandlerFunc(accounts.authHandler), nil))
	mux.Handle("/api/status", accounts.protect(http.HandlerFunc(rs.status), true))
	mux.Handle("/api/connections", accounts.protect(http.HandlerFunc(rs.connections), true))
	mux.Handle("/mcp", accounts.protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]string{"owner": requestOwner(r)})
	}), false))
	request := func(method, path, body string, cookie *http.Cookie, token, header, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-MCPWarden-Request", header)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		return out
	}
	call := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		return request(method, path, body, cookie, "", "browser", "")
	}
	cookies := map[string]*http.Cookie{}
	ids := map[string]string{}
	for _, username := range []string{"alice", "bob"} {
		body := `{"username":"` + username + `","password":"synthetic long passphrase"}`
		out := call("POST", "/api/auth/register", body, nil)
		if out.Code != 200 {
			t.Fatalf("register %s: %d %s", username, out.Code, out.Body)
		}
		cookies[username] = out.Result().Cookies()[0]
		if !cookies[username].HttpOnly || cookies[username].SameSite != http.SameSiteStrictMode || cookies[username].Path != "/api/" {
			t.Fatal("unsafe session cookie attributes")
		}
		status := call("GET", "/api/status", "", cookies[username])
		if status.Code != 200 {
			t.Fatal(status.Code)
		}
		var payload struct {
			Session struct{ Mode, Subject, Username string }
		}
		if err := json.Unmarshal(status.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Session.Mode != "account" || payload.Session.Username != username {
			t.Fatalf("wrong identity: %+v", payload)
		}
		ids[username] = payload.Session.Subject
	}
	if ids["alice"] == ids["bob"] || ids["alice"] == "local" {
		t.Fatal("accounts share ownership")
	}
	for _, username := range []string{"alice", "bob"} {
		if err := store.Add(catalog.Entry{Owner: ids[username], Name: "same-name", URL: "https://" + username + ".example.test/mcp"}); err != nil {
			t.Fatal(err)
		}
		response := call("GET", "/api/connections", "", cookies[username])
		if response.Code != 200 || !strings.Contains(response.Body.String(), username+".example.test") {
			t.Fatalf("bad private inventory: %d", response.Code)
		}
		other := "bob"
		if username == "bob" {
			other = "alice"
		}
		if strings.Contains(response.Body.String(), other+".example.test") {
			t.Fatal("cross-account inventory leak")
		}
	}
	if out := request("POST", "/api/auth/login", `{"username":"alice","password":"synthetic long passphrase"}`, nil, "", "", ""); out.Code != 403 {
		t.Fatal("login CSRF accepted")
	}
	if out := request("POST", "/api/connections", `{}`, cookies["alice"], "", "", ""); out.Code != 403 {
		t.Fatal("mutation without request header accepted")
	}
	if out := request("POST", "/api/auth/login", `{}`, nil, "", "browser", "https://evil.example"); out.Code != 403 {
		t.Fatal("foreign origin accepted")
	}
	if out := call("POST", "/api/auth/login", `{"username":"alice","password":"wrong"}`, nil); out.Code != 401 {
		t.Fatal("wrong password accepted")
	}
	if out := call("POST", "/api/auth/register", `{"username":"alice","password":"synthetic long passphrase"}`, nil); out.Code != 409 {
		t.Fatal("duplicate registration accepted")
	}
	if out := call("POST", "/api/auth/register", `{"username":"short","password":"short"}`, nil); out.Code != 400 {
		t.Fatal("short password accepted")
	}
	tokenResponse := call("POST", "/api/auth/client-token", `{}`, cookies["alice"])
	var issued struct{ Token string }
	if tokenResponse.Code != 200 || json.Unmarshal(tokenResponse.Body.Bytes(), &issued) != nil || !strings.HasPrefix(issued.Token, "mw_") {
		t.Fatal("token not issued")
	}
	if out := request("GET", "/mcp", "", nil, issued.Token, "", ""); out.Code != 200 || !strings.Contains(out.Body.String(), ids["alice"]) {
		t.Fatal("client token did not select account")
	}
	if out := call("GET", "/mcp", "", cookies["alice"]); out.Code != 401 {
		t.Fatal("browser session accepted for MCP")
	}
	call("POST", "/api/auth/client-token", `{}`, cookies["alice"])
	if out := request("GET", "/mcp", "", nil, issued.Token, "", ""); out.Code != 401 {
		t.Fatal("rotated token still accepted")
	}
	if out := request("GET", "/api/status", "", nil, "test-operator", "", ""); out.Code != 200 || !strings.Contains(out.Body.String(), `"subject":"local"`) {
		t.Fatal("operator compatibility broken")
	}
	login := call("POST", "/api/auth/login", `{"username":"alice","password":"synthetic long passphrase"}`, cookies["alice"])
	if login.Code != 200 {
		t.Fatal("login failed")
	}
	old := cookies["alice"]
	cookies["alice"] = login.Result().Cookies()[0]
	if out := call("GET", "/api/status", "", old); out.Code != 401 {
		t.Fatal("old session survived sign-in rotation")
	}
	call("POST", "/api/auth/logout", `{}`, cookies["alice"])
	if out := call("GET", "/api/status", "", cookies["alice"]); out.Code != 401 {
		t.Fatal("logged-out session accepted")
	}
	accounts.mu.Lock()
	for k, s := range accounts.sessions {
		s.expires = time.Now().Add(-time.Second)
		accounts.sessions[k] = s
	}
	accounts.mu.Unlock()
	if out := call("GET", "/api/status", "", cookies["bob"]); out.Code != 401 {
		t.Fatal("expired session accepted")
	}
	reopened, err := catalog.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	account, found := reopened.Account("alice")
	if !found || account.ID != ids["alice"] || len(account.PasswordHash) != 32 || account.Iterations != passwordIterations {
		t.Fatal("account did not persist")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "synthetic long passphrase") || strings.Contains(string(raw), "private-alice") || strings.Contains(string(raw), issued.Token) {
		t.Fatal("plaintext material persisted")
	}
	cfg.Accounts.AllowRegistration = false
	if out := call("POST", "/api/auth/register", `{"username":"newuser","password":"synthetic long passphrase"}`, nil); out.Code != 403 {
		t.Fatal("registration closure ignored")
	}
}

func TestAccountAuthCannotFallbackWithoutOperatorToken(t *testing.T) {
	store, err := catalog.Open(t.TempDir()+"/store", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	a := newAccountAuth(store, config.Config{Accounts: &config.Accounts{}})
	handler := a.protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("bypassed account auth") }), true)
	req := httptest.NewRequest("GET", "http://localhost/api/status", nil)
	req.Header.Set("Authorization", "Bearer arbitrary")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 401 {
		t.Fatal(out.Code)
	}
}

func TestChangePasswordRequiresCurrentAndRevokesOtherBrowsers(t *testing.T) {
	store, err := catalog.Open(t.TempDir()+"/store", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	accounts := newAccountAuth(store, config.Config{Accounts: &config.Accounts{AllowRegistration: true}})
	call := func(path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://localhost"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-MCPWarden-Request", "browser")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		accounts.authHandler(w, req)
		return w
	}
	original := `{"username":"alice","password":"original synthetic password"}`
	first := call("/api/auth/register", original, nil)
	if first.Code != 200 {
		t.Fatal(first.Code)
	}
	cookie := first.Result().Cookies()[0]
	second := call("/api/auth/login", original, nil)
	if second.Code != 200 {
		t.Fatal(second.Code)
	}
	other := second.Result().Cookies()[0]
	if got := call("/api/auth/password", `{"current_password":"wrong","new_password":"replacement synthetic password"}`, cookie); got.Code != 400 {
		t.Fatal(got.Code)
	}
	if got := call("/api/auth/password", `{"current_password":"original synthetic password","new_password":"replacement synthetic password"}`, nil); got.Code != 401 {
		t.Fatal(got.Code)
	}
	changed := call("/api/auth/password", `{"current_password":"original synthetic password","new_password":"replacement synthetic password"}`, cookie)
	if changed.Code != 204 {
		t.Fatal(changed.Code)
	}
	req := httptest.NewRequest("GET", "http://localhost/api/status", nil)
	req.AddCookie(other)
	if _, ok := accounts.session(req); ok {
		t.Fatal("other browser survived")
	}
	req = httptest.NewRequest("GET", "http://localhost/api/status", nil)
	req.AddCookie(cookie)
	if _, ok := accounts.session(req); !ok {
		t.Fatal("current browser revoked")
	}
	if got := call("/api/auth/login", original, nil); got.Code != 401 {
		t.Fatal("old password works")
	}
	if got := call("/api/auth/login", `{"username":"alice","password":"replacement synthetic password"}`, nil); got.Code != 200 {
		t.Fatal("new password rejected")
	}
}
