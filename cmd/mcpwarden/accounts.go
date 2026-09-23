package main

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
)

const sessionCookie = "mcpwarden_session"
const passwordIterations = 600000

type accountIdentity struct{ Owner, Username, Role, AccessID string }
type accountContextKey struct{}
type browserSession struct {
	identity accountIdentity
	expires  time.Time
}
type accountAuth struct {
	store    catalog.Repository
	cfg      config.Config
	mu       sync.Mutex
	sessions map[string]browserSession
	window   time.Time
	attempts int
	hashing  chan struct{}
	onRevoke func(string)
	// guard routes API-key revocation through the owner lease coordinator.
	guard accessGuard
	// sessionGuard serializes session/password revocation without ending leases.
	sessionGuard accessGuard
}

// accessGuard runs a mutation that can revoke an API key. With owner security
// enabled it first ends that owner's access windows; otherwise it just runs.
type accessGuard func(ctx context.Context, owner string, mutation func() error) error

func (g accessGuard) run(ctx context.Context, owner string, mutation func() error) error {
	if g == nil {
		return mutation()
	}
	return g(ctx, owner, mutation)
}
func (a *accountAuth) change(ctx context.Context, owner string, mutation func() error) error {
	return a.guard.run(ctx, owner, mutation)
}

func newAccountAuth(store catalog.Repository, cfg config.Config) *accountAuth {
	return &accountAuth{store: store, cfg: cfg, sessions: map[string]browserSession{}, hashing: make(chan struct{}, 2)}
}
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func randomToken() string    { return base64.RawURLEncoding.EncodeToString(randBytes(32)) }
func randBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
func accountFromRequest(r *http.Request) (accountIdentity, bool) {
	identity, ok := r.Context().Value(accountContextKey{}).(accountIdentity)
	return identity, ok
}
func (a *accountAuth) session(r *http.Request) (accountIdentity, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return accountIdentity{}, false
	}
	key := tokenHash(cookie.Value)
	a.mu.Lock()
	cached, known := a.sessions[key]
	a.mu.Unlock()
	if known && !cached.expires.After(time.Now()) {
		return accountIdentity{}, false
	}
	record, ok := a.store.AuthenticateAccess(key, "browser")
	if !ok {
		return accountIdentity{}, false
	}
	user, ok := a.store.AccountOwner(record.Owner)
	return accountIdentity{Owner: user.ID, Username: user.Username, Role: "admin", AccessID: record.ID}, ok
}
func (a *accountAuth) protect(next http.Handler, allowCookie bool, clientAction ...bool) http.Handler {
	return originOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var identity accountIdentity
		var ok bool
		authorization := r.Header.Get("Authorization")
		if isAPIKeyAuthorization(authorization) {
			record, found := authenticateAPIKey(a.store, strings.TrimPrefix(authorization, "Bearer "))
			user, _ := a.store.AccountOwner(record.Owner)
			identity, ok = accountIdentity{Owner: record.Owner, Username: user.Username, Role: record.Role, AccessID: record.ID}, found
		} else if authorization != "" && a.cfg.DownstreamAuth != nil && a.cfg.Token != "" {
			protected(next, a.cfg).ServeHTTP(w, r)
			return
		} else if allowCookie {
			identity, ok = a.session(r)
			if ok && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-MCPWarden-Request") != "browser" {
				http.Error(w, "request header required", http.StatusForbidden)
				return
			}
		}
		if !ok {
			http.Error(w, "sign in required", http.StatusUnauthorized)
			return
		}
		if allowCookie && (len(clientAction) == 0 || !clientAction[0]) && identity.Role != "admin" {
			http.Error(w, "management credential required", 403)
			return
		}
		record, _ := a.store.AccessByID(identity.Owner, identity.AccessID)
		ctx := context.WithValue(r.Context(), accountContextKey{}, identity)
		next.ServeHTTP(w, r.WithContext(withAccess(ctx, record)))
	}), a.cfg.Origins)
}
func (a *accountAuth) setCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || ip != nil && ip.IsLoopback()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/api/", HttpOnly: true, Secure: r.TLS != nil || !loopback, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}
func (a *accountAuth) startSession(w http.ResponseWriter, r *http.Request, user catalog.Account) {
	token := randomToken()
	now := time.Now()
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if old, ok := a.store.AuthenticateAccess(tokenHash(cookie.Value), "browser"); ok {
			if err := a.sessionGuard.run(r.Context(), old.Owner, func() error { return a.store.RevokeAccess(old.Owner, old.ID) }); err != nil {
				http.Error(w, "could not rotate session", 500)
				return
			}
			if a.onRevoke != nil {
				a.onRevoke(old.ID)
			}
		}
	}
	record := catalog.AccessRecord{ID: identity.New(), Owner: user.ID, Name: deviceName(r.UserAgent()), Device: r.UserAgent(), Kind: "browser", Role: "admin", SecretHash: tokenHash(token), ExpiresAt: now.Add(12 * time.Hour)}
	if len(record.Device) > 300 {
		record.Device = record.Device[:300]
	}
	if err := a.store.AddAccess(record); err != nil {
		http.Error(w, "session limit reached or session could not be saved", 409)
		return
	}
	a.mu.Lock()
	for key, s := range a.sessions {
		if !s.expires.After(now) {
			delete(a.sessions, key)
		}
	}
	// Replace this browser's old session when switching accounts.
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		delete(a.sessions, tokenHash(cookie.Value))
	}
	a.sessions[tokenHash(token)] = browserSession{accountIdentity{Owner: user.ID, Username: user.Username, Role: "admin", AccessID: record.ID}, now.Add(12 * time.Hour)}
	a.mu.Unlock()
	a.setCookie(w, r, token, 12*60*60)
	jsonResponse(w, http.StatusOK, map[string]string{"username": user.Username})
}
func (a *accountAuth) authHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	if r.Header.Get("X-MCPWarden-Request") != "browser" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "JSON and request header required", 403)
		return
	}
	if r.URL.Path == "/api/auth/logout" {
		if current, ok := a.session(r); ok {
			if err := a.sessionGuard.run(r.Context(), current.Owner, func() error { return a.store.RevokeAccess(current.Owner, current.AccessID) }); err != nil {
				http.Error(w, "could not revoke session", 500)
				return
			}
			if a.onRevoke != nil {
				a.onRevoke(current.AccessID)
			}
		}
		if cookie, err := r.Cookie(sessionCookie); err == nil {
			a.mu.Lock()
			delete(a.sessions, tokenHash(cookie.Value))
			a.mu.Unlock()
		}
		a.setCookie(w, r, "", -1)
		w.WriteHeader(204)
		return
	}
	if r.URL.Path == "/api/auth/client-token" {
		identity, ok := a.session(r)
		if !ok {
			http.Error(w, "sign in required", 401)
			return
		}
		token := "mw_" + randomToken()
		if err := a.change(r.Context(), identity.Owner, func() error { return a.store.SetClientToken(identity.Username, tokenHash(token)) }); err != nil {
			http.Error(w, "token could not be saved", 500)
			return
		}
		jsonResponse(w, 200, map[string]string{"token": token})
		return
	}
	if r.URL.Path != "/api/auth/register" && r.URL.Path != "/api/auth/login" && r.URL.Path != "/api/auth/password" {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/api/auth/register" && !a.cfg.Accounts.AllowRegistration {
		http.Error(w, "registration is closed", 403)
		return
	}
	if !a.allowAttempt() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts", 429)
		return
	}
	select {
	case a.hashing <- struct{}{}:
		defer func() { <-a.hashing }()
	default:
		http.Error(w, "try again shortly", 429)
		return
	}
	if r.URL.Path == "/api/auth/password" {
		a.changePassword(w, r)
		return
	}
	var input struct{ Username, Password string }
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || len(input.Password) > 1024 {
		http.Error(w, "invalid credentials", 400)
		return
	}
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`).MatchString(input.Username) {
		http.Error(w, "invalid username", 400)
		return
	}
	if r.URL.Path == "/api/auth/register" {
		if utf8.RuneCountInString(input.Password) < 15 {
			http.Error(w, "password must have at least 15 characters", 400)
			return
		}
		salt := randBytes(16)
		hash, err := pbkdf2.Key(sha256.New, input.Password, salt, passwordIterations, 32)
		if err != nil {
			http.Error(w, "registration failed", 500)
			return
		}
		user := catalog.Account{ID: "account:" + randomToken(), Username: input.Username, Salt: salt, PasswordHash: hash, Iterations: passwordIterations}
		if err := a.store.AddAccount(user); err != nil {
			http.Error(w, "registration could not be completed", 409)
			return
		}
		a.startSession(w, r, user)
		return
	}
	user, found := a.store.Account(input.Username)
	if !found {
		user.Salt = make([]byte, 16)
		user.Iterations = passwordIterations
		user.PasswordHash = make([]byte, 32)
	}
	hash, err := pbkdf2.Key(sha256.New, input.Password, user.Salt, user.Iterations, 32)
	if err != nil || subtle.ConstantTimeCompare(hash, user.PasswordHash) != 1 || !found {
		http.Error(w, "username or password incorrect", 401)
		return
	}
	a.startSession(w, r, user)
}

// allowAttempt is the shared password-attempt window for login, registration,
// password changes and fresh verification before owner security changes.
func (a *accountAuth) allowAttempt() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Since(a.window) >= time.Minute {
		a.window = time.Now()
		a.attempts = 0
	}
	a.attempts++
	return a.attempts <= 30
}

// passwordProof binds a completed password check to the exact stored verifier.
// Rechecking it under the owner gate keeps expensive hashing outside that gate.
type passwordProof struct {
	owner, username string
	hash            []byte
}

func (a *accountAuth) passwordUnchanged(p passwordProof) bool {
	account, ok := a.store.Account(p.username)
	return ok && account.ID == p.owner && len(p.hash) != 0 && subtle.ConstantTimeCompare(account.PasswordHash, p.hash) == 1
}

// verifyCurrentPassword returns proof and status 0 on success, or an HTTP error
// status. The proof must be checked again in the authorized owner transaction.
func (a *accountAuth) verifyCurrentPassword(owner, password string) (passwordProof, int) {
	if password == "" || len(password) > 1024 {
		return passwordProof{}, http.StatusBadRequest
	}
	if !a.allowAttempt() {
		return passwordProof{}, http.StatusTooManyRequests
	}
	select {
	case a.hashing <- struct{}{}:
		defer func() { <-a.hashing }()
	default:
		return passwordProof{}, http.StatusTooManyRequests
	}
	user, ok := a.store.AccountOwner(owner)
	if !ok {
		return passwordProof{}, http.StatusForbidden
	}
	account, ok := a.store.Account(user.Username)
	if !ok || account.ID != owner {
		return passwordProof{}, http.StatusForbidden
	}
	hash, err := pbkdf2.Key(sha256.New, password, account.Salt, account.Iterations, 32)
	defer clear(hash)
	if err != nil || subtle.ConstantTimeCompare(hash, account.PasswordHash) != 1 {
		return passwordProof{}, http.StatusForbidden
	}
	return passwordProof{owner: owner, username: account.Username, hash: append([]byte(nil), account.PasswordHash...)}, 0
}

func (a *accountAuth) changePassword(w http.ResponseWriter, r *http.Request) {
	current, ok := a.session(r)
	if !ok {
		http.Error(w, "sign in required", 401)
		return
	}
	var input struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if dec.Decode(&input) != nil || len(input.Current) > 1024 || len(input.New) > 1024 || utf8.RuneCountInString(input.New) < 15 {
		http.Error(w, "invalid password", 400)
		return
	}
	account, ok := a.store.Account(current.Username)
	if !ok {
		http.Error(w, "account unavailable", 401)
		return
	}
	oldHash, err := pbkdf2.Key(sha256.New, input.Current, account.Salt, account.Iterations, 32)
	if err != nil || subtle.ConstantTimeCompare(oldHash, account.PasswordHash) != 1 {
		http.Error(w, "current password incorrect", 400)
		return
	}
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		http.Error(w, "password update failed", 500)
		return
	}
	hash, err := pbkdf2.Key(sha256.New, input.New, salt, passwordIterations, 32)
	if err != nil {
		http.Error(w, "password update failed", 500)
		return
	}
	var ids []string
	err = a.sessionGuard.run(r.Context(), current.Owner, func() error {
		// Logout or session replacement may have completed while hashing.
		again, ok := a.session(r)
		if !ok || again.Owner != current.Owner || again.AccessID != current.AccessID {
			return errors.New("browser session no longer active")
		}
		var err error
		ids, err = a.store.ChangePassword(current.Username, account.PasswordHash, salt, hash, passwordIterations, current.AccessID)
		return err
	})
	if err != nil {
		http.Error(w, "password update failed", 409)
		return
	}
	if a.onRevoke != nil {
		for _, id := range ids {
			a.onRevoke(id)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
