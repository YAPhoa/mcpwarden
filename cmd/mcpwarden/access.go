package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
)

type accessContextKey struct{}

func withAccess(ctx context.Context, r catalog.AccessRecord) context.Context {
	r.SecretHash = ""
	actor := identity.Actor{Owner: r.Owner, Kind: r.Kind}
	// Storeless legacy operator/OAuth IDs contain verifier hashes. They must
	// never enter audit or public display metadata as access identifiers.
	if r.Kind == "api_key" || r.Kind == "browser" || r.Kind == "oauth" && identity.Valid(r.ID) {
		actor.AccessID, actor.PublicID, actor.Label = r.ID, r.PublicID, r.Name
	}
	return identity.WithActor(context.WithValue(ctx, accessContextKey{}, r), actor)
}
func accessFrom(ctx context.Context) (catalog.AccessRecord, bool) {
	r, ok := ctx.Value(accessContextKey{}).(catalog.AccessRecord)
	return r, ok
}
func deviceName(ua string) string {
	browser := "Browser"
	switch {
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	os := ""
	switch {
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "iPhone"):
		os = "iPhone"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}
	if os != "" {
		browser += " on " + os
	}
	return browser
}

type activeMCP struct {
	record  catalog.AccessRecord
	session *mcp.ServerSession
}
type accessManager struct {
	closing  bool
	cleanup  sync.WaitGroup
	store    catalog.Repository
	mu       sync.Mutex
	sessions map[*mcp.ServerSession]activeMCP
}

func newAccessManager(s catalog.Repository) *accessManager {
	return &accessManager{store: s, sessions: map[*mcp.ServerSession]activeMCP{}}
}

// Bind SDK sessions to a credential AND role, not just an account. This prevents
// a client key from reusing an admin session belonging to the same owner.
func (a *accessManager) bindMCP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential, ok := accessFrom(r.Context())
		if !ok {
			http.Error(w, "authenticated access required", 401)
			return
		}
		if credential.Kind == "operator" && r.Header.Get("Authorization") == "" {
			next.ServeHTTP(w, r)
			return
		}
		auth.RequireBearerToken(func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
			return &auth.TokenInfo{UserID: credential.ID + ":" + credential.Role, Expiration: credential.ExpiresAt}, nil
		}, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(next).ServeHTTP(w, r)
	})
}
func (a *accessManager) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		credential, ok := accessFrom(ctx)
		// Local stdio sessions have no HTTP credential and expose the client view.
		if !ok {
			return next(ctx, method, req)
		}
		if a.store != nil && credential.Kind != "operator" {
			if err := a.store.TouchAccess(credential.Owner, credential.ID); err != nil {
				return nil, errors.New("access revoked or expired")
			}
			current, found := a.store.AccessByID(credential.Owner, credential.ID)
			if !found || !current.Active() || current.Role != credential.Role || current.Kind != credential.Kind {
				return nil, errors.New("access revoked or changed")
			}
			// Stateful SDK handlers retain the initialization context. Refresh
			// the safe label snapshot from this exact record on every request.
			credential = current
			ctx = withAccess(ctx, current)
		}
		session, _ := req.GetSession().(*mcp.ServerSession)
		if session == nil {
			return next(ctx, method, req)
		}
		a.mu.Lock()
		if a.closing {
			a.mu.Unlock()
			return nil, errors.New("gateway shutting down")
		}
		active, exists := a.sessions[session]
		if !exists {
			// Recheck under the same lock used by revocation's session scan.
			if a.store != nil && credential.Kind != "operator" {
				if err := a.store.TouchAccess(credential.Owner, credential.ID); err != nil {
					a.mu.Unlock()
					go session.Close()
					return nil, errors.New("credential revoked or expired")
				}
			}
			if method != "initialize" {
				a.mu.Unlock()
				return nil, errors.New("initialize a new session")
			}
			count := 0
			for _, s := range a.sessions {
				if s.record.Owner == credential.Owner {
					count++
				}
			}
			if count >= catalog.MaxMCPSessions {
				a.mu.Unlock()
				go session.Close()
				return nil, errors.New("MCP connection limit reached (10)")
			}
			name := "MCP client"
			if p, ok := req.GetParams().(*mcp.InitializeParams); ok && p.ClientInfo != nil {
				name = p.ClientInfo.Name
				if len(name) > 100 {
					name = name[:100]
				}
			}
			if strings.TrimSpace(name) == "" {
				name = "MCP client"
			}
			record := catalog.AccessRecord{ID: identity.New(), Owner: credential.Owner, Name: name, Device: name, Kind: "mcp", Role: credential.Role, ParentID: credential.ID, SecretHash: tokenHash(randomToken()), ExpiresAt: credential.ExpiresAt}
			if a.store != nil {
				if err := a.store.AddAccess(record); err != nil {
					a.mu.Unlock()
					go session.Close()
					return nil, errors.New("MCP connection limit reached or session could not be saved")
				}
			}
			active = activeMCP{record, session}
			a.sessions[session] = active
			var expiryTimer *time.Timer
			if !record.ExpiresAt.IsZero() {
				expiryTimer = time.AfterFunc(time.Until(record.ExpiresAt), func() { _ = session.Close() })
			}
			a.cleanup.Add(1)
			go func() {
				defer a.cleanup.Done()
				_ = session.Wait()
				if expiryTimer != nil {
					expiryTimer.Stop()
				}
				a.mu.Lock()
				delete(a.sessions, session)
				a.mu.Unlock()
				if a.store != nil {
					_ = a.store.UpdateAccess(record.Owner, record.ID, "", true)
				}
			}()

		}
		a.mu.Unlock()
		if active.record.ParentID != credential.ID || active.record.Role != credential.Role {
			return nil, errors.New("session credential mismatch")
		}
		if a.store != nil {
			if err := a.store.TouchAccess(credential.Owner, active.record.ID); err != nil {
				return nil, errors.New("session revoked or expired")
			}
		}
		return next(ctx, method, req)
	}
}
func (a *accessManager) closeCredential(id string) {
	a.mu.Lock()
	var close []*mcp.ServerSession
	for _, active := range a.sessions {
		if active.record.ID == id || active.record.ParentID == id {
			close = append(close, active.session)
		}
	}
	a.mu.Unlock()
	for _, session := range close {
		_ = session.Close()
	}
}
func (a *accessManager) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.store == nil {
		http.Error(w, "access storage is not configured", 501)
		return
	}
	current, _ := accessFrom(r.Context())
	owner := requestOwner(r)
	id := strings.TrimPrefix(r.URL.Path, "/api/access/")
	if r.URL.Path == "/api/access" {
		switch r.Method {
		case http.MethodGet:
			jsonResponse(w, 200, map[string]any{"items": a.store.AccessList(owner), "current_id": current.ID, "limits": map[string]int{"api_keys": catalog.MaxAPIKeys, "login_sessions": catalog.MaxLoginSessions, "mcp_connections": catalog.MaxMCPSessions}})
		case http.MethodPost:
			var input struct {
				Name        string `json:"name"`
				Role        string `json:"role"`
				ExpiresDays int    `json:"expires_days"`
			}
			d := json.NewDecoder(io.LimitReader(r.Body, 4096))
			d.DisallowUnknownFields()
			if d.Decode(&input) != nil || strings.TrimSpace(input.Name) == "" || len(input.Name) > 100 || (input.Role != "admin" && input.Role != "client") || input.ExpiresDays < 1 || input.ExpiresDays > 365 {
				http.Error(w, "name, role, and expiry of 1–365 days required", 400)
				return
			}
			token, publicID := identity.NewAccessToken()
			record := catalog.AccessRecord{ID: identity.New(), PublicID: publicID, Owner: owner, Name: strings.TrimSpace(input.Name), Kind: "api_key", Role: input.Role, SecretHash: tokenHash(token), ExpiresAt: time.Now().UTC().Add(time.Duration(input.ExpiresDays) * 24 * time.Hour)}
			if err := a.store.AddAccess(record); err != nil {
				http.Error(w, "API key limit reached or key could not be saved", 409)
				return
			}
			jsonResponse(w, 201, map[string]string{"id": record.ID, "public_id": publicID, "token": token})
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", 405)
		}
		return
	}
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	if _, ok := a.store.AccessByID(owner, id); !ok {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := a.store.RevokeAccess(owner, id); err != nil {
			http.Error(w, "could not revoke access", 500)
			return
		}
		a.closeCredential(id)
		w.WriteHeader(204)
	case http.MethodPatch:
		var input struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input) != nil || strings.TrimSpace(input.Name) == "" || len(input.Name) > 100 {
			http.Error(w, "valid name required", 400)
			return
		}
		if err := a.store.UpdateAccess(owner, id, strings.TrimSpace(input.Name), false); err != nil {
			http.Error(w, "could not rename access", 500)
			return
		}
		w.WriteHeader(204)
	default:
		w.Header().Set("Allow", "DELETE, PATCH")
		http.Error(w, "method not allowed", 405)
	}
}

func (a *accessManager) keys(next http.Handler, management bool, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("Authorization")
		if !isAPIKeyAuthorization(value) {
			fallback.ServeHTTP(w, r)
			return
		}
		if a.store == nil {
			http.Error(w, "API keys not configured", 401)
			return
		}
		record, ok := authenticateAPIKey(a.store, strings.TrimPrefix(value, "Bearer "))
		if !ok {
			http.Error(w, "invalid, revoked, or expired API key", 401)
			return
		}
		if management && record.Role != "admin" {
			http.Error(w, "management credential required", 403)
			return
		}
		next.ServeHTTP(w, r.WithContext(withAccess(r.Context(), record)))
	})
}

func isAPIKeyAuthorization(value string) bool {
	return strings.HasPrefix(value, "Bearer mw_") || strings.HasPrefix(value, "Bearer mcpw_")
}

func authenticateAPIKey(store catalog.Repository, token string) (catalog.AccessRecord, bool) {
	var publicID string
	if strings.HasPrefix(token, "mcpw_") {
		var ok bool
		publicID, ok = identity.ParseAccessToken(token)
		if !ok {
			return catalog.AccessRecord{}, false
		}
	} else if !strings.HasPrefix(token, "mw_") {
		return catalog.AccessRecord{}, false
	}
	record, ok := store.AuthenticateAccess(tokenHash(token), "api_key")
	if !ok || publicID != "" && record.PublicID != publicID {
		return catalog.AccessRecord{}, false
	}
	return record, true
}

func (a *accessManager) close() {
	a.mu.Lock()
	a.closing = true
	sessions := make([]*mcp.ServerSession, 0, len(a.sessions))
	for s := range a.sessions {
		sessions = append(sessions, s)
	}
	a.mu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
	a.cleanup.Wait()
}
