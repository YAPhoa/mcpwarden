package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/yaphoa/mcpwarden/internal/config"
)

// Resource uses the SDK's OAuth middleware and protected-resource metadata.
// The external authorization server owns login, client registration, and token issuance.
type Resource struct {
	Observe     func(context.Context, string, *auth.TokenInfo, *http.Request) (context.Context, error)
	cfg         config.OAuth
	client      *http.Client
	metadataURL string
}

func New(cfg config.OAuth) (*Resource, error) {
	u, err := url.Parse(cfg.Resource)
	if err != nil {
		return nil, fmt.Errorf("oauth resource URL: %w", err)
	}
	return &Resource{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}, metadataURL: u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource"}, nil
}
func (r *Resource) MetadataURL() string { return r.metadataURL }
func (r *Resource) MetadataHandler() http.Handler {
	scopes := append([]string(nil), r.cfg.Scopes...)
	manageScope := r.cfg.ManageScope
	if manageScope == "" {
		manageScope = "mcp:manage"
	}
	if !slices.Contains(scopes, manageScope) {
		scopes = append(scopes, manageScope)
	}
	return auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource: r.cfg.Resource, AuthorizationServers: []string{r.cfg.AuthorizationServer},
		ScopesSupported: scopes, BearerMethodsSupported: []string{"header"}, ResourceName: "mcpwarden",
	})
}
func (r *Resource) ProtectAPI(next http.Handler) http.Handler {
	scope := r.cfg.ManageScope
	if scope == "" {
		scope = "mcp:manage"
	}
	return r.protect(next, []string{scope})
}
func (r *Resource) Protect(next http.Handler) http.Handler {
	return r.protect(next, nil)
}
func (r *Resource) verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.cfg.ClientID, r.cfg.ClientSecret)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspect token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection endpoint returned HTTP %d", resp.StatusCode)
	}
	var v struct {
		Active     bool            `json:"active"`
		Audience   json.RawMessage `json:"aud"`
		Expiration int64           `json:"exp"`
		Issuer     string          `json:"iss"`
		Scope      string          `json:"scope"`
		Subject    string          `json:"sub"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return nil, fmt.Errorf("decode introspection response: %w", err)
	}
	if !v.Active || v.Expiration <= time.Now().Unix() || (v.Issuer != "" && v.Issuer != r.cfg.AuthorizationServer) {
		return nil, auth.ErrInvalidToken
	}
	var audience []string
	if len(v.Audience) != 0 {
		var one string
		if json.Unmarshal(v.Audience, &one) == nil {
			audience = []string{one}
		} else if json.Unmarshal(v.Audience, &audience) != nil {
			return nil, auth.ErrInvalidToken
		}
	}
	if !slices.Contains(audience, r.cfg.Resource) {
		return nil, auth.ErrInvalidToken
	}
	if v.Subject == "" {
		return nil, auth.ErrInvalidToken
	}
	return &auth.TokenInfo{Scopes: strings.Fields(v.Scope), Expiration: time.Unix(v.Expiration, 0), UserID: v.Subject}, nil
}

func (r *Resource) protect(next http.Handler, required []string) http.Handler {
	return auth.RequireBearerToken(r.verify, &auth.RequireBearerTokenOptions{ResourceMetadataURL: r.metadataURL, Scopes: required})(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		info := auth.TokenInfoFromContext(req.Context())
		if required == nil {
			manage := r.cfg.ManageScope
			if manage == "" {
				manage = "mcp:manage"
			}
			allowed := slices.Contains(info.Scopes, manage)
			if !allowed {
				allowed = true
				for _, scope := range r.cfg.Scopes {
					if !slices.Contains(info.Scopes, scope) {
						allowed = false
					}
				}
			}
			if !allowed {
				http.Error(w, "MCP scope required", 403)
				return
			}
		}
		if r.Observe != nil {
			ctx, err := r.Observe(req.Context(), strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), info, req)
			if err != nil {
				http.Error(w, "OAuth access revoked or session limit reached", 401)
				return
			}
			req = req.WithContext(ctx)
		}
		next.ServeHTTP(w, req)
	}))
}
