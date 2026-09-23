// Package upstreamauth connects the SDK OAuth client to encrypted per-user storage.
package upstreamauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"golang.org/x/oauth2"
)

var ErrSignIn = errors.New("upstream OAuth sign-in required")

type pending struct {
	owner, name, binding string
	result               chan *auth.AuthorizationResult
	done                 chan error
	cancel               context.CancelFunc
}
type Service struct {
	store catalog.Repository
	mu    sync.Mutex
	flows map[string]*pending
}

func New(store catalog.Repository) *Service {
	return &Service{store: store, flows: map[string]*pending{}}
}

// Every discovered destination is checked; redirects cannot forward credentials.
type checkedTransport struct {
	base          http.RoundTripper
	allowLoopback bool
}

func (t checkedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	u := *r.URL
	u.RawQuery = ""
	if catalog.ValidateEndpoint(u.String()) != nil || (u.Scheme != "https" && !t.allowLoopback) {
		return nil, errors.New("invalid OAuth endpoint")
	}
	return t.base.RoundTrip(r)
}
func client(endpoint string) *http.Client {
	u, _ := url.Parse(endpoint)
	return &http.Client{Timeout: 15 * time.Second, Transport: checkedTransport{http.DefaultTransport, u.Scheme == "http"}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type savedSource struct {
	mu             sync.Mutex
	source         oauth2.TokenSource
	store          catalog.Repository
	owner, entryID string
	grant          catalog.OAuthGrant
}

func (s *savedSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := s.source.Token()
	if err != nil {
		return nil, ErrSignIn
	} // OAuth errors can include token endpoint response bodies.
	if token.AccessToken != s.grant.Token.AccessToken || token.RefreshToken != s.grant.Token.RefreshToken || !token.Expiry.Equal(s.grant.Token.Expiry) {
		next := s.grant
		next.Token = *token
		if err := s.store.SaveOAuth(s.owner, s.entryID, s.grant.ID, next); err != nil {
			return nil, errors.New("could not persist upstream OAuth token")
		}
		s.grant = next
	}
	return token, nil
}
func (s *Service) source(e catalog.Entry, grant catalog.OAuthGrant) oauth2.TokenSource {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client(e.URL))
	return &savedSource{source: grant.Config.TokenSource(ctx, &grant.Token), store: s.store, owner: e.Owner, entryID: e.ID, grant: grant}
}

type passiveHandler struct{ source oauth2.TokenSource }

func (h passiveHandler) TokenSource(context.Context) (oauth2.TokenSource, error) {
	return h.source, nil
}
func (h passiveHandler) Authorize(_ context.Context, _ *http.Request, r *http.Response) error {
	r.Body.Close()
	return ErrSignIn
}

// Background reconnects never open a browser or start consent on their own.
func (s *Service) Handler(e catalog.Entry) auth.OAuthHandler {
	var source oauth2.TokenSource
	if e.OAuth != nil && e.OAuth.Grant != nil {
		source = s.source(e, *e.OAuth.Grant)
	}
	return passiveHandler{source}
}

type Started struct{ URL, State, Binding string }

func (s *Service) Start(parent context.Context, e catalog.Entry, redirect string) (Started, error) {
	if e.OAuth == nil || e.AuthType != "oauth" {
		return Started{}, errors.New("connection does not use OAuth")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	p := &pending{owner: e.Owner, name: e.Name, binding: rand.Text(), result: make(chan *auth.AuthorizationResult, 1), done: make(chan error, 1), cancel: cancel}
	ready := make(chan Started, 1)
	state := ""
	cfg := &auth.AuthorizationCodeHandlerConfig{RedirectURL: redirect, Client: client(e.URL), RequestRefreshToken: true,
		AuthorizationCodeFetcher: func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			u, err := url.Parse(args.URL)
			if err != nil {
				return nil, errors.New("invalid authorization URL")
			}
			checked := *u
			checked.RawQuery = ""
			endpoint, _ := url.Parse(e.URL)
			if catalog.ValidateEndpoint(checked.String()) != nil || (u.Scheme != "https" && endpoint.Scheme != "http") {
				return nil, errors.New("invalid authorization URL")
			}
			state = u.Query().Get("state")
			s.mu.Lock()
			if len(s.flows) >= 256 {
				s.mu.Unlock()
				return nil, errors.New("too many pending authorizations")
			}
			s.flows[state] = p
			s.mu.Unlock()
			ready <- Started{URL: args.URL, State: state, Binding: p.binding}
			select {
			case result := <-p.result:
				return result, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		NewTokenSource: func(_ context.Context, cfg *oauth2.Config, token *oauth2.Token) (oauth2.TokenSource, error) {
			previous := ""
			if e.OAuth.Grant != nil {
				previous = e.OAuth.Grant.ID
			}
			grant := catalog.OAuthGrant{ID: identity.New(), Config: *cfg, Token: *token}
			if err := s.store.SaveOAuth(e.Owner, e.ID, previous, grant); err != nil {
				return nil, err
			}
			return s.source(e, grant), nil
		},
	}
	if e.OAuth.ClientID != "" {
		cfg.PreregisteredClient = &oauthex.ClientCredentials{ClientID: e.OAuth.ClientID, Issuer: e.OAuth.Issuer}
		if e.OAuth.ClientSecret != "" {
			cfg.PreregisteredClient.ClientSecretAuth = &oauthex.ClientSecretAuth{ClientSecret: e.OAuth.ClientSecret}
		}
	} else {
		cfg.DynamicClientRegistrationConfig = &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{ClientName: "MCPWarden", RedirectURIs: []string{redirect}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none"}}
	}
	if len(e.OAuth.Scopes) > 0 {
		cfg.ScopeFilter = func([]string) []string { return append([]string(nil), e.OAuth.Scopes...) }
	}
	handler, err := auth.NewAuthorizationCodeHandler(cfg)
	if err != nil {
		cancel()
		return Started{}, errors.New("invalid OAuth client configuration")
	}
	go func() {
		defer cancel()
		defer func() { s.mu.Lock(); delete(s.flows, state); s.mu.Unlock() }()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"mcpwarden","version":"0.1.0"}}}`))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			var response *http.Response
			response, err = cfg.Client.Do(req)
			if err == nil {
				if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
					err = handler.Authorize(ctx, req, response)
				} else {
					response.Body.Close()
					err = errors.New("upstream did not offer OAuth authentication")
				}
			}
		}
		if err != nil {
			err = errors.New("upstream OAuth authorization failed; check the server and client configuration")
		}
		p.done <- err
	}()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case started := <-ready:
		return started, nil
	case err := <-p.done:
		cancel()
		return Started{}, err
	case <-timer.C:
		cancel()
		return Started{}, errors.New("OAuth discovery timed out")
	case <-parent.Done():
		cancel()
		return Started{}, parent.Err()
	}
}

// Complete requires both the random SDK state and the browser's HttpOnly binding.
// It consumes the flow before exchanging the code, so callbacks cannot be replayed.
func (s *Service) Complete(ctx context.Context, state, binding, code, issuer, denied string) (string, string, error) {
	s.mu.Lock()
	p := s.flows[state]
	if p == nil || subtle.ConstantTimeCompare([]byte(binding), []byte(p.binding)) != 1 {
		s.mu.Unlock()
		return "", "", errors.New("invalid or expired OAuth session")
	}
	delete(s.flows, state)
	s.mu.Unlock()
	if denied != "" || code == "" {
		p.cancel()
		return p.owner, p.name, errors.New("authorization was cancelled")
	}
	p.result <- &auth.AuthorizationResult{Code: code, State: state, Iss: issuer}
	select {
	case err := <-p.done:
		return p.owner, p.name, err
	case <-ctx.Done():
		return p.owner, p.name, fmt.Errorf("authorization completion interrupted")
	}
}
