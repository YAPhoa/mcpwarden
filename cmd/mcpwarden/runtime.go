package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/approval"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/proxy"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

type userRuntime struct {
	proxy   *proxy.Proxy
	manager *upstream.Manager
}

// runtimes gives each authenticated user separate upstream sessions and tools.
// Static YAML upstreams are present for every user; panel entries belong to one user.
type runtimes struct {
	access *accessManager
	mu     sync.Mutex
	ctx    context.Context
	cfg    config.Config
	policy *policy.Policy
	audit  audit.Store
	store  catalog.Repository
	logger *slog.Logger
	users  map[string]*userRuntime
	// providerGuard ends the owner's access windows before a file catalog
	// changes a provider's availability or visible tools. The PostgreSQL
	// catalog does this in its own transaction and leaves it unset.
	providerGuard accessGuard
	// guarded is set when the owner vault runs, before any runtime exists.
	// Without it, credentialed connectors cannot be created.
	guarded *guardedCustody
}

func newRuntimes(ctx context.Context, cfg config.Config, pol *policy.Policy, log audit.Store, store catalog.Repository, logger *slog.Logger) *runtimes {
	return &runtimes{access: newAccessManager(store), ctx: ctx, cfg: cfg, policy: pol, audit: log, store: store, logger: logger, users: map[string]*userRuntime{}}
}

func (rs *runtimes) get(owner string) *userRuntime {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.getLocked(owner)
}

func (rs *runtimes) getLocked(owner string) *userRuntime {
	if rt := rs.users[owner]; rt != nil {
		return rt
	}
	upstreams := append([]config.Upstream(nil), rs.cfg.Upstreams...)
	reg := registry.NewForOwner(owner)
	if rs.store != nil {
		for _, entry := range rs.store.List(owner) {
			upstreams = append(upstreams, rs.upstreamConfig(entry))
			reg.SetProviderID(entry.Name, entry.ID)
		}
	}
	if rs.store != nil {
		for i := range upstreams {
			upstreams[i].Disabled = rs.store.Visibility(owner, upstreams[i].Name).Disabled
		}
	}
	p := proxy.New(reg, rs.policy, approval.None{}, rs.audit, rs.logger)
	p.Owner = owner
	p.Server.AddReceivingMiddleware(rs.access.middleware)
	p.AdminServer.AddReceivingMiddleware(rs.access.middleware)
	if rs.store != nil {
		p.Visible = func(name string) bool {
			provider, _, ok := registry.Split(name)
			return !ok || rs.store.ToolVisible(owner, provider, name)
		}
	}
	if rs.store != nil {
		for _, upstreamCfg := range upstreams {
			if cached, ok := rs.store.Discovery(owner, upstreamCfg.Name); ok {
				p.Changed(upstreamCfg.Name, cached.Tools, true)
				p.Changed(upstreamCfg.Name, nil, false)
			}
		}
	}
	m := upstream.New(upstreams, rs.logger, func(name string, tools []*mcp.Tool, healthy bool) {
		p.Changed(name, tools, healthy)
		if healthy && rs.store != nil {
			if err := rs.store.SetDiscovery(owner, name, tools); err != nil {
				rs.logger.Error("store tool discovery failed", "upstream", name, "error", err)
			}
		}
	})
	p.Manager = m
	if rs.guarded != nil {
		p.Security = rs.guarded.execution(m)
	}
	rs.registerGatewayTools(owner, p)
	m.Start(rs.ctx)
	rt := &userRuntime{proxy: p, manager: m}
	rs.users[owner] = rt
	return rt
}

// vaultOwner reports whether owner can hold credentialed connectors: the
// owner vault runs and owner is a local account. Owner routes need that
// account's browser session, so the shared operator workspace could never
// unlock one.
func (rs *runtimes) vaultOwner(owner string) bool {
	return rs.guarded != nil && strings.HasPrefix(owner, "account:")
}

func (rs *runtimes) add(e catalog.Entry) error {
	if rs.store == nil {
		return fmt.Errorf("panel-managed upstreams are not configured")
	}
	if e.ID == "" {
		e.ID = identity.New()
	}
	if err := catalog.Validate(e); err != nil {
		return err
	}
	if e.Credentialed() && !rs.vaultOwner(e.Owner) {
		return fmt.Errorf("connectors with credentials need the owner vault (owner_security) and a signed-in local account; only auth type none is available here")
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rt := rs.getLocked(e.Owner)
	for _, static := range rs.cfg.Upstreams {
		if static.Name == e.Name {
			return fmt.Errorf("upstream %s is defined in YAML", e.Name)
		}
	}
	if err := rs.store.Add(e); err != nil {
		return err
	}
	rt.proxy.Registry.SetProviderID(e.Name, e.ID)
	if err := rt.manager.Add(rs.upstreamConfig(e)); err != nil {
		if rollbackErr := rs.store.Delete(e.Owner, e.Name); rollbackErr != nil {
			return fmt.Errorf("add upstream: %w; rollback: %v", err, rollbackErr)
		}
		return err
	}
	return nil
}

func (rs *runtimes) remove(owner, name string) error {
	if rs.store == nil {
		return fmt.Errorf("panel-managed upstreams are not configured")
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rt := rs.getLocked(owner)
	var old *catalog.Entry
	for _, entry := range rs.store.List(owner) {
		if entry.Name == name {
			old = &entry
			break
		}
	}
	if old == nil {
		return fmt.Errorf("upstream %s does not exist", name)
	}
	if err := rt.manager.Remove(name); err != nil {
		return err
	}
	rt.proxy.Removed(name)
	if err := rs.store.Delete(owner, name); err != nil {
		_ = rt.manager.Add(rs.upstreamConfig(*old))
		return err
	}
	return nil
}

func (rs *runtimes) close() {
	rs.access.close()
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, rt := range rs.users {
		rt.manager.Close()
	}
}

func (rs *runtimes) anyReady() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, rt := range rs.users {
		if rt.manager.Ready() {
			return true
		}
	}
	return false
}

func requestOwner(r *http.Request) string {
	if access, ok := accessFrom(r.Context()); ok {
		return access.Owner
	}
	if identity, ok := accountFromRequest(r); ok {
		return identity.Owner
	}
	if info := auth.TokenInfoFromContext(r.Context()); info != nil {
		return info.UserID
	}
	return "local"
}

func (rs *runtimes) status(w http.ResponseWriter, r *http.Request) {
	rt := rs.get(requestOwner(r))
	mode, authentication, scope := "local", "none", ""
	username := ""
	if rs.cfg.Token != "" {
		authentication = "operator_token"
	}
	if rs.cfg.OAuth != nil {
		mode, authentication, scope = "oauth", "oauth", rs.cfg.OAuth.ManageScope
		if scope == "" {
			scope = "mcp:manage"
		}
	}
	if identity, ok := accountFromRequest(r); ok {
		mode, authentication, username = "account", "account", identity.Username
		if identity.Owner == "local" {
			mode = "local"
			authentication = "api_key"
		}
	}
	// This handler is behind the same management middleware as the inventory.
	// Report only server-validated identity, never claims decoded by the browser.
	jsonResponse(w, http.StatusOK, map[string]any{
		"ready": rt.manager.Ready(), "upstreams": rt.manager.States(),
		"session": map[string]any{"mode": mode, "subject": requestOwner(r), "authentication": authentication, "management_scope": scope, "username": username, "role": "admin", "access_id": func() string { a, _ := accessFrom(r.Context()); return a.ID }(), "vault": rs.vaultOwner(requestOwner(r))},
	})
}

func (rs *runtimes) tools(w http.ResponseWriter, r *http.Request) {
	rs.get(requestOwner(r)).proxy.ToolsJSON(w, r)
}

func (rs *runtimes) providers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	owner := requestOwner(r)
	rt := rs.get(owner)
	managed := map[string]bool{}
	if rs.store != nil {
		for _, entry := range rs.store.List(owner) {
			managed[entry.Name] = true
		}
	}
	type provider struct {
		Enabled        bool       `json:"enabled"`
		ID             string     `json:"id"`
		Name           string     `json:"name"`
		Transport      string     `json:"transport"`
		Healthy        bool       `json:"healthy"`
		Error          string     `json:"error,omitempty"`
		ToolCount      int        `json:"tool_count"`
		Source         string     `json:"source"`
		LastDiscovered *time.Time `json:"last_discovered,omitempty"`
		VisibilityMode string     `json:"visibility_mode"`
		EnabledTools   []string   `json:"enabled_tools"`
		Custody        string     `json:"custody,omitempty"`
	}
	out := make([]provider, 0)
	for _, state := range rt.manager.States() {
		p := provider{Custody: state.Custody, Enabled: state.Enabled, ID: rt.proxy.Registry.ProviderID(state.Name), Name: state.Name, Transport: state.Transport, Healthy: state.Healthy, Error: state.Error, ToolCount: len(rt.proxy.ToolItems(state.Name, "")), Source: "config"}
		if managed[state.Name] {
			p.Source = "personal"
		}
		if rs.store != nil {
			setting := rs.store.Visibility(owner, state.Name)
			p.VisibilityMode = setting.Mode
			p.EnabledTools = setting.Enabled
			if cached, ok := rs.store.Discovery(owner, state.Name); ok {
				p.LastDiscovered = &cached.UpdatedAt
			}
		}
		if p.VisibilityMode == "" {
			p.VisibilityMode = "all"
			p.EnabledTools = []string{}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	jsonResponse(w, http.StatusOK, out)
}

func (rs *runtimes) providerTools(w http.ResponseWriter, r *http.Request) {
	name, suffix, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/providers/"), "/")
	if !ok || name == "" || suffix != "tools" && suffix != "visibility" && suffix != "enabled" {
		http.Error(w, "invalid provider path", http.StatusBadRequest)
		return
	}
	rt := rs.get(requestOwner(r))
	found := false
	for _, state := range rt.manager.States() {
		if state.Name == name {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "provider not found", http.StatusNotFound)
		return
	}
	if suffix == "enabled" {
		rs.providerEnabled(w, r, name)
		return
	}
	if suffix == "visibility" {
		rs.providerVisibility(w, r, name)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, http.StatusOK, rt.proxy.ToolItems(name, r.URL.Query().Get("search")))
}

func (rs *runtimes) providerVisibility(w http.ResponseWriter, r *http.Request, name string) {
	if rs.store == nil {
		jsonResponse(w, http.StatusNotImplemented, map[string]string{"error": "tool visibility requires managed_upstreams configuration"})
		return
	}
	owner := requestOwner(r)
	switch r.Method {
	case http.MethodGet:
		jsonResponse(w, http.StatusOK, rs.store.Visibility(owner, name))
	case http.MethodPut:
		var setting catalog.Visibility
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&setting); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		set := func() error { return rs.store.SetVisibility(owner, name, setting) }
		var err error
		if visibilityChanges(rs.store.Visibility(owner, name), setting) {
			err = rs.providerGuard.run(r.Context(), owner, set)
		} else {
			err = set()
		}
		if err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		rs.get(owner).proxy.VisibilityChanged(name)
		jsonResponse(w, http.StatusOK, rs.store.Visibility(owner, name))
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// visibilityChanges reports whether a setting changes which tools are visible.
func visibilityChanges(old, next catalog.Visibility) bool {
	if old.Mode == "all" || next.Mode == "all" {
		return old.Mode != next.Mode
	}
	enabled := slices.Clone(next.Enabled)
	slices.Sort(enabled)
	return !slices.Equal(old.Enabled, enabled)
}

func (rs *runtimes) connections(w http.ResponseWriter, r *http.Request) {
	if rs.store == nil {
		jsonResponse(w, http.StatusNotImplemented, map[string]string{"error": "panel-managed upstreams are not configured"})
		return
	}
	owner := requestOwner(r)
	switch r.Method {
	case http.MethodGet:
		entries := rs.store.List(owner)
		type view struct {
			AuthType       string     `json:"auth_type"`
			Custody        string     `json:"custody,omitempty"`
			ID             string     `json:"id"`
			Name           string     `json:"name"`
			URL            string     `json:"url"`
			HeaderNames    []string   `json:"header_names"`
			CallTimeout    string     `json:"call_timeout"`
			LastDiscovered *time.Time `json:"last_discovered,omitempty"`
		}
		out := make([]view, 0, len(entries))
		for _, entry := range entries {
			kind := entry.AuthType
			if kind == "" {
				kind = "none"
			}
			v := view{AuthType: kind, ID: entry.ID, Name: entry.Name, URL: entry.URL, CallTimeout: entry.CallTimeout, HeaderNames: append([]string{}, entry.HeaderNames...)}
			if entry.Credentialed() {
				v.Custody = "vault"
			}
			if cached, ok := rs.store.Discovery(owner, entry.Name); ok {
				v.LastDiscovered = &cached.UpdatedAt
			}
			out = append(out, v)
		}
		jsonResponse(w, http.StatusOK, out)
	case http.MethodPost:
		var input struct {
			AuthType    string          `json:"auth_type"`
			Name        string          `json:"name"`
			URL         string          `json:"url"`
			HeaderNames []string        `json:"header_names"`
			CallTimeout string          `json:"call_timeout"`
			Headers     json.RawMessage `json:"headers"`
			OAuth       json.RawMessage `json:"oauth"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&input); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := oldConnectorFields(input.Headers, input.OAuth); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		e := catalog.Entry{AuthType: input.AuthType, Owner: owner, Name: input.Name, URL: input.URL, HeaderNames: input.HeaderNames, CallTimeout: input.CallTimeout}
		if err := rs.add(e); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		jsonResponse(w, http.StatusCreated, map[string]string{"name": e.Name})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (rs *runtimes) connection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/connections/")
	if name == "" || strings.Contains(name, "/") {
		http.Error(w, "invalid upstream name", http.StatusBadRequest)
		return
	}
	if err := rs.remove(requestOwner(r), name); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rs *runtimes) discovery(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/discovery/")
	name, action, ok := strings.Cut(path, "/")
	if name == "" || strings.Contains(name, "/") || action != "refresh" || !ok || r.Method != http.MethodPost {
		http.Error(w, "invalid discovery request", http.StatusBadRequest)
		return
	}
	if err := rs.get(requestOwner(r)).manager.Refresh(r.Context(), name); err != nil {
		status := http.StatusServiceUnavailable
		if strings.Contains(err.Error(), "does not exist") {
			status = http.StatusNotFound
		}
		if errors.Is(err, upstream.ErrGuarded) {
			status = http.StatusConflict
		}
		jsonResponse(w, status, map[string]string{"error": err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "refreshed"})
}

func (rs *runtimes) providerEnabled(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rs.store == nil {
		jsonResponse(w, http.StatusNotImplemented, map[string]string{"error": "provider settings require managed_upstreams"})
		return
	}
	var input struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&input); err != nil || input.Enabled == nil {
		http.Error(w, "enabled must be a boolean", http.StatusBadRequest)
		return
	}
	owner := requestOwner(r)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rt := rs.getLocked(owner)
	old := !rs.store.Visibility(owner, name).Disabled
	set := func() error { return rs.store.SetProviderEnabled(owner, name, *input.Enabled) }
	var err error
	if old != *input.Enabled {
		err = rs.providerGuard.run(r.Context(), owner, set)
	} else {
		err = set()
	}
	if err != nil {
		http.Error(w, "could not save provider setting", http.StatusInternalServerError)
		return
	}
	if err := rt.manager.SetEnabled(name, *input.Enabled); err != nil {
		if rollbackErr := rs.store.SetProviderEnabled(owner, name, old); rollbackErr != nil {
			rs.logger.Error("provider setting rollback failed", "error", rollbackErr)
		}
		http.Error(w, "could not update provider", http.StatusConflict)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]bool{"enabled": *input.Enabled})
}

// oldConnectorFields refuses header values and OAuth settings, which older
// builds accepted. Credentials go to the owner vault, never to this API.
func oldConnectorFields(headers, oauth json.RawMessage) error {
	if len(headers) > 0 && string(headers) != "null" {
		return fmt.Errorf("headers are not accepted: send header_names and store the values in the vault (/vault)")
	}
	if len(oauth) > 0 && string(oauth) != "null" {
		return fmt.Errorf("OAuth connectors return with roadmap step 6")
	}
	return nil
}

func (rs *runtimes) upstreamConfig(e catalog.Entry) config.Upstream {
	u := e.Upstream()
	if rs.store != nil {
		u.Disabled = rs.store.Visibility(e.Owner, e.Name).Disabled
	}
	return u
}
