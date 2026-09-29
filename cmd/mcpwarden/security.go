package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/custody"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

// Per-minute request budgets for owner routes. Password checks additionally use
// the account login window; the lease service caps pending requests itself.
const (
	ownerRouteLimit    = 120
	keyRouteLimit      = 60
	activationLimit    = 20
	rejectionAuditRate = 10
	maxSecurityBody    = 256 << 10
)

// securityAPI serves the owner vault, access-request, approval and lease routes.
// It stores ciphertext and authorization metadata only. Installing guarded
// execution for credentialed connectors is a separate startup step.
type securityAPI struct {
	service               *lease.Service
	store                 storageDB
	cache                 *vault.Cache
	index                 *custody.Index
	authority             *custody.Authority
	catalog               catalog.Repository
	accounts              *accountAuth
	origins               []string
	csrfKey               []byte
	limits                *rateLimits
	logger                *slog.Logger
	trustedProxies        []netip.Prefix
	allowInsecureLoopback bool
}

// startSecurity starts the lease executor on an open store. It owns db from
// here on and closes it on failure. The executor coordinates every catalog
// change in each HTTP mode; its owner routes are registered only with
// owner_security, whose transport settings it reads here.
func startSecurity(ctx context.Context, cfg config.Config, db storageDB, store custody.Catalog, tools *policy.Policy, accounts *accountAuth, logger *slog.Logger) (*securityAPI, error) {
	var trustedProxies []netip.Prefix
	var allowInsecureLoopback bool
	if cfg.OwnerSecurity != nil {
		var err error
		if trustedProxies, err = cfg.OwnerSecurity.ProxyPrefixes(); err != nil {
			closeStore(db)
			return nil, err
		}
		allowInsecureLoopback = cfg.OwnerSecurity.AllowInsecureLoopback
	}
	index, cache := custody.NewIndex(), &vault.Cache{}
	authority := custody.NewAuthority(store, tools, index)
	service, err := lease.New(ctx, db, authority, secret.Activator{Records: cache}, lease.DefaultOptions())
	if err != nil {
		closeStore(db)
		return nil, errors.New("security executor could not start")
	}
	api := &securityAPI{service: service, store: db, cache: cache, index: index, authority: authority, catalog: store,
		accounts: accounts, origins: cfg.Origins, csrfKey: randBytes(32), limits: newRateLimits(), logger: logger,
		trustedProxies: trustedProxies, allowInsecureLoopback: allowInsecureLoopback}
	snapshot, err := db.LoadCustody(ctx)
	if err == nil {
		err = index.Load(snapshot, cache)
	}
	if err != nil {
		api.close()
		return nil, errors.New("security state could not be loaded")
	}
	return api, nil
}

func closeStore(db storageDB) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = db.Close(ctx)
}

func (api *securityAPI) close() {
	api.service.Close()
	closeStore(api.store)
}

func (api *securityAPI) register(mux *http.ServeMux) {
	mux.Handle("/api/security/csrf", api.owner(api.csrf))
	mux.Handle("/api/security/approval-policy", api.owner(api.approvalPolicy))
	mux.Handle("/api/security/events", api.owner(api.events))
	mux.Handle("/api/vault/state", api.owner(api.vaultState))
	mux.Handle("/api/vault/setup", api.owner(api.vaultSetup))
	mux.Handle("/api/vault/wrappers", api.owner(api.vaultWrappers))
	mux.Handle("/api/vault/lock-execution", api.owner(api.lockExecution))
	mux.Handle("/api/vault/credentials", api.caller(api.credentials))
	mux.Handle("/api/vault/credentials/", api.owner(api.credential))
	mux.Handle("/api/access-requests", api.caller(api.accessRequests))
	mux.Handle("/api/access-requests/", api.caller(api.accessRequest))
	mux.Handle("/api/approvals/", api.owner(api.approval))
	mux.Handle("/api/leases", api.caller(api.leases))
	mux.Handle("/api/leases/", api.caller(api.revokeLease))
}

type securityHandler func(http.ResponseWriter, *http.Request, catalog.AccessRecord)

// owner admits only an interactive local-account browser session. Any
// Authorization header is refused, so an admin or client MCP key can never reach
// confirmation, key release, vault changes or execution lock. Unsafe methods also
// require an exact allowed Origin (HTTPS unless loopback), a same-origin fetch
// and the session-bound CSRF token; SameSite cookies are not the only barrier.
func (api *securityAPI) owner(next securityHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		if !api.secureTransport(w, r) {
			return
		}
		if value := r.Header.Get("Authorization"); value != "" {
			api.rejectKey(r, value)
			securityFailure(w, http.StatusForbidden, "interactive_owner_required", "An interactive owner browser session is required; access keys cannot use this route.")
			return
		}
		session, ok := api.accounts.session(r)
		if !ok {
			securityFailure(w, http.StatusUnauthorized, "sign_in_required", "Sign in required.")
			return
		}
		record, ok := api.catalog.AccessByID(session.Owner, session.AccessID)
		if !ok || record.Kind != "browser" || !record.Active() {
			securityFailure(w, http.StatusUnauthorized, "sign_in_required", "Sign in required.")
			return
		}
		if !api.browserRequest(w, r) {
			return
		}
		if !api.limits.allow("owner:"+record.Owner, ownerRouteLimit) {
			rateLimited(w)
			return
		}
		next(w, r.WithContext(withAccess(r.Context(), record)), record)
	})
}

// caller accepts a named API key (client or admin) or the owner's browser
// session. Handlers restrict key callers to their own requests and leases.
func (api *securityAPI) caller(next securityHandler) http.Handler {
	owner := api.owner(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("Authorization")
		if value == "" {
			owner.ServeHTTP(w, r)
			return
		}
		noStore(w)
		if !api.secureTransport(w, r) {
			return
		}
		if !isAPIKeyAuthorization(value) {
			securityFailure(w, http.StatusUnauthorized, "access_key_required", "A named access key or owner session is required.")
			return
		}
		record, ok := authenticateAPIKey(api.catalog, strings.TrimPrefix(value, "Bearer "))
		if !ok || record.Kind != "api_key" {
			securityFailure(w, http.StatusUnauthorized, "access_key_required", "Invalid, revoked, or expired access key.")
			return
		}
		if !validOrigin(r.Header.Get("Origin"), api.origins) {
			securityFailure(w, http.StatusForbidden, "origin_forbidden", "Origin forbidden.")
			return
		}
		if !api.limits.allow("key:"+record.ID, keyRouteLimit) {
			rateLimited(w)
			return
		}
		next(w, r.WithContext(withAccess(r.Context(), record)), record)
	})
}

func (api *securityAPI) browserRequest(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if !validOrigin(origin, api.origins) {
		securityFailure(w, http.StatusForbidden, "origin_forbidden", "Origin forbidden.")
		return false
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	if origin == "" || !secureOrigin(origin) {
		securityFailure(w, http.StatusForbidden, "origin_forbidden", "State changes require a same-origin HTTPS page.")
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		securityFailure(w, http.StatusForbidden, "origin_forbidden", "Cross-site requests are not accepted.")
		return false
	}
	expected, ok := api.csrfToken(r)
	given := r.Header.Get("X-CSRF-Token")
	if !ok || !hmac.Equal([]byte(given), []byte(expected)) {
		securityFailure(w, http.StatusForbidden, "csrf_required", "A valid CSRF token is required.")
		return false
	}
	if r.ContentLength != 0 && !jsonContentType(r.Header.Get("Content-Type")) {
		securityFailure(w, http.StatusUnsupportedMediaType, "json_required", "JSON body required.")
		return false
	}
	return true
}

func jsonContentType(value string) bool {
	media, _, err := mime.ParseMediaType(value)
	return err == nil && media == "application/json"
}

// secureOrigin requires the page that sends a secret body to be HTTPS. Plain
// HTTP is accepted only for loopback development. Forwarded headers are never
// trusted as proof of TLS.
func secureOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())
}

// csrfToken is bound to the session secret. A new process key invalidates old
// tokens; the UI fetches a fresh one after a 403.
func (api *securityAPI) csrfToken(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	mac := hmac.New(sha256.New, api.csrfKey)
	_, _ = mac.Write([]byte("mcpwarden.csrf.v1\x00"))
	_, _ = mac.Write([]byte(tokenHash(cookie.Value)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), true
}

// rejectKey records an authenticated access key that tried to use an owner
// route. Unauthenticated noise is not written to the security log.
func (api *securityAPI) rejectKey(r *http.Request, value string) {
	if !isAPIKeyAuthorization(value) {
		return
	}
	record, ok := authenticateAPIKey(api.catalog, strings.TrimPrefix(value, "Bearer "))
	if !ok || !api.limits.allow("reject:"+record.ID, rejectionAuditRate) {
		return
	}
	api.audit(r.Context(), record.Owner, lease.Event{Type: "owner_route.rejected", ActorID: record.ID, Reason: "api_key"})
}

// audit appends a standalone security event, used only for rejected attempts
// that change no state. State changes write their events in the same
// transaction as the change.
func (api *securityAPI) audit(ctx context.Context, owner string, e lease.Event) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	err := api.store.WithOwner(ctx, owner, func(tx lease.Tx) error {
		return tx.Event(api.newEvent(tx, owner, e))
	})
	if err != nil {
		api.logger.Error("security audit write failed", "event_type", e.Type)
	}
}

func (api *securityAPI) newEvent(tx lease.Tx, owner string, e lease.Event) lease.Event {
	e.ID, e.OwnerID, e.At, e.BootID = identity.New(), owner, tx.Now(), api.service.BootID()
	return e
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func securityFailure(w http.ResponseWriter, status int, code, message string) {
	jsonResponse(w, status, map[string]string{"error": code, "message": message})
}

func rateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	securityFailure(w, http.StatusTooManyRequests, "rate_limited", "Too many requests; try again shortly.")
}

// securityError maps service errors to fixed messages. Storage and driver
// details never reach the response.
func securityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errPasswordChanged):
		securityFailure(w, http.StatusForbidden, "reauthentication_required", "Current account password required.")
	case errors.Is(err, lease.ErrNotFound), errors.Is(err, vault.ErrNotFound):
		securityFailure(w, http.StatusNotFound, "not_found", "Not found.")
	case errors.Is(err, lease.ErrDenied):
		securityFailure(w, http.StatusForbidden, "denied", "Not permitted for this caller.")
	case errors.Is(err, lease.ErrStale), errors.Is(err, lease.ErrRequired):
		securityFailure(w, http.StatusConflict, "stale", "The request, credential or policy changed or expired. Start a new request.")
	case errors.Is(err, vault.ErrConflict), errors.Is(err, custody.ErrConflict):
		securityFailure(w, http.StatusConflict, "conflict", "The record changed; reload before saving.")
	case errors.Is(err, lease.ErrScope), errors.Is(err, vault.ErrInvalid), errors.Is(err, custody.ErrInvalid):
		securityFailure(w, http.StatusBadRequest, "invalid", "Invalid or unsupported request.")
	case errors.Is(err, lease.ErrKey):
		securityFailure(w, http.StatusUnprocessableEntity, "activation_failed", "Credential activation failed.")
	case errors.Is(err, lease.ErrBusy), errors.Is(err, lease.ErrLimit):
		rateLimited(w)
	case errors.Is(err, lease.ErrLocked):
		securityFailure(w, http.StatusLocked, "locked", "Execution is locked. Restarting the gateway or restoring storage requires new owner activation.")
	default:
		securityFailure(w, http.StatusServiceUnavailable, "unavailable", "Security storage is unavailable; execution is locked.")
	}
}

// decodeBody reads a bounded, strict JSON object: duplicate keys, malformed
// Unicode, unknown fields and trailing data are rejected. The raw buffer is
// cleared afterwards because some bodies carry a credential key.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int, v any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(limit)))
	defer clear(raw)
	if err != nil {
		securityFailure(w, http.StatusRequestEntityTooLarge, "too_large", "Request body too large.")
		return false
	}
	if len(raw) == 0 {
		raw = append(raw, "{}"...)
	}
	if json.Validate(raw, limit, 16) != nil || json.UnmarshalStrict(raw, v) != nil {
		securityFailure(w, http.StatusBadRequest, "invalid", "Invalid or unsupported request.")
		return false
	}
	return true
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	securityFailure(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
}

var errPasswordChanged = errors.New("account password changed during owner authorization")

// fresh requires the account password again for changes to the vault wrappers
// or approval policy. A long-lived session alone cannot weaken either.
func (api *securityAPI) fresh(w http.ResponseWriter, owner, password string) (passwordProof, bool) {
	proof, status := api.accounts.verifyCurrentPassword(owner, password)
	switch status {
	case 0:
		return proof, true
	case http.StatusTooManyRequests:
		rateLimited(w)
	default:
		securityFailure(w, http.StatusForbidden, "reauthentication_required", "Current account password required.")
	}
	return passwordProof{}, false
}

func (api *securityAPI) csrf(w http.ResponseWriter, r *http.Request, _ catalog.AccessRecord) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	token, _ := api.csrfToken(r)
	jsonResponse(w, http.StatusOK, map[string]string{"token": token})
}

type policyView struct {
	Mode        string     `json:"mode"`
	Revision    string     `json:"revision"`
	ChangedAt   *time.Time `json:"changed_at,omitempty"`
	DefaultMode string     `json:"default_mode"`
}

func viewPolicy(p custody.Policy) policyView {
	v := policyView{Mode: p.Mode, Revision: p.Revision, DefaultMode: custody.DefaultMode}
	if !p.ChangedAt.IsZero() {
		v.ChangedAt = &p.ChangedAt
	}
	return v
}

func (api *securityAPI) approvalPolicy(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	switch r.Method {
	case http.MethodGet:
		jsonResponse(w, http.StatusOK, viewPolicy(api.index.Policy(caller.Owner)))
	case http.MethodPut:
		var in struct {
			Mode             string `json:"mode"`
			ExpectedRevision string `json:"expected_revision"`
			CurrentPassword  string `json:"current_password"`
		}
		if !decodeBody(w, r, 4096, &in) {
			return
		}
		if in.Mode != "none" && in.Mode != "confirm" {
			securityError(w, custody.ErrInvalid)
			return
		}
		proof, ok := api.fresh(w, caller.Owner, in.CurrentPassword)
		if !ok {
			return
		}
		defer clear(proof.hash)
		var saved custody.Policy
		// The change stales pending requests and revokes live windows in the
		// same transaction, before success is reported.
		err := api.service.ChangeOwnerAtomic(r.Context(), func(tx lease.Tx) (func() error, error) {
			if !api.accounts.passwordUnchanged(proof) {
				return nil, errPasswordChanged
			}
			ctx := tx.(custody.Tx)
			if err := ctx.PutApprovalPolicy(custody.Policy{OwnerID: caller.Owner, Mode: in.Mode, ChangedBy: caller.ID}, in.ExpectedRevision); err != nil {
				return nil, err
			}
			p, err := ctx.ApprovalPolicy()
			if err != nil {
				return nil, err
			}
			if err := tx.Event(api.newEvent(tx, caller.Owner, lease.Event{Type: "policy.changed", ActorID: caller.ID, Mode: p.Mode, Revision: p.Revision})); err != nil {
				return nil, err
			}
			saved = p
			return api.index.PreparePolicy(p)
		})
		if err != nil {
			securityError(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, viewPolicy(saved))
	default:
		methodNotAllowed(w, "GET, PUT")
	}
}

func (api *securityAPI) events(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > custody.MaxEventPage {
			securityError(w, lease.ErrScope)
			return
		}
		limit = n
	}
	var out []lease.Event
	err := api.store.WithOwner(r.Context(), caller.Owner, func(tx lease.Tx) error {
		var err error
		out, err = tx.(custody.Tx).SecurityEvents(limit)
		return err
	})
	if err != nil {
		securityError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"items": out})
}

type rootView struct {
	RootID          string          `json:"root_id"`
	RootVersion     string          `json:"root_version"`
	WrapperRevision string          `json:"wrapper_revision"`
	Passphrase      json.RawMessage `json:"passphrase,omitempty"`
	Recovery        json.RawMessage `json:"recovery,omitempty"`
}

type credentialSummary struct {
	CredentialID  string              `json:"credential_id"`
	ConnectorID   string              `json:"connector_id"`
	ConnectorName string              `json:"connector_name,omitempty"`
	Epoch         string              `json:"epoch"`
	Revision      string              `json:"revision"`
	Deleted       bool                `json:"deleted"`
	Tools         []custody.ToolView  `json:"tools,omitempty"`
	Destination   *secret.Destination `json:"destination,omitempty"`
	WrappedKey    json.RawMessage     `json:"wrapped_key,omitempty"`
	Envelope      json.RawMessage     `json:"envelope,omitempty"`
}

func (api *securityAPI) summarize(owner string, h custody.Head) credentialSummary {
	s := credentialSummary{CredentialID: h.CredentialID, ConnectorID: h.ConnectorID, Epoch: h.Epoch, Revision: h.Revision, Deleted: h.Deleted}
	if entry, ok := api.authority.Connector(owner, h.ConnectorID); ok {
		s.ConnectorName = entry.Name
	}
	return s
}

func (api *securityAPI) root(ctx context.Context, owner string) (*vault.Root, error) {
	var out *vault.Root
	err := api.store.WithOwner(ctx, owner, func(tx lease.Tx) error {
		root, err := tx.(vault.Tx).VaultRoot()
		if errors.Is(err, vault.ErrNotFound) {
			return nil
		}
		out = &root
		return err
	})
	return out, err
}

func (api *securityAPI) vaultState(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	root, err := api.root(r.Context(), caller.Owner)
	if err != nil {
		securityError(w, err)
		return
	}
	view, err := api.service.View(r.Context(), caller.Owner)
	if err != nil {
		securityError(w, err)
		return
	}
	available := 0
	for _, l := range view.Leases {
		if l.RuntimeAvailable {
			available++
		}
	}
	state := map[string]any{
		"configured":      root != nil,
		"credentials":     []credentialSummary{},
		"approval_policy": viewPolicy(api.index.Policy(caller.Owner)),
		"gateway_boot_id": view.BootID,
		"active_leases":   available,
	}
	if root != nil {
		state["root"] = rootView{RootID: root.RootID, RootVersion: root.RootVersion, WrapperRevision: root.WrapperRevision}
	}
	credentials := []credentialSummary{}
	for _, h := range api.index.Credentials(caller.Owner) {
		credentials = append(credentials, api.summarize(caller.Owner, h))
	}
	state["credentials"] = credentials
	jsonResponse(w, http.StatusOK, state)
}

type rootInput struct {
	CurrentPassword         string     `json:"current_password"`
	ExpectedWrapperRevision string     `json:"expected_wrapper_revision"`
	Root                    vault.Root `json:"root"`
}

func (api *securityAPI) vaultSetup(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var in rootInput
	if !decodeBody(w, r, 16<<10, &in) {
		return
	}
	if in.ExpectedWrapperRevision != "" || in.Root.OwnerID != caller.Owner {
		securityError(w, vault.ErrInvalid)
		return
	}
	proof, ok := api.fresh(w, caller.Owner, in.CurrentPassword)
	if !ok {
		return
	}
	defer clear(proof.hash)
	api.putRoot(w, r, caller, proof, in.Root, "", "vault.created", http.StatusCreated)
}

func (api *securityAPI) putRoot(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord, proof passwordProof, root vault.Root, expected, event string, status int) {
	err := api.service.ChangeOwnerAtomic(r.Context(), func(tx lease.Tx) (func() error, error) {
		if !api.accounts.passwordUnchanged(proof) {
			return nil, errPasswordChanged
		}
		if err := tx.(vault.Tx).PutVaultRoot(root, expected); err != nil {
			return nil, err
		}
		return nil, tx.Event(api.newEvent(tx, caller.Owner, lease.Event{Type: event, ActorID: caller.ID, Revision: root.WrapperRevision}))
	})
	if err != nil {
		securityError(w, err)
		return
	}
	jsonResponse(w, status, rootView{RootID: root.RootID, RootVersion: root.RootVersion, WrapperRevision: root.WrapperRevision})
}

// vaultWrappers returns only encrypted wrappers and public context. A passphrase
// change uploads a new wrapper set for the same root under revision CAS.
func (api *securityAPI) vaultWrappers(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	switch r.Method {
	case http.MethodGet:
		var root *vault.Root
		var records []vault.Record
		err := api.store.WithOwner(r.Context(), caller.Owner, func(tx lease.Tx) error {
			v := tx.(vault.Tx)
			current, err := v.VaultRoot()
			if err == nil {
				root = &current
			} else if !errors.Is(err, vault.ErrNotFound) {
				return err
			}
			records, err = v.CredentialRecords()
			return err
		})
		if err != nil {
			securityError(w, err)
			return
		}
		out := map[string]any{"root": nil, "credentials": []credentialSummary{}}
		if root != nil {
			out["root"] = rootView{RootID: root.RootID, RootVersion: root.RootVersion, WrapperRevision: root.WrapperRevision, Passphrase: root.Passphrase, Recovery: root.Recovery}
		}
		credentials := []credentialSummary{}
		for _, record := range records {
			s := api.summarize(caller.Owner, custody.Head{CredentialID: record.CredentialID, ConnectorID: record.ConnectorID, Epoch: record.Epoch, Revision: record.Revision, Deleted: !record.DeletedAt.IsZero()})
			destination := record.Destination
			// The owner's browser authenticates the current ciphertext before it
			// releases a key; the server still cannot decrypt either value.
			s.Destination, s.WrappedKey = &destination, record.WrappedKey
			if record.DeletedAt.IsZero() {
				s.Envelope = record.Envelope
			}
			credentials = append(credentials, s)
		}
		out["credentials"] = credentials
		jsonResponse(w, http.StatusOK, out)
	case http.MethodPut:
		var in rootInput
		if !decodeBody(w, r, 16<<10, &in) {
			return
		}
		if _, ok := vault.Version(in.ExpectedWrapperRevision); !ok || in.Root.OwnerID != caller.Owner {
			securityError(w, vault.ErrInvalid)
			return
		}
		proof, ok := api.fresh(w, caller.Owner, in.CurrentPassword)
		if !ok {
			return
		}
		defer clear(proof.hash)
		api.putRoot(w, r, caller, proof, in.Root, in.ExpectedWrapperRevision, "vault.rewrapped", http.StatusOK)
	default:
		methodNotAllowed(w, "GET, PUT")
	}
}

// credentials lists selectable credentials and tools so an owner or requester
// can build a scope. It never returns wrappers, ciphertext or header values.
func (api *securityAPI) credentials(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	out := []credentialSummary{}
	for _, h := range api.index.Credentials(caller.Owner) {
		tools, ok := api.authority.SelectableTools(caller.Owner, h.CredentialID)
		if h.Deleted || !ok {
			continue
		}
		s := api.summarize(caller.Owner, h)
		s.Tools = tools
		out = append(out, s)
	}
	jsonResponse(w, http.StatusOK, out)
}

type pointerInput struct {
	Epoch    string `json:"epoch"`
	Revision string `json:"revision"`
}

// credential creates, replaces, rotates or deletes one encrypted credential
// under version CAS. The browser encrypts; the server checks the public binding
// to the owner's connector and stores ciphertext only.
func (api *securityAPI) credential(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	id := strings.TrimPrefix(r.URL.Path, "/api/vault/credentials/")
	if !identity.Valid(id) || strings.ToLower(id) != id {
		securityError(w, lease.ErrNotFound)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var in struct {
			Expected *pointerInput `json:"expected"`
			Record   vault.Record  `json:"record"`
		}
		if !decodeBody(w, r, 128<<10, &in) {
			return
		}
		record := in.Record
		if record.CredentialID != id || record.OwnerID != caller.Owner || !record.DeletedAt.IsZero() {
			securityError(w, vault.ErrInvalid)
			return
		}
		if !api.connectorBinding(caller.Owner, record) {
			securityFailure(w, http.StatusBadRequest, "destination_mismatch", "The destination must match the connector's URL and header names.")
			return
		}
		var expected *vault.Pointer
		event, status := "credential.created", http.StatusCreated
		if in.Expected != nil {
			expected = &vault.Pointer{Epoch: in.Expected.Epoch, Revision: in.Expected.Revision}
			event, status = "credential.updated", http.StatusOK
			if record.Epoch != in.Expected.Epoch {
				event = "credential.rotated"
			}
		}
		api.changeCredential(w, r, caller, id, event, status, func(tx vault.Tx) error { return tx.PutCredentialRecord(record, expected) })
	case http.MethodDelete:
		var in struct {
			Expected pointerInput `json:"expected"`
		}
		if !decodeBody(w, r, 4096, &in) {
			return
		}
		expected := vault.Pointer{Epoch: in.Expected.Epoch, Revision: in.Expected.Revision}
		api.changeCredential(w, r, caller, id, "credential.deleted", http.StatusOK, func(tx vault.Tx) error { return tx.DeleteCredentialRecord(id, expected) })
	default:
		methodNotAllowed(w, "PUT, DELETE")
	}
}

func (api *securityAPI) changeCredential(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord, id, event string, status int, write func(vault.Tx) error) {
	var stored vault.Record
	err := api.service.ChangeOwnerAtomic(r.Context(), func(tx lease.Tx) (func() error, error) {
		v := tx.(vault.Tx)
		if err := write(v); err != nil {
			return nil, err
		}
		var err error
		if stored, err = v.CredentialRecord(id); err != nil {
			return nil, err
		}
		e := lease.Event{Type: event, ActorID: caller.ID, CredentialID: id, Epoch: stored.Epoch, Revision: stored.Revision}
		if err := tx.Event(api.newEvent(tx, caller.Owner, e)); err != nil {
			return nil, err
		}
		ciphertext, err := api.cache.Prepare(stored)
		if err != nil {
			return nil, err
		}
		index, err := api.index.PrepareCredential(stored)
		if err != nil {
			return nil, err
		}
		return func() error {
			if err := ciphertext(); err != nil {
				return err
			}
			return index()
		}, nil
	})
	if err != nil {
		securityError(w, err)
		return
	}
	jsonResponse(w, status, credentialSummary{CredentialID: id, ConnectorID: stored.ConnectorID, Epoch: stored.Epoch, Revision: stored.Revision, Deleted: !stored.DeletedAt.IsZero()})
}

// connectorBinding keeps browser-supplied destination metadata consistent with
// the owner's existing HTTP connector. Only header credentials are supported.
// Private networks are limited to loopback development until an operator policy
// for private prefixes exists.
func (api *securityAPI) connectorBinding(owner string, record vault.Record) bool {
	var entry *catalog.Entry
	names := []string{}
	for _, e := range api.catalog.List(owner) {
		if e.ID == record.ConnectorID {
			entry = &e
			for _, name := range e.HeaderNames {
				names = append(names, strings.ToLower(name))
			}
		}
	}
	if entry == nil || !entry.Credentialed() || len(names) == 0 {
		return false
	}
	d := record.Destination
	given := slices.Clone(d.HeaderNames)
	slices.Sort(names)
	slices.Sort(given)
	if d.Endpoint != entry.URL || !slices.Equal(names, given) {
		return false
	}
	// Destination validation already limits loopback HTTP to loopback prefixes.
	return d.Network == "public" || d.Network == "private" && d.AllowLoopbackHTTP
}

type requestView struct {
	ID                     string            `json:"id"`
	State                  string            `json:"state"`
	ApprovalMode           string            `json:"approval_mode"`
	ApprovalPolicyRevision string            `json:"approval_policy_revision"`
	VerificationMethod     string            `json:"verification_method"`
	AuthorizationSource    string            `json:"authorization_source,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	ExpiresAt              time.Time         `json:"expires_at"`
	ActivationDeadline     *time.Time        `json:"activation_deadline,omitempty"`
	LeaseID                string            `json:"lease_id,omitempty"`
	Requester              callerView        `json:"requester"`
	Credential             credentialSummary `json:"credential"`
	DurationSeconds        int               `json:"duration_seconds"`
	MaxCalls               *int64            `json:"max_calls"`
	Tools                  []toolScopeView   `json:"tools"`
	// Owner-only binding fields used by confirmation and key release.
	GatewayBootID string `json:"gateway_boot_id,omitempty"`
	ScopeDigest   string `json:"scope_digest,omitempty"`
	RequestDigest string `json:"request_digest,omitempty"`
	Challenge     string `json:"challenge,omitempty"`
}
type callerView struct {
	AccessID string `json:"access_id"`
	PublicID string `json:"public_id,omitempty"`
	Label    string `json:"label,omitempty"`
}
type toolScopeView struct {
	ToolID           string             `json:"tool_id"`
	Name             string             `json:"name,omitempty"`
	DefinitionDigest string             `json:"definition_sha256"`
	Constraints      []lease.Constraint `json:"constraints"`
}

func (api *securityAPI) callerView(owner, id string) callerView {
	v := callerView{AccessID: id}
	if c, ok := api.authority.Caller(owner, id); ok {
		v.PublicID, v.Label = c.PublicID, c.Label
	}
	return v
}

func (api *securityAPI) viewRequest(r lease.Request, owner bool) requestView {
	s := r.Scope
	v := requestView{ID: r.ID, State: r.State, ApprovalMode: r.Mode, ApprovalPolicyRevision: r.ApprovalPolicyRevision, VerificationMethod: r.VerificationMethod,
		AuthorizationSource: r.AuthorizationSource, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, LeaseID: r.LeaseID,
		Requester:       api.callerView(s.OwnerID, s.RequesterAccessID),
		Credential:      api.summarize(s.OwnerID, custody.Head{CredentialID: s.CredentialID, ConnectorID: s.ConnectorID, Epoch: s.CredentialEpoch}),
		DurationSeconds: s.DurationSeconds, MaxCalls: s.MaxCalls, Tools: []toolScopeView{}}
	v.Credential.Revision = ""
	if !r.ActivationDeadline.IsZero() {
		v.ActivationDeadline = &r.ActivationDeadline
	}
	names := map[string]string{}
	if tools, ok := api.authority.SelectableTools(s.OwnerID, s.CredentialID); ok {
		for _, t := range tools {
			names[t.ID] = t.Name
		}
	}
	for _, t := range s.Tools {
		v.Tools = append(v.Tools, toolScopeView{ToolID: t.ToolID, Name: names[t.ToolID], DefinitionDigest: t.DefinitionDigest, Constraints: t.Constraints})
	}
	if owner {
		v.GatewayBootID, v.ScopeDigest, v.RequestDigest, v.Challenge = r.BootID, r.ScopeDigest, r.RequestDigest, r.Nonce
	}
	return v
}

func (api *securityAPI) accessRequests(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	interactive := caller.Kind == "browser"
	switch r.Method {
	case http.MethodGet:
		view, err := api.service.View(r.Context(), caller.Owner)
		if err != nil {
			securityError(w, err)
			return
		}
		out := []requestView{}
		for _, request := range view.Requests {
			if interactive || request.Scope.RequesterAccessID == caller.ID {
				out = append(out, api.viewRequest(request, interactive))
			}
		}
		jsonResponse(w, http.StatusOK, out)
	case http.MethodPost:
		var in custody.ScopeRequest
		if !decodeBody(w, r, maxSecurityBody, &in) {
			return
		}
		if in.RequesterAccessID == "" && !interactive {
			in.RequesterAccessID = caller.ID
		}
		// A key may request only for itself; the service rechecks this.
		if !interactive && in.RequesterAccessID != caller.ID {
			securityError(w, lease.ErrDenied)
			return
		}
		raw, err := api.authority.BuildScope(caller.Owner, in)
		if err != nil {
			securityError(w, err)
			return
		}
		request, err := api.service.Request(r.Context(), raw)
		if err != nil {
			securityError(w, err)
			return
		}
		jsonResponse(w, http.StatusCreated, api.viewRequest(request, interactive))
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (api *securityAPI) accessRequest(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/access-requests/")
	request, err := api.service.LookupRequest(r.Context(), caller.Owner, id)
	interactive := caller.Kind == "browser"
	if err == nil && !interactive && request.Scope.RequesterAccessID != caller.ID {
		err = lease.ErrNotFound
	}
	if err != nil {
		securityError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, api.viewRequest(request, interactive))
}

// keyInput decodes a base64url credential key directly into an owned buffer.
type keyInput []byte

func (k *keyInput) UnmarshalJSON(raw []byte) error {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return err
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(b) != 32 {
		clear(b)
		return lease.ErrKey
	}
	*k = b
	return nil
}

func (api *securityAPI) approval(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	id, action, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/approvals/"), "/")
	if !ok || !identity.Valid(id) || strings.ToLower(id) != id || action != "begin" && action != "deny" && action != "activate" {
		securityError(w, lease.ErrNotFound)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	switch action {
	case "begin":
		var in struct {
			RequestDigest string `json:"request_digest"`
		}
		if !decodeBody(w, r, 4096, &in) {
			return
		}
		request, err := api.service.Confirm(r.Context(), id, in.RequestDigest)
		if err != nil {
			securityError(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, api.viewRequest(request, true))
	case "deny":
		var in struct{}
		if !decodeBody(w, r, 4096, &in) {
			return
		}
		if err := api.service.Deny(r.Context(), id); err != nil {
			securityError(w, err)
			return
		}
		request, err := api.service.LookupRequest(r.Context(), caller.Owner, id)
		if err != nil {
			securityError(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, api.viewRequest(request, true))
	case "activate":
		api.activate(w, r, caller, id)
	}
}

// activate releases one credential key for one request. Owner, approver and
// mode come from authentication and the stored binding, never from the body.
// The raw body is cleared and the key is cleared by the lease service.
func (api *securityAPI) activate(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord, id string) {
	if !api.limits.allow("activate:"+caller.Owner, activationLimit) {
		rateLimited(w)
		return
	}
	operation := r.Header.Get("Idempotency-Key")
	if !identity.Valid(operation) || strings.ToLower(operation) != operation {
		securityFailure(w, http.StatusBadRequest, "idempotency_key_required", "A random lowercase UUID Idempotency-Key is required.")
		return
	}
	var in struct {
		GatewayBootID   string   `json:"gateway_boot_id"`
		RequestDigest   string   `json:"request_digest"`
		Challenge       string   `json:"challenge"`
		CredentialID    string   `json:"credential_id"`
		CredentialEpoch string   `json:"credential_epoch"`
		CEK             keyInput `json:"cek"`
	}
	defer func() { clear(in.CEK) }()
	if !decodeBody(w, r, 4096, &in) {
		return
	}
	if len(in.CEK) != 32 {
		securityError(w, lease.ErrKey)
		return
	}
	reject := func(err error, reason string, known bool) {
		e := lease.Event{Type: "activation.rejected", ActorID: caller.ID, Reason: reason}
		if known {
			e.RequestID = id
		}
		api.audit(r.Context(), caller.Owner, e)
		securityError(w, err)
	}
	request, err := api.service.LookupRequest(r.Context(), caller.Owner, id)
	if errors.Is(err, lease.ErrNotFound) {
		reject(err, "not_found", false)
		return
	}
	if err != nil {
		securityError(w, err)
		return
	}
	s := request.Scope
	if in.GatewayBootID != api.service.BootID() || in.GatewayBootID != request.BootID || !hmac.Equal([]byte(in.Challenge), []byte(request.Nonce)) || in.RequestDigest != request.RequestDigest || in.CredentialID != s.CredentialID || in.CredentialEpoch != s.CredentialEpoch {
		reject(lease.ErrStale, "stale", true)
		return
	}
	key := slices.Clone([]byte(in.CEK))
	l, err := api.service.Activate(r.Context(), lease.ActivationInput{RequestID: id, RequestDigest: in.RequestDigest, OperationID: operation, Key: key})
	clear(key)
	switch {
	case err == nil:
	case errors.Is(err, lease.ErrKey):
		reject(err, "key", true)
		return
	case errors.Is(err, lease.ErrStale):
		reject(err, "stale", true)
		return
	case errors.Is(err, lease.ErrDenied):
		reject(err, "denied", true)
		return
	default:
		securityError(w, err)
		return
	}
	// The window exists now; the response reflects the decided request.
	if decided, err := api.service.LookupRequest(r.Context(), caller.Owner, id); err == nil {
		request = decided
	}
	jsonResponse(w, http.StatusOK, api.viewLease(caller.Owner, lease.LeaseView{Lease: l, RuntimeAvailable: true}, request))
}

type leaseView struct {
	LeaseID                 string            `json:"lease_id"`
	RequestID               string            `json:"request_id"`
	Client                  callerView        `json:"client"`
	Credential              credentialSummary `json:"credential"`
	State                   string            `json:"state"`
	RuntimeAvailable        bool              `json:"runtime_available"`
	ActivatedAt             time.Time         `json:"activated_at"`
	ExpiresAt               time.Time         `json:"expires_at"`
	EndedAt                 *time.Time        `json:"ended_at,omitempty"`
	AdmittedCalls           int64             `json:"admitted_calls"`
	MaxCalls                *int64            `json:"max_calls"`
	InFlight                int               `json:"in_flight"`
	ApprovalMode            string            `json:"approval_mode"`
	AuthorizationSource     string            `json:"authorization_source"`
	VerificationMethod      string            `json:"verification_method"`
	RenewalRequiresOwner    bool              `json:"renewal_requires_owner_activation"`
	RenewalRequiresConfirm  bool              `json:"renewal_requires_confirmation"`
	RenewalRequiresStepUp   bool              `json:"renewal_requires_step_up"`
	RenewalApprovalRevision string            `json:"renewal_approval_policy_revision"`
}

func (api *securityAPI) viewLease(owner string, l lease.LeaseView, r lease.Request) leaseView {
	p := api.index.Policy(owner)
	v := leaseView{LeaseID: l.ID, RequestID: l.RequestID, Client: api.callerView(owner, l.CallerID),
		Credential: api.summarize(owner, custody.Head{CredentialID: l.CredentialID, ConnectorID: r.Scope.ConnectorID, Epoch: l.Epoch}),
		State:      l.State, RuntimeAvailable: l.RuntimeAvailable, ActivatedAt: l.ActivatedAt, ExpiresAt: l.ExpiresAt,
		AdmittedCalls: l.AdmittedCalls, MaxCalls: l.MaxCalls, InFlight: l.InFlight, ApprovalMode: r.Mode,
		AuthorizationSource: r.AuthorizationSource, VerificationMethod: r.VerificationMethod,
		RenewalRequiresOwner: true, RenewalRequiresConfirm: p.Mode == "confirm", RenewalApprovalRevision: p.Revision}
	v.Credential.Revision = ""
	if !l.EndedAt.IsZero() {
		v.EndedAt = &l.EndedAt
	}
	return v
}

// endedLeaseWindow bounds the optional history of ended windows returned with
// ?include=ended. It is display metadata; nothing here can restore a window.
const endedLeaseWindow = 24 * time.Hour

func (api *securityAPI) leases(w http.ResponseWriter, r *http.Request, caller catalog.AccessRecord) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	include := r.URL.Query().Get("include")
	if include != "" && include != "ended" {
		securityError(w, lease.ErrScope)
		return
	}
	view, err := api.service.View(r.Context(), caller.Owner)
	if err != nil {
		securityError(w, err)
		return
	}
	interactive := caller.Kind == "browser"
	all := append([]lease.LeaseView(nil), view.Leases...)
	if include == "ended" {
		var ended []lease.Lease
		err := api.store.WithOwner(r.Context(), caller.Owner, func(tx lease.Tx) error {
			var err error
			ended, err = tx.(custody.Tx).RecentLeases(tx.Now().Add(-endedLeaseWindow), custody.MaxEndedLeases)
			return err
		})
		if err != nil {
			securityError(w, err)
			return
		}
		live := map[string]bool{}
		for _, l := range view.Leases {
			live[l.ID] = true
		}
		for _, l := range ended {
			// A window that ended after the live view was read appears once.
			if !live[l.ID] {
				all = append(all, lease.LeaseView{Lease: l})
			}
		}
	}
	out := []leaseView{}
	for _, l := range all {
		if !interactive && l.CallerID != caller.ID {
			continue
		}
		request, err := api.service.LookupRequest(r.Context(), caller.Owner, l.RequestID)
		if err != nil {
			securityError(w, err)
			return
		}
		out = append(out, api.viewLease(caller.Owner, l, request))
	}
	jsonResponse(w, http.StatusOK, out)
}

func (api *securityAPI) revokeLease(w http.ResponseWriter, r *http.Request, _ catalog.AccessRecord) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w, "DELETE")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/leases/")
	if !identity.Valid(id) || strings.ToLower(id) != id {
		securityError(w, lease.ErrNotFound)
		return
	}
	// The service lets a key revoke only its own lease and the owner any lease.
	if err := api.service.Revoke(r.Context(), id); err != nil {
		securityError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *securityAPI) lockExecution(w http.ResponseWriter, r *http.Request, _ catalog.AccessRecord) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var in struct{}
	if !decodeBody(w, r, 4096, &in) {
		return
	}
	if err := api.service.LockExecution(r.Context()); err != nil {
		securityError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rateLimits is a fixed one-minute window per key. It bounds abuse from a
// single owner or key; the lease service separately caps pending requests.
type rateLimits struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}
type rateWindow struct {
	start time.Time
	count int
}

func newRateLimits() *rateLimits { return &rateLimits{windows: map[string]rateWindow{}} }

func (l *rateLimits) allow(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.windows) > 4096 {
		for k, w := range l.windows {
			if now.Sub(w.start) >= time.Minute {
				delete(l.windows, k)
			}
		}
	}
	w := l.windows[key]
	if now.Sub(w.start) >= time.Minute {
		w = rateWindow{start: now}
	}
	w.count++
	l.windows[key] = w
	return w.count <= limit
}
