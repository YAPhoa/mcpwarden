package lease

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

type Service struct {
	store     Store
	authority Authority
	activator Activator
	opts      Options
	boot      string
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	owners    map[string]*ownerState
}

type ownerState struct {
	mu                sync.Mutex
	blocked           bool
	suspensionPending bool
	wall              time.Time
	mono              time.Duration
	live              map[string]*runtimeLease
	inflight          map[string]int
	// Deferred effects run only after commit, while this gate is still held.
	publish []func() error
}
type runtimeLease struct {
	lease    Lease
	material Material
	revision string
	deadline time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	inflight int
	ended    bool
}

// Admission is a single-use, internal dispatch capability. Work starts directly
// in Run; retaining unused permits or putting them in a work queue is forbidden.
// Once admitted, cancellation is best effort and cannot undo upstream effects.
type Admission struct {
	Record   audit.Record
	material Material
	ctx      context.Context
	done     func()
	start    func() error
	mu       sync.Mutex
	used     bool
}

func (a *Admission) Run(fn func(context.Context) error) error {
	a.mu.Lock()
	if a.used {
		a.mu.Unlock()
		return ErrDenied
	}
	a.used = true
	a.mu.Unlock()
	defer a.done()
	if err := a.start(); err != nil {
		return err
	}
	if err := a.ctx.Err(); err != nil {
		return err
	}
	return fn(a.ctx)
}

// RunWithMaterial lends the opaque activation only for this single admitted
// call. Constrained transports must also CheckUse/ClaimCall on each HTTP request;
// retaining this material or a detached SDK context does not retain authority.
func (a *Admission) RunWithMaterial(fn func(context.Context, Material) error) error {
	return a.Run(func(ctx context.Context) error { return fn(ctx, a.material) })
}

func New(ctx context.Context, store Store, authority Authority, activator Activator, opts Options) (*Service, error) {
	if store == nil || authority == nil || activator == nil || opts.RequestTTL <= 0 || opts.RequestTTL > 5*time.Minute || opts.ActivationTTL <= 0 || opts.ActivationTTL > time.Minute || opts.MaxTTL <= 0 || opts.MaxTTL > time.Hour || opts.MaxConcurrent < 1 || opts.MaxConcurrent > 128 || opts.MaxPending < 1 || opts.MaxPending > 256 || opts.RequestsPerMinute < 1 || opts.RequestsPerMinute > 1024 || opts.ClockTolerance <= 0 || opts.ClockTolerance > 10*time.Second {
		return nil, ErrScope
	}
	if opts.Clock == nil {
		opts.Clock = realClock{start: time.Now()}
	}
	s := &Service{store: store, authority: authority, activator: activator, opts: opts, boot: identity.New(), done: make(chan struct{}), owners: map[string]*ownerState{}}
	s.ctx, s.cancel = context.WithCancel(ctx)
	if err := store.Start(ctx, s.boot); err != nil {
		s.cancel()
		return nil, err
	}
	go s.watch()
	return s, nil
}

func (s *Service) BootID() string { return s.boot }
func (s *Service) Close()         { s.cancel(); <-s.done }
func (s *Service) state(owner string) *ownerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.owners[owner]
	if o == nil {
		o = &ownerState{live: map[string]*runtimeLease{}, inflight: map[string]int{}}
		s.owners[owner] = o
	}
	return o
}
func (s *Service) states() map[string]*ownerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := make(map[string]*ownerState, len(s.owners))
	for k, v := range s.owners {
		copy[k] = v
	}
	return copy
}
func endRuntime(rt *runtimeLease) {
	if rt.ended {
		return
	}
	rt.ended = true
	rt.cancel()
	if rt.inflight == 0 {
		rt.material.Destroy()
		rt.material = nil
	}
}
func block(o *ownerState) {
	if !o.blocked {
		o.suspensionPending = true
	}
	o.blocked = true
	for id, rt := range o.live {
		endRuntime(rt)
		delete(o.live, id)
	}
}
func (s *Service) stopped() bool {
	select {
	case <-s.ctx.Done():
		return true
	case <-s.store.Lost():
		return true
	default:
		return false
	}
}
func (s *Service) uncertain(o *ownerState) bool {
	wall, mono := s.opts.Clock.Wall(), s.opts.Clock.Mono()
	if !o.wall.IsZero() {
		drift := wall.Sub(o.wall) - (mono - o.mono)
		if mono < o.mono || drift > s.opts.ClockTolerance || drift < -s.opts.ClockTolerance {
			return true
		}
	}
	o.wall, o.mono = wall, mono
	return false
}
func (s *Service) transition(ctx context.Context, owner string, fn func(Tx, *ownerState) error) error {
	if owner == "" || len(owner) > 512 {
		return ErrDenied
	}
	o := s.state(owner)
	o.mu.Lock()
	defer o.mu.Unlock()
	defer func() {
		o.publish = nil
		if value := recover(); value != nil {
			block(o)
			panic(value)
		}
	}()
	if s.stopped() || o.blocked {
		block(o)
		return ErrLocked
	}
	if s.uncertain(o) {
		block(o)
		if s.store.WithOwner(ctx, owner, func(tx Tx) error { return s.endAll(tx, owner, "suspended", "") }) == nil {
			o.suspensionPending = false
		}
		return ErrLocked
	}
	o.publish = nil
	err := s.store.WithOwner(ctx, owner, func(tx Tx) error { return fn(tx, o) })
	if err == nil && s.uncertain(o) {
		block(o)
		err = ErrLocked
	}
	if err == nil && !s.stopped() {
		for _, publish := range o.publish {
			if err = publish(); err != nil {
				break
			}
		}
	}
	o.publish = nil
	if errors.Is(err, ErrStorage) || s.stopped() {
		block(o)
	}
	if err == nil && s.stopped() {
		return ErrLocked
	}
	return err
}

func (s *Service) actor(ctx context.Context, now time.Time, interactive bool) (Caller, error) {
	a, ok := identity.ActorFrom(ctx)
	if !ok || !validID(a.AccessID) {
		return Caller{}, ErrDenied
	}
	c, ok := s.authority.Caller(a.Owner, a.AccessID)
	if !ok || c.Owner != a.Owner || c.AccessID != a.AccessID || !c.Active || !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt) {
		return Caller{}, ErrDenied
	}
	if interactive {
		if !c.Interactive || c.Kind != "browser" {
			return Caller{}, ErrDenied
		}
	} else if c.Kind != "api_key" && !(c.Kind == "browser" && c.Interactive) {
		return Caller{}, ErrDenied
	}
	return c, nil
}
func (s *Service) current(scope Scope, now time.Time) (Credential, Caller, error) {
	c, ok := s.authority.Caller(scope.OwnerID, scope.RequesterAccessID)
	if !ok || c.Owner != scope.OwnerID || c.AccessID != scope.RequesterAccessID || c.Kind != "api_key" || !identity.ValidPublicID(c.PublicID) || !c.Active || !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt) {
		return Credential{}, Caller{}, ErrDenied
	}
	k, ok := s.authority.Credential(scope.OwnerID, scope.CredentialID)
	if !ok || !k.Enabled || k.ID != scope.CredentialID || k.ConnectorID != scope.ConnectorID || k.Epoch != scope.CredentialEpoch || k.DestinationDigest != scope.DestinationDigest || k.PolicyRevision != scope.PolicyRevision || k.ConnectorSecurityRevision != scope.ConnectorSecurityRevision || !validVersion(k.Revision) || !validVersion(k.ApprovalPolicyRevision) || (k.ApprovalMode != "none" && k.ApprovalMode != "confirm") {
		return Credential{}, Caller{}, ErrStale
	}
	for _, t := range scope.Tools {
		current, ok := k.Tools[t.ToolID]
		if !ok || current.ID != t.ToolID || !current.Visible || !current.Allowed || current.DefinitionDigest != t.DefinitionDigest {
			return Credential{}, Caller{}, ErrStale
		}
	}
	return k, c, nil
}
func (s *Service) event(tx Tx, owner, kind, actor, request, leaseID, source string) error {
	return tx.Event(Event{ID: identity.New(), OwnerID: owner, Type: kind, At: tx.Now(), BootID: s.boot, ActorID: actor, RequestID: request, LeaseID: leaseID, Source: source})
}

func (s *Service) Request(ctx context.Context, raw []byte) (Request, error) {
	scope, scopeHash, err := ParseScope(raw)
	if err != nil {
		return Request{}, err
	}
	a, ok := identity.ActorFrom(ctx)
	if !ok || a.Owner != scope.OwnerID {
		return Request{}, ErrDenied
	}
	var out Request
	err = s.transition(ctx, a.Owner, func(tx Tx, _ *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), false)
		if err != nil {
			return err
		}
		if !actor.Interactive && actor.AccessID != scope.RequesterAccessID {
			return ErrDenied
		}
		if time.Duration(scope.DurationSeconds)*time.Second > s.opts.MaxTTL {
			return ErrScope
		}
		credential, _, err := s.current(scope, tx.Now())
		if err != nil {
			return err
		}
		requests, err := tx.Requests()
		if err != nil {
			return err
		}
		pending, recent := 0, 0
		for _, r := range requests {
			if r.CreatedAt.After(tx.Now().Add(-time.Minute)) {
				recent++
			}
			if r.State != "pending" && r.State != "approved" {
				continue
			}
			if !tx.Now().Before(r.ExpiresAt) || r.BootID != s.boot || r.State == "approved" && !tx.Now().Before(r.ActivationDeadline) {
				r.State = "expired"
				if r.BootID != s.boot {
					r.State = "stale"
				}
				if err := tx.PutRequest(r); err != nil {
					return err
				}
				if err := s.event(tx, a.Owner, "request."+r.State, actor.AccessID, r.ID, "", ""); err != nil {
					return err
				}
				continue
			}
			pending++
			if r.ScopeDigest == scopeHash && r.Mode == credential.ApprovalMode && r.ApprovalPolicyRevision == credential.ApprovalPolicyRevision {
				out = r
				return nil
			}
		}
		if pending >= s.opts.MaxPending || recent >= s.opts.RequestsPerMinute {
			return ErrLimit
		}
		var nonce [32]byte
		_, _ = rand.Read(nonce[:])
		b := Binding{ID: identity.New(), BootID: s.boot, Scope: scope, ScopeDigest: scopeHash,
			Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), Mode: credential.ApprovalMode, VerificationMethod: "none", ApprovalPolicyRevision: credential.ApprovalPolicyRevision,
			CreatedAt: tx.Now(), ExpiresAt: tx.Now().Add(s.opts.RequestTTL)}
		encoded, _ := json.Marshal(b)
		encoded, err = canonical(encoded, MaxScopeBytes+4096)
		if err != nil {
			return err
		}
		b.RequestDigest = digest(encoded)
		out = Request{Binding: b, State: "pending"}
		if err := tx.PutRequest(out); err != nil {
			return err
		}
		return s.event(tx, a.Owner, "request.created", actor.AccessID, out.ID, "", "")
	})
	if err != nil {
		return Request{}, err
	}
	return out, nil
}

func (s *Service) validateRequest(r Request, now time.Time) (Credential, Caller, error) {
	if r.BootID != s.boot || !now.Before(r.ExpiresAt) {
		return Credential{}, Caller{}, ErrStale
	}
	k, c, err := s.current(r.Scope, now)
	if err != nil || r.Mode != k.ApprovalMode || r.ApprovalPolicyRevision != k.ApprovalPolicyRevision {
		return Credential{}, Caller{}, ErrStale
	}
	return k, c, nil
}

func (s *Service) Confirm(ctx context.Context, requestID, requestDigest string) (Request, error) {
	a, ok := identity.ActorFrom(ctx)
	if !ok {
		return Request{}, ErrDenied
	}
	var out Request
	err := s.transition(ctx, a.Owner, func(tx Tx, _ *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), true)
		if err != nil {
			return err
		}
		r, err := tx.Request(requestID)
		if err != nil {
			return err
		}
		if r.RequestDigest != requestDigest || r.Mode != "confirm" {
			return ErrDenied
		}
		if _, _, err := s.validateRequest(r, tx.Now()); err != nil {
			return err
		}
		if r.State == "approved" && r.ApproverID == actor.AccessID && tx.Now().Before(r.ActivationDeadline) {
			out = r
			return nil
		}
		if r.State != "pending" {
			return ErrStale
		}
		r.State, r.ApproverID, r.AuthorizationSource = "approved", actor.AccessID, "owner_confirmation"
		r.DecidedAt = tx.Now()
		r.ActivationDeadline = minTime(r.ExpiresAt, tx.Now().Add(s.opts.ActivationTTL))
		if err := tx.PutRequest(r); err != nil {
			return err
		}
		out = r
		return s.event(tx, a.Owner, "request.confirmed", actor.AccessID, r.ID, "", r.AuthorizationSource)
	})
	if err != nil {
		return Request{}, err
	}
	return out, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Service) Activate(ctx context.Context, input ActivationInput) (Lease, error) {
	defer clear(input.Key)
	if !validID(input.RequestID) || !validID(input.OperationID) || !validDigest(input.RequestDigest) || len(input.Key) != 32 {
		return Lease{}, ErrKey
	}
	a, ok := identity.ActorFrom(ctx)
	if !ok {
		return Lease{}, ErrDenied
	}
	var out Lease
	var staged Material
	var publish *runtimeLease
	published := false
	defer func() {
		if !published {
			if publish != nil {
				publish.cancel()
			}
			if staged != nil {
				staged.Destroy()
			}
		}
	}()
	err := s.transition(ctx, a.Owner, func(tx Tx, o *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), true)
		if err != nil {
			return err
		}
		r, err := tx.Request(input.RequestID)
		if err != nil {
			return err
		}
		if r.RequestDigest != input.RequestDigest {
			return ErrDenied
		}
		// A replay cannot recreate lost memory, cross an owner session, or reset
		// the original clock, even when the original request has expired.
		if r.State == "activated" {
			l, err := tx.Lease(r.LeaseID)
			if err != nil {
				return err
			}
			rt := o.live[l.ID]
			if l.OperationID != input.OperationID || l.ActivationActorID != actor.AccessID || !s.live(rt, tx.Now()) {
				return ErrStale
			}
			k, _, err := s.current(r.Scope, tx.Now())
			if err != nil {
				return err
			}
			if r.Mode != k.ApprovalMode || r.ApprovalPolicyRevision != k.ApprovalPolicyRevision || rt.revision != k.Revision {
				return ErrStale
			}
			out = l
			return nil
		}
		k, caller, err := s.validateRequest(r, tx.Now())
		if err != nil {
			return err
		}
		switch r.Mode {
		case "none":
			if r.State != "pending" {
				return ErrStale
			}
			r.ApproverID, r.AuthorizationSource, r.DecidedAt = actor.AccessID, "client_activation", tx.Now()
			r.ActivationDeadline = r.ExpiresAt
		case "confirm":
			if r.State != "approved" || r.ApproverID != actor.AccessID || r.AuthorizationSource != "owner_confirmation" || !tx.Now().Before(r.ActivationDeadline) {
				return ErrStale
			}
		default:
			return ErrDenied
		}
		staged, err = s.activator.Stage(ctx, a.Owner, k, input.Key)
		if err != nil || staged == nil || !reflect.TypeOf(staged).Comparable() {
			return ErrKey
		}
		// Stage is local bounded crypto. Recheck clocks/authority afterward;
		// staging does not reserve authorization or start the working window.
		activationMono := s.opts.Clock.Mono()
		now := s.opts.Clock.Wall().UTC().Truncate(time.Microsecond)
		if now.Before(tx.Now()) {
			now = tx.Now()
		}
		if current, _, err := s.validateRequest(r, now); err != nil {
			return err
		} else if current.Revision != k.Revision {
			return ErrStale
		}
		if _, err := s.actor(ctx, now, true); err != nil {
			return err
		}
		if !now.Before(r.ActivationDeadline) {
			return ErrStale
		}
		duration := time.Duration(r.Scope.DurationSeconds) * time.Second
		end := now.Add(duration)
		if !caller.ExpiresAt.IsZero() {
			end = minTime(end, caller.ExpiresAt)
		}
		end = end.Truncate(time.Microsecond)
		if !end.After(now) {
			return ErrStale
		}
		out = Lease{ID: identity.New(), OwnerID: a.Owner, RequestID: r.ID, CallerID: caller.AccessID,
			CredentialID: k.ID, Epoch: k.Epoch, BootID: s.boot, ScopeDigest: r.ScopeDigest,
			State: "active", ActivatedAt: now, ExpiresAt: end, MaxCalls: r.Scope.MaxCalls,
			ActivationActorID: actor.AccessID, OperationID: input.OperationID}
		r.State, r.LeaseID = "activated", out.ID
		if err := tx.PutRequest(r); err != nil {
			return err
		}
		if err := tx.PutLease(out); err != nil {
			return err
		}
		if err := s.event(tx, a.Owner, "lease.activated", actor.AccessID, r.ID, out.ID, r.AuthorizationSource); err != nil {
			return err
		}
		callCtx, cancel := context.WithCancel(s.ctx)
		publish = &runtimeLease{lease: out, material: staged, revision: k.Revision, deadline: activationMono + end.Sub(now), ctx: callCtx, cancel: cancel}
		o.publish = append(o.publish, func() error {
			if !s.live(publish, s.opts.Clock.Wall()) || ctx.Err() != nil {
				return ErrStale
			}
			if _, err := s.actor(ctx, s.opts.Clock.Wall(), true); err != nil {
				return err
			}
			o.live[out.ID] = publish
			return nil
		})
		return nil
	})
	if err != nil {
		return Lease{}, err
	}
	published = true
	return out, nil
}

func (s *Service) live(rt *runtimeLease, now time.Time) bool {
	return rt != nil && !rt.ended && rt.lease.BootID == s.boot && now.Before(rt.lease.ExpiresAt) && s.opts.Clock.Wall().Before(rt.lease.ExpiresAt) && s.opts.Clock.Mono() < rt.deadline
}

// Admit commits counter reservation and admission audit together. All connection
// setup/refresh must already have completed under separate maintenance authority.
func (s *Service) Admit(ctx context.Context, credentialID, toolID, definition string, args []byte, record audit.Record) (*Admission, error) {
	return s.admit(ctx, credentialID, toolID, definition, args, record, "")
}

// AdmitPrepared binds final dispatch to the exact lease whose material was used
// for Prepare. A concurrent budget reservation or revocation fails closed; it
// never silently switches to another activation/session.
func (s *Service) AdmitPrepared(ctx context.Context, credentialID, toolID, definition string, args []byte, record audit.Record, preparedLeaseID string) (*Admission, error) {
	if !validID(preparedLeaseID) {
		return nil, ErrDenied
	}
	return s.admit(ctx, credentialID, toolID, definition, args, record, preparedLeaseID)
}

func (s *Service) admit(ctx context.Context, credentialID, toolID, definition string, args []byte, record audit.Record, preparedLeaseID string) (*Admission, error) {
	argumentHash, err := argumentBinding(args)
	if err != nil {
		return nil, err
	}
	a, ok := identity.ActorFrom(ctx)
	if !ok {
		return nil, ErrDenied
	}
	var out *Admission
	err = s.transition(ctx, a.Owner, func(tx Tx, o *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), false)
		if err != nil || actor.Kind != "api_key" {
			return ErrDenied
		}
		if o.inflight[actor.AccessID] >= s.opts.MaxConcurrent {
			return ErrBusy
		}
		leases, err := tx.Leases()
		if err != nil {
			return err
		}
		sort.Slice(leases, func(i, j int) bool {
			if leases[i].ExpiresAt.Equal(leases[j].ExpiresAt) {
				return leases[i].ID < leases[j].ID
			}
			return leases[i].ExpiresAt.Before(leases[j].ExpiresAt)
		})
		for _, l := range leases {
			if preparedLeaseID != "" && l.ID != preparedLeaseID {
				continue
			}
			if l.CallerID != actor.AccessID || l.CredentialID != credentialID || l.State != "active" || l.MaxCalls != nil && l.AdmittedCalls >= *l.MaxCalls || !s.live(o.live[l.ID], tx.Now()) {
				continue
			}
			r, err := tx.Request(l.RequestID)
			if err != nil {
				return err
			}
			k, currentCaller, err := s.current(r.Scope, tx.Now())
			if err != nil || r.Mode != k.ApprovalMode || r.ApprovalPolicyRevision != k.ApprovalPolicyRevision || o.live[l.ID].revision != k.Revision || !r.Scope.Matches(toolID, definition, args) {
				continue
			}
			if record.Owner != a.Owner || record.ToolID != toolID || record.UpstreamID != k.ConnectorID || record.ArgsSHA256 != audit.HashArgs(json.RawMessage(args)) {
				return ErrDenied
			}
			record.ActorType, record.ActorAccessID, record.ActorPublicID, record.ActorLabel = currentCaller.Kind, currentCaller.AccessID, currentCaller.PublicID, currentCaller.Label
			record.CredentialID, record.CredentialEpoch, record.CredentialRevision = k.ID, k.Epoch, k.Revision
			record.ApprovalID, record.LeaseID, record.ScopeDigest = r.ID, l.ID, r.ScopeDigest
			record.ApprovalMode, record.ApprovalPolicyRevision, record.AuthorizationSource, record.VerificationMethod = r.Mode, r.ApprovalPolicyRevision, r.AuthorizationSource, "none"
			record = record.Admission()
			record.OccurredAt = tx.Now()
			l.AdmittedCalls++
			if err := tx.PutLease(l); err != nil {
				return err
			}
			if err := tx.Admission(record); err != nil {
				return err
			}
			rt := o.live[l.ID]
			callCtx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(rt.ctx, cancel)
			out = &Admission{Record: record, material: rt.material}
			out.start = s.useCheck(callCtx, o, rt, r)
			out.ctx = withUse(callCtx, rt.material, "call", argumentHash, out.start)
			reserved := false
			out.done = func() {
				stop()
				cancel()
				o.mu.Lock()
				defer o.mu.Unlock()
				if !reserved {
					return
				}
				reserved = false
				rt.inflight--
				o.inflight[actor.AccessID]--
				if rt.ended && rt.inflight == 0 && rt.material != nil {
					rt.material.Destroy()
					rt.material = nil
				}
			}
			o.publish = append(o.publish, func() error {
				if !s.live(rt, s.opts.Clock.Wall()) || callCtx.Err() != nil {
					return ErrStale
				}
				rt.inflight++
				o.inflight[actor.AccessID]++
				rt.lease = l
				reserved = true
				return nil
			})
			return nil
		}
		return ErrRequired
	})
	if err != nil {
		if out != nil {
			out.done()
		}
		return nil, err
	}
	return out, nil
}

func (s *Service) endAll(tx Tx, owner, state, actor string) error {
	requests, err := tx.Requests()
	if err != nil {
		return err
	}
	for _, r := range requests {
		if r.State != "pending" && r.State != "approved" {
			continue
		}
		r.State = "stale"
		if err := tx.PutRequest(r); err != nil {
			return err
		}
		if err := s.event(tx, owner, "request.stale", actor, r.ID, "", ""); err != nil {
			return err
		}
	}
	leases, err := tx.Leases()
	if err != nil {
		return err
	}
	for _, l := range leases {
		l.State, l.EndedAt = state, tx.Now()
		if err := tx.PutLease(l); err != nil {
			return err
		}
		if err := s.event(tx, owner, "lease."+state, actor, l.RequestID, l.ID, ""); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	a, ok := identity.ActorFrom(ctx)
	if !ok {
		return ErrDenied
	}
	return s.transition(ctx, a.Owner, func(tx Tx, o *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), false)
		if err != nil {
			return err
		}
		l, err := tx.Lease(id)
		if err != nil {
			return err
		}
		if !actor.Interactive && actor.AccessID != l.CallerID {
			return ErrDenied
		}
		if l.State != "active" {
			return nil
		}
		l.State, l.EndedAt = "revoked", tx.Now()
		if err := tx.PutLease(l); err != nil {
			return err
		}
		if err := s.event(tx, a.Owner, "lease.revoked", actor.AccessID, l.RequestID, id, ""); err != nil {
			return err
		}
		o.publish = append(o.publish, func() error {
			if rt := o.live[id]; rt != nil {
				endRuntime(rt)
				delete(o.live, id)
			}
			return nil
		})
		return nil
	})
}

func (s *Service) Deny(ctx context.Context, id string) error {
	a, ok := identity.ActorFrom(ctx)
	if !ok {
		return ErrDenied
	}
	return s.transition(ctx, a.Owner, func(tx Tx, _ *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), true)
		if err != nil {
			return err
		}
		r, err := tx.Request(id)
		if err != nil {
			return err
		}
		if r.State != "pending" && r.State != "approved" {
			return ErrStale
		}
		if r.State == "pending" {
			r.DecidedAt, r.ApproverID = tx.Now(), actor.AccessID
		}
		r.State = "denied"
		if err := tx.PutRequest(r); err != nil {
			return err
		}
		return s.event(tx, a.Owner, "request.denied", actor.AccessID, id, "", "")
	})
}

func (s *Service) LockExecution(ctx context.Context) error {
	a, ok := identity.ActorFrom(ctx)
	if !ok {
		return ErrDenied
	}
	return s.transition(ctx, a.Owner, func(tx Tx, o *ownerState) error {
		actor, err := s.actor(ctx, tx.Now(), true)
		if err != nil {
			return err
		}
		if err := s.endAll(tx, a.Owner, "revoked", actor.AccessID); err != nil {
			return err
		}
		if err := s.event(tx, a.Owner, "execution.locked", actor.AccessID, "", "", ""); err != nil {
			return err
		}
		o.publish = append(o.publish, func() error {
			for id, rt := range o.live {
				endRuntime(rt)
				delete(o.live, id)
			}
			return nil
		})
		return nil
	})
}

// Change serializes a trusted catalog security mutation with admission. It
// invalidates old bindings first; a failed mutation conservatively keeps access
// stopped. Integrations must authenticate the mutation before invoking Change.
func (s *Service) Change(ctx context.Context, owner string, mutation func() error) error {
	return s.transition(ctx, owner, func(tx Tx, o *ownerState) error {
		if err := s.endAll(tx, owner, "revoked", ""); err != nil {
			return err
		}
		o.publish = append(o.publish, func() error {
			for id, rt := range o.live {
				endRuntime(rt)
				delete(o.live, id)
			}
			return mutation()
		})
		return nil
	})
}

// ChangeAtomic commits a trusted security mutation, revocations and their audit
// events in the same owner transaction. Integrations must authorize the mutation
// before calling this method. mutation may only write through tx; it must not
// modify shared caches or perform provider I/O. Its optional returned function
// publishes the committed snapshot under the owner gate, after old material is
// stopped. Publication failure locks this owner until a fresh process reloads.
// Neither callback is retried, including when the commit outcome is unknown.
func (s *Service) ChangeAtomic(ctx context.Context, owner string, mutation func(Tx) (func() error, error)) error {
	return s.changeAtomic(ctx, owner, false, mutation)
}

// ChangeOwnerAtomic authorizes an interactive browser under the owner gate,
// after the database owner lock is acquired, and again after the writes. Session
// revocation must use ChangeSessions so it cannot interleave with this commit.
func (s *Service) ChangeOwnerAtomic(ctx context.Context, mutation func(Tx) (func() error, error)) error {
	a, ok := identity.ActorFrom(ctx)
	if !ok {
		return ErrDenied
	}
	return s.changeAtomic(ctx, a.Owner, true, mutation)
}

// ChangeSessions serializes trusted browser-session and password changes with
// owner mutations. It does not end agent windows and still works with lost
// storage or a locked executor. The callback must not call back into Service.
func (s *Service) ChangeSessions(ctx context.Context, owner string, mutation func() error) error {
	if owner == "" || len(owner) > 512 || mutation == nil {
		return ErrDenied
	}
	o := s.state(owner)
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return mutation()
}

// Catalog commits one catalog change in a single owner transaction under the
// owner gate. With endLeases the same transaction ends pending requests and
// windows, and live material is dropped before publication. publish runs only
// after a successful commit, still under the gate, and must not fail. Unlike
// admission this also runs for a blocked owner: a blocked owner holds no live
// material, and revocations must not wait for a restart. Lost storage returns an
// error with the commit outcome possibly unknown; callers never retry the
// mutation or fall back to another store. The callback must not call Service.
func (s *Service) Catalog(ctx context.Context, owner string, endLeases bool, mutation func(Tx) (func(), error)) error {
	if owner == "" || len(owner) > 512 || mutation == nil {
		return ErrDenied
	}
	o := s.state(owner)
	o.mu.Lock()
	defer o.mu.Unlock()
	if s.stopped() {
		block(o)
		return ErrLocked
	}
	var publish func()
	err := s.store.WithOwner(ctx, owner, func(tx Tx) error {
		p, err := mutation(tx)
		if err != nil {
			return err
		}
		if endLeases {
			if err := s.endAll(tx, owner, "revoked", ""); err != nil {
				return err
			}
		}
		publish = p
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrStorage) || s.stopped() {
			block(o)
		}
		return err
	}
	if endLeases {
		for id, rt := range o.live {
			endRuntime(rt)
			delete(o.live, id)
		}
	}
	if publish != nil {
		publish()
	}
	return nil
}

func (s *Service) changeAtomic(ctx context.Context, owner string, interactive bool, mutation func(Tx) (func() error, error)) error {
	if mutation == nil {
		return ErrDenied
	}
	return s.transition(ctx, owner, func(tx Tx, o *ownerState) error {
		if interactive {
			if _, err := s.actor(ctx, tx.Now(), true); err != nil {
				return err
			}
		}
		publish, err := mutation(tx)
		if err != nil {
			return err
		}
		if err = s.endAll(tx, owner, "revoked", ""); err != nil {
			return err
		}
		if interactive {
			// A session can expire while a write is waiting on a database lock.
			if _, err := s.actor(ctx, s.opts.Clock.Wall(), true); err != nil {
				return err
			}
		}
		o.publish = append(o.publish, func() error {
			for id, rt := range o.live {
				endRuntime(rt)
				delete(o.live, id)
			}
			if publish != nil && publish() != nil {
				block(o)
				return ErrStorage
			}
			return nil
		})
		return nil
	})
}

// Sweep handles expiry and clock discontinuities even when no MCP request is
// arriving. Expired material is inaccessible immediately; in-flight users drain.
func (s *Service) Sweep(ctx context.Context) {
	for owner, o := range s.states() {
		o.mu.Lock()
		if s.stopped() {
			block(o)
			o.mu.Unlock()
			continue
		}
		if !o.blocked && s.uncertain(o) {
			block(o)
		}
		needed := o.suspensionPending
		for _, rt := range o.live {
			needed = needed || !s.live(rt, s.opts.Clock.Wall())
		}
		if !needed {
			o.mu.Unlock()
			continue
		}
		err := s.store.WithOwner(ctx, owner, func(tx Tx) error {
			if o.blocked {
				return s.endAll(tx, owner, "suspended", "")
			}
			for id, rt := range o.live {
				if s.live(rt, tx.Now()) {
					continue
				}
				l, err := tx.Lease(id)
				if err != nil {
					return err
				}
				l.State, l.EndedAt = "expired", tx.Now()
				if err := tx.PutLease(l); err != nil {
					return err
				}
				if err := s.event(tx, owner, "lease.expired", "", l.RequestID, id, ""); err != nil {
					return err
				}
				endRuntime(rt)
				delete(o.live, id)
			}
			return nil
		})
		if err != nil {
			block(o)
		} else {
			o.suspensionPending = false
		}
		o.mu.Unlock()
	}
}

func (s *Service) watch() {
	defer close(s.done)
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			for _, o := range s.states() {
				o.mu.Lock()
				block(o)
				o.mu.Unlock()
			}
			return
		case <-s.store.Lost():
			s.cancel()
		case <-timer.C:
			s.Sweep(s.ctx)
		}
	}
}
