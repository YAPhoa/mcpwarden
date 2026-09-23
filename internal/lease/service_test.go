package lease

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

type testClock struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func (c *testClock) Wall() time.Time     { c.mu.Lock(); defer c.mu.Unlock(); return c.wall }
func (c *testClock) Mono() time.Duration { c.mu.Lock(); defer c.mu.Unlock(); return c.mono }
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
	c.mono += d
}
func (c *testClock) jump(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.wall = c.wall.Add(d) }

type testState struct {
	Requests   map[string]Request
	Leases     map[string]Lease
	Events     []Event
	Admissions []audit.Record
}
type testStore struct {
	mu           sync.Mutex
	state        testState
	clock        *testClock
	lost         chan struct{}
	fail         bool
	beforeCommit func()
}

func (s *testStore) Start(_ context.Context, boot string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, l := range s.state.Leases {
		if l.State == "active" {
			l.State = "suspended"
			l.EndedAt = s.clock.Wall()
			s.state.Leases[id] = l
		}
	}
	for id, r := range s.state.Requests {
		if r.State == "pending" || r.State == "approved" {
			r.State = "stale"
			s.state.Requests[id] = r
		}
	}
	return nil
}
func (s *testStore) Lost() <-chan struct{} { return s.lost }
func (s *testStore) WithOwner(ctx context.Context, owner string, fn func(Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	b, _ := json.Marshal(s.state)
	var copy testState
	if err := json.Unmarshal(b, &copy); err != nil {
		panic(err)
	}
	tx := &testTx{owner: owner, now: s.clock.Wall(), state: &copy}
	if err := fn(tx); err != nil {
		return err
	}
	if s.beforeCommit != nil {
		s.beforeCommit()
	}
	if s.fail {
		s.fail = false
		return ErrStorage
	}
	s.state = copy
	return nil
}
func (s *testStore) snapshot() testState {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.state)
	var copy testState
	_ = json.Unmarshal(b, &copy)
	return copy
}

type testTx struct {
	owner string
	now   time.Time
	state *testState
}

func (x *testTx) Now() time.Time { return x.now }
func (x *testTx) Request(id string) (Request, error) {
	r, ok := x.state.Requests[id]
	if !ok || r.Scope.OwnerID != x.owner {
		return Request{}, ErrNotFound
	}
	return r, nil
}
func (x *testTx) Requests() ([]Request, error) {
	var rs []Request
	for _, r := range x.state.Requests {
		if r.Scope.OwnerID == x.owner && (r.State == "pending" || r.State == "approved" || r.CreatedAt.After(x.now.Add(-time.Minute))) {
			rs = append(rs, r)
		}
	}
	return rs, nil
}
func (x *testTx) PutRequest(r Request) error {
	if r.Scope.OwnerID != x.owner {
		return ErrDenied
	}
	x.state.Requests[r.ID] = r
	return nil
}
func (x *testTx) Lease(id string) (Lease, error) {
	l, ok := x.state.Leases[id]
	if !ok || l.OwnerID != x.owner {
		return Lease{}, ErrNotFound
	}
	return l, nil
}
func (x *testTx) Leases() ([]Lease, error) {
	var ls []Lease
	for _, l := range x.state.Leases {
		if l.OwnerID == x.owner && l.State == "active" {
			ls = append(ls, l)
		}
	}
	return ls, nil
}
func (x *testTx) PutLease(l Lease) error {
	if l.OwnerID != x.owner {
		return ErrDenied
	}
	x.state.Leases[l.ID] = l
	return nil
}
func (x *testTx) Event(e Event) error { x.state.Events = append(x.state.Events, e); return nil }
func (x *testTx) Admission(r audit.Record) error {
	x.state.Admissions = append(x.state.Admissions, r)
	return nil
}

type testAuthority struct {
	mu         sync.Mutex
	callers    map[string]Caller
	credential Credential
}

func (a *testAuthority) Caller(owner, id string) (Caller, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.callers[id]
	return c, ok && c.Owner == owner
}
func (a *testAuthority) Credential(owner, id string) (Credential, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.credential, owner == "alice" && a.credential.ID == id
}

type testMaterial struct{ destroyed atomic.Int32 }

func (m *testMaterial) Destroy() { m.destroyed.Add(1) }

type testActivator struct {
	mu        sync.Mutex
	materials []*testMaterial
	hook      func()
	fail      bool
}

func (a *testActivator) Stage(_ context.Context, _ string, _ Credential, key []byte) (Material, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hook != nil {
		a.hook()
	}
	if a.fail || key[0] != 42 {
		return nil, ErrKey
	}
	m := &testMaterial{}
	a.materials = append(a.materials, m)
	return m, nil
}
func (a *testActivator) last() *testMaterial {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.materials[len(a.materials)-1]
}

type harness struct {
	service         *Service
	store           *testStore
	clock           *testClock
	authority       *testAuthority
	activator       *testActivator
	caller, browser context.Context
	scope           Scope
}

func newHarness(t *testing.T, mode string, configure func(*Options)) *harness {
	t.Helper()
	scope := fixtureScope()
	clock := &testClock{wall: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}
	key := Caller{Actor: identity.Actor{Owner: "alice", AccessID: callerID, PublicID: "0123456789abcdef0123456789abcdef", Kind: "api_key", Label: "agent"}, Active: true}
	browser := Caller{Actor: identity.Actor{Owner: "alice", AccessID: browserID, Kind: "browser", Label: "owner"}, Active: true, Interactive: true}
	a := &testAuthority{callers: map[string]Caller{callerID: key, browserID: browser}, credential: Credential{ID: credentialID, ConnectorID: connectorID, Epoch: "1", Revision: "1", PolicyRevision: "1", ConnectorSecurityRevision: "1", ApprovalPolicyRevision: "1", ApprovalMode: mode, Enabled: true, DestinationDigest: scope.DestinationDigest, Tools: map[string]Tool{toolID: {ID: toolID, DefinitionDigest: scope.Tools[0].DefinitionDigest, Allowed: true, Visible: true}}}}
	store := &testStore{state: testState{Requests: map[string]Request{}, Leases: map[string]Lease{}}, clock: clock, lost: make(chan struct{})}
	act := &testActivator{}
	opts := DefaultOptions()
	opts.Clock = clock
	if configure != nil {
		configure(&opts)
	}
	s, err := New(context.Background(), store, a, act, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return &harness{s, store, clock, a, act, identity.WithActor(context.Background(), key.Actor), identity.WithActor(context.Background(), browser.Actor), scope}
}
func (h *harness) request(t *testing.T) Request {
	t.Helper()
	r, err := h.service.Request(h.caller, scopeBytes(t, h.scope))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func activation(r Request) ActivationInput {
	key := make([]byte, 32)
	key[0] = 42
	return ActivationInput{RequestID: r.ID, RequestDigest: r.RequestDigest, OperationID: identity.New(), Key: key}
}
func (h *harness) activate(t *testing.T) Lease {
	t.Helper()
	r := h.request(t)
	if r.Mode == "confirm" {
		var err error
		r, err = h.service.Confirm(h.browser, r.ID, r.RequestDigest)
		if err != nil {
			t.Fatal(err)
		}
	}
	l, err := h.service.Activate(h.browser, activation(r))
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func (h *harness) admit(ctx context.Context, args string) (*Admission, error) {
	r := audit.NewInvocation(ctx, "alice")
	r.ToolID = toolID
	r.Tool = "files.search"
	r.UpstreamID = connectorID
	r.ArgsSHA256 = audit.HashArgs(json.RawMessage(args))
	return h.service.Admit(ctx, credentialID, toolID, h.scope.Tools[0].DefinitionDigest, []byte(args), r)
}

func TestWorkingWindowRepeatedCallsAndFixedExpiry(t *testing.T) {
	h := newHarness(t, "none", nil)
	l := h.activate(t)
	for i := 0; i < 25; i++ {
		a, err := h.admit(h.caller, `{}`)
		if err != nil {
			t.Fatal(err)
		}
		if a.Record.LeaseID != l.ID || a.Record.ActorAccessID != callerID || a.Record.AuthorizationSource != "client_activation" {
			t.Fatal("incorrect audit attribution")
		}
		if err := a.Run(func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := a.Run(func(context.Context) error { t.Fatal("replayed"); return nil }); err != ErrDenied {
			t.Fatal("permit reusable")
		}
		h.clock.advance(30 * time.Second)
	}
	stored := h.store.snapshot().Leases[l.ID]
	if !stored.ExpiresAt.Equal(l.ExpiresAt) || stored.AdmittedCalls != 25 {
		t.Fatal("traffic changed fixed window")
	}
	h.clock.advance(150 * time.Second)
	if _, err := h.admit(h.caller, `{}`); err != ErrRequired {
		t.Fatalf("expired lease admitted: %v", err)
	}
	h.service.Sweep(context.Background())
	if h.activator.last().destroyed.Load() != 1 {
		t.Fatal("expired material not destroyed exactly once")
	}
}

func TestOwnerActivationAndReplay(t *testing.T) {
	for _, mode := range []string{"none", "confirm"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, mode, nil)
			r := h.request(t)
			if _, err := h.service.Activate(h.caller, activation(r)); err != ErrDenied {
				t.Fatal("MCP key activated itself")
			}
			if _, err := h.service.Confirm(h.caller, r.ID, r.RequestDigest); err != ErrDenied {
				t.Fatal("MCP key confirmed itself")
			}
			if mode == "confirm" {
				if _, err := h.service.Activate(h.browser, activation(r)); err != ErrStale {
					t.Fatal("activation without confirmation")
				}
				var err error
				r, err = h.service.Confirm(h.browser, r.ID, r.RequestDigest)
				if err != nil {
					t.Fatal(err)
				}
			}
			h.clock.advance(30 * time.Second)
			in := activation(r)
			op := in.OperationID
			l, err := h.service.Activate(h.browser, in)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range in.Key {
				if b != 0 {
					t.Fatal("release buffer retained")
				}
			}
			if !l.ActivatedAt.Equal(h.clock.Wall()) {
				t.Fatal("window started before activation")
			}
			h.clock.advance(6 * time.Minute)
			replay := activation(r)
			replay.OperationID = op
			again, err := h.service.Activate(h.browser, replay)
			if err != nil || !again.ExpiresAt.Equal(l.ExpiresAt) {
				t.Fatalf("idempotency changed deadline: %v", err)
			}
			if _, err := h.service.Activate(h.browser, activation(r)); err != ErrStale {
				t.Fatal("new operation reset same request")
			}
		})
	}
}

func TestActivationCommitFailureAndExpiredConfirmation(t *testing.T) {
	t.Run("commit", func(t *testing.T) {
		h := newHarness(t, "none", nil)
		r := h.request(t)
		h.store.mu.Lock()
		h.store.fail = true
		h.store.mu.Unlock()
		if _, err := h.service.Activate(h.browser, activation(r)); err != ErrStorage {
			t.Fatal(err)
		}
		if h.activator.last().destroyed.Load() != 1 || len(h.store.snapshot().Leases) != 0 {
			t.Fatal("failed transaction published material/state")
		}
		if _, err := h.admit(h.caller, `{}`); err != ErrLocked {
			t.Fatal("storage failure did not lock execution")
		}
	})
	t.Run("confirmation", func(t *testing.T) {
		h := newHarness(t, "confirm", nil)
		r := h.request(t)
		if _, err := h.service.Confirm(h.browser, r.ID, r.RequestDigest); err != nil {
			t.Fatal(err)
		}
		h.clock.advance(time.Minute)
		if _, err := h.service.Activate(h.browser, activation(r)); err != ErrStale {
			t.Fatal("expired activation challenge accepted")
		}
	})
	t.Run("commit delay", func(t *testing.T) {
		h := newHarness(t, "none", nil)
		r := h.request(t)
		h.store.mu.Lock()
		h.store.beforeCommit = func() { h.clock.advance(16 * time.Minute) }
		h.store.mu.Unlock()
		if _, err := h.service.Activate(h.browser, activation(r)); err != ErrStale {
			t.Fatal(err)
		}
		if h.activator.last().destroyed.Load() != 1 {
			t.Fatal("expired staged material published")
		}
	})
}

func TestExactCallerScopeAndMutation(t *testing.T) {
	h := newHarness(t, "none", nil)
	h.scope.Tools[0].Constraints = []Constraint{{Pointer: "/id", Operator: "equals", Value: []byte(`"allowed"`)}}
	h.activate(t)
	otherID := identity.New()
	h.authority.mu.Lock()
	other := h.authority.callers[callerID]
	other.AccessID = otherID
	h.authority.callers[otherID] = other
	h.authority.mu.Unlock()
	if _, err := h.admit(identity.WithActor(context.Background(), other.Actor), `{"id":"allowed"}`); err != ErrRequired {
		t.Fatal("different key borrowed lease")
	}
	if _, err := h.admit(h.caller, `{"id":"different"}`); err != ErrRequired {
		t.Fatal("constraint bypass")
	}
	if err := h.service.Change(context.Background(), "alice", func() error {
		h.authority.mu.Lock()
		defer h.authority.mu.Unlock()
		h.authority.credential.Epoch = "2"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admit(h.caller, `{"id":"allowed"}`); err != ErrRequired {
		t.Fatal("epoch change retained authority")
	}
	if h.activator.last().destroyed.Load() != 1 {
		t.Fatal("mutation retained material")
	}
}

func TestBudgetAdmissionAtomicAndConcurrency(t *testing.T) {
	h := newHarness(t, "none", func(o *Options) { o.MaxConcurrent = 128 })
	budget := int64(7)
	h.scope.MaxCalls = &budget
	l := h.activate(t)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := h.admit(h.caller, `{}`)
			if err == nil {
				successes.Add(1)
				if err := a.Run(func(context.Context) error { return nil }); err != nil {
					t.Error(err)
				}
			} else if err != ErrRequired {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	state := h.store.snapshot()
	if successes.Load() != 7 || state.Leases[l.ID].AdmittedCalls != 7 || len(state.Admissions) != 7 {
		t.Fatal("budget and admissions diverged")
	}
	h2 := newHarness(t, "none", nil)
	l2 := h2.activate(t)
	h2.store.mu.Lock()
	h2.store.fail = true
	h2.store.mu.Unlock()
	if _, err := h2.admit(h2.caller, `{}`); err != ErrStorage {
		t.Fatal(err)
	}
	snap := h2.store.snapshot()
	if snap.Leases[l2.ID].AdmittedCalls != 0 || len(snap.Admissions) != 0 {
		t.Fatal("partial admission commit")
	}
}

func TestRevocationDoesNotHoldGateAcrossNetwork(t *testing.T) {
	h := newHarness(t, "none", nil)
	l := h.activate(t)
	started := make(chan struct{})
	finished := make(chan error, 1)
	a, err := h.admit(h.caller, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		finished <- a.Run(func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() })
	}()
	<-started
	if err := h.service.Revoke(h.browser, l.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("revocation blocked on provider")
	}
	if h.activator.last().destroyed.Load() != 1 {
		t.Fatal("drained material retained")
	}
	if _, err := h.admit(h.caller, `{}`); err != ErrRequired {
		t.Fatal("revoked lease admitted")
	}
}

func TestClockDiscontinuityRestartAndLostLock(t *testing.T) {
	for _, d := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(d.String(), func(t *testing.T) {
			h := newHarness(t, "none", nil)
			h.activate(t)
			h.clock.jump(d)
			if _, err := h.admit(h.caller, `{}`); err != ErrLocked {
				t.Fatal("clock jump accepted")
			}
			if h.activator.last().destroyed.Load() != 1 {
				t.Fatal("clock jump retained material")
			}
		})
	}
	t.Run("restart", func(t *testing.T) {
		h := newHarness(t, "none", nil)
		l := h.activate(t)
		h.service.Close()
		opts := DefaultOptions()
		opts.Clock = h.clock
		next, err := New(context.Background(), h.store, h.authority, h.activator, opts)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(next.Close)
		h.service = next
		if _, err := h.admit(h.caller, `{}`); err != ErrRequired {
			t.Fatal("restart restored authority")
		}
		if h.store.snapshot().Leases[l.ID].State != "suspended" {
			t.Fatal("old boot not suspended")
		}
	})
	t.Run("lock loss", func(t *testing.T) {
		h := newHarness(t, "none", nil)
		h.activate(t)
		close(h.store.lost)
		if _, err := h.admit(h.caller, `{}`); err != ErrLocked {
			t.Fatal("lost executor lock admitted")
		}
	})
}

func TestConcurrencyRejectsAndUnusedAdmissionExpires(t *testing.T) {
	h := newHarness(t, "none", nil)
	h.activate(t)
	admissions := make([]*Admission, 4)
	for i := range admissions {
		var err error
		admissions[i], err = h.admit(h.caller, `{}`)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.admit(h.caller, `{}`); err != ErrBusy {
		t.Fatal("concurrent call queued or admitted")
	}
	h.clock.advance(15 * time.Minute)
	for _, a := range admissions {
		if err := a.Run(func(context.Context) error { t.Fatal("delayed permit dispatched after expiry"); return nil }); err == nil {
			t.Fatal("expired permit succeeded")
		}
	}
}

func TestRenewalBrowserClosureAndExecutionLock(t *testing.T) {
	h := newHarness(t, "none", nil)
	r := h.request(t)
	duplicate := h.request(t)
	if r.ID != duplicate.ID {
		t.Fatal("equivalent live request was not deduplicated")
	}
	if !r.Binding.Valid() {
		t.Fatal("generated binding is not self-consistent")
	}
	changed := r.Binding
	changed.VerificationMethod = "totp"
	if changed.Valid() {
		t.Fatal("verification substitution retained valid binding")
	}
	first, err := h.service.Activate(h.browser, activation(r))
	if err != nil {
		t.Fatal(err)
	}
	h.clock.advance(time.Minute)
	second := h.activate(t)
	if first.ID == second.ID || first.RequestID == second.RequestID || !second.ExpiresAt.After(first.ExpiresAt) {
		t.Fatal("renewal did not create a new window")
	}
	if !h.store.snapshot().Leases[first.ID].ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("renewal edited the old deadline")
	}
	// Loss of the browser connection does not terminate agent authority.
	closedBrowser, cancel := context.WithCancel(h.browser)
	cancel()
	if _, err := h.service.Activate(closedBrowser, activation(r)); err == nil {
		t.Fatal("cancelled owner request activated")
	}
	a, err := h.admit(h.caller, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if a.Record.LeaseID != first.ID {
		t.Fatal("selection did not prefer earliest expiry")
	}
	_ = a.Run(func(context.Context) error { return nil })
	if err := h.service.LockExecution(h.browser); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admit(h.caller, `{}`); err != ErrRequired {
		t.Fatal("execution lock retained a lease")
	}
}

func TestNoUnionAndCurrentToolPolicy(t *testing.T) {
	h := newHarness(t, "none", nil)
	constraint := func(repo, branch string) []Constraint {
		a, _ := json.Marshal(repo)
		b, _ := json.Marshal(branch)
		return []Constraint{{Pointer: "/repo", Operator: "equals", Value: a}, {Pointer: "/branch", Operator: "equals", Value: b}}
	}
	h.scope.Tools[0].Constraints = constraint("a", "main")
	h.activate(t)
	h.scope.Tools[0].Constraints = constraint("b", "dev")
	h.activate(t)
	if _, err := h.admit(h.caller, `{"repo":"a","branch":"dev"}`); err != ErrRequired {
		t.Fatal("partial scopes were combined")
	}
	for _, change := range []func(*Credential){func(k *Credential) { k.Enabled = false }, func(k *Credential) { tool := k.Tools[toolID]; tool.Visible = false; k.Tools[toolID] = tool }, func(k *Credential) {
		tool := k.Tools[toolID]
		tool.DefinitionDigest = digest([]byte("changed"))
		k.Tools[toolID] = tool
	}} {
		h.authority.mu.Lock()
		original := h.authority.credential
		originalTool := original.Tools[toolID]
		change(&h.authority.credential)
		h.authority.mu.Unlock()
		if _, err := h.admit(h.caller, `{"repo":"a","branch":"main"}`); err != ErrRequired {
			t.Fatal("old lease overrode current tool/provider restrictions")
		}
		h.authority.mu.Lock()
		h.authority.credential = original
		h.authority.credential.Tools[toolID] = originalTool
		h.authority.mu.Unlock()
	}
}

func TestCallerExpiryOwnerIsolationAndRequestLimits(t *testing.T) {
	h := newHarness(t, "confirm", func(o *Options) { o.MaxPending = 2; o.RequestsPerMinute = 3 })
	h.authority.mu.Lock()
	caller := h.authority.callers[callerID]
	caller.ExpiresAt = h.clock.Wall().Add(2 * time.Minute)
	h.authority.callers[callerID] = caller
	h.authority.mu.Unlock()
	l := h.activate(t)
	if !l.ExpiresAt.Equal(caller.ExpiresAt) {
		t.Fatal("lease outlived its caller key")
	}
	bobID := identity.New()
	h.authority.mu.Lock()
	bob := h.authority.callers[browserID]
	bob.Owner = "bob"
	bob.AccessID = bobID
	h.authority.callers[bobID] = bob
	h.authority.mu.Unlock()
	bobCtx := identity.WithActor(context.Background(), bob.Actor)
	if err := h.service.Revoke(bobCtx, l.ID); err != ErrNotFound {
		t.Fatal("cross-owner revocation")
	}
	if _, err := h.service.Confirm(bobCtx, l.RequestID, h.store.snapshot().Requests[l.RequestID].RequestDigest); err != ErrNotFound {
		t.Fatal("cross-owner confirmation")
	}
	h.scope.DurationSeconds = 600
	r := h.request(t)
	h.scope.DurationSeconds = 601
	h.request(t)
	h.scope.DurationSeconds = 602
	if _, err := h.service.Request(h.caller, scopeBytes(t, h.scope)); err != ErrLimit {
		t.Fatal("request caps ignored")
	}
	if _, err := h.service.Confirm(h.browser, r.ID, r.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if err := h.service.Deny(h.browser, r.ID); err != nil {
		t.Fatal(err)
	}
	h.clock.advance(2 * time.Minute)
	if _, err := h.admit(h.caller, `{}`); err != ErrDenied {
		t.Fatal("expired caller authenticated")
	}
}

func TestActivationClockAndOwnerExpiryDuringStage(t *testing.T) {
	t.Run("clock jump", func(t *testing.T) {
		h := newHarness(t, "none", nil)
		r := h.request(t)
		h.activator.hook = func() { h.clock.jump(-time.Hour) }
		if _, err := h.service.Activate(h.browser, activation(r)); err != ErrLocked {
			t.Fatal("clock jump during activation published material")
		}
		if h.activator.last().destroyed.Load() != 1 {
			t.Fatal("staged material retained")
		}
	})
	t.Run("owner expiry", func(t *testing.T) {
		h := newHarness(t, "none", nil)
		h.authority.mu.Lock()
		owner := h.authority.callers[browserID]
		owner.ExpiresAt = h.clock.Wall().Add(time.Second)
		h.authority.callers[browserID] = owner
		h.authority.mu.Unlock()
		r := h.request(t)
		h.activator.hook = func() { h.clock.advance(2 * time.Second) }
		if _, err := h.service.Activate(h.browser, activation(r)); err != ErrDenied {
			t.Fatal("expired owner completed activation")
		}
	})
}

func TestActivationPanicDiscardsStagedMaterial(t *testing.T) {
	h := newHarness(t, "none", nil)
	h.activate(t)
	old := h.activator.last()
	r := h.request(t)
	h.store.mu.Lock()
	h.store.beforeCommit = func() { panic("synthetic store interruption") }
	h.store.mu.Unlock()
	in := activation(r)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("fixture did not panic")
			}
		}()
		_, _ = h.service.Activate(h.browser, in)
	}()
	for _, value := range in.Key {
		if value != 0 {
			t.Fatal("panic retained activation input")
		}
	}
	if old.destroyed.Load() != 1 || h.activator.last().destroyed.Load() != 1 {
		t.Fatal("panic retained existing or staged material")
	}
	if _, err := h.admit(h.caller, `{}`); err != ErrLocked {
		t.Fatal("interrupted owner remained executable")
	}
}
