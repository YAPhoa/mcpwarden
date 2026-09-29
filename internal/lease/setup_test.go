package lease

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

func setupScope() Scope {
	s := fixtureScope()
	s.Purpose, s.RequesterAccessID, s.DurationSeconds, s.Tools = "setup_discovery", browserID, 300, nil
	return s
}

// startSetup requests and activates a setup window from the owner's browser.
func (h *harness) startSetup(t *testing.T) Lease {
	t.Helper()
	r, err := h.service.Request(h.browser, scopeBytes(t, setupScope()))
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode == "confirm" {
		if r, err = h.service.Confirm(h.browser, r.ID, r.RequestDigest); err != nil {
			t.Fatal(err)
		}
	}
	l, err := h.service.Activate(h.browser, activation(r))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// saveSetup stands in for the catalog's discovery save: an empty change that
// ends the setup window in its own transaction.
func (h *harness) saveSetup(l Lease, connector string) func() error {
	return func() error {
		return h.service.CatalogSetup(context.Background(), "alice", SetupEnd{LeaseID: l.ID, ConnectorID: connector}, func(Tx) (func(), Ending, error) {
			return nil, Ending{}, nil
		})
	}
}

func setupEvent(h *harness, leaseID string) string {
	for _, e := range h.store.snapshot().Events {
		if e.LeaseID == leaseID && e.Type == "lease.revoked" {
			return e.Source
		}
	}
	return ""
}

func TestSetupWindowIsTheOwnersOwn(t *testing.T) {
	h := newHarness(t, "none", nil)
	raw := scopeBytes(t, setupScope())
	if _, err := h.service.Request(h.caller, raw); !errors.Is(err, ErrDenied) {
		t.Fatalf("an API key requested the owner's setup window: %v", err)
	}
	forKey := setupScope()
	forKey.RequesterAccessID = callerID
	if _, err := h.service.Request(h.browser, scopeBytes(t, forKey)); !errors.Is(err, ErrDenied) {
		t.Fatalf("the owner requested a setup window for a key: %v", err)
	}
	if _, err := h.service.Request(h.caller, scopeBytes(t, forKey)); !errors.Is(err, ErrDenied) {
		t.Fatalf("a key requested a setup window for itself: %v", err)
	}
	oauth := setupScope()
	oauth.Purpose = "oauth_setup"
	if _, err := h.service.Request(h.browser, scopeBytes(t, oauth)); !errors.Is(err, ErrDenied) {
		t.Fatalf("an oauth_setup window was accepted before step 6: %v", err)
	}
	// Another browser session of the same owner cannot activate or run it.
	other := Caller{Actor: h.authority.callers[browserID].Actor, Active: true, Interactive: true}
	other.AccessID = "018fd508-fbbb-4e8c-bbad-6ac1b411ef59"
	h.authority.mu.Lock()
	h.authority.callers[other.AccessID] = other
	h.authority.mu.Unlock()
	otherCtx := identity.WithActor(context.Background(), other.Actor)
	r, err := h.service.Request(h.browser, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Activate(otherCtx, activation(r)); !errors.Is(err, ErrDenied) {
		t.Fatalf("another session activated this session's setup window: %v", err)
	}
	l, err := h.service.Activate(h.browser, activation(r))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.service.Setup(otherCtx, l.ID, func(context.Context, Material) error { t.Fatal("ran for another session"); return nil }, h.saveSetup(l, connectorID)); !errors.Is(err, ErrDenied) {
		t.Fatalf("another session ran the discovery: %v", err)
	}
	if err := h.service.Setup(h.caller, l.ID, func(context.Context, Material) error { t.Fatal("ran for a key"); return nil }, h.saveSetup(l, connectorID)); !errors.Is(err, ErrDenied) {
		t.Fatalf("a key ran the discovery: %v", err)
	}
}

func TestSetupWindowNeverAdmitsAToolCall(t *testing.T) {
	for _, mode := range []string{"none", "confirm"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, mode, nil)
			l := h.startSetup(t)
			if got := l.ExpiresAt.Sub(l.ActivatedAt); got != 300*time.Second {
				t.Fatalf("setup window lasts %s", got)
			}
			if _, err := h.admit(h.caller, `{}`); !errors.Is(err, ErrRequired) {
				t.Fatalf("a key call was admitted through a setup window: %v", err)
			}
			if _, err := h.admit(h.browser, `{}`); !errors.Is(err, ErrDenied) {
				t.Fatalf("the browser call was admitted: %v", err)
			}
			if _, err := h.service.Prepare(h.caller, credentialID, toolID, h.scope.Tools[0].DefinitionDigest, []byte(`{}`), func(context.Context, Material) error {
				t.Fatal("prepared a call through a setup window")
				return nil
			}); !errors.Is(err, ErrRequired) {
				t.Fatal(err)
			}
			var captured context.Context
			var material Material
			err := h.service.Setup(h.browser, l.ID, func(ctx context.Context, m Material) error {
				if phase, err := CheckUse(ctx, m); err != nil || phase != "setup" {
					t.Fatalf("setup phase %q, %v", phase, err)
				}
				if ClaimCall(ctx, m, []byte(`{}`)) != ErrDenied {
					t.Fatal("setup claimed a tool call")
				}
				captured, material = context.WithoutCancel(ctx), m
				return nil
			}, h.saveSetup(l, connectorID))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CheckUse(captured, material); err == nil {
				t.Fatal("detached setup kept authority")
			}
			st := h.store.snapshot()
			if st.Leases[l.ID].State != "revoked" || setupEvent(h, l.ID) != "setup_completed" || len(st.Admissions) != 0 || st.Leases[l.ID].AdmittedCalls != 0 {
				t.Fatalf("setup did not end cleanly: %+v", st.Leases[l.ID])
			}
			if h.activator.last().destroyed.Load() != 1 {
				t.Fatal("setup material was not destroyed")
			}
		})
	}
}

func TestSetupRunsOnceAndEndsOnFailure(t *testing.T) {
	h := newHarness(t, "none", nil)
	l := h.startSetup(t)
	ran := 0
	discover := func(context.Context, Material) error { ran++; return nil }
	failure := errors.New("upstream refused")
	if err := h.service.Setup(h.browser, l.ID, func(context.Context, Material) error { ran++; return failure }, h.saveSetup(l, connectorID)); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if st := h.store.snapshot(); st.Leases[l.ID].State != "revoked" || setupEvent(h, l.ID) != "setup_failed" {
		t.Fatal("a failed discovery kept its window")
	}
	if err := h.service.Setup(h.browser, l.ID, discover, h.saveSetup(l, connectorID)); !errors.Is(err, ErrStale) || ran != 1 {
		t.Fatalf("an ended window ran again: %v", err)
	}

	// A save that names another connector is refused and ends the window.
	l = h.startSetup(t)
	if err := h.service.Setup(h.browser, l.ID, discover, h.saveSetup(l, toolID)); !errors.Is(err, ErrStale) || !errors.Is(err, ErrRolledBack) {
		t.Fatalf("a save for another connector: %v", err)
	}
	if setupEvent(h, l.ID) != "setup_failed" {
		t.Fatal("a refused save kept its window")
	}

	// Concurrent runs of one window: only one discovers.
	l = h.startSetup(t)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- h.service.Setup(h.browser, l.ID, func(context.Context, Material) error { close(entered); <-release; return nil }, h.saveSetup(l, connectorID))
	}()
	<-entered
	if err := h.service.Setup(h.browser, l.ID, discover, h.saveSetup(l, connectorID)); !errors.Is(err, ErrStale) {
		t.Fatalf("a second run started while the first ran: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if setupEvent(h, l.ID) != "setup_completed" {
		t.Fatal("the first run did not complete")
	}
}

func TestSetupSaveRefusedAfterTheWindowEnds(t *testing.T) {
	h := newHarness(t, "none", nil)
	l := h.startSetup(t)
	saved := false
	err := h.service.Setup(h.browser, l.ID, func(context.Context, Material) error {
		// The window expires while the upstream answers.
		h.clock.advance(301 * time.Second)
		return nil
	}, func() error {
		return h.service.CatalogSetup(context.Background(), "alice", SetupEnd{LeaseID: l.ID, ConnectorID: connectorID}, func(Tx) (func(), Ending, error) {
			return func() { saved = true }, Ending{}, nil
		})
	})
	if !errors.Is(err, ErrStale) || saved {
		t.Fatalf("a discovery saved after its window ended: %v", err)
	}

	// Revoking the window during discovery stops the save too.
	l = h.startSetup(t)
	err = h.service.Setup(h.browser, l.ID, func(context.Context, Material) error {
		return h.service.Revoke(h.browser, l.ID)
	}, h.saveSetup(l, connectorID))
	if !errors.Is(err, ErrStale) {
		t.Fatalf("a revoked window saved: %v", err)
	}
	// A new credential version stales the window before its save.
	l = h.startSetup(t)
	err = h.service.Setup(h.browser, l.ID, func(context.Context, Material) error {
		h.authority.mu.Lock()
		h.authority.credential.Revision = "2"
		h.authority.mu.Unlock()
		return nil
	}, h.saveSetup(l, connectorID))
	if !errors.Is(err, ErrStale) {
		t.Fatalf("a changed credential saved: %v", err)
	}
}

func TestSetupRequesterRules(t *testing.T) {
	h := newHarness(t, "none", nil)
	// A tool window names a key, never a browser session.
	browserTools := fixtureScope()
	browserTools.RequesterAccessID = browserID
	if _, err := h.service.Request(h.browser, scopeBytes(t, browserTools)); !errors.Is(err, ErrDenied) {
		t.Fatalf("a browser session was named as a tool window's requester: %v", err)
	}
	// Another browser session of the same owner cannot ask for this session's
	// setup window.
	other := Caller{Actor: h.authority.callers[browserID].Actor, Active: true, Interactive: true}
	other.AccessID = "018fd508-fbbb-4e8c-bbad-6ac1b411ef59"
	h.authority.mu.Lock()
	h.authority.callers[other.AccessID] = other
	h.authority.mu.Unlock()
	if _, err := h.service.Request(identity.WithActor(context.Background(), other.Actor), scopeBytes(t, setupScope())); !errors.Is(err, ErrDenied) {
		t.Fatalf("another session requested this session's setup window: %v", err)
	}
	// A save for a window that never ran is refused.
	l := h.startSetup(t)
	if err := h.saveSetup(l, connectorID)(); !errors.Is(err, ErrStale) || !errors.Is(err, ErrRolledBack) {
		t.Fatalf("saved without a discovery run: %v", err)
	}
	if st := h.store.snapshot(); st.Leases[l.ID].State != "active" {
		t.Fatal("a refused save ended an unused window")
	}
}

func TestEventSources(t *testing.T) {
	h := newHarness(t, "none", nil)
	h.startSetup(t)
	events := h.store.snapshot().Events
	if len(events) == 0 {
		t.Fatal("no events")
	}
	e := events[len(events)-1]
	for _, source := range []string{"", "client_activation", "owner_confirmation", "setup_completed", "setup_failed"} {
		e.Source = source
		if !ValidEvent(e.OwnerID, e) {
			t.Fatalf("source %q refused", source)
		}
	}
	e.Source = "setup_skipped"
	if ValidEvent(e.OwnerID, e) {
		t.Fatal("an unknown event source was accepted")
	}
}
