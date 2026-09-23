package lease

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

func TestPreparationIsScopedAndCannotRetainOrDispatchMaterial(t *testing.T) {
	h := newHarness(t, "none", nil)
	prepare := func(ctx context.Context, fn func(context.Context, Material) error) (string, error) {
		return h.service.Prepare(ctx, credentialID, toolID, h.scope.Tools[0].DefinitionDigest, []byte(`{}`), fn)
	}
	if _, err := prepare(h.caller, func(context.Context, Material) error { t.Fatal("prepared while locked"); return nil }); err != ErrRequired {
		t.Fatal(err)
	}
	l := h.activate(t)
	var captured context.Context
	var material Material
	id, err := prepare(h.caller, func(ctx context.Context, m Material) error {
		if phase, err := CheckUse(ctx, m); err != nil || phase != "prepare" {
			t.Fatal("missing maintenance authorization")
		}
		if ClaimCall(ctx, m, []byte(`{}`)) != ErrDenied {
			t.Fatal("maintenance dispatched a tool")
		}
		captured, material = context.WithoutCancel(ctx), m
		return nil
	})
	if err != nil || id != l.ID {
		t.Fatal("wrong prepared activation")
	}
	if _, err := CheckUse(captured, material); err == nil {
		t.Fatal("detached maintenance retained authority")
	}
	if h.store.snapshot().Leases[l.ID].AdmittedCalls != 0 || len(h.store.snapshot().Admissions) != 0 {
		t.Fatal("setup consumed call budget or claimed dispatch")
	}
	a, err := h.admit(h.caller, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RunWithMaterial(func(ctx context.Context, m Material) error {
		if m != material {
			t.Fatal("material changed")
		}
		if ClaimCall(ctx, m, []byte(`{"wrong":true}`)) != ErrDenied {
			t.Fatal("changed arguments admitted")
		}
		if err := ClaimCall(ctx, m, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if ClaimCall(ctx, m, []byte(`{}`)) != ErrDenied {
			t.Fatal("HTTP retry reused admission")
		}
		captured = context.WithoutCancel(ctx)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckUse(captured, material); err == nil {
		t.Fatal("detached dispatch retained authority")
	}
}

func TestDispatchBindingPreservesLargeNumberTokens(t *testing.T) {
	h := newHarness(t, "none", nil)
	h.activate(t)
	original := []byte(`{"n":9007199254740992,"text":"<雪>"}`)
	changed := []byte(`{"n":9007199254740993,"text":"<雪>"}`)
	if audit.HashArgs(json.RawMessage(original)) != audit.HashArgs(json.RawMessage(changed)) {
		t.Fatal("legacy audit-hash fixture changed")
	}
	a, err := h.admit(h.caller, string(original))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RunWithMaterial(func(ctx context.Context, m Material) error {
		if ClaimCall(ctx, m, changed) != ErrDenied {
			t.Fatal("legacy float rounding admitted changed wire arguments")
		}
		// Object order, whitespace and JSON escaping can change in SDK encoding.
		return ClaimCall(ctx, m, []byte(`{ "text":"\u003c雪\u003e", "n":9007199254740992 }`))
	}); err != nil {
		t.Fatal("equivalent wire arguments rejected:", err)
	}
}

func TestPreparationDrainsOnRevocationAndRechecksBeforeDispatch(t *testing.T) {
	h := newHarness(t, "none", func(o *Options) { o.MaxConcurrent = 1 })
	l := h.activate(t)
	started, finish := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := h.service.Prepare(h.caller, credentialID, toolID, h.scope.Tools[0].DefinitionDigest, []byte(`{}`), func(ctx context.Context, m Material) error {
			close(started)
			<-finish
			_, err := CheckUse(ctx, m)
			return err
		})
		done <- err
	}()
	<-started
	if _, err := h.admit(h.caller, `{}`); err != ErrBusy {
		t.Fatal("preparation did not reserve concurrency")
	}
	if err := h.service.Revoke(h.browser, l.ID); err != nil {
		t.Fatal(err)
	}
	if h.activator.last().destroyed.Load() != 0 {
		t.Fatal("in-use material destroyed before drain")
	}
	close(finish)
	if err := <-done; err == nil {
		t.Fatal("revoked preparation kept authority")
	}
	if h.activator.last().destroyed.Load() != 1 {
		t.Fatal("drained material not destroyed")
	}
	if _, err := h.admit(h.caller, `{}`); err != ErrRequired {
		t.Fatal("revoked material admitted")
	}
}

func TestMaterialRevisionCannotBeMisreported(t *testing.T) {
	h := newHarness(t, "none", nil)
	h.activate(t)
	a, err := h.admit(h.caller, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	// Even a broken future adapter that publishes a revision without replacing
	// the material must not record/use that revision with the old headers.
	h.authority.mu.Lock()
	h.authority.credential.Revision = "2"
	h.authority.mu.Unlock()
	if err := a.RunWithMaterial(func(context.Context, Material) error { t.Fatal("stale revision dispatched"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if _, err := h.admit(h.caller, `{}`); err != ErrRequired {
		t.Fatal("stale material stamped with new revision")
	}
	if _, err := h.service.Prepare(h.caller, credentialID, toolID, h.scope.Tools[0].DefinitionDigest, []byte(`{}`), func(context.Context, Material) error { t.Fatal("stale revision used for setup"); return nil }); err != ErrRequired {
		t.Fatal(err)
	}
}

func TestMaterialRechecksClockAndCallerAtInjection(t *testing.T) {
	for _, change := range []string{"clock", "caller", "policy"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t, "none", nil)
			h.activate(t)
			a, err := h.admit(h.caller, `{}`)
			if err != nil {
				t.Fatal(err)
			}
			_ = a.RunWithMaterial(func(ctx context.Context, m Material) error {
				switch change {
				case "clock":
					h.clock.advance(901 * time.Second)
				case "caller":
					h.authority.mu.Lock()
					c := h.authority.callers[callerID]
					c.Active = false
					h.authority.callers[callerID] = c
					h.authority.mu.Unlock()
				case "policy":
					h.authority.mu.Lock()
					h.authority.credential.PolicyRevision = "2"
					h.authority.mu.Unlock()
				}
				if _, err := CheckUse(ctx, m); err == nil {
					t.Fatal("changed authority survived injection check")
				}
				return nil
			})
		})
	}
}

func TestPreparationDoesNotSwitchToAnotherLease(t *testing.T) {
	h := newHarness(t, "none", nil)
	first := h.activate(t)
	prepared, err := h.service.Prepare(h.caller, credentialID, toolID, h.scope.Tools[0].DefinitionDigest, []byte(`{}`), func(context.Context, Material) error { return nil })
	if err != nil || prepared != first.ID {
		t.Fatal(err)
	}
	if err := h.service.Revoke(h.browser, first.ID); err != nil {
		t.Fatal(err)
	}
	h.activate(t)
	r := audit.NewInvocation(h.caller, "alice")
	r.ToolID = toolID
	r.Tool = "files.search"
	r.UpstreamID = connectorID
	r.ArgsSHA256 = audit.HashArgs(map[string]any{})
	if _, err := h.service.AdmitPrepared(h.caller, credentialID, toolID, h.scope.Tools[0].DefinitionDigest, []byte(`{}`), r, prepared); err != ErrRequired {
		t.Fatal("prepared session silently switched activations")
	}
	if _, err := h.service.AdmitPrepared(h.caller, credentialID, toolID, h.scope.Tools[0].DefinitionDigest, []byte(`{}`), r, identity.New()); err != ErrRequired {
		t.Fatal("forged preparation accepted")
	}
}
