package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

func stillOpen(t *testing.T, s *Store) {
	t.Helper()
	select {
	case <-s.Lost():
		t.Fatal("the store stopped")
	default:
	}
}

// run, the path catalog loads and history inserts take, returns a gone
// caller's error without running. The rest of the cancellation contract is in
// storetest.
func TestRunWithGoneCaller(t *testing.T) {
	f := testDatabase(t)
	s := f.store(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	gone, cancel := context.WithCancel(t.Context())
	cancel()
	ran := false
	err := s.run(gone, ownerDeadline, func(context.Context, DB) error { ran = true; return nil })
	if !errors.Is(err, context.Canceled) || ran {
		t.Fatal("run with a gone caller:", err, ran)
	}
	stillOpen(t, s)
}
