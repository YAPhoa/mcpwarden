package pgcatalog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// cancelBeforeCommit ends the repository's context after the mutation, just
// before COMMIT.
type cancelBeforeCommit struct{ Coordinator }

func (c cancelBeforeCommit) Catalog(ctx context.Context, owner string, mutation func(lease.Tx) (func(), lease.Ending, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return c.Coordinator.Catalog(ctx, owner, func(tx lease.Tx) (func(), lease.Ending, error) {
		publish, ending, err := mutation(tx)
		if err == nil {
			cancel()
		}
		return publish, ending, err
	})
}

// deadlineBeforeCommit uses most of the repository's own deadline before the
// owner transaction, as a queue can, and lets it expire before COMMIT while
// the store's deadline still holds.
type deadlineBeforeCommit struct {
	Coordinator
	left time.Duration
}

func (c deadlineBeforeCommit) Catalog(ctx context.Context, owner string, mutation func(lease.Tx) (func(), lease.Ending, error)) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("catalog context has no deadline")
	}
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(c.left))
	defer cancel()
	if deadline.Before(time.Now().Add(c.left)) {
		return errors.New("catalog deadline shorter than the test needs")
	}
	return c.Coordinator.Catalog(ctx, owner, func(tx lease.Tx) (func(), lease.Ending, error) {
		publish, ending, err := mutation(tx)
		if err == nil {
			<-ctx.Done()
		}
		return publish, ending, err
	})
}

// A change the store rolled back before COMMIT committed nothing: it fails,
// publishes nothing, and leaves the catalog and the gateway running.
func TestRolledBackChangeKeepsCatalogUp(t *testing.T) {
	for name, wrap := range map[string]func(Coordinator) Coordinator{
		"cancelled": func(c Coordinator) Coordinator { return cancelBeforeCommit{c} },
		"deadline":  func(c Coordinator) Coordinator { return deadlineBeforeCommit{c, time.Second} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.cutover()
			repo, db, service, failed := f.gateway()
			repo.Attach(wrap(service))
			err := repo.Add(catalog.Entry{Owner: f.alice, Name: "rolled-back", URL: "https://example.test/mcp"})
			if !errors.Is(err, ErrNotSaved) {
				t.Fatal("rolled-back change:", err)
			}
			if n := f.count("SELECT count(*) FROM mcpwarden_security.catalog_connectors WHERE name='rolled-back'"); n != 0 {
				t.Fatal("rolled-back connector committed")
			}
			for _, e := range repo.List(f.alice) {
				if e.Name == "rolled-back" {
					t.Fatal("rolled-back connector published")
				}
			}
			select {
			case <-db.Lost():
				t.Fatal("the database session was lost")
			default:
			}
			if *failed || repo.Failed() {
				t.Fatal("a rolled-back change stopped the catalog:", *failed, repo.Failed())
			}
			repo.Attach(service)
			if err := repo.Add(catalog.Entry{Owner: f.alice, Name: "after", URL: "https://example.test/mcp"}); err != nil {
				t.Fatal("next change:", err)
			}
		})
	}
}

// commitThenFail lets the real transaction commit and then reports storage
// loss, as a lost COMMIT acknowledgement would.
type commitThenFail struct{ Coordinator }

func (c commitThenFail) Catalog(ctx context.Context, owner string, mutation func(lease.Tx) (func(), lease.Ending, error)) error {
	if err := c.Coordinator.Catalog(ctx, owner, mutation); err != nil {
		return err
	}
	return lease.ErrStorage
}

// Any other error after the writes leaves the outcome unknown, so the catalog
// stops and refuses further changes.
func TestUncertainCommitStopsCatalog(t *testing.T) {
	f := newFixture(t)
	f.cutover()
	repo, _, service, failed := f.gateway()
	repo.Attach(commitThenFail{service})
	if err := repo.Add(catalog.Entry{Owner: f.alice, Name: "uncertain", URL: "https://example.test/mcp"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("uncertain commit:", err)
	}
	if !*failed || !repo.Failed() {
		t.Fatal("an uncertain commit left the catalog up:", *failed, repo.Failed())
	}
	repo.Attach(service)
	if err := repo.Add(catalog.Entry{Owner: f.alice, Name: "after", URL: "https://example.test/mcp"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("change after an uncertain commit:", err)
	}
}
