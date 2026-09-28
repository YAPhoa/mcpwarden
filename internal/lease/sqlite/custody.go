package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/yaphoa/mcpwarden/internal/custody"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

func (x *ownerTx) CredentialRecords() ([]vault.Record, error) {
	out := []vault.Record{}
	err := x.t.query("SELECT "+credentialColumns+credentialJoin+" WHERE h.owner_id=$1 ORDER BY h.credential_id", []any{x.owner}, func(rows *sql.Rows) error {
		r, err := scanCredential(rows.Scan)
		if err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	if err != nil {
		return nil, lease.ErrStorage
	}
	return out, nil
}

const policyColumns = `owner_id,mode,revision,changed_at,changed_by`

func scanPolicy(scan func(...any) error) (custody.Policy, error) {
	var p custody.Policy
	var revision, changed int64
	if err := scan(&p.OwnerID, &p.Mode, &revision, &changed, &p.ChangedBy); err != nil {
		return custody.Policy{}, err
	}
	p.Revision, p.ChangedAt = strconv.FormatInt(revision, 10), fromMicros(changed)
	if !p.Valid() {
		return custody.Policy{}, lease.ErrStorage
	}
	return p, nil
}

func (x *ownerTx) ApprovalPolicy() (custody.Policy, error) {
	p, err := scanPolicy(func(dest ...any) error {
		return x.t.queryRow("SELECT "+policyColumns+" FROM approval_policies WHERE owner_id=$1", []any{x.owner}, dest...)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return custody.Default(x.owner), nil
	}
	if err != nil {
		return custody.Policy{}, lease.ErrStorage
	}
	return p, nil
}

// PutApprovalPolicy writes exactly the next revision after expected. The caller
// supplies mode and actor; the revision and timestamp come from this transaction.
func (x *ownerTx) PutApprovalPolicy(p custody.Policy, expected string) error {
	n, ok := vault.Version(expected)
	if !ok || p.OwnerID != x.owner || p.Mode != "none" && p.Mode != "confirm" {
		return custody.ErrInvalid
	}
	current, err := x.ApprovalPolicy()
	if err != nil {
		return err
	}
	if current.Revision != expected {
		return custody.ErrConflict
	}
	p.Revision, p.ChangedAt = strconv.FormatInt(n+1, 10), x.now
	if !p.Valid() {
		return custody.ErrInvalid
	}
	if expected == "1" {
		_, err = x.t.exec(`INSERT INTO approval_policies(owner_id,mode,revision,changed_at,changed_by) VALUES($1,$2,$3,$4,$5)`, x.owner, p.Mode, n+1, micros(p.ChangedAt), p.ChangedBy)
	} else {
		_, err = x.t.exec(`UPDATE approval_policies SET mode=$2,revision=$3,changed_at=$4,changed_by=$5 WHERE owner_id=$1`, x.owner, p.Mode, n+1, micros(p.ChangedAt), p.ChangedBy)
	}
	return custodyError(err)
}

// SecurityEvents returns the newest owner events first. Metadata is decoded
// strictly; a row that does not match the allowlisted shape fails closed.
func (x *ownerTx) SecurityEvents(limit int) ([]lease.Event, error) {
	if limit < 1 || limit > MaxEventPage {
		return nil, lease.ErrDenied
	}
	out := []lease.Event{}
	err := x.t.query(`SELECT metadata FROM security_events WHERE owner_id=$1 ORDER BY occurred_at DESC, event_id DESC LIMIT $2`, []any{x.owner, limit}, func(rows *sql.Rows) error {
		var raw string
		var e lease.Event
		if rows.Scan(&raw) != nil || json.UnmarshalStrict([]byte(raw), &e) != nil || e.OwnerID != x.owner {
			return lease.ErrStorage
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, lease.ErrStorage
	}
	return out, nil
}

const (
	MaxEventPage = 200
	// MaxEndedLeases bounds RecentLeases. Ended windows are display history
	// only; reading them never reactivates or extends a window.
	MaxEndedLeases = 50
)

// RecentLeases returns the owner's windows that ended (expired, revoked or
// suspended) at or after since, newest first.
func (x *ownerTx) RecentLeases(since time.Time, limit int) ([]lease.Lease, error) {
	if limit < 1 || limit > MaxEndedLeases {
		return nil, lease.ErrDenied
	}
	return x.leases("SELECT "+leaseColumns+" FROM leases WHERE owner_id=$1 AND state<>'active' AND ended_at >= $2 ORDER BY ended_at DESC, lease_id LIMIT $3",
		x.owner, micros(since), limit)
}

// LoadCustody reads every committed credential head and approval policy once,
// after Start and before any owner route or admission runs.
func (s *Store) LoadCustody(ctx context.Context) (custody.Snapshot, error) {
	var out custody.Snapshot
	err := s.run(ctx, loadDeadline, func(t *tx) error {
		err := t.query("SELECT "+credentialColumns+credentialJoin+" ORDER BY h.owner_id,h.credential_id", nil, func(rows *sql.Rows) error {
			r, err := scanCredential(rows.Scan)
			if err != nil {
				return err
			}
			out.Credentials = append(out.Credentials, r)
			return nil
		})
		if err != nil {
			return lease.ErrStorage
		}
		err = t.query("SELECT "+policyColumns+" FROM approval_policies ORDER BY owner_id", nil, func(rows *sql.Rows) error {
			p, err := scanPolicy(rows.Scan)
			if err != nil {
				return err
			}
			out.Policies = append(out.Policies, p)
			return nil
		})
		if err != nil {
			return lease.ErrStorage
		}
		return nil
	})
	if err != nil {
		return custody.Snapshot{}, lease.ErrStorage
	}
	return out, nil
}

var _ custody.Tx = (*ownerTx)(nil)
