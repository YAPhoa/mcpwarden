package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/custody"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

const MaxEventPage = 200

func (x *ownerTx) CredentialRecords() ([]vault.Record, error) {
	rows, err := x.tx.Query(x.ctx, "SELECT "+credentialColumns+credentialJoin+" WHERE h.owner_id=$1 ORDER BY h.credential_id", x.owner)
	if err != nil {
		return nil, lease.ErrStorage
	}
	defer rows.Close()
	out := []vault.Record{}
	for rows.Next() {
		r, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, lease.ErrStorage
	}
	return out, nil
}

func scanPolicy(row pgx.Row) (custody.Policy, error) {
	var p custody.Policy
	if err := row.Scan(&p.OwnerID, &p.Mode, &p.Revision, &p.ChangedAt, &p.ChangedBy); err != nil {
		return custody.Policy{}, err
	}
	if !p.Valid() {
		return custody.Policy{}, lease.ErrStorage
	}
	return p, nil
}

const policyColumns = `owner_id,mode,revision::text,changed_at,changed_by::text`

func (x *ownerTx) ApprovalPolicy() (custody.Policy, error) {
	p, err := scanPolicy(x.tx.QueryRow(x.ctx, "SELECT "+policyColumns+" FROM mcpwarden_security.approval_policies WHERE owner_id=$1", x.owner))
	if errors.Is(err, pgx.ErrNoRows) {
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
		_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.approval_policies(owner_id,mode,revision,changed_at,changed_by) VALUES($1,$2,$3,$4,$5)`, x.owner, p.Mode, p.Revision, p.ChangedAt, p.ChangedBy)
	} else {
		_, err = x.tx.Exec(x.ctx, `UPDATE mcpwarden_security.approval_policies SET mode=$2,revision=$3,changed_at=$4,changed_by=$5 WHERE owner_id=$1`, x.owner, p.Mode, p.Revision, p.ChangedAt, p.ChangedBy)
	}
	if err := vaultWriteError(err); err != nil {
		if errors.Is(err, vault.ErrConflict) {
			return custody.ErrConflict
		}
		return err
	}
	return nil
}

// SecurityEvents returns the newest owner events first. Metadata is decoded
// strictly; a row that does not match the allowlisted shape fails closed.
func (x *ownerTx) SecurityEvents(limit int) ([]lease.Event, error) {
	if limit < 1 || limit > MaxEventPage {
		return nil, lease.ErrDenied
	}
	rows, err := x.tx.Query(x.ctx, `SELECT metadata FROM mcpwarden_security.security_events WHERE owner_id=$1 ORDER BY occurred_at DESC, event_id DESC LIMIT $2`, x.owner, limit)
	if err != nil {
		return nil, lease.ErrStorage
	}
	defer rows.Close()
	out := []lease.Event{}
	for rows.Next() {
		var raw []byte
		var e lease.Event
		if rows.Scan(&raw) != nil || json.UnmarshalStrict(raw, &e) != nil || e.OwnerID != x.owner {
			return nil, lease.ErrStorage
		}
		out = append(out, e)
	}
	if rows.Err() != nil {
		return nil, lease.ErrStorage
	}
	return out, nil
}

// MaxEndedLeases bounds RecentLeases. Ended windows are display history only;
// reading them never reactivates or extends a window.
const MaxEndedLeases = 50

// RecentLeases returns the owner's windows that ended (expired, revoked or
// suspended) at or after since, newest first.
func (x *ownerTx) RecentLeases(since time.Time, limit int) ([]lease.Lease, error) {
	if limit < 1 || limit > MaxEndedLeases {
		return nil, lease.ErrDenied
	}
	rows, err := x.tx.Query(x.ctx, "SELECT "+leaseColumns+" FROM mcpwarden_security.leases WHERE owner_id=$1 AND state<>'active' AND ended_at >= $2 ORDER BY ended_at DESC, lease_id LIMIT $3", x.owner, since, limit)
	if err != nil {
		return nil, lease.ErrStorage
	}
	defer rows.Close()
	out := []lease.Lease{}
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if rows.Err() != nil {
		return nil, lease.ErrStorage
	}
	return out, nil
}

// LoadCustody reads every committed credential head and approval policy once,
// after Start and before any owner route or admission runs. It is the only
// cross-owner read; its result is validated before anything is published.
func (s *Store) LoadCustody(ctx context.Context) (custody.Snapshot, error) {
	if err := s.acquire(ctx); err != nil {
		return custody.Snapshot{}, err
	}
	defer s.release()
	if !s.started {
		return custody.Snapshot{}, lease.ErrLocked
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out custody.Snapshot
	err := s.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"); err != nil {
			return lease.ErrStorage
		}
		rows, err := tx.Query(ctx, "SELECT "+credentialColumns+credentialJoin+" ORDER BY h.owner_id,h.credential_id")
		if err != nil {
			return lease.ErrStorage
		}
		for rows.Next() {
			r, err := scanCredential(rows)
			if err != nil {
				rows.Close()
				return lease.ErrStorage
			}
			out.Credentials = append(out.Credentials, r)
		}
		rows.Close()
		if rows.Err() != nil {
			return lease.ErrStorage
		}
		rows, err = tx.Query(ctx, "SELECT "+policyColumns+" FROM mcpwarden_security.approval_policies ORDER BY owner_id")
		if err != nil {
			return lease.ErrStorage
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPolicy(rows)
			if err != nil {
				return lease.ErrStorage
			}
			out.Policies = append(out.Policies, p)
		}
		if rows.Err() != nil {
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
