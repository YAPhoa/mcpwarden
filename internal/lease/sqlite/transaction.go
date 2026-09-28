package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// ownerTx is the owner transaction. It implements lease.Tx, vault.Tx,
// custody.Tx and catalogdb.OwnerTx, and every method maps errors exactly as
// the PostgreSQL method of the same name does.
type ownerTx struct {
	t     *tx
	owner string
	now   time.Time
}

func (x *ownerTx) Now() time.Time { return x.now }

func loadError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return lease.ErrNotFound
	}
	return lease.ErrStorage
}

const requestColumns = `binding,state,decided_at,activation_deadline,approver_id,authorization_source,lease_id`

func scanRequest(scan func(...any) error) (lease.Request, error) {
	var r lease.Request
	var raw string
	var decided, deadline sql.NullInt64
	var approver, source, leaseID sql.NullString
	if err := scan(&raw, &r.State, &decided, &deadline, &approver, &source, &leaseID); err != nil {
		return lease.Request{}, loadError(err)
	}
	if len(raw) > lease.MaxScopeBytes+4096 || json.UnmarshalStrict([]byte(raw), &r.Binding) != nil || !r.Binding.Valid() {
		return lease.Request{}, lease.ErrStorage
	}
	r.DecidedAt, r.ActivationDeadline = fromOptMicros(decided), fromOptMicros(deadline)
	r.ApproverID, r.AuthorizationSource, r.LeaseID = approver.String, source.String, leaseID.String
	return r, nil
}

func (x *ownerTx) Request(id string) (lease.Request, error) {
	if !identity.Valid(id) {
		return lease.Request{}, lease.ErrNotFound
	}
	return scanRequest(func(dest ...any) error {
		return x.t.queryRow("SELECT "+requestColumns+" FROM requests WHERE owner_id=$1 AND request_id=$2", []any{x.owner, id}, dest...)
	})
}

func (x *ownerTx) Requests() ([]lease.Request, error) {
	var out []lease.Request
	err := x.t.query("SELECT "+requestColumns+" FROM requests WHERE owner_id=$1 AND (state IN ('pending','approved') OR created_at >= $2) ORDER BY created_at, request_id",
		[]any{x.owner, micros(x.now.Add(-time.Minute))}, func(rows *sql.Rows) error {
			r, err := scanRequest(rows.Scan)
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

func (x *ownerTx) PutRequest(r lease.Request) error {
	if r.Scope.OwnerID != x.owner || !r.Binding.Valid() {
		return lease.ErrDenied
	}
	raw, err := json.Marshal(r.Binding)
	if err != nil {
		return lease.ErrStorage
	}
	_, err = x.t.exec(`INSERT INTO requests
        (owner_id,request_id,boot_id,created_at,expires_at,binding,state,decided_at,activation_deadline,approver_id,authorization_source,lease_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT (owner_id,request_id) DO UPDATE SET boot_id=excluded.boot_id,created_at=excluded.created_at,
        expires_at=excluded.expires_at,binding=excluded.binding,state=excluded.state,decided_at=excluded.decided_at,
        activation_deadline=excluded.activation_deadline,approver_id=excluded.approver_id,authorization_source=excluded.authorization_source,lease_id=excluded.lease_id`,
		x.owner, r.ID, r.BootID, micros(r.CreatedAt), micros(r.ExpiresAt), string(raw), r.State, optMicros(r.DecidedAt), optMicros(r.ActivationDeadline),
		optText(r.ApproverID), optText(r.AuthorizationSource), optText(r.LeaseID))
	return leaseError(err)
}

const leaseColumns = `lease_id,owner_id,request_id,caller_id,credential_id,epoch,boot_id,scope_digest,state,activated_at,expires_at,ended_at,max_calls,admitted_calls,activation_actor_id,operation_id`

func scanLease(scan func(...any) error) (lease.Lease, error) {
	var l lease.Lease
	var epoch, activated, expires int64
	var ended, maxCalls sql.NullInt64
	if err := scan(&l.ID, &l.OwnerID, &l.RequestID, &l.CallerID, &l.CredentialID, &epoch, &l.BootID, &l.ScopeDigest, &l.State,
		&activated, &expires, &ended, &maxCalls, &l.AdmittedCalls, &l.ActivationActorID, &l.OperationID); err != nil {
		return lease.Lease{}, loadError(err)
	}
	l.Epoch = strconv.FormatInt(epoch, 10)
	l.ActivatedAt, l.ExpiresAt, l.EndedAt = fromMicros(activated), fromMicros(expires), fromOptMicros(ended)
	if maxCalls.Valid {
		n := maxCalls.Int64
		l.MaxCalls = &n
	}
	return l, nil
}

func (x *ownerTx) Lease(id string) (lease.Lease, error) {
	if !identity.Valid(id) {
		return lease.Lease{}, lease.ErrNotFound
	}
	return scanLease(func(dest ...any) error {
		return x.t.queryRow("SELECT "+leaseColumns+" FROM leases WHERE owner_id=$1 AND lease_id=$2", []any{x.owner, id}, dest...)
	})
}

func (x *ownerTx) leases(query string, args ...any) ([]lease.Lease, error) {
	out := []lease.Lease{}
	err := x.t.query(query, args, func(rows *sql.Rows) error {
		l, err := scanLease(rows.Scan)
		if err != nil {
			return err
		}
		out = append(out, l)
		return nil
	})
	if err != nil {
		return nil, lease.ErrStorage
	}
	return out, nil
}

func (x *ownerTx) Leases() ([]lease.Lease, error) {
	out, err := x.leases("SELECT "+leaseColumns+" FROM leases WHERE owner_id=$1 AND state='active' ORDER BY expires_at, lease_id", x.owner)
	if len(out) == 0 {
		out = nil
	}
	return out, err
}

func (x *ownerTx) PutLease(l lease.Lease) error {
	if l.OwnerID != x.owner || !identity.Valid(l.ID) || !identity.Valid(l.OperationID) {
		return lease.ErrDenied
	}
	r, err := x.Request(l.RequestID)
	if err != nil {
		return err
	}
	if err := lease.CheckLease(x.owner, l, r); err != nil {
		return err
	}
	epoch, err := strconv.ParseInt(l.Epoch, 10, 64)
	if err != nil {
		return lease.ErrDenied
	}
	var maxCalls any
	if l.MaxCalls != nil {
		maxCalls = *l.MaxCalls
	}
	_, err = x.t.exec(`INSERT INTO leases
        (lease_id,owner_id,request_id,caller_id,credential_id,epoch,boot_id,scope_digest,state,activated_at,expires_at,ended_at,max_calls,admitted_calls,activation_actor_id,operation_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ON CONFLICT (owner_id,lease_id) DO UPDATE SET request_id=excluded.request_id,caller_id=excluded.caller_id,
        credential_id=excluded.credential_id,epoch=excluded.epoch,boot_id=excluded.boot_id,scope_digest=excluded.scope_digest,
        state=excluded.state,activated_at=excluded.activated_at,expires_at=excluded.expires_at,ended_at=excluded.ended_at,
        max_calls=excluded.max_calls,admitted_calls=excluded.admitted_calls,activation_actor_id=excluded.activation_actor_id,operation_id=excluded.operation_id`,
		l.ID, l.OwnerID, l.RequestID, l.CallerID, l.CredentialID, epoch, l.BootID, l.ScopeDigest, l.State, micros(l.ActivatedAt), micros(l.ExpiresAt),
		optMicros(l.EndedAt), maxCalls, l.AdmittedCalls, l.ActivationActorID, l.OperationID)
	return leaseError(err)
}

func (x *ownerTx) Event(e lease.Event) error {
	if !lease.ValidEvent(x.owner, e) {
		return lease.ErrDenied
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return lease.ErrStorage
	}
	_, err = x.t.exec(`INSERT INTO security_events (owner_id,event_id,event_type,occurred_at,boot_id,request_id,lease_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		x.owner, e.ID, e.Type, micros(e.At), e.BootID, optText(e.RequestID), optText(e.LeaseID), string(raw))
	return leaseError(err)
}

func (x *ownerTx) Admission(r audit.Record) error {
	if r.EventType != audit.DispatchAdmitted || r.Owner != x.owner || r.LeaseID == "" || audit.ValidateInvocation(r) != nil {
		return lease.ErrDenied
	}
	l, err := x.Lease(r.LeaseID)
	if err != nil {
		return err
	}
	request, err := x.Request(l.RequestID)
	if err != nil {
		return err
	}
	if err := lease.CheckAdmission(r, l, request, x.now); err != nil {
		return err
	}
	return x.invocation(r)
}

func (x *ownerTx) invocation(r audit.Record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return lease.ErrStorage
	}
	_, err = x.t.exec(`INSERT INTO invocation_events(owner_id,event_id,invocation_id,event_type,occurred_at,request_id,lease_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		x.owner, r.EventID, r.InvocationID, r.EventType, micros(r.OccurredAt), r.ApprovalID, r.LeaseID, string(raw))
	return leaseError(err)
}

// Complete appends an actual outcome using the admission's identity snapshot.
// Failure never means the provider failed, and must never trigger a tool retry.
func (s *Store) Complete(ctx context.Context, r audit.Record) error {
	if r.EventType != audit.DispatchCompleted || audit.ValidateInvocation(r) != nil || r.LeaseID == "" {
		return lease.ErrDenied
	}
	return s.WithOwner(ctx, r.Owner, func(tx lease.Tx) error {
		x := tx.(*ownerTx)
		var raw string
		err := x.t.queryRow(`SELECT metadata FROM invocation_events WHERE owner_id=$1 AND invocation_id=$2 AND event_type=$3`,
			[]any{r.Owner, r.InvocationID, audit.DispatchAdmitted}, &raw)
		if err != nil {
			return loadError(err)
		}
		var admitted audit.Record
		if json.UnmarshalStrict([]byte(raw), &admitted) != nil || audit.ValidateInvocation(admitted) != nil {
			return lease.ErrStorage
		}
		if !lease.SameInvocation(r, admitted) {
			return lease.ErrDenied
		}
		return x.invocation(r)
	})
}
