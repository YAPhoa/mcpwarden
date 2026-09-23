package postgres

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

type ownerTx struct {
	ctx   context.Context
	tx    pgx.Tx
	owner string
	now   time.Time
}

func (x *ownerTx) Now() time.Time { return x.now }
func nullableID(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
func loadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return lease.ErrNotFound
	}
	return lease.ErrStorage
}

const requestColumns = `binding,state,decided_at,activation_deadline,approver_id::text,authorization_source,lease_id::text`

func scanRequest(row pgx.Row) (lease.Request, error) {
	var r lease.Request
	var raw []byte
	var decided, deadline *time.Time
	var approver, source, leaseID *string
	if err := row.Scan(&raw, &r.State, &decided, &deadline, &approver, &source, &leaseID); err != nil {
		return lease.Request{}, loadError(err)
	}
	if len(raw) > lease.MaxScopeBytes+4096 || json.UnmarshalStrict(raw, &r.Binding) != nil || !r.Binding.Valid() {
		return lease.Request{}, lease.ErrStorage
	}
	if decided != nil {
		r.DecidedAt = *decided
	}
	if deadline != nil {
		r.ActivationDeadline = *deadline
	}
	if approver != nil {
		r.ApproverID = *approver
	}
	if source != nil {
		r.AuthorizationSource = *source
	}
	if leaseID != nil {
		r.LeaseID = *leaseID
	}
	return r, nil
}
func (x *ownerTx) Request(id string) (lease.Request, error) {
	if !identity.Valid(id) {
		return lease.Request{}, lease.ErrNotFound
	}
	return scanRequest(x.tx.QueryRow(x.ctx, "SELECT "+requestColumns+" FROM mcpwarden_security.requests WHERE owner_id=$1 AND request_id=$2", x.owner, id))
}
func (x *ownerTx) Requests() ([]lease.Request, error) {
	rows, err := x.tx.Query(x.ctx, "SELECT "+requestColumns+" FROM mcpwarden_security.requests WHERE owner_id=$1 AND (state IN ('pending','approved') OR created_at >= $2::timestamptz - interval '1 minute') ORDER BY created_at,request_id", x.owner, x.now)
	if err != nil {
		return nil, lease.ErrStorage
	}
	defer rows.Close()
	var out []lease.Request
	for rows.Next() {
		r, err := scanRequest(rows)
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
func (x *ownerTx) PutRequest(r lease.Request) error {
	if r.Scope.OwnerID != x.owner || !r.Binding.Valid() {
		return lease.ErrDenied
	}
	raw, err := json.Marshal(r.Binding)
	if err != nil {
		return lease.ErrStorage
	}
	_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.requests
        (owner_id,request_id,boot_id,created_at,expires_at,binding,state,decided_at,activation_deadline,approver_id,authorization_source,lease_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT (owner_id,request_id) DO UPDATE SET boot_id=excluded.boot_id,created_at=excluded.created_at,
        expires_at=excluded.expires_at,binding=excluded.binding,state=excluded.state,decided_at=excluded.decided_at,
        activation_deadline=excluded.activation_deadline,approver_id=excluded.approver_id,authorization_source=excluded.authorization_source,lease_id=excluded.lease_id`,
		x.owner, r.ID, r.BootID, r.CreatedAt, r.ExpiresAt, raw, r.State, nullableTime(r.DecidedAt), nullableTime(r.ActivationDeadline), nullableID(r.ApproverID), nullableID(r.AuthorizationSource), nullableID(r.LeaseID))
	if err != nil {
		return lease.ErrStorage
	}
	return nil
}

const leaseColumns = `lease_id::text,owner_id,request_id::text,caller_id::text,credential_id::text,epoch::text,boot_id::text,scope_digest,state,activated_at,expires_at,ended_at,max_calls,admitted_calls,activation_actor_id::text,operation_id::text`

func scanLease(row pgx.Row) (lease.Lease, error) {
	var l lease.Lease
	var ended *time.Time
	if err := row.Scan(&l.ID, &l.OwnerID, &l.RequestID, &l.CallerID, &l.CredentialID, &l.Epoch, &l.BootID, &l.ScopeDigest, &l.State, &l.ActivatedAt, &l.ExpiresAt, &ended, &l.MaxCalls, &l.AdmittedCalls, &l.ActivationActorID, &l.OperationID); err != nil {
		return lease.Lease{}, loadError(err)
	}
	if ended != nil {
		l.EndedAt = *ended
	}
	return l, nil
}
func (x *ownerTx) Lease(id string) (lease.Lease, error) {
	if !identity.Valid(id) {
		return lease.Lease{}, lease.ErrNotFound
	}
	return scanLease(x.tx.QueryRow(x.ctx, "SELECT "+leaseColumns+" FROM mcpwarden_security.leases WHERE owner_id=$1 AND lease_id=$2", x.owner, id))
}
func (x *ownerTx) Leases() ([]lease.Lease, error) {
	rows, err := x.tx.Query(x.ctx, "SELECT "+leaseColumns+" FROM mcpwarden_security.leases WHERE owner_id=$1 AND state='active' ORDER BY expires_at,lease_id", x.owner)
	if err != nil {
		return nil, lease.ErrStorage
	}
	defer rows.Close()
	var out []lease.Lease
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
func (x *ownerTx) PutLease(l lease.Lease) error {
	if l.OwnerID != x.owner || !identity.Valid(l.ID) || !identity.Valid(l.OperationID) {
		return lease.ErrDenied
	}
	r, err := x.Request(l.RequestID)
	if err != nil {
		return err
	}
	if r.State != "activated" || r.LeaseID != l.ID || l.CallerID != r.Scope.RequesterAccessID || l.CredentialID != r.Scope.CredentialID || l.Epoch != r.Scope.CredentialEpoch || l.BootID != r.BootID || l.ScopeDigest != r.ScopeDigest || l.ActivationActorID != r.ApproverID || (l.MaxCalls == nil) != (r.Scope.MaxCalls == nil) || l.MaxCalls != nil && *l.MaxCalls != *r.Scope.MaxCalls || l.ExpiresAt.Sub(l.ActivatedAt) > time.Duration(r.Scope.DurationSeconds)*time.Second {
		return lease.ErrDenied
	}
	epoch, err := strconv.ParseInt(l.Epoch, 10, 64)
	if err != nil {
		return lease.ErrDenied
	}
	_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.leases
        (lease_id,owner_id,request_id,caller_id,credential_id,epoch,boot_id,scope_digest,state,activated_at,expires_at,ended_at,max_calls,admitted_calls,activation_actor_id,operation_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ON CONFLICT (owner_id,lease_id) DO UPDATE SET request_id=excluded.request_id,caller_id=excluded.caller_id,
        credential_id=excluded.credential_id,epoch=excluded.epoch,boot_id=excluded.boot_id,scope_digest=excluded.scope_digest,
        state=excluded.state,activated_at=excluded.activated_at,expires_at=excluded.expires_at,ended_at=excluded.ended_at,
        max_calls=excluded.max_calls,admitted_calls=excluded.admitted_calls,activation_actor_id=excluded.activation_actor_id,operation_id=excluded.operation_id`,
		l.ID, l.OwnerID, l.RequestID, l.CallerID, l.CredentialID, epoch, l.BootID, l.ScopeDigest, l.State, l.ActivatedAt, l.ExpiresAt, nullableTime(l.EndedAt), l.MaxCalls, l.AdmittedCalls, l.ActivationActorID, l.OperationID)
	if err != nil {
		return lease.ErrStorage
	}
	return nil
}
func (x *ownerTx) Event(e lease.Event) error {
	if e.OwnerID != x.owner || !identity.Valid(e.ID) || !identity.Valid(e.BootID) || e.At.IsZero() || e.ActorID != "" && !identity.Valid(e.ActorID) || e.Source != "" && e.Source != "client_activation" && e.Source != "owner_confirmation" {
		return lease.ErrDenied
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return lease.ErrStorage
	}
	_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.security_events (owner_id,event_id,event_type,occurred_at,boot_id,request_id,lease_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, x.owner, e.ID, e.Type, e.At, e.BootID, nullableID(e.RequestID), nullableID(e.LeaseID), raw)
	if err != nil {
		return lease.ErrStorage
	}
	return nil
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
	if l.State != "active" || !x.now.Before(l.ExpiresAt) || r.ApprovalID != l.RequestID || r.ActorAccessID != l.CallerID || r.CredentialID != l.CredentialID || r.CredentialEpoch != l.Epoch || r.ScopeDigest != l.ScopeDigest || r.UpstreamID != request.Scope.ConnectorID || r.ApprovalMode != request.Mode || r.ApprovalPolicyRevision != request.ApprovalPolicyRevision || r.AuthorizationSource != request.AuthorizationSource {
		return lease.ErrDenied
	}
	return x.invocation(r)
}
func (x *ownerTx) invocation(r audit.Record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return lease.ErrStorage
	}
	_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.invocation_events(owner_id,event_id,invocation_id,event_type,occurred_at,request_id,lease_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, x.owner, r.EventID, r.InvocationID, r.EventType, r.OccurredAt, r.ApprovalID, r.LeaseID, raw)
	if err != nil {
		return lease.ErrStorage
	}
	return nil
}

// Complete appends an actual outcome using the admission's identity snapshot.
// Failure never means the provider failed, and must never trigger a tool retry.
// This is not the legacy JSONL history reader or a general-purpose audit import.
func (s *Store) Complete(ctx context.Context, r audit.Record) error {
	if r.EventType != audit.DispatchCompleted || audit.ValidateInvocation(r) != nil || r.LeaseID == "" {
		return lease.ErrDenied
	}
	return s.WithOwner(ctx, r.Owner, func(tx lease.Tx) error {
		x := tx.(*ownerTx)
		var raw []byte
		err := x.tx.QueryRow(x.ctx, `SELECT metadata FROM mcpwarden_security.invocation_events WHERE owner_id=$1 AND invocation_id=$2 AND event_type=$3`, r.Owner, r.InvocationID, audit.DispatchAdmitted).Scan(&raw)
		if err != nil {
			return loadError(err)
		}
		var admitted audit.Record
		if json.UnmarshalStrict(raw, &admitted) != nil || audit.ValidateInvocation(admitted) != nil {
			return lease.ErrStorage
		}
		if !bytes.Equal(invocationOrigin(r), invocationOrigin(admitted)) {
			return lease.ErrDenied
		}
		return x.invocation(r)
	})
}
func invocationOrigin(r audit.Record) []byte {
	r.EventID, r.EventType, r.Decision, r.Status = "", "", "", ""
	r.OccurredAt, r.CompletedAt = time.Time{}, time.Time{}
	r.Timing = nil
	r.DurationMS, r.ResponseItems, r.Structured = 0, 0, false
	b, _ := json.Marshal(r)
	return b
}
