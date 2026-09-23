package postgres

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

// Only expected validation/uniqueness failures are retryable after reloading.
// Callers must propagate this error out of the owner transaction, not continue
// using a transaction that PostgreSQL has aborted. Driver errors stay private.
func vaultWriteError(err error) error {
	if err == nil {
		return nil
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23514" || pg.Code == "23503") {
		return vault.ErrConflict
	}
	return lease.ErrStorage
}

func (x *ownerTx) VaultRoot() (vault.Root, error) {
	var r vault.Root
	err := x.tx.QueryRow(x.ctx, `SELECT r.owner_id,r.root_id::text,r.root_version::text,r.wrapper_revision::text,w.passphrase,w.recovery
        FROM mcpwarden_security.vault_roots r JOIN mcpwarden_security.vault_wrapper_sets w
        USING(owner_id,root_id,root_version,wrapper_revision) WHERE r.owner_id=$1`, x.owner).
		Scan(&r.OwnerID, &r.RootID, &r.RootVersion, &r.WrapperRevision, &r.Passphrase, &r.Recovery)
	if errors.Is(err, pgx.ErrNoRows) {
		return vault.Root{}, vault.ErrNotFound
	}
	if err != nil {
		return vault.Root{}, lease.ErrStorage
	}
	r, err = r.Normalize()
	if err != nil {
		return vault.Root{}, lease.ErrStorage
	}
	return r, nil
}

func (x *ownerTx) PutVaultRoot(r vault.Root, expected string) error {
	r, err := r.Normalize()
	if err != nil || r.OwnerID != x.owner {
		return vault.ErrInvalid
	}
	if expected == "" {
		if r.RootVersion != "1" || r.WrapperRevision != "1" {
			return vault.ErrInvalid
		}
		_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.vault_roots(owner_id,root_id,root_version,wrapper_revision) VALUES($1,$2,$3,$4)`, x.owner, r.RootID, r.RootVersion, r.WrapperRevision)
		if err != nil {
			return vaultWriteError(err)
		}
	} else {
		n, ok := vault.Version(expected)
		if !ok || r.WrapperRevision != strconv.FormatInt(n+1, 10) {
			return vault.ErrInvalid
		}
		old, err := x.VaultRoot()
		if err != nil {
			return err
		}
		if old.WrapperRevision != expected || old.RootID != r.RootID || old.RootVersion != r.RootVersion {
			return vault.ErrConflict
		}
		_, err = x.tx.Exec(x.ctx, `UPDATE mcpwarden_security.vault_roots SET wrapper_revision=$2 WHERE owner_id=$1`, x.owner, r.WrapperRevision)
		if err != nil {
			return vaultWriteError(err)
		}
	}
	_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.vault_wrapper_sets(owner_id,root_id,root_version,wrapper_revision,passphrase,recovery) VALUES($1,$2,$3,$4,$5,$6)`, x.owner, r.RootID, r.RootVersion, r.WrapperRevision, []byte(r.Passphrase), []byte(r.Recovery))
	return vaultWriteError(err)
}

const credentialColumns = `h.owner_id,e.root_id::text,e.root_version::text,h.connector_id::text,h.credential_id::text,h.epoch::text,h.revision::text,e.destination,e.wrapped_key,v.envelope,h.deleted_at`
const credentialJoin = ` FROM mcpwarden_security.credential_heads h JOIN mcpwarden_security.credential_epochs e USING(owner_id,credential_id,epoch)
    JOIN mcpwarden_security.credential_versions v USING(owner_id,credential_id,epoch,revision)`

func scanCredential(row pgx.Row) (vault.Record, error) {
	var r vault.Record
	var destination []byte
	var deleted *time.Time
	err := row.Scan(&r.OwnerID, &r.RootID, &r.RootVersion, &r.ConnectorID, &r.CredentialID, &r.Epoch, &r.Revision, &destination, &r.WrappedKey, &r.Envelope, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return vault.Record{}, vault.ErrNotFound
	}
	if err != nil || json.Validate(destination, 16384, 8) != nil || json.UnmarshalStrict(destination, &r.Destination) != nil {
		return vault.Record{}, lease.ErrStorage
	}
	r, err = r.Normalize()
	if err != nil {
		return vault.Record{}, lease.ErrStorage
	}
	if deleted != nil {
		r.DeletedAt = *deleted
	}
	return r, nil
}

func (x *ownerTx) CredentialRecord(id string) (vault.Record, error) {
	if !identity.Valid(id) {
		return vault.Record{}, vault.ErrNotFound
	}
	return scanCredential(x.tx.QueryRow(x.ctx, "SELECT "+credentialColumns+credentialJoin+" WHERE h.owner_id=$1 AND h.credential_id=$2", x.owner, id))
}

func sameJSON(a, b any) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && bytes.Equal(x, y)
}

func (x *ownerTx) PutCredentialRecord(r vault.Record, expected *vault.Pointer) error {
	r, err := r.Normalize()
	if err != nil || r.OwnerID != x.owner {
		return vault.ErrInvalid
	}
	newEpoch := expected == nil
	if expected == nil {
		if r.Epoch != "1" || r.Revision != "1" {
			return vault.ErrInvalid
		}
		_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.credential_heads(owner_id,credential_id,connector_id,epoch,revision) VALUES($1,$2,$3,1,0)`, x.owner, r.CredentialID, r.ConnectorID)
		if err != nil {
			return vaultWriteError(err)
		}
	} else {
		epoch, ok := vault.Version(expected.Epoch)
		if !ok {
			return vault.ErrInvalid
		}
		rev, ok := vault.Version(expected.Revision)
		if !ok {
			return vault.ErrInvalid
		}
		old, err := x.CredentialRecord(r.CredentialID)
		if err != nil {
			return err
		}
		if !old.DeletedAt.IsZero() || old.Epoch != expected.Epoch || old.Revision != expected.Revision {
			return vault.ErrConflict
		}
		if old.ConnectorID != r.ConnectorID || old.RootID != r.RootID || old.RootVersion != r.RootVersion {
			return vault.ErrInvalid
		}
		if r.Epoch == old.Epoch {
			if r.Revision != strconv.FormatInt(rev+1, 10) || !bytes.Equal(old.WrappedKey, r.WrappedKey) || !sameJSON(old.Destination, r.Destination) {
				return vault.ErrInvalid
			}
		} else {
			if r.Epoch != strconv.FormatInt(epoch+1, 10) || r.Revision != "1" {
				return vault.ErrInvalid
			}
			_, err = x.tx.Exec(x.ctx, `UPDATE mcpwarden_security.credential_heads SET epoch=$3,revision=0 WHERE owner_id=$1 AND credential_id=$2`, x.owner, r.CredentialID, r.Epoch)
			if err != nil {
				return vaultWriteError(err)
			}
			newEpoch = true
		}
	}
	if newEpoch {
		root, err := x.VaultRoot()
		if err != nil {
			return err
		}
		if root.RootID != r.RootID || root.RootVersion != r.RootVersion {
			return vault.ErrInvalid
		}
		w, _ := secret.ParseCredentialWrapper(r.WrappedKey, r.CredentialContext)
		nonce, _ := base64.RawURLEncoding.DecodeString(w.Nonce)
		digest, _ := r.Destination.Digest()
		destination, _ := json.Marshal(r.Destination)
		_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.credential_epochs(owner_id,credential_id,connector_id,epoch,root_id,root_version,destination_digest,destination,wrapped_key,wrap_nonce)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, x.owner, r.CredentialID, r.ConnectorID, r.Epoch, r.RootID, r.RootVersion, digest, destination, []byte(r.WrappedKey), nonce)
		if err != nil {
			return vaultWriteError(err)
		}
	}
	var e secret.Envelope
	_ = json.Unmarshal(r.Envelope, &e)
	nonce, _ := base64.RawURLEncoding.DecodeString(e.Nonce)
	_, err = x.tx.Exec(x.ctx, `INSERT INTO mcpwarden_security.credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope) VALUES($1,$2,$3,$4,$5,$6)`, x.owner, r.CredentialID, r.Epoch, r.Revision, nonce, []byte(r.Envelope))
	return vaultWriteError(err)
}

func (x *ownerTx) DeleteCredentialRecord(id string, expected vault.Pointer) error {
	if !identity.Valid(id) {
		return vault.ErrInvalid
	}
	if _, ok := vault.Version(expected.Epoch); !ok {
		return vault.ErrInvalid
	}
	if _, ok := vault.Version(expected.Revision); !ok {
		return vault.ErrInvalid
	}
	tag, err := x.tx.Exec(x.ctx, `UPDATE mcpwarden_security.credential_heads SET deleted_at=$5 WHERE owner_id=$1 AND credential_id=$2 AND epoch=$3 AND revision=$4 AND deleted_at IS NULL`, x.owner, id, expected.Epoch, expected.Revision, x.now)
	if err != nil {
		return vaultWriteError(err)
	}
	if tag.RowsAffected() != 1 {
		return vault.ErrConflict
	}
	return nil
}

var _ vault.Tx = (*ownerTx)(nil)
