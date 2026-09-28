package sqlite

import (
	"bytes"
	"database/sql"
	"errors"
	"strconv"

	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

func (x *ownerTx) VaultRoot() (vault.Root, error) {
	var r vault.Root
	var version, revision int64
	var passphrase, recovery string
	err := x.t.queryRow(`SELECT r.owner_id,r.root_id,r.root_version,r.wrapper_revision,w.passphrase,w.recovery
        FROM vault_roots r JOIN vault_wrapper_sets w USING(owner_id,root_id,root_version,wrapper_revision) WHERE r.owner_id=$1`,
		[]any{x.owner}, &r.OwnerID, &r.RootID, &version, &revision, &passphrase, &recovery)
	if errors.Is(err, sql.ErrNoRows) {
		return vault.Root{}, vault.ErrNotFound
	}
	if err != nil {
		return vault.Root{}, lease.ErrStorage
	}
	r.RootVersion, r.WrapperRevision = strconv.FormatInt(version, 10), strconv.FormatInt(revision, 10)
	r.Passphrase, r.Recovery = json.RawMessage(passphrase), json.RawMessage(recovery)
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
	version, ok := vault.Version(r.RootVersion)
	if !ok {
		return vault.ErrInvalid
	}
	revision, _ := vault.Version(r.WrapperRevision)
	if expected == "" {
		if r.RootVersion != "1" || r.WrapperRevision != "1" {
			return vault.ErrInvalid
		}
		if _, err := x.t.exec(`INSERT INTO vault_roots(owner_id,root_id,root_version,wrapper_revision) VALUES($1,$2,$3,$4)`, x.owner, r.RootID, version, revision); err != nil {
			return vaultError(err)
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
		if _, err := x.t.exec(`UPDATE vault_roots SET wrapper_revision=$2 WHERE owner_id=$1`, x.owner, revision); err != nil {
			return vaultError(err)
		}
	}
	_, err = x.t.exec(`INSERT INTO vault_wrapper_sets(owner_id,root_id,root_version,wrapper_revision,passphrase,recovery,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		x.owner, r.RootID, version, revision, string(r.Passphrase), string(r.Recovery), micros(x.now))
	return vaultError(err)
}

const credentialColumns = `h.owner_id,e.root_id,e.root_version,h.connector_id,h.credential_id,h.epoch,h.revision,e.destination,e.wrapped_key,v.envelope,h.deleted_at`
const credentialJoin = ` FROM credential_heads h JOIN credential_epochs e USING(owner_id,credential_id,epoch)
    JOIN credential_versions v USING(owner_id,credential_id,epoch,revision)`

func scanCredential(scan func(...any) error) (vault.Record, error) {
	var r vault.Record
	var rootVersion, epoch, revision int64
	var destination, wrapped, envelope string
	var deleted sql.NullInt64
	err := scan(&r.OwnerID, &r.RootID, &rootVersion, &r.ConnectorID, &r.CredentialID, &epoch, &revision, &destination, &wrapped, &envelope, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return vault.Record{}, vault.ErrNotFound
	}
	if err != nil || json.Validate([]byte(destination), 16384, 8) != nil || json.UnmarshalStrict([]byte(destination), &r.Destination) != nil {
		return vault.Record{}, lease.ErrStorage
	}
	r.RootVersion, r.Epoch, r.Revision = strconv.FormatInt(rootVersion, 10), strconv.FormatInt(epoch, 10), strconv.FormatInt(revision, 10)
	r.WrappedKey, r.Envelope = json.RawMessage(wrapped), json.RawMessage(envelope)
	r, err = r.Normalize()
	if err != nil {
		return vault.Record{}, lease.ErrStorage
	}
	r.DeletedAt = fromOptMicros(deleted)
	return r, nil
}

func (x *ownerTx) CredentialRecord(id string) (vault.Record, error) {
	if !identity.Valid(id) {
		return vault.Record{}, vault.ErrNotFound
	}
	return scanCredential(func(dest ...any) error {
		return x.t.queryRow("SELECT "+credentialColumns+credentialJoin+" WHERE h.owner_id=$1 AND h.credential_id=$2", []any{x.owner, id}, dest...)
	})
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
	epochN, ok := vault.Version(r.Epoch)
	if !ok {
		return vault.ErrInvalid
	}
	revisionN, ok := vault.Version(r.Revision)
	if !ok {
		return vault.ErrInvalid
	}
	rootVersion, ok := vault.Version(r.RootVersion)
	if !ok {
		return vault.ErrInvalid
	}
	newEpoch := expected == nil
	if expected == nil {
		if r.Epoch != "1" || r.Revision != "1" {
			return vault.ErrInvalid
		}
		if _, err := x.t.exec(`INSERT INTO credential_heads(owner_id,credential_id,connector_id,epoch,revision) VALUES($1,$2,$3,1,0)`, x.owner, r.CredentialID, r.ConnectorID); err != nil {
			return vaultError(err)
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
			if _, err := x.t.exec(`UPDATE credential_heads SET epoch=$3,revision=0 WHERE owner_id=$1 AND credential_id=$2`, x.owner, r.CredentialID, epochN); err != nil {
				return vaultError(err)
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
		digest, _ := r.Destination.Digest()
		destination, _ := json.Marshal(r.Destination)
		// The nonce is stored as its canonical unpadded base64url text: 12
		// bytes encode exactly, so text uniqueness is byte uniqueness.
		if _, err := x.t.exec(`INSERT INTO credential_epochs(owner_id,credential_id,connector_id,epoch,root_id,root_version,destination_digest,destination,wrapped_key,wrap_nonce)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, x.owner, r.CredentialID, r.ConnectorID, epochN, r.RootID, rootVersion, digest, string(destination), string(r.WrappedKey), w.Nonce); err != nil {
			return vaultError(err)
		}
	}
	var e secret.Envelope
	_ = json.Unmarshal(r.Envelope, &e)
	_, err = x.t.exec(`INSERT INTO credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		x.owner, r.CredentialID, epochN, revisionN, e.Nonce, string(r.Envelope), micros(x.now))
	return vaultError(err)
}

func (x *ownerTx) DeleteCredentialRecord(id string, expected vault.Pointer) error {
	if !identity.Valid(id) {
		return vault.ErrInvalid
	}
	epoch, ok := vault.Version(expected.Epoch)
	if !ok {
		return vault.ErrInvalid
	}
	revision, ok := vault.Version(expected.Revision)
	if !ok {
		return vault.ErrInvalid
	}
	n, err := x.t.exec(`UPDATE credential_heads SET deleted_at=$5 WHERE owner_id=$1 AND credential_id=$2 AND epoch=$3 AND revision=$4 AND deleted_at IS NULL`,
		x.owner, id, epoch, revision, micros(x.now))
	if err != nil {
		return vaultError(err)
	}
	if n != 1 {
		return vault.ErrConflict
	}
	return nil
}

var _ vault.Tx = (*ownerTx)(nil)
