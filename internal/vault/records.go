// Package vault defines ciphertext-only persistence records. It never owns a
// vault root, passphrase, recovery secret, credential key or plaintext bundle.
package vault

import (
	"errors"
	"strconv"
	"time"

	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/secret"
)

const MaxEpochWrites = 1 << 20

var (
	ErrInvalid  = errors.New("invalid vault record")
	ErrConflict = errors.New("vault record changed; reload before saving")
	ErrNotFound = errors.New("vault record not found")
)

type Root struct {
	OwnerID         string          `json:"owner_id"`
	RootID          string          `json:"root_id"`
	RootVersion     string          `json:"root_version"`
	WrapperRevision string          `json:"wrapper_revision"`
	Passphrase      json.RawMessage `json:"passphrase"`
	Recovery        json.RawMessage `json:"recovery"`
}

type Pointer struct{ Epoch, Revision string }
type Record struct {
	secret.CredentialContext
	Revision    string             `json:"revision"`
	Destination secret.Destination `json:"destination"`
	WrappedKey  json.RawMessage    `json:"wrapped_key"`
	Envelope    json.RawMessage    `json:"envelope"`
	DeletedAt   time.Time          `json:"deleted_at,omitzero"`
}

// Tx is an extension implemented by the PostgreSQL owner transaction. Security
// writes must be called inside lease.Service.ChangeAtomic, with metadata/cache
// publication after its commit. There is no uncoordinated write convenience API.
type Tx interface {
	VaultRoot() (Root, error)
	PutVaultRoot(Root, string) error // empty expected revision creates once
	CredentialRecord(string) (Record, error)
	PutCredentialRecord(Record, *Pointer) error // nil expected creates once
	DeleteCredentialRecord(string, Pointer) error
}

func Version(v string) (int64, bool) {
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == v
}

// Normalize validates wire records before JSONB can erase duplicate keys. The
// normalized return values own their buffers and retain no caller-owned slices.
func (r Root) Normalize() (Root, error) {
	if _, ok := Version(r.WrapperRevision); !ok {
		return Root{}, ErrInvalid
	}
	values := []*json.RawMessage{&r.Passphrase, &r.Recovery}
	var ids []string
	for i, p := range values {
		if json.Validate(*p, secret.MaxWrapperBytes, 8) != nil {
			return Root{}, ErrInvalid
		}
		var w secret.RootWrapper
		if json.UnmarshalStrict(*p, &w) != nil {
			return Root{}, ErrInvalid
		}
		method := "passphrase"
		if i == 1 {
			method = "recovery"
		}
		expected := secret.RootContext{OwnerID: r.OwnerID, RootID: r.RootID, RootVersion: r.RootVersion, WrapperID: w.WrapperID, Method: method}
		if _, err := secret.ParseRootWrapper(*p, expected); err != nil {
			return Root{}, ErrInvalid
		}
		ids = append(ids, w.WrapperID)
		var object any
		_ = json.Unmarshal(*p, &object)
		*p, _ = json.Marshal(object)
	}
	if ids[0] == ids[1] {
		return Root{}, ErrInvalid
	}
	return r, nil
}

func (r Record) Normalize() (Record, error) {
	if !r.DeletedAt.IsZero() {
		return Record{}, ErrInvalid
	}
	w, err := secret.ParseCredentialWrapper(r.WrappedKey, r.CredentialContext)
	if err != nil {
		return Record{}, ErrInvalid
	}
	digest, err := r.Destination.Digest()
	if err != nil {
		return Record{}, ErrInvalid
	}
	h := secret.Header{Format: secret.Format, Algorithm: secret.Algorithm, Purpose: "upstream-credential", OwnerID: r.OwnerID, ConnectorID: r.ConnectorID, CredentialID: r.CredentialID, Epoch: r.Epoch, Revision: r.Revision, DestinationDigest: digest}
	e, err := secret.Parse(r.Envelope, h)
	if err != nil {
		return Record{}, ErrInvalid
	}
	r.WrappedKey, _ = json.Marshal(w)
	r.Envelope, _ = json.Marshal(e)
	// Round-trip public destination metadata to detach caller-owned arrays.
	raw, _ := json.Marshal(r.Destination)
	var destination secret.Destination
	_ = json.Unmarshal(raw, &destination)
	r.Destination = destination
	return r, nil
}

func (r Record) SecretRecord() (secret.Record, error) {
	r, err := r.Normalize()
	if err != nil {
		return secret.Record{}, err
	}
	return secret.Record{Envelope: r.Envelope, Destination: r.Destination}, nil
}
