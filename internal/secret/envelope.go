// Package secret authenticates client-encrypted credential records. It never
// receives a vault root, passphrase or recovery key. Decryption is an explicit
// lease activation operation, not a side effect of catalog reads.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

const (
	MaxBundleBytes   = 64 << 10
	MaxEnvelopeBytes = 96 << 10
	Format           = "mcpwarden.secret.v1"
	Algorithm        = "AES-256-GCM"
)

var ErrInvalid = errors.New("invalid encrypted credential")

// Header is reconstructed from the current trusted catalog snapshot. A stored
// envelope's self-described owner, version or destination is never authority.
type Header struct {
	Format            string `json:"format"`
	Algorithm         string `json:"algorithm"`
	OwnerID           string `json:"owner_id"`
	ConnectorID       string `json:"connector_id"`
	CredentialID      string `json:"credential_id"`
	Epoch             string `json:"epoch"`
	Revision          string `json:"revision"`
	Purpose           string `json:"purpose"`
	DestinationDigest string `json:"destination_profile_sha256"`
}

type Envelope struct {
	Header
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func validID(v string) bool { return identity.Valid(v) && strings.ToLower(v) == v }
func validVersion(v string) bool {
	n, err := strconv.ParseInt(v, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == v
}
func decode(v string, min, max int) ([]byte, error) {
	if len(v) < base64.RawURLEncoding.EncodedLen(min) || len(v) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, ErrInvalid
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(v)
	if err != nil || len(b) < min || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != v {
		return nil, ErrInvalid
	}
	return b, nil
}
func (h Header) valid() bool {
	_, err := decode(h.DestinationDigest, 32, 32)
	return h.Format == Format && h.Algorithm == Algorithm && h.Purpose == "upstream-credential" &&
		len(h.OwnerID) > 0 && len(h.OwnerID) <= 512 && utf8.ValidString(h.OwnerID) &&
		validID(h.ConnectorID) && validID(h.CredentialID) && validVersion(h.Epoch) && validVersion(h.Revision) && err == nil
}

func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || json.Validate(raw, MaxEnvelopeBytes, 16) != nil {
		return nil, ErrInvalid
	}
	b, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

// Parse authenticates structure and expected identity, not the ciphertext tag.
// Every field is mandatory; unknown fields, duplicates and nulls are rejected.
func Parse(raw []byte, expected Header) (Envelope, error) {
	if !expected.valid() || json.Validate(raw, MaxEnvelopeBytes, 8) != nil {
		return Envelope{}, ErrInvalid
	}
	var e Envelope
	if json.UnmarshalStrict(raw, &e) != nil || e.Header != expected {
		return Envelope{}, ErrInvalid
	}
	if _, err := decode(e.Nonce, 12, 12); err != nil {
		return Envelope{}, ErrInvalid
	}
	if _, err := decode(e.Ciphertext, 17, MaxBundleBytes+16); err != nil {
		return Envelope{}, ErrInvalid
	}
	return e, nil
}

// open only returns plaintext inside this package. Callers cannot use this
// package as a general credential-export API.
func open(raw []byte, expected Header, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	e, err := Parse(raw, expected)
	if err != nil {
		return nil, ErrInvalid
	}
	aad, err := canonical(expected)
	if err != nil {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	nonce, _ := decode(e.Nonce, 12, 12)
	ciphertext, _ := decode(e.Ciphertext, 17, MaxBundleBytes+16)
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		clear(plain)
		return nil, ErrInvalid
	}
	return plain, nil
}
