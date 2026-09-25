// Package pgcatalog is the PostgreSQL catalog and history backend: the runtime
// repository, the audit store, and the operator import, cutover and rollback.
//
// Secret-bearing values stay in legacy server-managed custody. They are sealed
// with a key derived from the existing catalog key before reaching PostgreSQL;
// the gateway can still decrypt them, exactly as it can decrypt the file.
package pgcatalog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

const sealVersion = 1

var errSealed = errors.New("catalog record failed authentication")

type sealer struct {
	aead cipher.AEAD
	mac  []byte
}

// newSealer derives independent field-encryption and verifier-digest keys, so
// no PostgreSQL value is encrypted under the file key itself.
func newSealer(encodedKey string) (*sealer, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("managed upstream key must be base64-encoded 32 bytes")
	}
	defer clear(key)
	enc, err := hkdf.Key(sha256.New, key, nil, "mcpwarden catalog postgres fields v1", 32)
	if err != nil {
		return nil, err
	}
	defer clear(enc)
	mac, err := hkdf.Key(sha256.New, key, nil, "mcpwarden catalog postgres verifier digest v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead, mac: mac}, nil
}

// seal binds the payload to its row identity (aad), so rows cannot be swapped.
func (s *sealer) seal(aad string, v any) ([]byte, error) {
	plain, err := jsoncodec.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode catalog record failed")
	}
	defer clear(plain)
	out := make([]byte, 1+s.aead.NonceSize(), 1+s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	out[0] = sealVersion
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, fmt.Errorf("create catalog nonce: %w", err)
	}
	return s.aead.Seal(out, out[1:], plain, []byte("mcpwarden.catalog.v1/"+aad)), nil
}

func (s *sealer) open(aad string, data []byte, v any) error {
	n := s.aead.NonceSize()
	if len(data) < 1+n+s.aead.Overhead() || data[0] != sealVersion {
		return errSealed
	}
	plain, err := s.aead.Open(nil, data[1:1+n], data[1+n:], []byte("mcpwarden.catalog.v1/"+aad))
	if err != nil {
		return errSealed
	}
	defer clear(plain)
	// The file catalog decodes with encoding/json; keep the same decoder.
	if json.Unmarshal(plain, v) != nil {
		return errSealed
	}
	return nil
}

// digest is the unique, non-reversible index for a stored token verifier.
func (s *sealer) digest(secretHash string) []byte {
	h := hmac.New(sha256.New, s.mac)
	h.Write([]byte(secretHash))
	return h.Sum(nil)
}

func accountAAD(owner string) string             { return "account/" + owner }
func accessAAD(id string) string                 { return "access/" + id }
func connectorAAD(id string) string              { return "connector/" + id }
func discoveryAAD(owner, provider string) string { return "discovery/" + owner + "\x00" + provider }
func visibilityAAD(owner, provider string) string {
	return "visibility/" + owner + "\x00" + provider
}
