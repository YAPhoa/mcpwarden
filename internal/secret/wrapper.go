package secret

import (
	"unicode/utf8"

	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

const (
	MaxWrapperBytes = 4096
	PassphraseInfo  = "mcpwarden/v1/passphrase-root-wrap"
	RecoveryInfo    = "mcpwarden/v1/recovery-root-wrap"
	CredentialInfo  = "mcpwarden/v1/credential-key-wrap"
)

type RootContext struct {
	OwnerID     string `json:"owner_id"`
	RootID      string `json:"root_id"`
	RootVersion string `json:"root_version"`
	WrapperID   string `json:"wrapper_id"`
	Method      string `json:"method"`
}
type RootWrapper struct {
	Format    string `json:"format"`
	Algorithm string `json:"algorithm"`
	Purpose   string `json:"purpose"`
	RootContext
	KDF        json.RawMessage `json:"kdf"`
	Nonce      string          `json:"nonce"`
	Ciphertext string          `json:"ciphertext"`
}
type PassphraseKDF struct {
	Suite        string `json:"suite"`
	ArgonVersion int    `json:"argon_version"`
	MemoryKiB    int    `json:"memory_kib"`
	Iterations   int    `json:"iterations"`
	Parallelism  int    `json:"parallelism"`
	Salt         string `json:"salt"`
	OutputBytes  int    `json:"output_bytes"`
	HKDFInfo     string `json:"hkdf_info"`
}
type RecoveryKDF struct {
	Suite       string `json:"suite"`
	OutputBytes int    `json:"output_bytes"`
	HKDFInfo    string `json:"hkdf_info"`
}
type CredentialContext struct {
	OwnerID      string `json:"owner_id"`
	RootID       string `json:"root_id"`
	RootVersion  string `json:"root_version"`
	ConnectorID  string `json:"connector_id"`
	CredentialID string `json:"credential_id"`
	Epoch        string `json:"epoch"`
}
type CredentialWrapper struct {
	Format    string `json:"format"`
	Algorithm string `json:"algorithm"`
	Purpose   string `json:"purpose"`
	CredentialContext
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func validOwner(owner string) bool {
	// Reuse strict Unicode validation without normalizing the stable identity.
	raw, err := json.Marshal(owner)
	return err == nil && len(owner) > 0 && len(owner) <= 512 && utf8.ValidString(owner) && json.Validate(raw, 4096, 1) == nil
}

// ParseRootWrapper validates public wrapping metadata. The server never derives
// a passphrase/recovery key or unwraps a vault root. Only the client can authenticate
// this ciphertext. Expected context comes from the current owner-scoped records.
func ParseRootWrapper(raw []byte, expected RootContext) (RootWrapper, error) {
	if !validOwner(expected.OwnerID) || !validID(expected.RootID) || !validVersion(expected.RootVersion) || !validID(expected.WrapperID) || (expected.Method != "passphrase" && expected.Method != "recovery") || json.Validate(raw, MaxWrapperBytes, 8) != nil {
		return RootWrapper{}, ErrInvalid
	}
	var w RootWrapper
	if json.UnmarshalStrict(raw, &w) != nil || w.RootContext != expected || w.Format != "mcpwarden.root-wrap.v1" || w.Algorithm != Algorithm || w.Purpose != "vault-root" {
		return RootWrapper{}, ErrInvalid
	}
	if _, err := decode(w.Nonce, 12, 12); err != nil {
		return RootWrapper{}, ErrInvalid
	}
	if _, err := decode(w.Ciphertext, 48, 48); err != nil {
		return RootWrapper{}, ErrInvalid
	}
	if expected.Method == "passphrase" {
		var k PassphraseKDF
		if json.UnmarshalStrict(w.KDF, &k) != nil || k.Suite != "ARGON2ID-HKDF-SHA256" || k.ArgonVersion != 19 || k.MemoryKiB != 65536 || k.Iterations != 3 || k.Parallelism != 4 || k.OutputBytes != 32 || k.HKDFInfo != PassphraseInfo {
			return RootWrapper{}, ErrInvalid
		}
		if _, err := decode(k.Salt, 16, 16); err != nil {
			return RootWrapper{}, ErrInvalid
		}
	} else {
		var k RecoveryKDF
		if json.UnmarshalStrict(w.KDF, &k) != nil || k.Suite != "HKDF-SHA256" || k.OutputBytes != 32 || k.HKDFInfo != RecoveryInfo {
			return RootWrapper{}, ErrInvalid
		}
	}
	return w, nil
}

func ParseCredentialWrapper(raw []byte, expected CredentialContext) (CredentialWrapper, error) {
	if !validOwner(expected.OwnerID) || !validID(expected.RootID) || !validVersion(expected.RootVersion) || !validID(expected.ConnectorID) || !validID(expected.CredentialID) || !validVersion(expected.Epoch) || json.Validate(raw, MaxWrapperBytes, 8) != nil {
		return CredentialWrapper{}, ErrInvalid
	}
	var w CredentialWrapper
	if json.UnmarshalStrict(raw, &w) != nil || w.CredentialContext != expected || w.Format != "mcpwarden.credential-wrap.v1" || w.Algorithm != Algorithm || w.Purpose != "credential-key" {
		return CredentialWrapper{}, ErrInvalid
	}
	if _, err := decode(w.Nonce, 12, 12); err != nil {
		return CredentialWrapper{}, ErrInvalid
	}
	if _, err := decode(w.Ciphertext, 48, 48); err != nil {
		return CredentialWrapper{}, ErrInvalid
	}
	return w, nil
}
