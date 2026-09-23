package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

func wrapperFixture(t *testing.T) (RootWrapper, []byte) {
	t.Helper()
	k, _ := json.Marshal(PassphraseKDF{Suite: "ARGON2ID-HKDF-SHA256", ArgonVersion: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: base64.RawURLEncoding.EncodeToString(make([]byte, 16)), OutputBytes: 32, HKDFInfo: PassphraseInfo})
	w := RootWrapper{Format: "mcpwarden.root-wrap.v1", Algorithm: Algorithm, Purpose: "vault-root", RootContext: RootContext{OwnerID: "alice", RootID: identity.New(), RootVersion: "1", WrapperID: identity.New(), Method: "passphrase"}, KDF: k, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 12)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 48))}
	raw, _ := json.Marshal(w)
	return w, raw
}

func TestStrictWrapperParsing(t *testing.T) {
	w, raw := wrapperFixture(t)
	if _, err := ParseRootWrapper(raw, w.RootContext); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	for field, old := range object {
		for _, remove := range []bool{true, false} {
			if remove {
				delete(object, field)
			} else {
				object[field] = nil
			}
			bad, _ := json.Marshal(object)
			if _, err := ParseRootWrapper(bad, w.RootContext); err == nil {
				t.Fatal("missing/null wrapper field accepted", field)
			}
		}
		object[field] = old
	}
	for _, bad := range [][]byte{
		append([]byte(`{"owner_\u0069d":"alice",`), raw[1:]...),
		bytes.Replace(raw, []byte(`"memory_kib":65536`), []byte(`"memory_kib":8`), 1),
		bytes.Replace(raw, []byte(`"parallelism":4`), []byte(`"parallelism":400`), 1),
		bytes.Replace(raw, []byte(`"root_version":"1"`), []byte(`"root_version":"01"`), 1),
		bytes.Replace(raw, []byte(`"iterations":3`), []byte(`"iterations":3,"extra":true`), 1),
		bytes.Replace(raw, []byte(`"alice"`), []byte(`"\ud800"`), 1),
		bytes.Repeat([]byte(" "), MaxWrapperBytes+1),
	} {
		if _, err := ParseRootWrapper(bad, w.RootContext); err == nil {
			t.Fatal("invalid root wrapper accepted")
		}
	}
	badContext := w.RootContext
	badContext.OwnerID = string([]byte{0xff})
	if _, err := ParseRootWrapper(raw, badContext); err == nil {
		t.Fatal("invalid expected Unicode accepted")
	}
	c := CredentialWrapper{Format: "mcpwarden.credential-wrap.v1", Algorithm: Algorithm, Purpose: "credential-key", CredentialContext: CredentialContext{OwnerID: "alice", RootID: w.RootID, RootVersion: "1", ConnectorID: identity.New(), CredentialID: identity.New(), Epoch: "1"}, Nonce: w.Nonce, Ciphertext: w.Ciphertext}
	raw, _ = json.Marshal(c)
	if _, err := ParseCredentialWrapper(raw, c.CredentialContext); err != nil {
		t.Fatal(err)
	}
	object = map[string]any{}
	_ = json.Unmarshal(raw, &object)
	for field, old := range object {
		delete(object, field)
		bad, _ := json.Marshal(object)
		if _, err := ParseCredentialWrapper(bad, c.CredentialContext); err == nil {
			t.Fatal("missing CEK wrapper field accepted", field)
		}
		object[field] = old
	}
}

func TestBrowserVaultWrapperInteroperability(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node WebCrypto not available")
	}
	destination := Destination{Schema: "mcpwarden.destination.v1", Endpoint: "https://example.com/mcp", HeaderNames: []string{"authorization"}, Network: "public"}
	digest, err := destination.Digest()
	if err != nil {
		t.Fatal(err)
	}
	script := "../../ui/tests/fixtures/vault-interop.mjs"
	raw, err := exec.CommandContext(t.Context(), node, script, digest).Output()
	if err != nil {
		t.Fatal("synthetic browser fixture failed", err)
	}
	var f struct {
		Root struct {
			OwnerID         string      `json:"owner_id"`
			RootID          string      `json:"root_id"`
			RootVersion     string      `json:"root_version"`
			WrapperRevision string      `json:"wrapper_revision"`
			Passphrase      RootWrapper `json:"passphrase"`
			Recovery        RootWrapper `json:"recovery"`
			RecoveryKey     string      `json:"recovery_key"`
		} `json:"root"`
		Context    CredentialContext `json:"context"`
		Credential struct {
			WrappedKey CredentialWrapper `json:"wrapped_key"`
			Envelope   Envelope          `json:"envelope"`
		} `json:"credential"`
		Destination Destination `json:"destination"`
		KDFOutput   string      `json:"kdf_output"`
	}
	if err := json.UnmarshalStrict(raw, &f); err != nil {
		t.Fatal(err)
	}
	unb64 := func(value string) []byte {
		b, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	derive := func(input []byte, info string) []byte {
		b, err := hkdf.Key(sha256.New, input, make([]byte, 32), info, 32)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	aead := func(key []byte) cipher.AEAD {
		b, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		g, err := cipher.NewGCM(b)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	// Both sides canonicalize the complete validated public header, including KDF.
	header := func(value any) []byte {
		b, _ := json.Marshal(value)
		var fields map[string]any
		_ = json.Unmarshal(b, &fields)
		delete(fields, "nonce")
		delete(fields, "ciphertext")
		b, err := canonical(fields)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	unwrap := func(key []byte, value any, nonce, ciphertext string) []byte {
		plain, err := aead(key).Open(nil, unb64(nonce), unb64(ciphertext), header(value))
		if err != nil {
			t.Fatal("Go could not authenticate browser wrapper")
		}
		return plain
	}
	p := f.Root.Passphrase
	r := f.Root.Recovery
	for _, w := range []RootWrapper{p, r} {
		b, _ := json.Marshal(w)
		if _, err := ParseRootWrapper(b, w.RootContext); err != nil {
			t.Fatal(err)
		}
	}
	passKey := derive(unb64(f.KDFOutput), PassphraseInfo)
	recoveryKey := derive(unb64(f.Root.RecoveryKey), RecoveryInfo)
	root := unwrap(passKey, p, p.Nonce, p.Ciphertext)
	recovered := unwrap(recoveryKey, r, r.Nonce, r.Ciphertext)
	if len(root) != 32 || !bytes.Equal(root, recovered) {
		t.Fatal("passphrase and recovery root disagree")
	}
	wrapKey := derive(root, CredentialInfo)
	w := f.Credential.WrappedKey
	encoded, _ := json.Marshal(w)
	if _, err := ParseCredentialWrapper(encoded, f.Context); err != nil {
		t.Fatal(err)
	}
	cek := unwrap(wrapKey, w, w.Nonce, w.Ciphertext)
	encoded, _ = json.Marshal(f.Credential.Envelope)
	plain, err := open(encoded, f.Credential.Envelope.Header, cek)
	if err != nil || !strings.Contains(string(plain), "SYNTHETIC_INTEROP") {
		t.Fatal("Go could not authenticate browser credential")
	}
	// Reverse direction: independently reseal every layer in Go, then unlock and
	// release with the actual browser module using passphrase AND recovery.
	seal := func(key, plain []byte, value any) (string, string) {
		nonce := make([]byte, 12)
		_, _ = rand.Read(nonce)
		ct := aead(key).Seal(nil, nonce, plain, header(value))
		return base64.RawURLEncoding.EncodeToString(nonce), base64.RawURLEncoding.EncodeToString(ct)
	}
	f.Root.Passphrase.Nonce, f.Root.Passphrase.Ciphertext = seal(passKey, root, f.Root.Passphrase)
	f.Root.Recovery.Nonce, f.Root.Recovery.Ciphertext = seal(recoveryKey, root, f.Root.Recovery)
	f.Credential.WrappedKey.Nonce, f.Credential.WrappedKey.Ciphertext = seal(wrapKey, cek, f.Credential.WrappedKey)
	f.Credential.Envelope.Nonce, f.Credential.Envelope.Ciphertext = seal(cek, plain, f.Credential.Envelope)
	raw, _ = json.Marshal(f)
	cmd := exec.CommandContext(t.Context(), node, script, "open")
	cmd.Stdin = bytes.NewReader(raw)
	result, err := cmd.Output()
	if err != nil {
		t.Fatal("browser could not authenticate Go wrappers", err)
	}
	var keys struct {
		Pass     string `json:"pass"`
		Recovery string `json:"recovery"`
	}
	if json.Unmarshal(result, &keys) != nil || !bytes.Equal(unb64(keys.Pass), cek) || !bytes.Equal(unb64(keys.Recovery), cek) {
		t.Fatal("released CEKs disagree")
	}
	for _, buffer := range [][]byte{root, recovered, passKey, recoveryKey, wrapKey, cek, plain} {
		clear(buffer)
	}
}
