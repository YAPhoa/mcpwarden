package secret

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

type vector struct {
	Key      string   `json:"key_hex"`
	AAD      string   `json:"aad_utf8"`
	Plain    string   `json:"plaintext_utf8"`
	Envelope Envelope `json:"envelope"`
}

func fixture(t testing.TB) (vector, []byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/security/spec-v1.1/reference/envelope-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(v.Key)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(v.Envelope)
	return v, key, envelope
}

// sealFixture is test-only. Production Go has no encryption API until durable
// revision CAS, nonce uniqueness and a cross-writer epoch usage cap are installed.
func sealFixture(t testing.TB, h Header, key, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	aad, err := canonical(h)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Header: h, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plain, aad))}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPublishedEnvelopeVector(t *testing.T) {
	v, key, raw := fixture(t)
	aad, err := canonical(v.Envelope.Header)
	if err != nil || string(aad) != v.AAD {
		t.Fatal("AAD differs from public vector")
	}
	plain, err := open(raw, v.Envelope.Header, key)
	if err != nil || string(plain) != v.Plain {
		t.Fatal("public vector decryption failed")
	}
	clear(plain)
	for _, mutate := range []func(*Header){
		func(h *Header) { h.OwnerID = "other" }, func(h *Header) { h.ConnectorID = "44444444-4444-4444-8444-444444444444" },
		func(h *Header) { h.CredentialID = "44444444-4444-4444-8444-444444444444" }, func(h *Header) { h.Epoch = "2" },
		func(h *Header) { h.Revision = "4" }, func(h *Header) { h.Purpose = "credential-key" },
		func(h *Header) { h.DestinationDigest = strings.Repeat("A", 43) }, func(h *Header) { h.Algorithm = "AES-128-GCM" },
	} {
		h := v.Envelope.Header
		mutate(&h)
		// Change both self-described fields and expected metadata. It must fail
		// cryptographic authentication, not merely the header equality check.
		e := v.Envelope
		e.Header = h
		changed, _ := json.Marshal(e)
		if _, err := open(changed, h, key); err != ErrInvalid {
			t.Fatal("modified authenticated binding accepted")
		}
	}
	key[0] ^= 1
	if _, err := open(raw, v.Envelope.Header, key); err != ErrInvalid {
		t.Fatal("wrong key accepted")
	}
	key[0] ^= 1
	for _, field := range []string{"nonce", "ciphertext"} {
		e := v.Envelope
		value := &e.Nonce
		if field == "ciphertext" {
			value = &e.Ciphertext
		}
		b, _ := base64.RawURLEncoding.DecodeString(*value)
		b[0] ^= 1
		*value = base64.RawURLEncoding.EncodeToString(b)
		changed, _ := json.Marshal(e)
		if _, err := open(changed, e.Header, key); err != ErrInvalid {
			t.Fatal("tampered nonce/ciphertext accepted")
		}
	}
}

func TestEnvelopeStrictParsing(t *testing.T) {
	v, key, raw := fixture(t)
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	for name := range object {
		original := object[name]
		delete(object, name)
		b, _ := json.Marshal(object)
		if _, err := Parse(b, v.Envelope.Header); err != ErrInvalid {
			t.Fatalf("missing %s accepted", name)
		}
		object[name] = nil
		b, _ = json.Marshal(object)
		if _, err := Parse(b, v.Envelope.Header); err != ErrInvalid {
			t.Fatalf("null %s accepted", name)
		}
		object[name] = original
	}
	bad := [][]byte{
		append([]byte(`{"owner_id":"local",`), raw[1:]...),
		append([]byte(`{"owner_\u0069d":"local",`), raw[1:]...),
		append([]byte(`{"unknown":"PRIVATE_TEST_VALUE",`), raw[1:]...),
		append(append([]byte{}, raw...), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`"epoch":"1"`), []byte(`"epoch":"01"`), 1),
		bytes.Replace(raw, []byte(`"revision":"3"`), []byte(`"revision":3`), 1),
		bytes.Replace(raw, []byte(v.Envelope.Nonce), []byte(v.Envelope.Nonce+"="), 1),
		bytes.Replace(raw, []byte(v.Envelope.Nonce), []byte("AAECAwQFBgcICQp"), 1),
		bytes.Repeat([]byte(" "), MaxEnvelopeBytes+1),
	}
	for i, b := range bad {
		if _, err := open(b, v.Envelope.Header, key); err != ErrInvalid {
			t.Fatalf("invalid envelope %d accepted", i)
		}
	}
	if _, err := open(raw, v.Envelope.Header, key[:31]); err != ErrInvalid {
		t.Fatal("short key accepted")
	}
}

type recordSource struct{ record Record }

func (s recordSource) Current(owner, id string) (Record, bool) {
	return s.record, owner == "local" && id == "33333333-3333-4333-8333-333333333333"
}

func TestActivationAuthenticatesBundleAndClearsOwnedBuffers(t *testing.T) {
	v, key, _ := fixture(t)
	d := Destination{Schema: "mcpwarden.destination.v1", Endpoint: "https://example.com/mcp", HeaderNames: []string{"authorization"}, Network: "public"}
	digest, _ := d.Digest()
	h := v.Envelope.Header
	h.DestinationDigest = digest
	credential := lease.Credential{ID: h.CredentialID, ConnectorID: h.ConnectorID, Epoch: h.Epoch, Revision: h.Revision, DestinationDigest: digest}
	for _, plain := range []string{v.Plain, `{"kind":"header_bundle","headers":[{"name":"authorization","value":"Bearer SAFE_TEST"}]}`} {
		a := Activator{Records: recordSource{Record{Envelope: sealFixture(t, h, key, []byte(plain)), Destination: d}}}
		input := bytes.Clone(key)
		material, err := a.Stage(t.Context(), "local", credential, input)
		if err != nil || !bytes.Equal(input, make([]byte, 32)) {
			t.Fatal("activation failed or key retained")
		}
		handle := material.(*Handle)
		owned := handle.headers[0].value
		if strings.Contains(fmt.Sprintf("%v %#v %+v", handle, handle, handle), "Bearer") {
			t.Fatal("handle diagnostic exposed credentials")
		}
		if _, err := json.Marshal(handle); err == nil {
			t.Fatal("handle serialized")
		}
		handle.Destroy()
		handle.Destroy()
		if !bytes.Equal(owned, make([]byte, len(owned))) || len(handle.headers) != 0 {
			t.Fatal("owned plaintext not cleared")
		}
	}
	bad := []string{
		`{"kind":"oauth","headers":[]}`, `{"kind":"header_bundle","headers":null}`,
		`{"kind":"header_bundle","headers":[{"name":"authorization"}]}`,
		`{"kind":"header_bundle","headers":[{"name":"authorization","value":null}]}`,
		`{"kind":"header_bundle","headers":[{"name":"authorization","value":"x\r\ny"}]}`,
		`{"kind":"header_bundle","headers":[{"name":"authorization","value":" x "}]}`,
		`{"kind":"header_bundle","headers":[{"name":"x-other","value":"PRIVATE_TEST_VALUE"}]}`,
		`{"kind":"header_bundle","headers":[{"name":"authorization","value":"x","value":"y"}]}`,
		`{"kind":"header_bundle","headers":[{"name":"authorization","value":"x","unknown":true}]}`,
		`{"kind":"header_bundle","headers":[{"name":"authorization","value":"x"},{"name":"Authorization","value":"y"}]}`,
	}
	for i, plain := range bad {
		a := Activator{Records: recordSource{Record{Envelope: sealFixture(t, h, key, []byte(plain)), Destination: d}}}
		if _, err := a.Stage(t.Context(), "local", credential, bytes.Clone(key)); err != lease.ErrKey {
			t.Fatalf("invalid bundle %d accepted", i)
		}
	}
	a := Activator{Records: recordSource{Record{Envelope: sealFixture(t, h, key, []byte(v.Plain)), Destination: d}}}
	credential.Revision = "4"
	if _, err := a.Stage(t.Context(), "local", credential, bytes.Clone(key)); err != lease.ErrKey {
		t.Fatal("old ciphertext activated as current revision")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := a.Stage(ctx, "local", credential, bytes.Clone(key)); err != lease.ErrKey {
		t.Fatal("canceled activation accepted")
	}
}

func TestWebCryptoInteroperability(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node WebCrypto unavailable")
	}
	v, key, _ := fixture(t)
	h := v.Envelope.Header
	h.OwnerID = "用户/😀/e\u0301/<>&"
	raw := sealFixture(t, h, key, []byte(v.Plain))
	input, _ := json.Marshal(map[string]any{"key": v.Key, "envelope": json.RawMessage(raw), "plaintext": v.Plain})
	cmd := exec.Command("node", "testdata/webcrypto.cjs")
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal("independent WebCrypto fixture failed")
	}
	plain, err := open(output, h, key)
	if err != nil || string(plain) != v.Plain {
		t.Fatal("WebCrypto encryption / Go decryption differs")
	}
	clear(plain)
}

func FuzzEnvelope(f *testing.F) {
	v, key, raw := fixture(f)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		plain, err := open(raw, v.Envelope.Header, key)
		if err != nil && err != ErrInvalid {
			t.Fatal("unsafe parser error")
		}
		clear(plain)
	})
}
