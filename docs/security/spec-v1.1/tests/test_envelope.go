// Run from bundle root: go run tests/test_envelope.go
// SYNTHETIC TEST DATA ONLY. This explicit deterministic nonce is never for production.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type fixture struct {
	KeyHex        string            `json:"key_hex"`
	NonceHex      string            `json:"nonce_hex"`
	AAD           string            `json:"aad_utf8"`
	Plaintext     string            `json:"plaintext_utf8"`
	CiphertextHex string            `json:"ciphertext_and_tag_hex"`
	Envelope      map[string]string `json:"envelope"`
}

func decode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
func aead(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	c, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return c
}
func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func main() {
	path := "reference/envelope-vector.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var v fixture
	if err := json.Unmarshal(raw, &v); err != nil {
		panic(err)
	}
	key, nonce, ct := decode(v.KeyHex), decode(v.NonceHex), decode(v.CiphertextHex)
	aad := []byte(v.AAD)
	box := aead(key)
	plaintext, err := box.Open(nil, nonce, ct, aad)
	if err != nil {
		panic(err)
	}
	require(bytes.Equal(plaintext, []byte(v.Plaintext)), "plaintext mismatch")
	require(bytes.Equal(box.Seal(nil, nonce, plaintext, aad), ct), "ciphertext mismatch")
	require(base64.RawURLEncoding.EncodeToString(ct) == v.Envelope["ciphertext"], "ciphertext encoding mismatch")
	require(base64.RawURLEncoding.EncodeToString(nonce) == v.Envelope["nonce"], "nonce encoding mismatch")
	delete(v.Envelope, "nonce")
	delete(v.Envelope, "ciphertext")
	// encoding/json is adequate only for this fixed ASCII string-only fixture,
	// not a claim of a general RFC 8785 implementation.
	encodedAAD, err := json.Marshal(v.Envelope)
	if err != nil {
		panic(err)
	}
	require(bytes.Equal(encodedAAD, aad), "AAD mismatch")
	badTag := append([]byte(nil), ct...)
	badTag[len(badTag)-1] ^= 1
	badNonce := append([]byte(nil), nonce...)
	badNonce[0] ^= 1
	badKey := append([]byte(nil), key...)
	badKey[0] ^= 1
	badOwner := bytes.Replace(aad, []byte(`"owner_id":"local"`), []byte(`"owner_id":"other"`), 1)
	for _, test := range []struct{ key, nonce, ct, aad []byte }{
		{key, nonce, ct, badOwner}, {key, nonce, badTag, aad},
		{key, badNonce, ct, aad}, {badKey, nonce, ct, aad},
	} {
		_, err := aead(test.key).Open(nil, test.nonce, test.ct, test.aad)
		require(err != nil, "tampered input was accepted")
	}
	fmt.Println("PASS Go: AES-GCM roundtrip, exact encoding, wrong owner/tag/nonce/key rejection")
}
