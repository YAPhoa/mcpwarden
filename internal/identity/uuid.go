// Package identity supplies internal UUIDs; these are identifiers, not credentials.
package identity

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

const Namespace = "d364c149-6fcb-4e3f-9f90-3d72ca3a6d21"

func New() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return format(b[:])
}
func Valid(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	// Only the canonical lowercase form, so every store compares IDs the
	// same way (PostgreSQL's uuid type would fold case; SQLite text would not).
	for i := 0; i < len(id); i++ {
		if c := id[i]; c >= 'A' && c <= 'F' {
			return false
		}
	}
	b, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return err == nil && len(b) == 16 && b[8]&0xc0 == 0x80
}

// Derive implements RFC 9562 UUIDv5 using the binary namespace and exact name.
func Derive(namespace, name string) string {
	b, err := hex.DecodeString(strings.ReplaceAll(namespace, "-", ""))
	if err != nil || len(b) != 16 {
		panic("invalid internal UUID namespace")
	}
	h := sha1.New()
	_, _ = h.Write(b)
	_, _ = h.Write([]byte(name))
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return format(sum[:16])
}
func format(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
