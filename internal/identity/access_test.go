package identity

import (
	"strings"
	"testing"
)

func TestAccessTokenFormatAndIndependentPublicIDs(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		token, publicID := NewAccessToken()
		parsed, ok := ParseAccessToken(token)
		if !ok || parsed != publicID || !ValidPublicID(publicID) || seen[publicID] {
			t.Fatal("invalid or repeated public ID")
		}
		seen[publicID] = true
	}
}

func TestAccessTokenRejectsNoncanonicalForms(t *testing.T) {
	good := "mcpw_" + strings.Repeat("a", 32) + "_" + strings.Repeat("A", 43)
	if _, ok := ParseAccessToken(good); !ok {
		t.Fatal("synthetic canonical token rejected")
	}
	for _, token := range []string{
		"", "mw_legacy", good[:80], good + "A", good + "=",
		strings.Replace(good, "aaaa", "AAAA", 1),
		good[:37] + "-" + good[38:], good[:80] + "B", // nonzero base64 pad bits
		good[:38] + "+" + good[39:], good[:38] + "/" + good[39:],
		good[:38] + "\n" + good[39:], good + "\r\n",
	} {
		if _, ok := ParseAccessToken(token); ok {
			t.Fatal("noncanonical token accepted")
		}
	}
}
