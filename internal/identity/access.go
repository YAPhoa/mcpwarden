package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// NewPublicID returns an independent, non-secret display identifier. It is not
// derived from a token, verifier, owner, or transport session.
func NewPublicID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func ValidPublicID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// NewAccessToken returns the token for one-time delivery and its public ID.
// Authentication continues to hash the entire token, including the public ID.
func NewAccessToken() (token, publicID string) {
	publicID = NewPublicID()
	var secret [32]byte
	_, _ = rand.Read(secret[:])
	return "mcpw_" + publicID + "_" + base64.RawURLEncoding.EncodeToString(secret[:]), publicID
}

// ParseAccessToken accepts only the canonical new format. Legacy mw_ keys are
// handled separately by authentication; parsing a public ID never authenticates.
func ParseAccessToken(token string) (publicID string, ok bool) {
	if len(token) != 81 || !strings.HasPrefix(token, "mcpw_") || token[37] != '_' || !ValidPublicID(token[5:37]) {
		return "", false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(token[38:])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != token[38:] {
		return "", false
	}
	return token[5:37], true
}

// Actor contains only safe authentication metadata. Only the server's
// authentication boundary populates it; MCP metadata is never an identity source.
type Actor struct {
	Owner, AccessID, PublicID, Label, Kind string
}

type actorContextKey struct{}

func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

func ActorFrom(ctx context.Context) (Actor, bool) {
	actor, ok := ctx.Value(actorContextKey{}).(Actor)
	return actor, ok
}
