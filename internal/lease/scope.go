// Package lease implements caller-bound working windows. It has no authority to
// authenticate a user or unlock a vault; those are separate, explicit boundaries.
package lease

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

const (
	ScopeSchema      = "mcpwarden.lease-scope.v1"
	MaxScopeBytes    = 256 << 10
	MaxArgumentBytes = 1 << 20
	MaxTools         = 256
	MaxConstraints   = 64
	MaxSetValues     = 64
	maxSafeInteger   = 9007199254740991
)

var ErrScope = errors.New("invalid or unsupported lease scope")

type Scope struct {
	Schema                    string      `json:"schema"`
	OwnerID                   string      `json:"owner_id"`
	RequesterAccessID         string      `json:"requester_access_id"`
	ConnectorID               string      `json:"connector_id"`
	CredentialID              string      `json:"credential_id"`
	CredentialEpoch           string      `json:"credential_epoch"`
	Purpose                   string      `json:"purpose"`
	DurationSeconds           int         `json:"duration_seconds"`
	PolicyRevision            string      `json:"policy_revision"`
	ConnectorSecurityRevision string      `json:"connector_security_revision"`
	DestinationDigest         string      `json:"destination_profile_sha256"`
	Tools                     []ToolScope `json:"tools"`
	MaxCalls                  *int64      `json:"max_calls"`
}

type ToolScope struct {
	ToolID           string       `json:"tool_id"`
	DefinitionDigest string       `json:"definition_sha256"`
	Constraints      []Constraint `json:"constraints"`
}

// Values are only exact strings, booleans or safe integers. An absent value is
// distinct from false, an empty string, and zero. Null never means a wildcard.
type Constraint struct {
	Pointer  string            `json:"pointer"`
	Operator string            `json:"operator"`
	Value    json.RawMessage   `json:"value,omitempty"`
	Values   []json.RawMessage `json:"values,omitempty"`
}

func canonical(raw []byte, limit int) ([]byte, error) {
	if json.Validate(raw, limit, 64) != nil {
		return nil, ErrScope
	}
	// The upstream Go entry point accepts objects/arrays. A one-element array
	// lets the same reviewed implementation canonicalize a scalar as well.
	wrapped := append([]byte{'['}, raw...)
	wrapped = append(wrapped, ']')
	b, err := jsoncanonicalizer.Transform(wrapped)
	if err != nil {
		return nil, ErrScope
	}
	return b[1 : len(b)-1], nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func validDigest(s string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func validID(s string) bool { return identity.Valid(s) && strings.ToLower(s) == s }
func validVersion(s string) bool {
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == s
}

func ParseScope(raw []byte) (Scope, string, error) {
	if json.Validate(raw, MaxScopeBytes, 64) != nil {
		return Scope{}, "", ErrScope
	}
	var s Scope
	if json.UnmarshalStrict(raw, &s) != nil {
		return Scope{}, "", ErrScope
	}
	if s.Schema != ScopeSchema || len(s.OwnerID) == 0 || len(s.OwnerID) > 512 || !validID(s.RequesterAccessID) || !validID(s.ConnectorID) || !validID(s.CredentialID) || !validVersion(s.CredentialEpoch) || !validVersion(s.PolicyRevision) || !validVersion(s.ConnectorSecurityRevision) || !validDigest(s.DestinationDigest) || s.DurationSeconds < 1 || s.DurationSeconds > 3600 || s.MaxCalls != nil && (*s.MaxCalls < 1 || *s.MaxCalls > maxSafeInteger) {
		return Scope{}, "", ErrScope
	}
	switch s.Purpose {
	case "tool_use":
		if len(s.Tools) == 0 || len(s.Tools) > MaxTools {
			return Scope{}, "", ErrScope
		}
	case "setup_discovery", "oauth_setup":
		if len(s.Tools) != 0 || s.MaxCalls != nil || s.DurationSeconds > 300 {
			return Scope{}, "", ErrScope
		}
		s.Tools = []ToolScope{}
	default:
		return Scope{}, "", ErrScope
	}
	seen := map[string]bool{}
	for i := range s.Tools {
		t := &s.Tools[i]
		if t.Constraints == nil {
			t.Constraints = []Constraint{}
		}
		if !validID(t.ToolID) || seen[t.ToolID] || !validDigest(t.DefinitionDigest) || len(t.Constraints) > MaxConstraints {
			return Scope{}, "", ErrScope
		}
		seen[t.ToolID] = true
		constraints := map[string]bool{}
		for j := range t.Constraints {
			c := &t.Constraints[j]
			if _, ok := pointer(c.Pointer); !ok {
				return Scope{}, "", ErrScope
			}
			switch c.Operator {
			case "required":
				if c.Value != nil || c.Values != nil {
					return Scope{}, "", ErrScope
				}
			case "equals":
				if c.Values != nil || !scalar(c.Value) {
					return Scope{}, "", ErrScope
				}
				value, err := canonical(c.Value, MaxScopeBytes)
				if err != nil {
					return Scope{}, "", ErrScope
				}
				c.Value = value
			case "in":
				if c.Value != nil || len(c.Values) == 0 || len(c.Values) > MaxSetValues {
					return Scope{}, "", ErrScope
				}
				values := map[string]bool{}
				for i, v := range c.Values {
					if !scalar(v) {
						return Scope{}, "", ErrScope
					}
					v, err := canonical(v, MaxScopeBytes)
					if err != nil || values[string(v)] {
						return Scope{}, "", ErrScope
					}
					c.Values[i] = v
					values[string(v)] = true
				}
				sort.Slice(c.Values, func(i, j int) bool { return bytes.Compare(c.Values[i], c.Values[j]) < 0 })
			default:
				return Scope{}, "", ErrScope
			}
			v, _ := json.Marshal(c)
			if constraints[string(v)] {
				return Scope{}, "", ErrScope
			}
			constraints[string(v)] = true
		}
		sort.Slice(t.Constraints, func(i, j int) bool {
			a, _ := json.Marshal(t.Constraints[i])
			b, _ := json.Marshal(t.Constraints[j])
			return bytes.Compare(a, b) < 0
		})
	}
	sort.Slice(s.Tools, func(i, j int) bool { return s.Tools[i].ToolID < s.Tools[j].ToolID })
	// Normalization materializes ordering before hashing. Approval hashing is
	// separate from audit.HashArgs, whose existing bytes are unchanged.
	b, err := json.Marshal(s)
	if err != nil {
		return Scope{}, "", ErrScope
	}
	b, err = canonical(b, MaxScopeBytes)
	if err != nil {
		return Scope{}, "", err
	}
	return s, digest(b), nil
}

func scalar(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	switch v := v.(type) {
	case string, bool:
		return true
	case json.Number:
		n, err := v.Int64()
		return err == nil && n >= -maxSafeInteger && n <= maxSafeInteger
	default:
		return false
	}
}

func pointer(p string) ([]string, bool) {
	if len(p) == 0 || len(p) > 1024 || p[0] != '/' {
		return nil, false
	}
	parts := strings.Split(p[1:], "/")
	for i, part := range parts {
		for j := 0; j < len(part); j++ {
			if part[j] == '~' {
				if j+1 == len(part) || part[j+1] != '0' && part[j+1] != '1' {
					return nil, false
				}
				j++
			}
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
	}
	return parts, true
}

func valueAt(v any, p string) (any, bool) {
	parts, ok := pointer(p)
	if !ok {
		return nil, false
	}
	for _, part := range parts {
		switch current := v.(type) {
		case map[string]any:
			v, ok = current[part]
			if !ok {
				return nil, false
			}
		case []any:
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n >= len(current) || strconv.Itoa(n) != part {
				return nil, false
			}
			v = current[n]
		default:
			return nil, false
		}
	}
	return v, true
}

// Matches reports whether a tool-use scope admits one tools/call. A setup
// scope names no tools and never admits a call: its window only lends material
// for connection setup and tools/list (Service.Setup).
func (s Scope) Matches(toolID, definition string, arguments []byte) bool {
	if s.Purpose != "tool_use" {
		return false
	}
	if json.Validate(arguments, MaxArgumentBytes, 64) != nil {
		return false
	}
	var v any
	if json.Unmarshal(arguments, &v) != nil {
		return false
	}
	if _, ok := v.(map[string]any); !ok {
		return false
	}
	for _, t := range s.Tools {
		if t.ToolID != toolID || t.DefinitionDigest != definition {
			continue
		}
		for _, c := range t.Constraints {
			value, exists := valueAt(v, c.Pointer)
			if !exists {
				return false
			}
			if c.Operator == "required" {
				continue
			}
			raw, _ := json.Marshal(value)
			// Reject fractional/out-of-range values before JCS could round them
			// into a permitted safe integer.
			if !scalar(raw) {
				return false
			}
			raw, err := canonical(raw, MaxArgumentBytes)
			if err != nil {
				return false
			}
			match := c.Operator == "equals" && bytes.Equal(raw, c.Value)
			if c.Operator == "in" {
				for _, candidate := range c.Values {
					match = match || bytes.Equal(raw, candidate)
				}
			}
			if !match {
				return false
			}
		}
		return true
	}
	return false
}

// DefinitionDigest pins the entire validated public tool definition, including
// schemas, annotations and parameter/header mappings. No hint grants authority.
func DefinitionDigest(raw []byte) (string, error) {
	b, err := canonical(raw, MaxArgumentBytes)
	if err != nil || len(b) == 0 || b[0] != '{' {
		return "", ErrScope
	}
	return digest(b), nil
}
