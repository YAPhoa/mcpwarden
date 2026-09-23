// Package jsoncodec centralizes Sonic settings for new security/storage data.
// Legacy audit argument hashing deliberately continues to use its original codec.
package jsoncodec

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/bytedance/sonic"
)

type RawMessage = stdjson.RawMessage
type Number = stdjson.Number

var api = sonic.Config{EscapeHTML: true, SortMapKeys: true, CopyString: true,
	UseNumber: true, UseUnicodeErrors: true, ValidateString: true, CaseSensitive: true}.Froze()
var strict = sonic.Config{EscapeHTML: true, SortMapKeys: true, CopyString: true,
	UseNumber: true, UseUnicodeErrors: true, ValidateString: true, CaseSensitive: true,
	DisallowUnknownFields: true}.Froze()

func Marshal(value any) ([]byte, error)           { return api.Marshal(value) }
func Unmarshal(raw []byte, value any) error       { return api.Unmarshal(raw, value) }
func UnmarshalStrict(raw []byte, value any) error { return strict.Unmarshal(raw, value) }

var ErrInvalid = errors.New("invalid JSON document")

// Validate rejects duplicates (including escaped names), unpaired surrogates,
// invalid UTF-8, multiple roots, and excessive nesting before security decoding.
// Sonic decoding stays strict too; no skip-validation or zero-copy options are
// enabled. Errors intentionally exclude input fragments and secret values.
func Validate(raw []byte, maxBytes, maxDepth int) error {
	if len(raw) == 0 || len(raw) > maxBytes || !utf8.Valid(raw) || !validEscapes(raw) {
		return ErrInvalid
	}
	d := stdjson.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > maxDepth {
			return ErrInvalid
		}
		t, err := d.Token()
		if err != nil {
			return ErrInvalid
		}
		switch t := t.(type) {
		case stdjson.Number:
			if _, err := strconv.ParseFloat(t.String(), 64); err != nil {
				return ErrInvalid
			}
		case stdjson.Delim:
			switch t {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return ErrInvalid
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return ErrInvalid
					}
					seen[name] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return ErrInvalid
			}
			if _, err := d.Token(); err != nil {
				return ErrInvalid
			}
		}
		return nil
	}
	if walk(0) != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func validEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		first, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if first >= 0xdc00 && first <= 0xdfff {
			return false
		}
		if first < 0xd800 || first > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		second, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || second < 0xdc00 || second > 0xdfff {
			return false
		}
		i += 6
	}
	return !inString
}
