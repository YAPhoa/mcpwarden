package audit

import (
	"encoding/json"
	"testing"
)

func TestHashArgsCanonical(t *testing.T) {
	a := HashArgs(json.RawMessage(`{"b":2,"a":{"z":1,"c":3}}`))
	b := HashArgs(json.RawMessage(`{ "a": {"c":3,"z":1}, "b":2 }`))
	if a != b {
		t.Fatal("argument hash depends on JSON key order")
	}
}

// The stored argument hash bytes never change: history compares them across
// releases.
func TestHashArgsPinned(t *testing.T) {
	for args, want := range map[string]string{
		`{"b":2,"a":{"z":1,"c":3},"u":"é<&>","n":9007199254740993}`: "9acf574a78458d9e33431d29cb79b7393cf73c916b8d39f8f1d99849c0ea0549",
	} {
		if got := HashArgs(json.RawMessage(args)); got != want {
			t.Fatalf("HashArgs(%s) = %s", args, got)
		}
	}
	if got := HashArgs(map[string]any{"q": "x"}); got != "a69fbbcf7209c6f659a75067c9fa03037c2ae23f55a6f854d5994209129bbbf6" {
		t.Fatalf("HashArgs(map) = %s", got)
	}
}

// Only schema 2 invocation events are stored.
func TestEncodeRequiresInvocationEvent(t *testing.T) {
	r := invocationFixture("alice", "key-a").Admission()
	if _, raw, err := Encode(r); err != nil || len(raw) == 0 {
		t.Fatalf("admission refused: %v", err)
	}
	for _, version := range []int{0, 1, 3} {
		bad := r
		bad.SchemaVersion = version
		if _, _, err := Encode(bad); err == nil {
			t.Fatalf("schema %d accepted", version)
		}
	}
	bad := r
	bad.EventType = ""
	if _, _, err := Encode(bad); err == nil {
		t.Fatal("event without a type accepted")
	}
}
