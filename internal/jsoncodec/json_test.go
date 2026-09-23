package jsoncodec

import (
	"bytes"
	stdjson "encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bytedance/sonic"
)

func TestStrictBoundary(t *testing.T) {
	valid := []string{`{}`, `{"x":"\\ud800"}`, `{"x":"\ud83d\ude00"}`, `{"x":"a\\\"b","a":[true,false,null,1]}`, `{"a":{"x":1},"b":{"x":2}}`}
	for _, raw := range valid {
		if err := Validate([]byte(raw), 1024, 8); err != nil {
			t.Errorf("valid document rejected: %q", raw)
		}
	}
	invalid := []string{`{"x":1,"x":2}`, `{"x":1,"\u0078":2}`, `{"a":[{"x":1,"x":2}]}`, `{"x":"\ud800"}`, `{"x":"\ud800\ud800"}`, `{"x":"\udc00"}`, `{"x":"\ud800\u0041"}`, `{"x":"\u00xz"}`, `{} {}`, `{"x":1e999}`, `{"x":NaN}`, `{"x":}`, `{"x":1,}`, `{"x":[1}}`, "{\"x\":\"\xff\"}"}
	for _, raw := range invalid {
		if err := Validate([]byte(raw), 1024, 8); err != ErrInvalid {
			t.Errorf("invalid document accepted: %q: %v", raw, err)
		}
	}
	if Validate([]byte(`{"x":[[[]]]}`), 1024, 2) == nil || Validate([]byte(`{"x":1}`), 4, 8) == nil {
		t.Fatal("limits ignored")
	}
	var value struct {
		Name string `json:"name"`
	}
	for _, raw := range []string{`{"unknown":1}`, `{"Name":"case variant"}`} {
		if UnmarshalStrict([]byte(raw), &value) == nil {
			t.Fatal("strict decoder accepted unknown/case-variant field")
		}
	}
}

func TestSonicCompatibility(t *testing.T) {
	if runtime.GOARCH == "amd64" && sonic.APIKind != sonic.UseSonicJSON {
		t.Fatal("Sonic unexpectedly fell back to encoding/json on amd64")
	}
	raw := []byte(`{"label":"copied string","number":9007199254740991}`)
	var decoded map[string]any
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	clear(raw)
	if decoded["label"] != "copied string" || decoded["number"] != Number("9007199254740991") {
		t.Fatal("number precision or string ownership lost")
	}
	value := struct {
		Label string         `json:"label"`
		At    time.Time      `json:"at,omitzero"`
		Map   map[string]int `json:"map"`
	}{Label: "<safe>&", Map: map[string]int{"z": 2, "a": 1}}
	got, err := Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := stdjson.Marshal(value)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire compatibility: got %s, want %s", got, want)
	}
}

func BenchmarkMetadataCodec(b *testing.B) {
	type tool struct {
		ID          string         `json:"id"`
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Schema      map[string]any `json:"inputSchema"`
	}
	value := make([]tool, 32)
	for i := range value {
		value[i] = tool{"018fd508-fbbb-4e8c-bbad-6ac1b411ef50", "files.search", strings.Repeat("Search documents. ", 8), map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}, "required": []string{"query"}}}
	}
	raw, _ := Marshal(value)
	b.Run("sonic/marshal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := Marshal(value); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("stdlib/marshal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := stdjson.Marshal(value); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("sonic/unmarshal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var v []tool
			if err := Unmarshal(raw, &v); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("stdlib/unmarshal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var v []tool
			if err := stdjson.Unmarshal(raw, &v); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("strict-validation", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := Validate(raw, 1<<20, 64); err != nil {
				b.Fatal(err)
			}
		}
	})
}
