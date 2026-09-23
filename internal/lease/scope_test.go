package lease

import (
	"strings"
	"testing"

	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

const (
	callerID     = "018fd508-fbbb-4e8c-bbad-6ac1b411ef50"
	browserID    = "018fd508-fbbb-4e8c-bbad-6ac1b411ef51"
	connectorID  = "018fd508-fbbb-4e8c-bbad-6ac1b411ef52"
	credentialID = "018fd508-fbbb-4e8c-bbad-6ac1b411ef53"
	toolID       = "018fd508-fbbb-4e8c-bbad-6ac1b411ef54"
)

func fixtureScope() Scope {
	return Scope{Schema: ScopeSchema, OwnerID: "alice", RequesterAccessID: callerID, ConnectorID: connectorID,
		CredentialID: credentialID, CredentialEpoch: "1", Purpose: "tool_use", DurationSeconds: 900, PolicyRevision: "1",
		ConnectorSecurityRevision: "1", DestinationDigest: digest([]byte("destination")),
		Tools: []ToolScope{{ToolID: toolID, DefinitionDigest: digest([]byte("definition")), Constraints: []Constraint{}}}}
}
func scopeBytes(t testing.TB, s Scope) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestScopeCanonicalBinding(t *testing.T) {
	s := fixtureScope()
	s.Tools[0].Constraints = []Constraint{{Pointer: "/x", Operator: "in", Values: []json.RawMessage{[]byte(`"b"`), []byte(`"a"`)}}, {Pointer: "/y", Operator: "required"}}
	_, first, err := ParseScope(scopeBytes(t, s))
	if err != nil {
		t.Fatal(err)
	}
	s.Tools[0].Constraints[0].Values[0], s.Tools[0].Constraints[0].Values[1] = s.Tools[0].Constraints[0].Values[1], s.Tools[0].Constraints[0].Values[0]
	s.Tools[0].Constraints[0], s.Tools[0].Constraints[1] = s.Tools[0].Constraints[1], s.Tools[0].Constraints[0]
	_, second, err := ParseScope(scopeBytes(t, s))
	if err != nil || first != second {
		t.Fatal("equivalent set/constraint order changed binding")
	}
	s.DurationSeconds++
	_, changed, err := ParseScope(scopeBytes(t, s))
	if err != nil || first == changed {
		t.Fatal("duration not bound")
	}
	// RFC 8785 example: binary64 numbers, control characters and UTF-16 sorting.
	raw := []byte(`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"€$\u000f\nA'B\"\\\"/","literals":[null,true,false]}`)
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\"/"}`
	b, err := canonical(raw, 4096)
	if err != nil || string(b) != want {
		t.Fatalf("JCS mismatch: %s %v", b, err)
	}
	b, err = canonical([]byte(`{"\ue000":1,"😀":2,"a":3}`), 4096)
	if err != nil || string(b) != `{"a":3,"😀":2,"":1}` {
		t.Fatalf("UTF-16 key order: %s %v", b, err)
	}
}

func TestRejectUnsupportedScope(t *testing.T) {
	mutations := []func(*Scope){
		func(s *Scope) { s.CredentialEpoch = "01" }, func(s *Scope) { s.DurationSeconds = 3601 },
		func(s *Scope) { s.Purpose = "wildcard" }, func(s *Scope) { s.Tools = nil },
		func(s *Scope) { s.Tools = append(s.Tools, s.Tools[0]) }, func(s *Scope) { s.Tools[0].DefinitionDigest = "anything" },
		func(s *Scope) { s.Tools[0].Constraints = []Constraint{{Pointer: "/bad~", Operator: "required"}} },
		func(s *Scope) {
			s.Tools[0].Constraints = []Constraint{{Pointer: "/x", Operator: "regex", Value: []byte(`".*"`)}}
		},
	}
	for i, mutate := range mutations {
		s := fixtureScope()
		mutate(&s)
		if _, _, err := ParseScope(scopeBytes(t, s)); err == nil {
			t.Errorf("mutation %d accepted", i)
		}
	}
	for _, value := range []string{`null`, `{}`, `[]`, `1.0`, `1e0`, `9007199254740992`, `-9007199254740992`, `1.00000000000000001`} {
		s := fixtureScope()
		s.Tools[0].Constraints = []Constraint{{Pointer: "/x", Operator: "equals", Value: []byte(value)}}
		if _, _, err := ParseScope(scopeBytes(t, s)); err == nil {
			t.Errorf("unsafe scalar accepted: %s", value)
		}
	}
	raw := string(scopeBytes(t, fixtureScope()))
	for _, modified := range []string{strings.Replace(raw, `"schema":`, `"unknown":1,"schema":`, 1), strings.Replace(raw, `"schema":`, `"schema":"duplicate","schema":`, 1), strings.Replace(raw, `"schema":`, `"Schema":`, 1)} {
		if _, _, err := ParseScope([]byte(modified)); err == nil {
			t.Fatal("unknown/duplicate/case-variant field accepted")
		}
	}
}

func TestResourceConstraints(t *testing.T) {
	s := fixtureScope()
	s.Tools[0].Constraints = []Constraint{{Pointer: "/files/0/id", Operator: "in", Values: []json.RawMessage{[]byte(`"a"`), []byte(`"b"`)}}, {Pointer: "/a~1b/~0flag", Operator: "equals", Value: []byte(`false`)}, {Pointer: "/version", Operator: "equals", Value: []byte(`9007199254740991`)}, {Pointer: "/present", Operator: "required"}}
	s, _, err := ParseScope(scopeBytes(t, s))
	if err != nil {
		t.Fatal(err)
	}
	good := `{"files":[{"id":"b"}],"a/b":{"~flag":false},"version":9007199254740991,"present":null}`
	if !s.Matches(toolID, s.Tools[0].DefinitionDigest, []byte(good)) {
		t.Fatal("matching arguments rejected")
	}
	for _, bad := range []string{strings.Replace(good, `"b"`, `"c"`, 1), strings.Replace(good, `false`, `"false"`, 1), strings.Replace(good, `9007199254740991`, `9007199254740991.1`, 1), strings.Replace(good, `9007199254740991`, `9007199254740992`, 1), strings.Replace(good, `,"present":null`, ``, 1), strings.Replace(good, `"present":null`, `"present":null,"present":true`, 1), `[]`} {
		if s.Matches(toolID, s.Tools[0].DefinitionDigest, []byte(bad)) {
			t.Fatalf("unsafe arguments accepted: %s", bad)
		}
	}
	if s.Matches(toolID, digest([]byte("changed")), []byte(good)) {
		t.Fatal("changed definition accepted")
	}
	if _, ok := valueAt([]any{"a"}, "/00"); ok {
		t.Fatal("noncanonical array index accepted")
	}
}

func FuzzParseScope(f *testing.F) {
	b, _ := json.Marshal(fixtureScope())
	f.Add(b)
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, h, err := ParseScope(raw)
		if err != nil {
			return
		}
		again, h2, err := ParseScope(scopeBytes(t, s))
		if err != nil || h != h2 {
			t.Fatal("unstable normalized scope")
		}
		_ = again.Matches(toolID, digest([]byte("definition")), []byte(`{}`))
	})
}
