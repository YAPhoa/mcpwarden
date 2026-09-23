package policy

import (
	"github.com/yaphoa/mcpwarden/internal/config"
	"testing"
)

func TestFirstMatch(t *testing.T) {
	p, err := New(config.Policy{Default: "deny", Rules: []config.Rule{{Match: "fs__read_*", Action: "allow"}, {Match: "fs__*", Action: "deny"}, {Match: "remote__*", Action: "allow"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		allow bool
	}{{"fs__read_file", true}, {"fs__write_file", false}, {"remote__search", true}, {"other__tool", false}} {
		if got := p.Allow(tc.name); got != tc.allow {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}
func TestInvalidPattern(t *testing.T) {
	if _, err := New(config.Policy{Rules: []config.Rule{{Match: "[", Action: "allow"}}}); err == nil {
		t.Fatal("accepted invalid glob")
	}
}
