package identity

import "testing"

func TestUUIDs(t *testing.T) {
	a, b := New(), New()
	if !Valid(a) || !Valid(b) || a == b || a[14] != '4' {
		t.Fatal("invalid random IDs")
	}
	if got := Derive("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "www.widgets.com"); got != "21f7f8de-8051-5b89-8680-0195ef798b6a" {
		t.Fatal(got)
	}
	if Valid("not-a-uuid") {
		t.Fatal("accepted invalid UUID")
	}
}
