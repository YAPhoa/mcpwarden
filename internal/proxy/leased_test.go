package proxy

import (
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/registry"
)

// A converted connector keeps its own call timeout up to the guarded cap; an
// unset or invalid one falls back to 30 seconds.
func TestLeasedTimeoutClamp(t *testing.T) {
	for given, want := range map[time.Duration]time.Duration{
		0:                30 * time.Second,
		-time.Second:     30 * time.Second,
		10 * time.Second: 10 * time.Second,
		5 * time.Minute:  5 * time.Minute,
		10 * time.Minute: 5 * time.Minute,
	} {
		p := &Proxy{Security: &LeasedExecution{Timeout: func(registry.Entry) time.Duration { return given }}}
		if got := p.leasedTimeout(registry.Entry{}); got != want {
			t.Errorf("timeout %v: got %v, want %v", given, got, want)
		}
	}
	if got := (&Proxy{Security: &LeasedExecution{}}).leasedTimeout(registry.Entry{}); got != 30*time.Second {
		t.Errorf("no timeout func: got %v", got)
	}
}
