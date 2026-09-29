// Package audittest provides an in-memory audit.Store for tests that do not
// need a database.
package audittest

import (
	"fmt"
	"slices"
	"sync"

	"github.com/yaphoa/mcpwarden/internal/audit"
)

// Memory keeps every encoded record. It shows history as the database stores
// do: an admission whose completion is stored is hidden, newest first.
type Memory struct {
	mu      sync.Mutex
	records []audit.Record
}

var _ audit.Store = (*Memory)(nil)

func (m *Memory) Write(r audit.Record) error {
	r, _, err := audit.Encode(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, r)
	return nil
}

// Records returns every stored record in write order.
func (m *Memory) Records() []audit.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

// History returns one owner's visible events, newest first.
func (m *Memory) History(owner string) []audit.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	completed := map[string]bool{}
	for _, r := range m.records {
		if r.Owner == owner && r.EventType == audit.DispatchCompleted {
			completed[r.InvocationID] = true
		}
	}
	var out []audit.Record
	for _, r := range m.records {
		if r.Owner == owner && !(r.EventType == audit.DispatchAdmitted && completed[r.InvocationID]) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b audit.Record) int {
		if c := audit.HistoryTime(b).Compare(audit.HistoryTime(a)); c != 0 {
			return c
		}
		if a.EventID > b.EventID {
			return -1
		}
		if a.EventID < b.EventID {
			return 1
		}
		return 0
	})
	return out
}

// QueryHistoryPerformance pages History for q.Owner. Other filters and
// timing summaries are left to the database stores.
func (m *Memory) QueryHistoryPerformance(q audit.HistoryFilter) ([]audit.Record, int, []audit.ToolRef, audit.Performance, error) {
	if q.Page < 1 || q.Size < 1 {
		return nil, 0, nil, audit.Performance{}, fmt.Errorf("invalid pagination")
	}
	all := m.History(q.Owner)
	start := min((q.Page-1)*q.Size, len(all))
	end := min(start+q.Size, len(all))
	return all[start:end], len(all), []audit.ToolRef{}, audit.Performance{}, nil
}
