package registry

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"strings"
	"sync"
	"testing"
)

func TestNames(t *testing.T) {
	if name, ok := Join("fs", "read_file"); !ok || name != "fs__read_file" {
		t.Fatal(name, ok)
	}
	if _, ok := Join("fs", strings.Repeat("x", 63)); ok {
		t.Fatal("accepted long name")
	}
	if _, ok := Join("fs", "bad.name"); ok {
		t.Fatal("accepted bad name")
	}
	u, n, ok := Split("fs__a__b")
	if !ok || u != "fs" || n != "a__b" {
		t.Fatal(u, n, ok)
	}
}
func TestConcurrentReplaceAndRead(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if i%2 == 0 {
					r.Replace("fs", []*mcp.Tool{{Name: "echo"}}, true)
				} else {
					r.Lookup("fs__echo")
					r.All()
					r.Names()
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestStableToolIdentity(t *testing.T) {
	r := NewForOwner("alice")
	r.SetProviderID("drive", "d364c149-6fcb-4e3f-9f90-3d72ca3a6d21")
	tools := []*mcp.Tool{{Name: "get__info"}}
	r.Replace("drive", tools, true)
	first, _ := r.Lookup("drive__get__info")
	r.Replace("drive", nil, false)
	r.Replace("drive", tools, true)
	after, _ := r.Lookup("drive__get__info")
	if first.ID == "" || first.ID != after.ID || first.Original != "get__info" || first.Tool.Name != "drive__get__info" {
		t.Fatal("identity or wire name changed")
	}
	restored := NewForOwner("alice")
	restored.SetProviderID("renamed", first.UpstreamID)
	restored.Replace("renamed", tools, true)
	renamed, _ := restored.Lookup("renamed__get__info")
	if renamed.ID != first.ID {
		t.Fatal("connector label affected stable ID")
	}
	for _, owner := range []string{"alice", "bob"} {
		other := NewForOwner(owner)
		other.Replace("other", tools, true)
		entry, _ := other.Lookup("other__get__info")
		if entry.ID == first.ID {
			t.Fatal("tool IDs collide")
		}
	}
	a, b := NewForOwner("alice"), NewForOwner("bob")
	if a.ProviderID("shared") == b.ProviderID("shared") {
		t.Fatal("shared provider IDs cross users")
	}
}
