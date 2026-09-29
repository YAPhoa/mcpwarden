package registry

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

var exposedName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type Entry struct {
	ID         string
	UpstreamID string
	Upstream   string
	Original   string
	Tool       *mcp.Tool
	Healthy    bool
}
type Registry struct {
	mu             sync.RWMutex
	entries        map[string]Entry  // UUID -> entry
	names          map[string]string // MCP name -> UUID
	providerIDs    map[string]string
	ownerNamespace string
}

func New() *Registry { return NewForOwner("local") }
func NewForOwner(owner string) *Registry {
	return &Registry{entries: map[string]Entry{}, names: map[string]string{}, providerIDs: map[string]string{}, ownerNamespace: identity.Derive(identity.Namespace, owner)}
}
func (r *Registry) SetProviderID(name, id string) {
	if !identity.Valid(id) {
		panic("invalid provider UUID")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providerIDs[name] = id
}
func (r *Registry) providerID(name string) string {
	if id := r.providerIDs[name]; id != "" {
		return id
	}
	return identity.Derive(r.ownerNamespace, name)
}
func (r *Registry) ProviderID(name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.providerID(name)
}
func Join(upstream, name string) (string, bool) {
	result := upstream + "__" + name
	return result, exposedName.MatchString(result)
}

// Skipped is a tool Replace left out, by its upstream name.
type Skipped struct {
	Name   string
	Reason string // "name" or "schema"
}

var errInputSchema = errors.New(`input schema must be a JSON object with type "object"`)

// CheckSchemas reports whether the SDK server can register t. mcp.Server.AddTool
// panics on a missing input schema, one that is not a JSON object, one whose
// type is not "object", and an output schema that does not encode as JSON. An
// upstream can list any of these, so every tool is checked before it is saved
// or published.
func CheckSchemas(t *mcp.Tool) error {
	if t == nil || t.InputSchema == nil {
		return errInputSchema
	}
	var input map[string]any
	if raw, err := json.Marshal(t.InputSchema); err != nil || json.Unmarshal(raw, &input) != nil || input == nil || input["type"] != "object" {
		return errInputSchema
	}
	if t.OutputSchema != nil {
		var output any
		if raw, err := json.Marshal(t.OutputSchema); err != nil || json.Unmarshal(raw, &output) != nil || output == nil {
			return errors.New("output schema must encode as JSON")
		}
	}
	return nil
}

func Split(name string) (string, string, bool) {
	u, n, ok := strings.Cut(name, "__")
	return u, n, ok && u != "" && n != ""
}

// Replace sets the tools of an upstream. It leaves out, and returns, tools
// whose exposed name is invalid or that the SDK server could not register.
func (r *Registry) Replace(upstream string, tools []*mcp.Tool, healthy bool) (skipped []Skipped) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !healthy {
		for name, e := range r.entries {
			if e.Upstream == upstream {
				e.Healthy = false
				r.entries[name] = e
			}
		}
		return nil
	}
	for name, e := range r.entries {
		if e.Upstream == upstream {
			delete(r.entries, name)
			delete(r.names, e.Tool.Name)
		}
	}
	for _, t := range tools {
		if t == nil {
			continue
		}
		name, valid := Join(upstream, t.Name)
		if !valid {
			skipped = append(skipped, Skipped{Name: t.Name, Reason: "name"})
			continue
		}
		if CheckSchemas(t) != nil {
			skipped = append(skipped, Skipped{Name: t.Name, Reason: "schema"})
			continue
		}
		copyTool := *t
		copyTool.Name = name
		providerID := r.providerID(upstream)
		id := identity.Derive(providerID, t.Name)
		r.entries[id] = Entry{ID: id, UpstreamID: providerID, Upstream: upstream, Original: t.Name, Tool: &copyTool, Healthy: true}
		r.names[name] = id
	}
	return skipped
}
func (r *Registry) Delete(upstream string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, e := range r.entries {
		if e.Upstream == upstream {
			delete(r.entries, name)
			delete(r.names, e.Tool.Name)
		}
	}
}
func (r *Registry) Lookup(name string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[r.names[name]]
	return e, ok
}
func (r *Registry) All() map[string]Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]Entry, len(r.entries))
	for _, v := range r.entries {
		out[v.Tool.Name] = v
	}
	return out
}
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for k := range r.names {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
