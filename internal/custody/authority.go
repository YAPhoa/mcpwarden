package custody

import (
	"sort"
	"sync"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/policy"
	"github.com/yaphoa/mcpwarden/internal/registry"
)

// Until the PostgreSQL catalog (roadmap step 3) keeps real counters, tool policy
// and connector security metadata report a fixed revision. Every admission and
// activation still rechecks the live tool visibility, policy and definition
// digest, so a stale scope fails even though these numbers do not move. File
// connectors are immutable apart from enablement: replacing one gives it a new ID.
const (
	PolicyRevision            = "1"
	ConnectorSecurityRevision = "1"
)

// Authority implements lease.Authority over the file catalog and the committed
// custody index. It performs in-memory reads only and never resolves secrets.
type Authority struct {
	Catalog catalog.Repository
	Policy  *policy.Policy
	Index   *Index

	mu      sync.Mutex
	digests map[digestKey]map[string]lease.Tool
}

type digestKey struct {
	owner, connector string
	updated          time.Time
	count            int
}

func NewAuthority(store catalog.Repository, tools *policy.Policy, index *Index) *Authority {
	return &Authority{Catalog: store, Policy: tools, Index: index, digests: map[digestKey]map[string]lease.Tool{}}
}

// Caller maps an exact access record. Only a local-account browser session is
// interactive; API keys, MCP sessions and OAuth tokens never are.
func (a *Authority) Caller(owner, id string) (lease.Caller, bool) {
	r, ok := a.Catalog.AccessByID(owner, id)
	if !ok || r.Owner != owner || r.ID != id {
		return lease.Caller{}, false
	}
	return lease.Caller{
		Actor:       identity.Actor{Owner: r.Owner, AccessID: r.ID, PublicID: r.PublicID, Label: r.Name, Kind: r.Kind},
		Active:      r.Active(),
		ExpiresAt:   r.ExpiresAt,
		Interactive: r.Kind == "browser",
	}, true
}

// Connector returns the owner's catalog entry for a stable connector ID.
func (a *Authority) Connector(owner, id string) (catalog.Entry, bool) {
	for _, e := range a.Catalog.List(owner) {
		if e.ID == id {
			clear(e.Headers)
			e.Headers = nil
			return e, true
		}
	}
	return catalog.Entry{}, false
}

func (a *Authority) Credential(owner, id string) (lease.Credential, bool) {
	h, ok := a.Index.Credential(owner, id)
	if !ok || h.Deleted {
		return lease.Credential{}, false
	}
	p := a.Index.Policy(owner)
	k := lease.Credential{ID: h.CredentialID, ConnectorID: h.ConnectorID, Epoch: h.Epoch, Revision: h.Revision,
		DestinationDigest: h.DestinationDigest, PolicyRevision: PolicyRevision, ConnectorSecurityRevision: ConnectorSecurityRevision,
		ApprovalPolicyRevision: p.Revision, ApprovalMode: p.Mode, Tools: map[string]lease.Tool{}}
	entry, ok := a.Connector(owner, h.ConnectorID)
	// Header-bundle custody only. OAuth connectors need encrypted grant state.
	if !ok || entry.AuthType == "oauth" || a.Catalog.Visibility(owner, entry.Name).Disabled {
		return k, true
	}
	k.Enabled = true
	for id, t := range a.tools(owner, entry) {
		t.Allowed = a.Policy.Allow(t.name)
		t.Visible = a.Catalog.ToolVisible(owner, entry.Name, t.name)
		k.Tools[id] = t.Tool
	}
	return k, true
}

type namedTool struct {
	lease.Tool
	name string
}

// tools derives the same stable IDs and definition digests as the registry and
// guarded dispatch: UUIDv5(connector, original name) over the namespaced tool.
func (a *Authority) tools(owner string, entry catalog.Entry) map[string]namedTool {
	d, ok := a.Catalog.Discovery(owner, entry.Name)
	if !ok {
		return nil
	}
	key := digestKey{owner, entry.ID, d.UpdatedAt, len(d.Tools)}
	a.mu.Lock()
	cached, hit := a.digests[key]
	a.mu.Unlock()
	if !hit {
		cached = map[string]lease.Tool{}
		for _, t := range d.Tools {
			name, valid := registry.Join(entry.Name, t.Name)
			if !valid {
				continue
			}
			tool := *t
			tool.Name = name
			raw, err := json.Marshal(&tool)
			if err != nil {
				continue
			}
			digest, err := lease.DefinitionDigest(raw)
			if err != nil {
				continue
			}
			id := identity.Derive(entry.ID, t.Name)
			cached[id] = lease.Tool{ID: id, DefinitionDigest: digest}
		}
		a.mu.Lock()
		for k := range a.digests {
			if k.owner == owner && k.connector == entry.ID {
				delete(a.digests, k)
			}
		}
		a.digests[key] = cached
		a.mu.Unlock()
	}
	names := map[string]string{}
	for _, t := range d.Tools {
		if name, valid := registry.Join(entry.Name, t.Name); valid {
			names[identity.Derive(entry.ID, t.Name)] = name
		}
	}
	out := make(map[string]namedTool, len(cached))
	for id, t := range cached {
		out[id] = namedTool{Tool: t, name: names[id]}
	}
	return out
}

// ToolView is the public selection metadata an owner or requester needs to
// build a scope. It carries no schema bodies or credential values.
type ToolView struct {
	ID               string `json:"tool_id"`
	Name             string `json:"name"`
	DefinitionDigest string `json:"definition_sha256"`
}

// SelectableTools lists allowed, visible tools of an enabled credential.
func (a *Authority) SelectableTools(owner, credentialID string) ([]ToolView, bool) {
	h, ok := a.Index.Credential(owner, credentialID)
	if !ok || h.Deleted {
		return nil, false
	}
	entry, ok := a.Connector(owner, h.ConnectorID)
	if !ok || entry.AuthType == "oauth" || a.Catalog.Visibility(owner, entry.Name).Disabled {
		return []ToolView{}, true
	}
	out := []ToolView{}
	for id, t := range a.tools(owner, entry) {
		if a.Policy.Allow(t.name) && a.Catalog.ToolVisible(owner, entry.Name, t.name) {
			out = append(out, ToolView{ID: id, Name: t.name, DefinitionDigest: t.DefinitionDigest})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

// ScopeRequest is the caller-selected part of a scope. The gateway fills every
// binding field (owner, connector, epoch, revisions, destination and definition
// digests) from current authority, so a caller cannot pin stale metadata.
type ScopeRequest struct {
	RequesterAccessID string          `json:"requester_access_id"`
	CredentialID      string          `json:"credential_id"`
	DurationSeconds   int             `json:"duration_seconds"`
	MaxCalls          *int64          `json:"max_calls"`
	Tools             []ToolSelection `json:"tools"`
}
type ToolSelection struct {
	ToolID      string             `json:"tool_id"`
	Constraints []lease.Constraint `json:"constraints"`
}

// BuildScope materializes a finite tool-use scope from current metadata. The
// result is still validated by lease.ParseScope and the lease service.
func (a *Authority) BuildScope(owner string, in ScopeRequest) ([]byte, error) {
	k, ok := a.Credential(owner, in.CredentialID)
	if !ok || !k.Enabled {
		return nil, lease.ErrStale
	}
	if len(in.Tools) == 0 || len(in.Tools) > lease.MaxTools {
		return nil, lease.ErrScope
	}
	s := lease.Scope{Schema: lease.ScopeSchema, OwnerID: owner, RequesterAccessID: in.RequesterAccessID, ConnectorID: k.ConnectorID,
		CredentialID: k.ID, CredentialEpoch: k.Epoch, Purpose: "tool_use", DurationSeconds: in.DurationSeconds,
		PolicyRevision: k.PolicyRevision, ConnectorSecurityRevision: k.ConnectorSecurityRevision,
		DestinationDigest: k.DestinationDigest, MaxCalls: in.MaxCalls}
	for _, selected := range in.Tools {
		t, ok := k.Tools[selected.ToolID]
		if !ok || !t.Allowed || !t.Visible {
			return nil, lease.ErrStale
		}
		constraints := selected.Constraints
		if constraints == nil {
			constraints = []lease.Constraint{}
		}
		s.Tools = append(s.Tools, lease.ToolScope{ToolID: t.ID, DefinitionDigest: t.DefinitionDigest, Constraints: constraints})
	}
	return json.Marshal(s)
}
