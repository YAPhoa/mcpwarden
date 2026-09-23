package upstream

import (
	"context"
	"errors"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/secret"
)

var ErrLeasedUpstream = errors.New("authorized upstream operation failed")

// LeasedCall owns a per-call SDK session. The conservative first adapter opens
// it only inside authorized maintenance, verifies the selected public definition,
// and closes it after the call. It has no background reconnect, refresh, OAuth,
// subscription or keepalive path. A later pool must preserve these same gates.
type LeasedCall struct {
	service                           *lease.Service
	session                           *mcp.ClientSession
	material                          *secret.Handle
	credentialID, leaseID, definition string
	entry                             registry.Entry
	args                              json.RawMessage
}

func PrepareLeased(ctx context.Context, service *lease.Service, credentialID string, entry registry.Entry, args []byte) (*LeasedCall, error) {
	if service == nil || entry.Tool == nil {
		return nil, lease.ErrLocked
	}
	raw, err := json.Marshal(entry.Tool)
	if err != nil {
		return nil, lease.ErrStale
	}
	definition, err := lease.DefinitionDigest(raw)
	if err != nil {
		return nil, lease.ErrStale
	}
	p := &LeasedCall{service: service, credentialID: credentialID, definition: definition, entry: entry, args: append(json.RawMessage(nil), args...)}
	setupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p.leaseID, err = service.Prepare(setupCtx, credentialID, entry.ID, definition, p.args, func(ctx context.Context, material lease.Material) error {
		handle, ok := material.(*secret.Handle)
		if !ok {
			return lease.ErrKey
		}
		p.material = handle
		client := mcp.NewClient(&mcp.Implementation{Name: "mcpwarden", Version: "0.1.0"}, nil)
		var err error
		p.session, err = client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: handle.Endpoint(), HTTPClient: handle.Client(entry.Original), MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			return ErrLeasedUpstream
		}
		cursor := ""
		seen := map[string]bool{}
		count, matches := 0, 0
		for page := 0; page < 16; page++ {
			res, err := p.session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
			if err != nil {
				return ErrLeasedUpstream
			}
			count += len(res.Tools)
			if count > lease.MaxTools {
				return ErrLeasedUpstream
			}
			for _, tool := range res.Tools {
				if tool.Name != entry.Original {
					continue
				}
				matches++
				copy := *tool
				copy.Name = entry.Tool.Name
				raw, err := json.Marshal(&copy)
				if err != nil {
					return lease.ErrStale
				}
				digest, err := lease.DefinitionDigest(raw)
				if err != nil || digest != definition || matches > 1 {
					return lease.ErrStale
				}
			}
			if res.NextCursor == "" {
				if matches == 1 {
					return nil
				}
				return lease.ErrStale
			}
			if seen[res.NextCursor] {
				return ErrLeasedUpstream
			}
			seen[res.NextCursor] = true
			cursor = res.NextCursor
		}
		return ErrLeasedUpstream
	})
	if err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

func (p *LeasedCall) Admit(ctx context.Context, record audit.Record) (*lease.Admission, error) {
	return p.service.AdmitPrepared(ctx, p.credentialID, p.entry.ID, p.definition, p.args, record, p.leaseID)
}

func (p *LeasedCall) Call(ctx context.Context, material lease.Material) (*mcp.CallToolResult, error) {
	if material != p.material || p.session == nil {
		return nil, lease.ErrDenied
	}
	result, err := p.session.CallTool(ctx, &mcp.CallToolParams{Name: p.entry.Original, Arguments: p.args})
	if err != nil {
		return nil, ErrLeasedUpstream
	}
	return result, nil
}

func (p *LeasedCall) Close() {
	if p != nil && p.session != nil {
		_ = p.session.Close()
	}
	if p != nil {
		clear(p.args)
	}
}
