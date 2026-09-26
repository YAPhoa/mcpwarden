package main

import (
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/proxy"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

// guardedCustody installs guarded execution. A credentialed connector is in
// vault custody from creation: the manager never connects it, the gateway never
// holds its credential, and every call needs an owner-activated access window.
// Until its owner stores a vault credential, and after one is deleted, the
// connector stays locked.
type guardedCustody struct {
	api     *securityAPI
	store   catalog.Repository
	history audit.Appender
}

// credential reports the connector's binding. A credentialed connector is
// always required; with no credential or a tombstone, the proxy treats it as
// locked. A no-auth connector is required only if a credential is bound to it,
// which fails closed.
func (g *guardedCustody) credential(owner, connectorID string) (string, bool) {
	if connectorID == "" {
		return "", false
	}
	if h, ok := g.api.index.ConnectorCredential(owner, connectorID); ok {
		if h.Deleted {
			return "", true
		}
		return h.CredentialID, true
	}
	for _, e := range g.store.List(owner) {
		if e.ID == connectorID {
			return "", e.Credentialed()
		}
	}
	return "", false
}

// execution returns the owner's adapter. Calls use the connector's own call
// timeout.
func (g *guardedCustody) execution(m *upstream.Manager) *proxy.LeasedExecution {
	return &proxy.LeasedExecution{
		Service:    g.api.service,
		Credential: g.credential,
		Complete:   g.api.store.Complete,
		Available: func(owner, provider string) bool {
			return !g.store.Visibility(owner, provider).Disabled
		},
		History: g.history,
		Timeout: func(e registry.Entry) time.Duration { return m.Timeout(e.Upstream) },
	}
}
