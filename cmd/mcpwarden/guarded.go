package main

import (
	"time"

	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/proxy"
	"github.com/yaphoa/mcpwarden/internal/registry"
	"github.com/yaphoa/mcpwarden/internal/upstream"
)

// guardedCustody installs guarded execution (custody_mode client_release). A
// connector is converted once its owner stores a vault credential for it. From
// then on the legacy manager never connects it, its server-held headers are
// never read for it, and every call needs an owner-activated access window. A
// deleted vault credential leaves a tombstone that keeps the connector locked;
// it never falls back to legacy execution.
type guardedCustody struct {
	api     *securityAPI
	store   catalog.Repository
	history audit.Appender
}

// credential reports the connector's binding. A tombstone stays required with
// no credential, which the proxy treats as locked.
func (g *guardedCustody) credential(owner, connectorID string) (string, bool) {
	if connectorID == "" {
		return "", false
	}
	h, ok := g.api.index.ConnectorCredential(owner, connectorID)
	if !ok {
		return "", false
	}
	if h.Deleted {
		return "", true
	}
	return h.CredentialID, true
}

func (g *guardedCustody) bound(owner, connectorID string) bool {
	_, required := g.credential(owner, connectorID)
	return required
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

// converted stops the legacy session of a connector whose vault credential was
// just committed. Routing already switched when the custody index published;
// this closes the connection that still holds server-held headers.
func (rs *runtimes) converted(owner, connectorID string) {
	if rs.guarded == nil || !rs.guarded.bound(owner, connectorID) {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rt := rs.users[owner]
	if rt == nil {
		return // The runtime is built guarded on first use.
	}
	for _, e := range rs.store.List(owner) {
		clear(e.Headers)
		if e.ID == connectorID {
			if err := rt.manager.SetGuarded(e.Name); err != nil {
				rs.logger.Error("could not stop legacy connection", "upstream", e.Name, "error", err)
			}
			return
		}
	}
}
