package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/catalog/dbcatalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease/sqlite"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

// errStdioStorage refuses --stdio on PostgreSQL: a stdio config would need
// the runtime role and the catalog key.
var errStdioStorage = errors.New("--stdio needs SQLite storage; connect this client over HTTP")

// errStdioLost stops a stdio client whose database file was replaced or
// whose history commit had an unknown outcome.
var errStdioLost = errors.New("storage database changed or failed; the stdio client stopped")

// runStdio serves one downstream client over transport (stdin/stdout) as
// owner local until the client disconnects or the database is lost.
func runStdio(ctx context.Context, cfg config.Config, pol *policy.Policy, logger *slog.Logger, transport mcp.Transport) error {
	ctx, fail := context.WithCancelCause(ctx)
	defer fail(nil)
	g, err := openStdio(ctx, cfg, pol, logger)
	if err != nil {
		return err
	}
	defer g.close()
	go func() {
		select {
		case <-g.client.Lost():
			fail(errStdioLost)
		case <-ctx.Done():
		}
	}()
	err = g.server.Run(ctx, transport)
	if cause := context.Cause(ctx); errors.Is(cause, errStdioLost) {
		return cause
	}
	return err
}

// stdioGateway is a --stdio process: it shares the SQLite database with
// other stdio clients, never with a gateway, serves a read-only catalog
// snapshot taken at start and writes only history. It never runs the
// executor, so credentialed connectors are not served.
type stdioGateway struct {
	client *sqlite.Client
	rs     *runtimes
	server *mcp.Server
}

func openStdio(ctx context.Context, cfg config.Config, pol *policy.Policy, logger *slog.Logger) (*stdioGateway, error) {
	if cfg.Storage.Driver != "sqlite" {
		return nil, errStdioStorage
	}
	client, err := sqlite.OpenClient(ctx, cfg.Storage.Path, sqlite.Options{Warn: func(m string) { logger.Warn(m) }})
	if err != nil {
		return nil, err
	}
	repo, err := dbcatalog.NewSnapshot(ctx, cfg.Storage.Key, client, "local")
	if err != nil {
		client.Close()
		return nil, err
	}
	rs := newRuntimes(ctx, cfg, pol, dbcatalog.NewHistoryWriter(client), repo, logger)
	server := rs.get("local").proxy.Server
	server.AddReceivingMiddleware(stdioActor)
	return &stdioGateway{client: client, rs: rs, server: server}, nil
}

func (g *stdioGateway) close() {
	g.rs.close()
	g.client.Close()
}

// stdioActor records stdio calls with actor type stdio.
func stdioActor(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		return next(identity.WithActor(ctx, identity.Actor{Owner: "local", Kind: "stdio"}), method, req)
	}
}
