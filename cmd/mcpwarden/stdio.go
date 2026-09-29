package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

// runStdio serves one downstream client over stdin/stdout.
func runStdio(ctx context.Context, cfg config.Config, pol *policy.Policy, logger *slog.Logger) error {
	if cfg.Storage.Driver != "sqlite" {
		return errors.New("--stdio needs SQLite storage; connect this client over HTTP")
	}
	return errors.New("--stdio is not implemented yet")
}
