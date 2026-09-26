package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/oauth"
	"github.com/yaphoa/mcpwarden/internal/policy"
)

func main() {
	configPath := flag.String("config", "config.yaml", "YAML configuration path")
	stdio := flag.Bool("stdio", false, "serve one downstream client over stdin/stdout")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*configPath, *stdio, logger); err != nil {
		logger.Error("mcpwarden stopped", "error", err)
		os.Exit(1)
	}
}
func run(path string, stdio bool, logger *slog.Logger) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if stdio && cfg.Audit.Path == "-" {
		return fmt.Errorf("audit.path '-' cannot be used with --stdio")
	}
	pol, err := policy.New(cfg.Policy)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, fail := context.WithCancelCause(ctx)
	defer fail(nil)
	var store catalog.Repository
	var history audit.Store
	var pg *pgBackend
	if cfg.Managed != nil && cfg.Managed.Backend == "postgres" {
		if stdio {
			return fmt.Errorf("--stdio cannot use the postgres catalog backend")
		}
		pg, err = openPostgresCatalog(ctx, cfg, pol, logger, fail)
		if err != nil {
			return err
		}
		defer pg.close()
		store, history = pg.repo, pg.history
	} else {
		auditLog, err := audit.Open(cfg.Audit.Path)
		if err != nil {
			return err
		}
		defer auditLog.Close()
		history = auditLog
		if cfg.Managed != nil {
			fileStore, err := catalog.Open(cfg.Managed.Path, cfg.Managed.Key)
			if err != nil {
				return err
			}
			defer fileStore.Close()
			store = fileStore
		}
	}
	// The owner security executor and its custody caches load before any
	// runtime exists, so no connector can start without its guard.
	var security *securityAPI
	var fileAccounts *accountAuth
	if pg != nil {
		security = pg.security
	} else if cfg.Accounts != nil && cfg.OwnerSecurity != nil && !stdio {
		fileAccounts = newAccountAuth(store, cfg)
		security, err = openSecurity(ctx, cfg, store, pol, fileAccounts, logger)
		if err != nil {
			return err
		}
		defer security.close()
		if err := fileAuthority(ctx, security.store); err != nil {
			return err
		}
	}
	rs := newRuntimes(ctx, cfg, pol, history, store, logger)
	defer rs.close()
	// Credentialed connectors run only through access windows. Without the
	// owner vault none can be created, and any stored one never dials.
	if security != nil {
		rs.guarded = &guardedCustody{api: security, store: store, history: history}
	}
	local := rs.get("local")
	if stdio {
		return local.proxy.Server.Run(ctx, &mcp.StdioTransport{})
	}
	mux := http.NewServeMux()
	mcpHandler := rs.access.bindMCP(mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		p := rs.get(requestOwner(r)).proxy
		if a, ok := accessFrom(r.Context()); ok && a.Role == "admin" {
			return p.AdminServer
		}
		return p.Server
	}, &mcp.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute}))
	var apiProtect func(http.Handler) http.Handler
	var clientProtect func(http.Handler) http.Handler
	if cfg.OAuth != nil {
		resource, err := oauth.New(*cfg.OAuth)
		if err != nil {
			return err
		}
		resource.Observe = func(ctx context.Context, token string, info *auth.TokenInfo, req *http.Request) (context.Context, error) {
			role := "client"
			scope := cfg.OAuth.ManageScope
			if scope == "" {
				scope = "mcp:manage"
			}
			for _, s := range info.Scopes {
				if s == scope {
					role = "admin"
				}
			}
			record := catalog.AccessRecord{ID: tokenHash(token), Owner: info.UserID, Kind: "oauth", Role: role, ExpiresAt: info.Expiration}
			if store != nil {
				var err error
				record, err = store.ObserveOAuth(info.UserID, tokenHash(token), role, info.Expiration, req.UserAgent())
				if err != nil {
					return ctx, err
				}
			}
			return withAccess(ctx, record), nil
		}
		mux.Handle("/.well-known/oauth-protected-resource", resource.MetadataHandler())
		mux.Handle("/.well-known/oauth-protected-resource/mcp", resource.MetadataHandler())
		mcpHandler = originOnly(rs.access.keys(mcpHandler, false, resource.Protect(mcpHandler)), cfg.Origins)
		clientProtect = func(h http.Handler) http.Handler {
			return originOnly(rs.access.keys(h, false, resource.Protect(h)), cfg.Origins)
		}
		apiProtect = func(h http.Handler) http.Handler {
			return originOnly(rs.access.keys(h, true, resource.ProtectAPI(h)), cfg.Origins)
		}
	} else if pg != nil {
		// The PostgreSQL catalog coordinates every change with the lease
		// service itself, so the file backend's guards stay unset.
		pg.accounts.onRevoke = rs.access.closeCredential
		pg.security.register(mux)
		accounts := pg.accounts
		mcpHandler = accounts.protect(mcpHandler, false)
		clientProtect = func(h http.Handler) http.Handler { return accounts.protect(h, true, true) }
		apiProtect = func(h http.Handler) http.Handler { return accounts.protect(h, true) }
		mux.Handle("/api/auth/", originOnly(http.HandlerFunc(accounts.authHandler), cfg.Origins))
	} else if cfg.Accounts != nil {
		accounts := fileAccounts
		if accounts == nil {
			accounts = newAccountAuth(store, cfg)
		}
		accounts.onRevoke = rs.access.closeCredential
		if security != nil {
			security.register(mux)
			accounts.guard = security.guardAccess
			rs.access.guard = security.guardAccess
			rs.providerGuard = security.guardAccess
			accounts.sessionGuard = security.service.ChangeSessions
			rs.access.sessionGuard = security.service.ChangeSessions
		}
		mcpHandler = accounts.protect(mcpHandler, false)
		clientProtect = func(h http.Handler) http.Handler { return accounts.protect(h, true, true) }
		apiProtect = func(h http.Handler) http.Handler { return accounts.protect(h, true) }
		mux.Handle("/api/auth/", originOnly(http.HandlerFunc(accounts.authHandler), cfg.Origins))
	} else {
		mcpHandler = originOnly(rs.access.keys(mcpHandler, false, protected(mcpHandler, cfg)), cfg.Origins)
		clientProtect = func(h http.Handler) http.Handler {
			return originOnly(rs.access.keys(h, false, protected(h, cfg)), cfg.Origins)
		}
		apiProtect = func(h http.Handler) http.Handler {
			return originOnly(rs.access.keys(h, true, protected(h, cfg)), cfg.Origins)
		}
	}
	mux.HandleFunc("/api/auth/options", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		mode := "operator"
		if cfg.OAuth != nil {
			mode = "oauth"
		} else if cfg.Accounts != nil {
			mode = "accounts"
		}
		jsonResponse(w, 200, map[string]any{"mode": mode, "registration": cfg.Accounts != nil && cfg.Accounts.AllowRegistration})
	})
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/api/access", apiProtect(http.HandlerFunc(rs.access.handler)))
	mux.Handle("/api/access/", apiProtect(http.HandlerFunc(rs.access.handler)))
	mux.Handle("/api/history", apiProtect(http.HandlerFunc(rs.history)))
	mux.Handle("/api/tools", apiProtect(http.HandlerFunc(rs.tools)))
	mux.Handle("/api/providers", apiProtect(http.HandlerFunc(rs.providers)))
	mux.Handle("/api/providers/", apiProtect(http.HandlerFunc(rs.providerTools)))
	mux.Handle("/api/status", apiProtect(http.HandlerFunc(rs.status)))
	mux.Handle("/api/connections", apiProtect(http.HandlerFunc(rs.connections)))
	mux.Handle("/api/connections/", apiProtect(http.HandlerFunc(rs.connection)))
	mux.Handle("/api/discovery/", clientProtect(http.HandlerFunc(rs.discovery)))
	if testRoutes != nil {
		testRoutes(mux, rs, apiProtect)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		status := http.StatusServiceUnavailable
		if rs.anyReady() {
			status = http.StatusOK
		}
		jsonResponse(w, status, map[string]any{"upstreams": local.manager.States()})
	})
	server := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	logger.Info("listening", "address", listener.Addr().String())
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("shutdown HTTP: %w", err)
		}
		if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
			return cause
		}
		return nil
	}
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func protected(next http.Handler, cfg config.Config) http.Handler {
	return originOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.DownstreamAuth != nil {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			given := sha256.Sum256([]byte(token))
			expected := sha256.Sum256([]byte(cfg.Token))
			if token == r.Header.Get("Authorization") || subtle.ConstantTimeCompare(given[:], expected[:]) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		record := catalog.AccessRecord{ID: "operator:" + tokenHash(cfg.Token), Owner: "local", Kind: "operator", Role: "admin"}
		next.ServeHTTP(w, r.WithContext(withAccess(r.Context(), record)))
	}), cfg.Origins)
}
func originOnly(next http.Handler, allowed []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validOrigin(r.Header.Get("Origin"), allowed) {
			http.Error(w, "origin forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func validOrigin(origin string, allowed []string) bool {
	if origin == "" {
		return true
	}
	for _, v := range allowed {
		if origin == v {
			return true
		}
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}
