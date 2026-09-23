package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"net/http"
	"net/url"
)

func flowCookie(state string) string {
	h := sha256.Sum256([]byte(state))
	return fmt.Sprintf("mw_oauth_%x", h[:12])
}
func (rs *runtimes) startUpstreamOAuth(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	if rs.store == nil {
		http.Error(w, "managed connections are not configured", 501)
		return
	}
	// The browser supplies Origin on this POST. Never derive callback hosts from
	// untrusted forwarded headers, and never accept an arbitrary redirect URL.
	origin := r.Header.Get("Origin")
	if origin == "" || !validOrigin(origin, rs.cfg.Origins) {
		http.Error(w, "valid browser origin required", 400)
		return
	}
	var entry *catalog.Entry
	for _, e := range rs.store.List(requestOwner(r)) {
		if e.Name == name {
			entry = &e
			break
		}
	}
	if entry == nil || entry.AuthType != "oauth" {
		http.Error(w, "OAuth connection not found", 404)
		return
	}
	started, err := rs.upstreamAuth.Start(rs.ctx, *entry, origin+"/api/upstream-oauth/callback")
	if err != nil {
		jsonResponse(w, 400, map[string]string{"error": err.Error()})
		return
	}
	u, _ := url.Parse(origin)
	http.SetCookie(w, &http.Cookie{Name: flowCookie(started.State), Value: started.Binding, Path: "/api/upstream-oauth/callback", HttpOnly: true, Secure: u.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: 300})
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, 200, map[string]string{"authorization_url": started.URL})
}
func (rs *runtimes) upstreamOAuthCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	cookie, err := r.Cookie(flowCookie(state))
	if err != nil {
		http.Error(w, "OAuth session missing or expired. Start again from the connector page.", 400)
		return
	}
	owner, name, err := rs.upstreamAuth.Complete(r.Context(), state, cookie.Value, q.Get("code"), q.Get("iss"), q.Get("error"))
	http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", Path: "/api/upstream-oauth/callback", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if err != nil {
		http.Error(w, "Authorization did not complete. Close this window and try connecting again.", 400)
		return
	}
	rs.mu.Lock()
	rt := rs.getLocked(owner)
	for _, entry := range rs.store.List(owner) {
		if entry.Name != name {
			continue
		}
		if err = rt.manager.Remove(name); err == nil {
			rt.proxy.Changed(name, nil, false)
			err = rt.manager.Add(rs.upstreamConfig(entry))
		}
		break
	}
	rs.mu.Unlock()
	if err != nil {
		http.Error(w, "Account authorized, but the connection could not restart. Reload the connector page.", 503)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Account connected</title><h1>Account connected</h1><p>You can close this window and reload the connector inventory.</p></html>")
}
