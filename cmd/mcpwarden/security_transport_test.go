package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

type bodyReadHook struct {
	io.Reader
	before func()
}

func (r *bodyReadHook) Read(p []byte) (int, error) {
	if r.before != nil {
		fn := r.before
		r.before = nil
		fn()
	}
	return r.Reader.Read(p)
}

func (f *ownerFixture) csrfToken() string {
	var out struct {
		Token string `json:"token"`
	}
	f.expect(req{path: "/api/security/csrf", user: "alice"}, 200, &out)
	return out.Token
}

func TestOwnerTransportTrust(t *testing.T) {
	for _, tt := range []struct {
		name, peer, host          string
		tls, development, trusted bool
		proto                     []string
		forwarded                 string
		want                      bool
	}{
		{name: "direct TLS", peer: "198.51.100.23:443", host: "panel.example.test", tls: true, want: true},
		{name: "external HTTP", peer: "198.51.100.23:80", host: "panel.example.test"},
		{name: "forged scheme", peer: "198.51.100.23:80", host: "panel.example.test", proto: []string{"https"}},
		{name: "forged standard forwarding", peer: "198.51.100.23:80", host: "panel.example.test", forwarded: "proto=https"},
		{name: "trusted TLS terminator", peer: "192.0.2.8:5000", host: "panel.example.test", trusted: true, proto: []string{"https"}, want: true},
		{name: "trusted IPv6 terminator", peer: "[2001:db8::8]:5000", host: "panel.example.test", trusted: true, proto: []string{"https"}, want: true},
		{name: "proxy missing scheme", peer: "192.0.2.8:5000", host: "panel.example.test", trusted: true},
		{name: "proxy insecure scheme", peer: "192.0.2.8:5000", host: "panel.example.test", trusted: true, proto: []string{"http"}},
		{name: "proxy duplicate scheme", peer: "192.0.2.8:5000", host: "panel.example.test", trusted: true, proto: []string{"http", "https"}},
		{name: "proxy appended scheme", peer: "192.0.2.8:5000", host: "panel.example.test", trusted: true, proto: []string{"https, http"}},
		{name: "loopback default denied", peer: "127.0.0.1:5000", host: "localhost:8787"},
		{name: "direct development", peer: "127.0.0.1:5000", host: "localhost:8787", development: true, want: true},
		{name: "IPv6 development", peer: "[::1]:5000", host: "[::1]:8787", development: true, want: true},
		{name: "non-loopback development peer", peer: "198.51.100.23:5000", host: "localhost:8787", development: true},
		{name: "non-loopback development host", peer: "127.0.0.1:5000", host: "panel.example.test", development: true},
		{name: "development forwarded claim", peer: "127.0.0.1:5000", host: "localhost:8787", development: true, proto: []string{"https"}},
		{name: "development standard forwarding", peer: "127.0.0.1:5000", host: "localhost:8787", development: true, forwarded: "proto=https"},
		{name: "loopback proxy cannot use development exception", peer: "127.0.0.1:5000", host: "localhost:8787", trusted: true, development: true, proto: []string{"http"}},
		{name: "invalid peer", peer: "not-an-address", host: "localhost:8787", development: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &securityAPI{allowInsecureLoopback: tt.development}
			if tt.trusted {
				api.trustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.8/32"), netip.MustParsePrefix("2001:db8::8/128"), netip.MustParsePrefix("127.0.0.1/32")}
			}
			r := httptest.NewRequest("POST", "http://"+tt.host+"/api/vault/setup", nil)
			r.RemoteAddr = tt.peer
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for _, value := range tt.proto {
				r.Header.Add("X-Forwarded-Proto", value)
			}
			r.Header.Set("Forwarded", tt.forwarded)
			if tt.forwarded == "" {
				r.Header.Del("Forwarded")
			}
			w := httptest.NewRecorder()
			if got := api.secureTransport(w, r); got != tt.want {
				t.Fatalf("transport accepted = %v, want %v", got, tt.want)
			}
			if !tt.want && w.Code != http.StatusForbidden {
				t.Fatalf("insecure transport status = %d", w.Code)
			}
		})
	}
}

func TestOwnerRejectsInsecureExternalActivation(t *testing.T) {
	f := newOwnerFixture(t)
	_, record := f.provision("none")
	pending := f.requestAccess("agent", record.CredentialID)
	owner := f.ownerRequest(pending.ID)
	body := f.activation(owner, f.cek)
	read := false
	r := httptest.NewRequest("POST", "http://gateway.example.test/api/approvals/"+pending.ID+"/activate", &bodyReadHook{Reader: strings.NewReader(body), before: func() { read = true }})
	r.RemoteAddr = "198.51.100.23:41000"
	r.Header.Set("Origin", panelOrigin)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", f.csrfToken())
	r.Header.Set("Idempotency-Key", identity.New())
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookies["alice"]})
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	active := f.count("SELECT count(*) FROM leases WHERE request_id=$1 AND state='active'", pending.ID)
	if w.Code != http.StatusForbidden || read || active != 0 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("insecure activation: status=%d, body read=%v, active leases=%d", w.Code, read, active)
	}
	// The same valid activation can be submitted through the configured TLS
	// terminator, which overwrites X-Forwarded-Proto from its own TLS state.
	f.api.trustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.8/32")}
	r = httptest.NewRequest("POST", "http://gateway.internal/api/approvals/"+pending.ID+"/activate", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.8:41000"
	r.Header.Set("Origin", panelOrigin)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", f.csrfToken())
	r.Header.Set("Idempotency-Key", identity.New())
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookies["alice"]})
	w = httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("trusted HTTPS activation failed: %d", w.Code)
	}
}
