package main

import (
	"github.com/yaphoa/mcpwarden/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOriginValidation(t *testing.T) {
	for _, tc := range []struct {
		origin string
		ok     bool
	}{{"", true}, {"http://localhost:3000", true}, {"http://127.0.0.1:3000", true}, {"https://[::1]", true}, {"https://remote.test", false}, {"null", false}, {"ftp://localhost", false}, {"http://localhost.evil.test", false}} {
		if got := validOrigin(tc.origin, nil); got != tc.ok {
			t.Errorf("%q: got %v", tc.origin, got)
		}
	}
}
func TestBearerAndOrigin(t *testing.T) {
	cfg := config.Config{DownstreamAuth: &config.Auth{}, Token: "test-token"}
	h := protected(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), cfg)
	for _, tc := range []struct {
		token, origin string
		code          int
	}{{"Bearer test-token", "", 204}, {"Bearer wrong", "", 401}, {"", "", 401}, {"Bearer test-token", "https://evil.test", 403}} {
		req := httptest.NewRequest("GET", "http://localhost/mcp", nil)
		req.Header.Set("Authorization", tc.token)
		req.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.code {
			t.Errorf("%q/%q: got %d", tc.token, tc.origin, w.Code)
		}
	}
}
