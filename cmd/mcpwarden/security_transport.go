package main

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// secureTransport runs before authentication or body parsing. Origin and
// client-supplied forwarding headers cannot establish transport confidentiality.
func (api *securityAPI) secureTransport(w http.ResponseWriter, r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	peer, parseErr := netip.ParseAddr(host)
	if err == nil && parseErr == nil {
		peer = peer.Unmap()
		for _, network := range api.trustedProxies {
			if network.Contains(peer) {
				// The configured proxy must overwrite this header, never append
				// to a client-provided value. Reject missing or ambiguous values.
				values := r.Header.Values("X-Forwarded-Proto")
				if len(values) == 1 && values[0] == "https" {
					return true
				}
				return insecureTransport(w)
			}
		}
		// Development HTTP must be an explicitly enabled direct loopback
		// request, with no claimed proxy hop. A loopback Origin alone is not
		// enough, and the exception never permits HTTP from a trusted proxy.
		if api.allowInsecureLoopback && peer.IsLoopback() && loopbackHost(r.Host) &&
			len(r.Header.Values("X-Forwarded-Proto")) == 0 && len(r.Header.Values("Forwarded")) == 0 {
			return true
		}
	}
	return insecureTransport(w)
}

func insecureTransport(w http.ResponseWriter) bool {
	securityFailure(w, http.StatusForbidden, "secure_transport_required", "HTTPS is required for the owner security API.")
	return false
}

func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}
