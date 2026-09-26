package secret

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Destination is trusted security metadata, included in the credential AAD and
// lease scope through Digest. Changes require a new epoch and owner approval.
// Private networks must be narrow operator-approved prefixes. HTTP is allowed
// only for an explicitly approved loopback destination (local development).
// There is deliberately no proxy, redirect, wildcard path or arbitrary TLS option.
type Destination struct {
	Schema            string   `json:"schema"`
	Endpoint          string   `json:"endpoint"`
	HeaderNames       []string `json:"header_names"`
	Network           string   `json:"network"`
	PrivatePrefixes   []string `json:"private_prefixes"`
	AllowLoopbackHTTP bool     `json:"allow_loopback_http"`
}

type destination struct {
	profile  Destination
	url      *url.URL
	port     string
	prefixes []netip.Prefix
}

func (p Destination) Digest() (string, error) {
	d, err := p.validate()
	if err != nil {
		return "", ErrInvalid
	}
	b, err := canonical(d.profile)
	if err != nil {
		return "", ErrInvalid
	}
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

func (p Destination) validate() (destination, error) {
	fail := func() (destination, error) { return destination{}, ErrInvalid }
	if p.Schema != "mcpwarden.destination.v1" || len(p.Endpoint) > 2048 || len(p.HeaderNames) < 1 || len(p.HeaderNames) > 32 || len(p.PrivatePrefixes) > 16 {
		return fail()
	}
	u, err := url.Parse(p.Endpoint)
	if err != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || u.RawQuery != "" || u.ForceQuery || u.Host == "" || u.String() != p.Endpoint {
		return fail()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && p.AllowLoopbackHTTP && p.Network == "private") {
		return fail()
	}
	if p.AllowLoopbackHTTP && u.Scheme != "http" {
		return fail()
	}
	host := u.Hostname()
	if host == "" || strings.ToLower(host) != host || strings.HasSuffix(host, ".") || strings.ContainsAny(host, "%\\") {
		return fail()
	}
	if a, e := netip.ParseAddr(host); e == nil {
		if a.String() != host || a.Is4In6() {
			return fail()
		}
	} else {
		if len(host) > 253 {
			return fail()
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return fail()
			}
			for _, c := range label {
				if c != '-' && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
					return fail()
				}
			}
		}
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	} else {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return fail()
		}
	}
	// Exact paths are used, including escaping. No traversal, alternate slash
	// encoding or dot segments can turn this endpoint into another resource.
	if u.Path == "" || !strings.HasPrefix(u.Path, "/") || strings.ContainsAny(u.Path, "\\\x00\r\n") {
		return fail()
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return fail()
		}
	}
	if strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") || strings.Contains(strings.ToLower(u.EscapedPath()), "%5c") {
		return fail()
	}
	p.HeaderNames = slices.Clone(p.HeaderNames)
	p.PrivatePrefixes = slices.Clone(p.PrivatePrefixes)
	if p.PrivatePrefixes == nil {
		p.PrivatePrefixes = []string{}
	}
	slices.Sort(p.HeaderNames)
	slices.Sort(p.PrivatePrefixes)
	for i, name := range p.HeaderNames {
		if name != strings.ToLower(name) || !CredentialHeader(name) || i > 0 && name == p.HeaderNames[i-1] {
			return fail()
		}
	}
	d := destination{profile: p, url: u, port: port}
	switch p.Network {
	case "public":
		if len(p.PrivatePrefixes) != 0 || p.AllowLoopbackHTTP {
			return fail()
		}
	case "private":
		if len(p.PrivatePrefixes) == 0 {
			return fail()
		}
		for i, raw := range p.PrivatePrefixes {
			prefix, e := netip.ParsePrefix(raw)
			if e != nil || prefix.Masked().String() != raw || prefix.Addr().Is4In6() || i > 0 && raw == p.PrivatePrefixes[i-1] || !privatePrefix(prefix) {
				return fail()
			}
			if p.AllowLoopbackHTTP && !prefix.Addr().IsLoopback() {
				return fail()
			}
			d.prefixes = append(d.prefixes, prefix)
		}
	default:
		return fail()
	}
	if a, e := netip.ParseAddr(host); e == nil && !d.permits(a) {
		return fail()
	}
	return d, nil
}

// CredentialHeader reports whether a lowercase header name may carry a vault
// credential. The connector catalog uses it too, so every name a connector
// declares is one the vault destination accepts.
func CredentialHeader(name string) bool {
	if len(name) < 1 || len(name) > 128 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			return false
		}
	}
	switch name {
	case "host", "connection", "proxy-connection", "proxy-authorization", "proxy-authenticate", "content-length", "transfer-encoding", "te", "trailer", "upgrade", "keep-alive", "accept", "accept-encoding", "content-type", "user-agent", "origin", "referer", "cookie", "set-cookie", "forwarded", "authorization-server", "idempotency-key", "x-idempotency-key":
		return false
	}
	return !strings.HasPrefix(name, "mcp-") && !strings.HasPrefix(name, "sec-") && !strings.HasPrefix(name, "x-forwarded-")
}

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("::1/128"),
}

func privatePrefix(p netip.Prefix) bool {
	for _, allowed := range privateRanges {
		if allowed.Contains(p.Addr()) && p.Bits() >= allowed.Bits() {
			return true
		}
	}
	return false
}

// Conservative public egress policy: reject special-use, transition, metadata,
// link-local and documentation ranges even if IsGlobalUnicast accepts them.
var specialRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("168.63.129.16/32"), // Azure platform virtual address.
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("100:0:0:1::/64"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"), netip.MustParsePrefix("fec0::/10"),
}

func (d destination) permits(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return false
	}
	if d.profile.Network == "private" {
		for _, p := range d.prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() {
		return false
	}
	for _, p := range specialRanges {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

type lookupIP func(context.Context, string, string) ([]netip.Addr, error)
type dialIP func(context.Context, string, string) (net.Conn, error)

// dial validates every DNS answer, then dials a checked IP directly. No second
// resolver call can swap the validated address. Tests replace only these private
// seams; production has no arbitrary dialer or insecure TLS configuration.
func (d destination) dial(ctx context.Context, network, address string, lookup lookupIP, dial dialIP) (net.Conn, error) {
	if network != "tcp" || address != net.JoinHostPort(d.url.Hostname(), d.port) {
		return nil, ErrInvalid
	}
	var addresses []netip.Addr
	if a, err := netip.ParseAddr(d.url.Hostname()); err == nil {
		addresses = []netip.Addr{a}
	} else {
		var err error
		addresses, err = lookup(ctx, "ip", d.url.Hostname())
		if err != nil {
			return nil, ErrInvalid
		}
	}
	if len(addresses) == 0 || len(addresses) > 16 {
		return nil, ErrInvalid
	}
	for _, a := range addresses {
		if !d.permits(a) {
			return nil, ErrInvalid
		}
	}
	for _, a := range addresses {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		conn, err := dial(ctx, "tcp", net.JoinHostPort(a.String(), d.port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, ErrInvalid
}

func (d destination) transport(check func(context.Context) error) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	return &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.dial(ctx, network, address, net.DefaultResolver.LookupNetIP, func(ctx context.Context, network, address string) (net.Conn, error) {
				// DNS can block. Recheck the original use after resolution, before
				// opening a socket; a detached SDK context cannot outlive its grant.
				if err := check(ctx); err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, address)
			})
		},
	}
}
