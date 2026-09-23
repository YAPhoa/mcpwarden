package secret

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func publicDestination() Destination {
	return Destination{Schema: "mcpwarden.destination.v1", Endpoint: "https://example.com/mcp", HeaderNames: []string{"authorization"}, Network: "public"}
}

func TestDestinationProfileAndDigest(t *testing.T) {
	p := publicDestination()
	first, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	p.HeaderNames = []string{"x-api-key", "authorization"}
	second, err := p.Digest()
	if err != nil || first == second {
		t.Fatal("header authority not bound")
	}
	p.HeaderNames[0], p.HeaderNames[1] = p.HeaderNames[1], p.HeaderNames[0]
	third, err := p.Digest()
	if err != nil || second != third {
		t.Fatal("equivalent profile ordering changed digest")
	}
	p.Endpoint += "/other"
	if fourth, _ := p.Digest(); third == fourth {
		t.Fatal("endpoint not bound")
	}
	for _, endpoint := range []string{
		"http://example.com/mcp", "https://user:pass@example.com/mcp", "https://example.com/mcp?token=PRIVATE_TEST",
		"https://example.com/mcp?", "https://example.com/mcp#fragment", "https://EXAMPLE.com/mcp", "https://example.com./mcp",
		"https://example.com", "https://example.com/a/../mcp", "https://example.com/a/%2e%2e/mcp", "https://example.com/mcp%2fother",
		"https://example.com:0443/mcp", "https://example.com:0/mcp", "https://127.0.0.1/mcp", "https://[::ffff:127.0.0.1]/mcp",
		"https://[fe80::1%25eth0]/mcp", "https://169.254.169.254/mcp", "https://10.0.0.1/mcp", "https://例子.test/mcp",
	} {
		p := publicDestination()
		p.Endpoint = endpoint
		if _, err := p.Digest(); err != ErrInvalid {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	for _, header := range []string{"Host", "host", "connection", "proxy-authorization", "content-length", "mcp-session-id", "sec-fetch-site", "x-forwarded-host", "idempotency-key", "authorization\r\nX-Fake", "cookie"} {
		p := publicDestination()
		p.HeaderNames = []string{header}
		if _, err := p.Digest(); err != ErrInvalid {
			t.Fatalf("unsafe header %q accepted", header)
		}
	}
}

func TestDestinationIPPolicy(t *testing.T) {
	d, err := publicDestination().validate()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"0.0.0.0", "127.1.2.3", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254", "168.63.129.16", "100.100.100.200", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:8.8.8.8", "fe80::1", "fc00::1", "ff02::1", "64:ff9b::7f00:1", "2001:db8::1", "2002:7f00:1::", "2001::1", "3fff::1", "100:0:0:1::1", "5f00::1", "fec0::1"} {
		if d.permits(netip.MustParseAddr(raw)) {
			t.Fatalf("special address %s accepted", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !d.permits(netip.MustParseAddr(raw)) {
			t.Fatalf("public address %s blocked", raw)
		}
	}
	p := publicDestination()
	p.Network = "private"
	p.PrivatePrefixes = []string{"10.2.3.0/24"}
	d, err = p.validate()
	if err != nil || !d.permits(netip.MustParseAddr("10.2.3.4")) || d.permits(netip.MustParseAddr("10.2.4.4")) || d.permits(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("private policy did not stay within approved prefix")
	}
	for _, prefix := range []string{"0.0.0.0/0", "169.254.0.0/16", "10.0.0.1/8", "::/0", "::ffff:127.0.0.1/128"} {
		p.PrivatePrefixes = []string{prefix}
		if _, err := p.validate(); err != ErrInvalid {
			t.Fatal("unsafe private prefix accepted")
		}
	}
	p = publicDestination()
	p.Endpoint = "http://127.0.0.1:12345/mcp"
	p.Network = "private"
	p.PrivatePrefixes = []string{"127.0.0.1/32"}
	p.AllowLoopbackHTTP = true
	if _, err := p.validate(); err != nil {
		t.Fatal("explicit local fixture rejected")
	}
	p.PrivatePrefixes = []string{"10.0.0.0/8"}
	p.Endpoint = "http://10.0.0.1/mcp"
	if _, err := p.validate(); err != ErrInvalid {
		t.Fatal("plaintext remote credential destination accepted")
	}
}

func TestDialChecksAllAnswersAndPinsCheckedIP(t *testing.T) {
	d, _ := publicDestination().validate()
	lookups, dials := 0, 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		dials++
		if network != "tcp" || address != "1.1.1.1:443" {
			t.Fatal("dial repeated DNS or changed approved address")
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	c, err := d.dial(t.Context(), "tcp", "example.com:443", lookup, dial)
	if err != nil || lookups != 1 || dials != 1 {
		t.Fatal("approved IP not dialed directly")
	}
	_ = c.Close()
	for _, addresses := range [][]netip.Addr{
		{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("::ffff:1.1.1.1")}, {netip.MustParseAddr("169.254.169.254")}, nil,
	} {
		dials = 0
		lookup := func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil }
		if _, err := d.dial(t.Context(), "tcp", "example.com:443", lookup, dial); err != ErrInvalid || dials != 0 {
			t.Fatal("DNS rebinding/mixed answer dialed")
		}
	}
	dials = 0
	if _, err := d.dial(t.Context(), "tcp", "attacker.example:443", lookup, dial); err != ErrInvalid || dials != 0 {
		t.Fatal("changed host dialed")
	}
	lookupFail := func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("PRIVATE_TEST_DNS_ERROR")
	}
	if _, err := d.dial(t.Context(), "tcp", "example.com:443", lookupFail, dial); err != ErrInvalid {
		t.Fatal("unsafe DNS error escaped")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportWithoutLiveAdmissionCannotUseCredentials(t *testing.T) {
	d, _ := publicDestination().validate()
	h := &Handle{destination: d, headers: []privateHeader{{name: "Authorization", value: []byte("Bearer PRIVATE_TEST")}}}
	defer h.Destroy()
	rt := &credentialTransport{handle: h, tool: "read", base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unleased HTTP request forwarded")
		return nil, nil
	})}
	r, _ := http.NewRequestWithContext(t.Context(), "POST", d.profile.Endpoint, strings.NewReader(`{"method":"tools/call","params":{"name":"read","arguments":{}}}`))
	if _, err := rt.RoundTrip(r); err == nil {
		t.Fatal("transport accepted an ordinary context")
	}
	client := h.Client("read")
	if client.CheckRedirect(r, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects enabled")
	}
	transport := client.Transport.(*credentialTransport).base.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig != nil || !transport.DisableKeepAlives {
		t.Fatal("transport has uncontrolled proxy/TLS/replay behavior")
	}
}
