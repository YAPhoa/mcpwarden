package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"gopkg.in/yaml.v3"
)

type Accounts struct {
	AllowRegistration bool `yaml:"allow_registration"`
}

type Config struct {
	Accounts       *Accounts      `yaml:"accounts"`
	Listen         string         `yaml:"listen"`
	DownstreamAuth *Auth          `yaml:"downstream_auth"`
	OAuth          *OAuth         `yaml:"oauth"`
	Origins        []string       `yaml:"allowed_origins"`
	Upstreams      []Upstream     `yaml:"upstreams"`
	Policy         Policy         `yaml:"policy"`
	Audit          Audit          `yaml:"audit"`
	Managed        *Managed       `yaml:"managed_upstreams"`
	OwnerSecurity  *OwnerSecurity `yaml:"owner_security"`
	Token          string         `yaml:"-"`
}

// OwnerSecurity enables the owner vault, access-request and lease routes backed
// by PostgreSQL. It does not change credential custody or tool execution: the
// guarded execution path is installed separately (roadmap step 4).
type OwnerSecurity struct {
	DatabaseURLEnv        string   `yaml:"database_url_env"`
	DatabaseURL           string   `yaml:"-"`
	TrustedProxies        []string `yaml:"trusted_proxies"`
	AllowInsecureLoopback bool     `yaml:"allow_insecure_loopback"`
}

// ProxyPrefixes accepts explicit, canonical IP networks, never hostnames or a
// catch-all network. Only these immediate peers may assert X-Forwarded-Proto.
func (c OwnerSecurity) ProxyPrefixes() ([]netip.Prefix, error) {
	if len(c.TrustedProxies) > 16 {
		return nil, fmt.Errorf("owner_security.trusted_proxies: at most 16 networks are supported")
	}
	out := make([]netip.Prefix, 0, len(c.TrustedProxies))
	for _, raw := range c.TrustedProxies {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Bits() == 0 || p.Addr().Is4In6() || p.Masked() != p || p.String() != raw {
			return nil, fmt.Errorf("owner_security.trusted_proxies requires canonical IP CIDRs with a nonzero prefix length")
		}
		out = append(out, p)
	}
	return out, nil
}

type Managed struct {
	Path   string `yaml:"path"`
	KeyEnv string `yaml:"key_env"`
	Key    string `yaml:"-"`
	// Backend is file (default) or postgres. PostgreSQL requires owner_security
	// and a completed catalog import and cutover.
	Backend string `yaml:"backend"`
}
type Auth struct {
	BearerTokenEnv string `yaml:"bearer_token_env"`
}
type OAuth struct {
	Resource                     string   `yaml:"resource"`
	AuthorizationServer          string   `yaml:"authorization_server"`
	IntrospectionURL             string   `yaml:"introspection_url"`
	IntrospectionClientIDEnv     string   `yaml:"introspection_client_id_env"`
	IntrospectionClientSecretEnv string   `yaml:"introspection_client_secret_env"`
	Scopes                       []string `yaml:"scopes"`
	ManageScope                  string   `yaml:"manage_scope"`
	ClientID                     string   `yaml:"-"`
	ClientSecret                 string   `yaml:"-"`
}
type Upstream struct {
	OAuthHandler auth.OAuthHandler `yaml:"-"`
	Disabled     bool              `yaml:"-"` // Per-user runtime setting from the encrypted catalog.
	Name         string            `yaml:"name"`
	Transport    string            `yaml:"transport"`
	Command      string            `yaml:"command"`
	Args         []string          `yaml:"args"`
	Env          map[string]string `yaml:"env"`
	URL          string            `yaml:"url"`
	Headers      map[string]string `yaml:"headers"`
	CallTimeout  string            `yaml:"call_timeout"`
	Timeout      time.Duration     `yaml:"-"`
}
type Policy struct {
	Default string `yaml:"default"`
	Rules   []Rule `yaml:"rules"`
}
type Rule struct {
	Match  string `yaml:"match"`
	Action string `yaml:"action"`
}
type Audit struct {
	Path string `yaml:"path"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,20}$`)
var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := c.ResolveAndValidate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) ResolveAndValidate() error {
	if c.Accounts != nil && (c.Managed == nil || c.OAuth != nil) {
		return fmt.Errorf("accounts requires managed_upstreams and cannot be combined with oauth mode")
	}
	if c.OwnerSecurity != nil {
		// Only local-account browser sessions can prove an interactive owner.
		// Operator bearer and external OAuth modes cannot distinguish a human.
		if c.Accounts == nil {
			return fmt.Errorf("owner_security requires accounts mode")
		}
		if _, err := c.OwnerSecurity.ProxyPrefixes(); err != nil {
			return err
		}
		if c.OwnerSecurity.DatabaseURLEnv == "" {
			return fmt.Errorf("owner_security.database_url_env is required")
		}
		var ok bool
		c.OwnerSecurity.DatabaseURL, ok = os.LookupEnv(c.OwnerSecurity.DatabaseURLEnv)
		if !ok || c.OwnerSecurity.DatabaseURL == "" {
			return fmt.Errorf("owner_security: environment variable %s is unset or empty", c.OwnerSecurity.DatabaseURLEnv)
		}
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8787"
	}
	if c.Audit.Path == "" {
		c.Audit.Path = "./audit.jsonl"
	}
	if c.Audit.Path == "-" {
		return fmt.Errorf("audit.path must be a persistent file; stdout cannot provide durable dispatch admission")
	}
	if c.Managed != nil {
		if c.Managed.Path == "" || c.Managed.KeyEnv == "" {
			return fmt.Errorf("managed_upstreams.path and key_env are required")
		}
		var ok bool
		c.Managed.Key, ok = os.LookupEnv(c.Managed.KeyEnv)
		if !ok || c.Managed.Key == "" {
			return fmt.Errorf("managed_upstreams: environment variable %s is unset or empty", c.Managed.KeyEnv)
		}
		switch c.Managed.Backend {
		case "":
			c.Managed.Backend = "file"
		case "file":
		case "postgres":
			if c.OwnerSecurity == nil {
				return fmt.Errorf("managed_upstreams.backend postgres requires owner_security")
			}
		default:
			return fmt.Errorf("managed_upstreams.backend must be file or postgres")
		}
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !loopback && c.DownstreamAuth == nil {
		return fmt.Errorf("downstream_auth required for non-loopback listen address")
	}
	if c.DownstreamAuth != nil {
		if c.DownstreamAuth.BearerTokenEnv == "" {
			return fmt.Errorf("downstream_auth.bearer_token_env is required")
		}
		var ok bool
		c.Token, ok = os.LookupEnv(c.DownstreamAuth.BearerTokenEnv)
		if !ok || c.Token == "" {
			return fmt.Errorf("downstream_auth: environment variable %s is unset or empty", c.DownstreamAuth.BearerTokenEnv)
		}
	}
	if c.OAuth != nil {
		o := c.OAuth
		if !validOAuthURL(o.Resource) || !validOAuthURL(o.AuthorizationServer) || !validOAuthURL(o.IntrospectionURL) {
			return fmt.Errorf("oauth: resource, authorization_server, and introspection_url must be HTTPS URLs (HTTP loopback allowed for tests)")
		}
		if o.IntrospectionClientIDEnv == "" || o.IntrospectionClientSecretEnv == "" {
			return fmt.Errorf("oauth: introspection client environment variable names are required")
		}
		var ok bool
		o.ClientID, ok = os.LookupEnv(o.IntrospectionClientIDEnv)
		if !ok || o.ClientID == "" {
			return fmt.Errorf("oauth: environment variable %s is unset or empty", o.IntrospectionClientIDEnv)
		}
		o.ClientSecret, ok = os.LookupEnv(o.IntrospectionClientSecretEnv)
		if !ok || o.ClientSecret == "" {
			return fmt.Errorf("oauth: environment variable %s is unset or empty", o.IntrospectionClientSecretEnv)
		}
		if len(o.Scopes) == 0 {
			o.Scopes = []string{"mcp:tools"}
		}
		if o.ManageScope == "" {
			o.ManageScope = "mcp:manage"
		}
	}
	if c.Policy.Default == "" {
		c.Policy.Default = "allow"
	}
	if !validAction(c.Policy.Default) {
		return fmt.Errorf("policy.default must be allow or deny")
	}
	for i, r := range c.Policy.Rules {
		if r.Match == "" || !validAction(r.Action) {
			return fmt.Errorf("policy.rules[%d]: match and allow/deny action required", i)
		}
	}
	seen := map[string]bool{}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if !namePattern.MatchString(u.Name) || seen[u.Name] {
			return fmt.Errorf("upstreams[%d]: invalid or duplicate name %q", i, u.Name)
		}
		seen[u.Name] = true
		switch u.Transport {
		case "stdio":
			if u.Command == "" {
				return fmt.Errorf("upstream %s: command required", u.Name)
			}
		case "http":
			if !strings.HasPrefix(u.URL, "https://") && !strings.HasPrefix(u.URL, "http://") {
				return fmt.Errorf("upstream %s: http URL required", u.Name)
			}
		default:
			return fmt.Errorf("upstream %s: transport must be stdio or http", u.Name)
		}
		if u.CallTimeout == "" {
			u.CallTimeout = "30s"
		}
		u.Timeout, err = time.ParseDuration(u.CallTimeout)
		if err != nil || u.Timeout <= 0 {
			return fmt.Errorf("upstream %s: invalid call_timeout %q", u.Name, u.CallTimeout)
		}
		for k, v := range u.Env {
			if u.Env[k], err = expand(v); err != nil {
				return fmt.Errorf("upstream %s env %s: %w", u.Name, k, err)
			}
		}
		for k, v := range u.Headers {
			if u.Headers[k], err = expand(v); err != nil {
				return fmt.Errorf("upstream %s header %s: %w", u.Name, k, err)
			}
		}
		for j, v := range u.Args {
			if u.Args[j], err = expand(v); err != nil {
				return fmt.Errorf("upstream %s arg %d: %w", u.Name, j, err)
			}
		}
	}
	for _, origin := range c.Origins {
		if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return fmt.Errorf("allowed_origins: invalid origin %q", origin)
		}
	}
	return nil
}

func validAction(s string) bool { return s == "allow" || s == "deny" }
func validOAuthURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()))
}
func expand(s string) (string, error) {
	var missing string
	out := envPattern.ReplaceAllStringFunc(s, func(ref string) string {
		key := ref[2 : len(ref)-1]
		val, ok := os.LookupEnv(key)
		if !ok {
			missing = key
		}
		return val
	})
	if missing != "" {
		return "", fmt.Errorf("environment variable %s is unset", missing)
	}
	return out, nil
}
