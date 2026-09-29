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
	Storage        *Storage       `yaml:"storage"`
	OwnerSecurity  *OwnerSecurity `yaml:"owner_security"`
	Token          string         `yaml:"-"`
}

// Storage keeps the catalog, tool-call history and security metadata in one
// database: a local SQLite file or PostgreSQL. See docs/storage.md.
type Storage struct {
	// Driver is sqlite (default) or postgres.
	Driver string `yaml:"driver"`
	// Path is the SQLite database file, on a local filesystem.
	Path string `yaml:"path"`
	// DatabaseURLEnv names the variable holding the PostgreSQL runtime
	// role's URL, never the migration role's.
	DatabaseURLEnv string `yaml:"database_url_env"`
	DatabaseURL    string `yaml:"-"`
	// KeyEnv names the variable holding the catalog sealing key.
	KeyEnv string `yaml:"key_env"`
	Key    string `yaml:"-"`
}

// OwnerSecurity enables the owner vault, access-request and lease routes on
// the storage database. Credentialed personal connectors run only through
// access windows; the server never holds their credentials.
type OwnerSecurity struct {
	// DatabaseURLEnv was replaced by storage.database_url_env; it is kept
	// only to refuse it with a specific message.
	DatabaseURLEnv        string   `yaml:"database_url_env"`
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

// Managed is the encrypted file catalog, used when storage is not set.
type Managed struct {
	Path   string `yaml:"path"`
	KeyEnv string `yaml:"key_env"`
	Key    string `yaml:"-"`
	// Backend was replaced by the storage section; it is kept only to refuse
	// it with a specific message.
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
	Disabled bool `yaml:"-"` // Per-user runtime setting from the encrypted catalog.
	// Guarded marks a connector whose credential is in vault custody. The
	// manager never connects it; calls run through access windows.
	Guarded     bool              `yaml:"-"`
	Name        string            `yaml:"name"`
	Transport   string            `yaml:"transport"`
	Command     string            `yaml:"command"`
	Args        []string          `yaml:"args"`
	Env         map[string]string `yaml:"env"`
	URL         string            `yaml:"url"`
	Headers     map[string]string `yaml:"headers"`
	CallTimeout string            `yaml:"call_timeout"`
	Timeout     time.Duration     `yaml:"-"`
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
	if c.Accounts != nil && (c.Managed == nil && c.Storage == nil || c.OAuth != nil) {
		return fmt.Errorf("accounts requires storage (or managed_upstreams) and cannot be combined with oauth mode")
	}
	if c.Managed != nil && c.Managed.Backend != "" {
		return fmt.Errorf("managed_upstreams.backend was replaced by the storage section; see docs/storage.md")
	}
	if c.Storage != nil {
		if err := c.Storage.resolve(); err != nil {
			return err
		}
		if c.Managed != nil {
			return fmt.Errorf("managed_upstreams cannot be combined with storage: the catalog is in the storage database, sealed with storage.key_env")
		}
		if c.Audit.Path != "" {
			return fmt.Errorf("audit.path must be unset with storage: tool-call history is in the storage database")
		}
	}
	if c.OwnerSecurity != nil {
		// Only local-account browser sessions can prove an interactive owner.
		// Operator bearer and external OAuth modes cannot distinguish a human.
		if c.Accounts == nil {
			return fmt.Errorf("owner_security requires accounts mode")
		}
		if c.OwnerSecurity.DatabaseURLEnv != "" {
			return fmt.Errorf("owner_security.database_url_env was replaced by storage.database_url_env with storage.driver postgres; see docs/storage.md")
		}
		if c.Storage == nil {
			return fmt.Errorf("owner_security requires the storage section")
		}
		if _, err := c.OwnerSecurity.ProxyPrefixes(); err != nil {
			return err
		}
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8787"
	}
	if c.Storage == nil && c.Audit.Path == "" {
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

func (s *Storage) resolve() error {
	switch s.Driver {
	case "", "sqlite":
		s.Driver = "sqlite"
		if s.Path == "" {
			return fmt.Errorf("storage.path is required with storage.driver sqlite")
		}
		if s.DatabaseURLEnv != "" {
			return fmt.Errorf("storage.database_url_env is only for storage.driver postgres")
		}
	case "postgres":
		if s.Path != "" {
			return fmt.Errorf("storage.path is only for storage.driver sqlite")
		}
		if s.DatabaseURLEnv == "" {
			return fmt.Errorf("storage.database_url_env is required with storage.driver postgres")
		}
		var ok bool
		s.DatabaseURL, ok = os.LookupEnv(s.DatabaseURLEnv)
		if !ok || s.DatabaseURL == "" {
			return fmt.Errorf("storage: environment variable %s is unset or empty", s.DatabaseURLEnv)
		}
	default:
		return fmt.Errorf("storage.driver must be sqlite or postgres")
	}
	if s.KeyEnv == "" {
		return fmt.Errorf("storage.key_env is required")
	}
	var ok bool
	s.Key, ok = os.LookupEnv(s.KeyEnv)
	if !ok || s.Key == "" {
		return fmt.Errorf("storage: environment variable %s is unset or empty", s.KeyEnv)
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
