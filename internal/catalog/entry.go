package catalog

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/secret"
)

// Entry is a user-owned remote MCP connection. A credentialed connector
// declares only the names of its credential headers; the values live in the
// owner's vault and are released per access window. The gateway never stores
// them in the catalog.
type Entry struct {
	Lifecycle
	AuthType    string   `json:"auth_type,omitempty"`
	ID          string   `json:"id"`
	Owner       string   `json:"owner"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	HeaderNames []string `json:"header_names,omitempty"`
	CallTimeout string   `json:"call_timeout"`
}

// Credentialed reports whether the connector needs a vault credential. Such a
// connector never connects without an owner-activated access window.
func (e Entry) Credentialed() bool {
	return e.AuthType == "bearer" || e.AuthType == "api_key" || e.AuthType == "headers"
}

// ErrOldFormat refuses catalog data written before vault-only custody: stored
// header values or upstream OAuth settings. There is no conversion.
var ErrOldFormat = errors.New("created by an older build; start with a new catalog")

// ProviderKey names per-provider settings.
type ProviderKey struct{ Owner, Provider string }

type Visibility struct {
	Lifecycle
	Disabled bool     `json:"disabled,omitempty"`
	Mode     string   `json:"mode"`
	Enabled  []string `json:"enabled"`
}

type Discovery struct {
	Tools     []*mcp.Tool `json:"tools"`
	UpdatedAt time.Time   `json:"updated_at"`
}

type Account struct {
	Lifecycle
	ID           string `json:"id"`
	Username     string `json:"username"`
	Salt         []byte `json:"salt"`
	PasswordHash []byte `json:"password_hash"`
	Iterations   int    `json:"iterations"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,20}$`)
var headerPattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

func Validate(e Entry) error {
	switch e.AuthType {
	case "", "none":
		if len(e.HeaderNames) > 0 {
			return fmt.Errorf("no authentication cannot include headers")
		}
	case "bearer":
		if len(e.HeaderNames) != 1 || !strings.EqualFold(e.HeaderNames[0], "Authorization") {
			return fmt.Errorf("a bearer credential uses the Authorization header")
		}
	case "api_key":
		if len(e.HeaderNames) != 1 {
			return fmt.Errorf("an API key needs exactly one header name")
		}
	case "headers":
		if len(e.HeaderNames) < 1 || len(e.HeaderNames) > 32 {
			return fmt.Errorf("custom headers need 1 to 32 header names")
		}
	case "oauth":
		return fmt.Errorf("OAuth connectors return with roadmap step 6")
	default:
		return fmt.Errorf("unsupported authentication method")
	}

	if e.ID != "" && !identity.Valid(e.ID) {
		return fmt.Errorf("invalid upstream ID")
	}
	if e.Owner == "" {
		return fmt.Errorf("owner is required")
	}
	if !namePattern.MatchString(e.Name) {
		return fmt.Errorf("name must match [a-z0-9-]{1,20}")
	}
	u, err := url.Parse(e.URL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("URL must be an HTTPS URL or a loopback HTTP URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return fmt.Errorf("URL must be an HTTPS URL or a loopback HTTP URL")
	}
	if e.CallTimeout == "" {
		e.CallTimeout = "30s"
	}
	d, err := time.ParseDuration(e.CallTimeout)
	if err != nil || d <= 0 {
		return fmt.Errorf("invalid call_timeout")
	}
	// The vault destination accepts exactly the names checked here, so a
	// credential can be saved for every connector the catalog accepts.
	seen := make(map[string]bool, len(e.HeaderNames))
	for _, name := range e.HeaderNames {
		if !headerPattern.MatchString(name) {
			return fmt.Errorf("invalid HTTP header name")
		}
		lower := strings.ToLower(name)
		if !secret.CredentialHeader(lower) {
			return fmt.Errorf("header %s cannot carry a credential", name)
		}
		if seen[lower] {
			return fmt.Errorf("header %s is listed twice", name)
		}
		seen[lower] = true
	}
	// The endpoint must also be one the vault accepts: public HTTPS, or
	// loopback HTTP for development.
	if e.Credentialed() {
		if _, err := secret.ConnectorDestination(e.URL, e.HeaderNames); err != nil {
			return fmt.Errorf("connectors with credentials need a public HTTPS endpoint with a lowercase host and a path, or HTTP on this machine")
		}
	}
	return nil
}

func (e Entry) Upstream() config.Upstream {
	timeout := e.CallTimeout
	if timeout == "" {
		timeout = "30s"
	}
	d, _ := time.ParseDuration(timeout)
	return config.Upstream{Name: e.Name, Transport: "http", URL: e.URL, CallTimeout: timeout, Timeout: d, Guarded: e.Credentialed()}
}

func ValidName(name string) bool { return namePattern.MatchString(name) }
