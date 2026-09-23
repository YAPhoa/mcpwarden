package catalog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"golang.org/x/oauth2"
)

// Entry is a user-owned remote MCP connection. Headers are only returned by
// List internally and are never included in API responses or logs.
type Entry struct {
	Lifecycle
	AuthType    string            `json:"auth_type,omitempty"`
	OAuth       *OAuthSettings    `json:"oauth,omitempty"`
	ID          string            `json:"id"`
	Owner       string            `json:"owner"`
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	CallTimeout string            `json:"call_timeout"`
}

type Store struct {
	mu         sync.RWMutex
	path       string
	aead       cipher.AEAD
	entries    map[string]Entry
	discovery  map[string]Discovery
	visibility map[string]Visibility
	accounts   map[string]Account
	access     map[string]AccessRecord
	deleted    map[string]Lifecycle
}

// Close implements Repository. The encrypted file store has no persistent
// handles, but database-backed repositories can use this lifecycle hook to
// release connection pools.
func (s *Store) Close() error { return nil }

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
	ID              string `json:"id"`
	Username        string `json:"username"`
	Salt            []byte `json:"salt"`
	PasswordHash    []byte `json:"password_hash"`
	Iterations      int    `json:"iterations"`
	ClientTokenHash string `json:"client_token_hash,omitempty"`
}

type diskState struct {
	Access     map[string]AccessRecord `json:"access,omitempty"`
	Deleted    map[string]Lifecycle    `json:"deleted,omitempty"`
	Accounts   map[string]Account      `json:"accounts,omitempty"`
	Entries    []Entry                 `json:"entries"`
	Discovery  map[string]Discovery    `json:"discovery"`
	Visibility map[string]Visibility   `json:"visibility"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,20}$`)
var headerPattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

func Open(path, encodedKey string) (*Store, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("managed upstream key must be base64-encoded 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create credential cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create credential cipher: %w", err)
	}
	s := &Store{path: path, aead: aead, entries: map[string]Entry{}, discovery: map[string]Discovery{}, visibility: map[string]Visibility{}, accounts: map[string]Account{}, access: map[string]AccessRecord{}, deleted: map[string]Lifecycle{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read managed upstreams: %w", err)
	}
	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("managed upstream store is invalid")
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt managed upstreams: %w", err)
	}
	var state diskState
	if err := json.Unmarshal(plain, &state); err != nil {
		return nil, fmt.Errorf("decode managed upstreams: %w", err)
	}
	if state.Access != nil {
		s.access = state.Access
	}
	if state.Deleted != nil {
		s.deleted = state.Deleted
	}
	migrated := false
	for id, r := range s.access {
		if r.Kind == "mcp" && r.EndedAt.IsZero() {
			r.EndedAt = time.Now().UTC()
			r.UpdatedAt = r.EndedAt
			s.access[id] = r
			migrated = true
		}
	}
	seenIDs := map[string]bool{}
	for _, entry := range state.Entries {
		if entry.ID == "" {
			entry.ID = identity.New()
			migrated = true
		}
		if seenIDs[entry.ID] {
			return nil, fmt.Errorf("duplicate stored upstream ID")
		}
		seenIDs[entry.ID] = true
		if err := Validate(entry); err != nil {
			return nil, fmt.Errorf("stored upstream %s: %w", entry.Name, err)
		}
		k := keyFor(entry.Owner, entry.Name)
		if _, exists := s.entries[k]; exists {
			return nil, fmt.Errorf("duplicate stored upstream %s", entry.Name)
		}
		s.entries[k] = entry
	}
	if state.Discovery != nil {
		s.discovery = state.Discovery
	}
	if state.Accounts != nil {
		s.accounts = state.Accounts
	}
	for username, a := range s.accounts {
		if a.ClientTokenHash != "" {
			id := identity.New()
			s.access[id] = AccessRecord{ID: id, Owner: a.ID, Name: "Legacy client key", Kind: "api_key", Role: "client", SecretHash: a.ClientTokenHash, Lifecycle: Lifecycle{UpdatedAt: time.Now().UTC()}}
			a.ClientTokenHash = ""
			s.accounts[username] = a
			migrated = true
		}
	}
	// Backfill only public metadata. Preserve legacy verifier bytes, access IDs,
	// ownership, role, expiry, and lifecycle timestamps (including revoked keys).
	publicIDs := map[string]bool{}
	for id, r := range s.access {
		if r.Kind == "api_key" && r.PublicID == "" {
			r.PublicID = identity.NewPublicID()
			s.access[id] = r
			migrated = true
		}
		if r.PublicID != "" {
			if !identity.ValidPublicID(r.PublicID) || publicIDs[r.PublicID] {
				return nil, fmt.Errorf("invalid or duplicate stored access public ID")
			}
			publicIDs[r.PublicID] = true
		}
	}
	for key, setting := range state.Visibility {
		if setting.Mode != "all" && setting.Mode != "selected" {
			return nil, fmt.Errorf("invalid stored tool visibility")
		}
		s.visibility[key] = setting
	}
	if migrated {
		if err := s.save(); err != nil {
			return nil, fmt.Errorf("persist catalog migration: %w", err)
		}
	}
	return s, nil
}

func Validate(e Entry) error {
	switch e.AuthType {
	case "", "none", "headers", "bearer", "api_key":
		if e.AuthType == "none" && len(e.Headers) > 0 {
			return fmt.Errorf("no authentication cannot include headers")
		}
		if e.AuthType == "bearer" || e.AuthType == "api_key" {
			if len(e.Headers) != 1 {
				return fmt.Errorf("credential requires exactly one header")
			}
			for name, value := range e.Headers {
				if value == "" {
					return fmt.Errorf("credential cannot be empty")
				}
				if e.AuthType == "bearer" && (!strings.EqualFold(name, "Authorization") || !strings.HasPrefix(value, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(value, "Bearer ")) == "") {
					return fmt.Errorf("invalid bearer credential")
				}
			}
		}
		if e.OAuth != nil {
			return fmt.Errorf("OAuth settings require OAuth authentication")
		}
	case "oauth":
		if e.OAuth == nil {
			return fmt.Errorf("OAuth settings are required")
		}
		for name := range e.Headers {
			if strings.EqualFold(name, "Authorization") {
				return fmt.Errorf("OAuth cannot be combined with an Authorization header")
			}
		}
		if e.OAuth.ClientID != "" && e.OAuth.Issuer == "" {
			return fmt.Errorf("registered OAuth clients require an issuer")
		}
		if e.OAuth.ClientSecret != "" && e.OAuth.ClientID == "" {
			return fmt.Errorf("OAuth client secret requires a client ID")
		}
		if e.OAuth.Issuer != "" {
			if err := ValidateEndpoint(e.OAuth.Issuer); err != nil {
				return fmt.Errorf("invalid OAuth issuer")
			}
		}
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
	for name, value := range e.Headers {
		if !headerPattern.MatchString(name) || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid HTTP header")
		}
		switch http.CanonicalHeaderKey(name) {
		case "Host", "Content-Length", "Connection", "Transfer-Encoding", "Upgrade", "Mcp-Session-Id":
			return fmt.Errorf("header %s cannot be configured", name)
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
	return config.Upstream{Name: e.Name, Transport: "http", URL: e.URL, Headers: e.Headers, CallTimeout: timeout, Timeout: d}
}

func (s *Store) List(owner string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0)
	for _, e := range s.entries {
		if e.Owner == owner {
			copyEntry := e
			if e.OAuth != nil {
				data, _ := json.Marshal(e.OAuth)
				copyEntry.OAuth = nil
				_ = json.Unmarshal(data, &copyEntry.OAuth)
			}
			copyEntry.Headers = make(map[string]string, len(e.Headers))
			for k, v := range e.Headers {
				copyEntry.Headers[k] = v
			}
			out = append(out, copyEntry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) Add(e Entry) error {
	if e.ID == "" {
		e.ID = identity.New()
	}
	if err := Validate(e); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyFor(e.Owner, e.Name)
	if _, exists := s.entries[k]; exists {
		return fmt.Errorf("upstream %s already exists", e.Name)
	}
	for _, existing := range s.entries {
		if existing.ID == e.ID {
			return fmt.Errorf("upstream ID already exists")
		}
	}
	e.CreatedAt = time.Now().UTC()
	e.UpdatedAt = e.CreatedAt
	s.entries[k] = e
	if err := s.save(); err != nil {
		delete(s.entries, k)
		return err
	}
	return nil
}

func (s *Store) Delete(owner, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyFor(owner, name)
	e, exists := s.entries[k]
	if !exists {
		return fmt.Errorf("upstream %s does not exist", name)
	}
	delete(s.entries, k)
	deleted := e.Lifecycle
	deleted.DeletedAt = time.Now().UTC()
	deleted.UpdatedAt = deleted.DeletedAt
	s.deleted[e.ID] = deleted
	oldDiscovery, hadDiscovery := s.discovery[k]
	delete(s.discovery, k)
	oldVisibility, hadVisibility := s.visibility[k]
	delete(s.visibility, k)
	if err := s.save(); err != nil {
		s.entries[k] = e
		delete(s.deleted, e.ID)
		if hadDiscovery {
			s.discovery[k] = oldDiscovery
		}
		if hadVisibility {
			s.visibility[k] = oldVisibility
		}
		return err
	}
	return nil
}

func (s *Store) Visibility(owner, provider string) Visibility {
	s.mu.RLock()
	defer s.mu.RUnlock()
	setting, ok := s.visibility[keyFor(owner, provider)]
	if !ok {
		return Visibility{Mode: "all", Enabled: []string{}}
	}
	setting.Enabled = append([]string(nil), setting.Enabled...)
	if setting.Enabled == nil {
		setting.Enabled = []string{}
	}
	return setting
}

func (s *Store) ToolVisible(owner, provider, tool string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	setting, ok := s.visibility[keyFor(owner, provider)]
	if !ok || setting.Mode == "all" {
		return true
	}
	for _, enabled := range setting.Enabled {
		if enabled == tool {
			return true
		}
	}
	return false
}

func (s *Store) SetVisibility(owner, provider string, setting Visibility) error {
	if owner == "" || !namePattern.MatchString(provider) || setting.Mode != "all" && setting.Mode != "selected" {
		return fmt.Errorf("invalid visibility setting")
	}
	seen := map[string]bool{}
	for _, name := range setting.Enabled {
		if !strings.HasPrefix(name, provider+"__") || seen[name] {
			return fmt.Errorf("invalid or duplicate enabled tool %q", name)
		}
		seen[name] = true
	}
	setting.Enabled = append([]string(nil), setting.Enabled...)
	sort.Strings(setting.Enabled)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyFor(owner, provider)
	old, hadOld := s.visibility[k]
	setting.Disabled = old.Disabled
	setting.Lifecycle = old.Lifecycle
	setting.touch()
	s.visibility[k] = setting
	if err := s.save(); err != nil {
		if hadOld {
			s.visibility[k] = old
		} else {
			delete(s.visibility, k)
		}
		return err
	}
	return nil
}

func (s *Store) Discovery(owner, name string) (Discovery, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.discovery[keyFor(owner, name)]
	if !ok {
		return Discovery{}, false
	}
	return copyDiscovery(d), true
}

func (s *Store) SetDiscovery(owner, name string, tools []*mcp.Tool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyFor(owner, name)
	old, hadOld := s.discovery[k]
	d := copyDiscovery(Discovery{Tools: tools, UpdatedAt: time.Now().UTC()})
	s.discovery[k] = d
	if err := s.save(); err != nil {
		if hadOld {
			s.discovery[k] = old
		} else {
			delete(s.discovery, k)
		}
		return err
	}
	return nil
}

func copyDiscovery(d Discovery) Discovery {
	out := Discovery{UpdatedAt: d.UpdatedAt, Tools: make([]*mcp.Tool, 0, len(d.Tools))}
	for _, tool := range d.Tools {
		if tool == nil {
			continue
		}
		copyTool := *tool
		out.Tools = append(out.Tools, &copyTool)
	}
	return out
}

func (s *Store) save() error {
	entries := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Owner == entries[j].Owner {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Owner < entries[j].Owner
	})
	plain, err := jsoncodec.Marshal(diskState{Access: s.access, Deleted: s.deleted, Entries: entries, Discovery: s.discovery, Visibility: s.visibility, Accounts: s.accounts})
	if err != nil {
		return fmt.Errorf("encode managed upstreams failed")
	}
	defer clear(plain)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("create credential nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nonce, nonce, plain, nil)
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create managed upstream directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".mcpwarden-*")
	if err != nil {
		return fmt.Errorf("create managed upstream file: %w", err)
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return fmt.Errorf("save managed upstreams: %w", err)
	}
	return nil
}

func keyFor(owner, name string) string {
	h := sha256.Sum256([]byte(owner))
	return fmt.Sprintf("%x/%s", h, name)
}

// Account material is internal only and is persisted in the encrypted catalog.
func (s *Store) Account(username string) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.accounts[username]
	a.Salt = append([]byte(nil), a.Salt...)
	a.PasswordHash = append([]byte(nil), a.PasswordHash...)
	return a, ok
}
func (s *Store) AddAccount(a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[a.Username]; exists {
		return fmt.Errorf("username unavailable")
	}
	a.CreatedAt = time.Now().UTC()
	a.UpdatedAt = a.CreatedAt
	s.accounts[a.Username] = a
	if err := s.save(); err != nil {
		delete(s.accounts, a.Username)
		return err
	}
	return nil
}
func (s *Store) SetClientToken(username, hash string) error {
	a, ok := s.Account(username)
	if !ok {
		return fmt.Errorf("account not found")
	}
	for _, record := range s.AccessList(a.ID) {
		if record.Kind == "api_key" && record.Name == "Legacy client key" && record.RevokedAt.IsZero() {
			if err := s.RevokeAccess(a.ID, record.ID); err != nil {
				return err
			}
		}
	}
	return s.AddAccess(AccessRecord{Owner: a.ID, Name: "Legacy client key", Kind: "api_key", Role: "client", SecretHash: hash})
}
func (s *Store) AccountForToken(hash string) (Account, bool) {
	record, ok := s.AuthenticateAccess(hash, "api_key")
	if !ok {
		return Account{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts {
		if a.ID == record.Owner {
			return Account{ID: a.ID, Username: a.Username}, true
		}
	}
	return Account{}, false
}

// SetProviderEnabled changes connection availability without changing tool selections.
func (s *Store) SetProviderEnabled(owner, provider string, enabled bool) error {
	if owner == "" || !namePattern.MatchString(provider) {
		return fmt.Errorf("invalid provider")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyFor(owner, provider)
	old, exists := s.visibility[k]
	setting := old
	if !exists {
		setting.Mode = "all"
	}
	setting.Disabled = !enabled
	setting.touch()
	s.visibility[k] = setting
	if err := s.save(); err != nil {
		if exists {
			s.visibility[k] = old
		} else {
			delete(s.visibility, k)
		}
		return err
	}
	return nil
}

// OAuth material is encrypted with the catalog and never returned in API views.
type OAuthSettings struct {
	ClientID     string      `json:"client_id,omitempty"`
	ClientSecret string      `json:"client_secret,omitempty"`
	Issuer       string      `json:"issuer,omitempty"`
	Scopes       []string    `json:"scopes,omitempty"`
	Grant        *OAuthGrant `json:"grant,omitempty"`
}
type OAuthGrant struct {
	ID     string        `json:"id"`
	Config oauth2.Config `json:"config"`
	Token  oauth2.Token  `json:"token"`
}

func ValidateEndpoint(endpoint string) error {
	return Validate(Entry{Owner: "validation", Name: "validation", URL: endpoint})
}
func (s *Store) SaveOAuth(owner, id, previousGrant string, grant OAuthGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, e := range s.entries {
		if e.Owner != owner || e.ID != id {
			continue
		}
		if e.AuthType != "oauth" || e.OAuth == nil {
			break
		}
		current := ""
		if e.OAuth.Grant != nil {
			current = e.OAuth.Grant.ID
		}
		if current != previousGrant {
			return fmt.Errorf("OAuth connection changed")
		}
		old := e
		copied := *e.OAuth
		copied.Grant = &grant
		e.OAuth = &copied
		e.UpdatedAt = time.Now().UTC()
		s.entries[key] = e
		if err := s.save(); err != nil {
			s.entries[key] = old
			return err
		}
		return nil
	}
	return fmt.Errorf("OAuth connection no longer exists")
}

func (s *Store) ChangePassword(username string, expected, salt, hash []byte, iterations int, keepSession string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.accounts[username]
	if !ok || subtle.ConstantTimeCompare(old.PasswordHash, expected) != 1 {
		return nil, fmt.Errorf("credentials changed")
	}
	next := old
	next.Salt = salt
	next.PasswordHash = hash
	next.Iterations = iterations
	next.UpdatedAt = time.Now().UTC()
	s.accounts[username] = next
	previous := map[string]AccessRecord{}
	ids := []string{}
	for id, r := range s.access {
		if r.Owner == old.ID && r.Kind == "browser" && id != keepSession && r.Active() {
			previous[id] = r
			r.RevokedAt = next.UpdatedAt
			r.UpdatedAt = next.UpdatedAt
			s.access[id] = r
			ids = append(ids, id)
		}
	}
	if err := s.save(); err != nil {
		s.accounts[username] = old
		for id, r := range previous {
			s.access[id] = r
		}
		return nil, err
	}
	return ids, nil
}
