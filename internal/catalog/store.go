package catalog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/config"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/jsoncodec"
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
	// rollback is set only in a file written by a PostgreSQL rollback export.
	rollback string
	unlock   func()
}

// Close releases the shared catalog lock. Database-backed repositories use
// this lifecycle hook to release connections.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unlock != nil {
		s.unlock()
		s.unlock = nil
	}
	return nil
}

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

// legacyEntries finds the fields an older build stored in each connector.
type legacyEntries struct {
	Entries []struct {
		Headers map[string]string `json:"headers"`
		OAuth   json.RawMessage   `json:"oauth"`
	} `json:"entries"`
}

type diskState struct {
	Access     map[string]AccessRecord `json:"access,omitempty"`
	Deleted    map[string]Lifecycle    `json:"deleted,omitempty"`
	Accounts   map[string]Account      `json:"accounts,omitempty"`
	Entries    []Entry                 `json:"entries"`
	Discovery  map[string]Discovery    `json:"discovery"`
	Visibility map[string]Visibility   `json:"visibility"`
	Rollback   string                  `json:"rollback,omitempty"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,20}$`)
var headerPattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

func newAEAD(encodedKey string) (cipher.AEAD, error) {
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
	return aead, nil
}

// readDisk decrypts and decodes the file without changing it. A missing file
// is an empty catalog.
func readDisk(path string, aead cipher.AEAD) (diskState, bool, error) {
	var state diskState
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, false, nil
	}
	if err != nil {
		return state, false, fmt.Errorf("read managed upstreams: %w", err)
	}
	if len(data) < aead.NonceSize() {
		return state, false, fmt.Errorf("managed upstream store is invalid")
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
	if err != nil {
		return state, false, fmt.Errorf("decrypt managed upstreams: %w", err)
	}
	defer clear(plain)
	var legacy legacyEntries
	if err := json.Unmarshal(plain, &legacy); err != nil {
		return state, false, fmt.Errorf("decode managed upstreams: %w", err)
	}
	for _, e := range legacy.Entries {
		old := len(e.Headers) > 0 || len(e.OAuth) > 0 && string(e.OAuth) != "null"
		clear(e.Headers)
		if old {
			return state, false, fmt.Errorf("managed upstream store was %w", ErrOldFormat)
		}
	}
	if err := json.Unmarshal(plain, &state); err != nil {
		return state, false, fmt.Errorf("decode managed upstreams: %w", err)
	}
	return state, true, nil
}

func Open(path, encodedKey string) (*Store, error) {
	aead, err := newAEAD(encodedKey)
	if err != nil {
		return nil, err
	}
	// The shared lock lets a catalog migration detect a running file gateway.
	unlock, err := Lock(path, false)
	if err != nil {
		if errors.Is(err, ErrCatalogBusy) {
			return nil, fmt.Errorf("a catalog migration is running; the file backend must not start")
		}
		return nil, err
	}
	s, err := open(path, aead)
	if err != nil {
		unlock()
		return nil, err
	}
	s.unlock = unlock
	return s, nil
}

func open(path string, aead cipher.AEAD) (*Store, error) {
	s := &Store{path: path, aead: aead, entries: map[string]Entry{}, discovery: map[string]Discovery{}, visibility: map[string]Visibility{}, accounts: map[string]Account{}, access: map[string]AccessRecord{}, deleted: map[string]Lifecycle{}}
	state, exists, err := readDisk(path, aead)
	if err != nil {
		return nil, err
	}
	// A PostgreSQL cutover leaves a marker beside the file. Only the file its
	// rollback wrote may be used again; an older copy could revive revoked keys,
	// sessions or passwords.
	if err := checkMarker(path, state.Rollback); err != nil {
		return nil, err
	}
	if !exists {
		return s, nil
	}
	s.rollback = state.Rollback
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

func (s *Store) List(owner string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0)
	for _, e := range s.entries {
		if e.Owner == owner {
			copyEntry := e
			copyEntry.HeaderNames = slices.Clone(e.HeaderNames)
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
	plain, err := jsoncodec.Marshal(diskState{Access: s.access, Deleted: s.deleted, Entries: entries, Discovery: s.discovery, Visibility: s.visibility, Accounts: s.accounts, Rollback: s.rollback})
	if err != nil {
		return fmt.Errorf("encode managed upstreams failed")
	}
	defer clear(plain)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("create credential nonce: %w", err)
	}
	return writeEncrypted(s.path, s.aead.Seal(nonce, nonce, plain, nil))
}

// writeEncrypted atomically replaces path with a synced 0600 file.
func writeEncrypted(path string, ciphertext []byte) error {
	dir := filepath.Dir(path)
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
	if err := os.Rename(f.Name(), path); err != nil {
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

// ValidName reports whether name is a valid connector or provider name.
func ValidName(name string) bool { return namePattern.MatchString(name) }
