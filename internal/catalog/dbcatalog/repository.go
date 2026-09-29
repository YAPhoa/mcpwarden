package dbcatalog

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease"
)

// Coordinator is the owner security gate: lease.Service. Each catalog change
// is one owner transaction under it, together with any lease revocation and
// its security event, and the in-memory view changes only after the commit.
type Coordinator interface {
	// Catalog runs mutation in one owner transaction. A context error
	// returned before the mutation ran, or one wrapped in lease.ErrRolledBack
	// after it, means nothing was committed; any other error after the
	// mutation ran leaves the outcome unknown.
	Catalog(ctx context.Context, owner string, mutation func(lease.Tx) (func(), lease.Ending, error)) error
	BootID() string
}

// Loader reads every committed catalog row on the executor session, under
// the startup deadline.
type Loader interface {
	LoadCatalog(ctx context.Context) (catalogdb.Rows, error)
}

var (
	// ErrUnavailable means the catalog cannot accept changes: it is not ready,
	// or an earlier commit had an unknown outcome and the process must restart.
	ErrUnavailable = errors.New("catalog storage unavailable")
	// ErrNotSaved means the change was rolled back before commit; the
	// catalog is unchanged and the change can be tried again.
	ErrNotSaved = errors.New("change not saved; try again")
)

// Repository implements catalog.Repository over a database store for one active
// gateway process. Reads come from the committed in-memory view. A change
// takes the owner gate, then the view lock inside the owner transaction, and
// publishes after commit before releasing the view lock, so readers never see
// uncommitted state and never miss committed state. Database failures are
// returned; there is no fallback to the file catalog.
type Repository struct {
	seal   *sealer
	loader Loader
	coord  atomic.Pointer[coordinator]
	failed atomic.Bool
	lost   <-chan struct{}
	onFail func()
	now    func() time.Time

	mu sync.RWMutex
	st *state
}

type coordinator struct{ Coordinator }

var _ catalog.Repository = (*Repository)(nil)

// New prepares a repository. It serves nothing until Load succeeds and a
// coordinator is attached. onFail runs once if a commit outcome becomes
// unknown; the caller should stop the process.
func New(encodedKey string, loader Loader, onFail func()) (*Repository, error) {
	s, err := newSealer(encodedKey)
	if err != nil {
		return nil, err
	}
	r := &Repository{seal: s, loader: loader, onFail: onFail, now: func() time.Time { return time.Now().UTC() }}
	if l, ok := loader.(interface{ Lost() <-chan struct{} }); ok {
		r.lost = l.Lost()
	}
	return r, nil
}

// Load reads and verifies every row in one transaction.
func (r *Repository) Load(ctx context.Context) error {
	var st *state
	rows, err := r.loader.LoadCatalog(ctx)
	if err == nil {
		st, err = r.seal.decode(rows)
	}
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.st = st
	r.mu.Unlock()
	return nil
}

// Attach sets the owner gate. Changes fail until it is attached.
func (r *Repository) Attach(c Coordinator) { r.coord.Store(&coordinator{c}) }

func (r *Repository) Close() error { return nil }

func (r *Repository) fail() {
	if r.failed.CompareAndSwap(false, true) && r.onFail != nil {
		r.onFail()
	}
}

// Failed reports that a commit outcome was unknown or the database session
// was lost; the view may be stale and authentication fails closed.
func (r *Repository) Failed() bool {
	if r.failed.Load() {
		return true
	}
	select {
	case <-r.lost:
		return true
	default:
		return false
	}
}

type change struct {
	tx     catalogdb.OwnerTx
	rows   catalogdb.Tx
	events []lease.Event
	boot   string
	now    time.Time
	// end names a connector whose requests and windows this change ends.
	end string
}

func (c *change) event(kind, subject string) {
	e := lease.Event{ID: identity.New(), OwnerID: c.tx.CatalogOwner(), Type: kind, BootID: c.boot}
	if identity.Valid(subject) {
		e.SubjectID = subject
	}
	c.events = append(c.events, e)
}

// apply runs one owner transaction. plan runs with the view locked and must
// not change the view; it returns the writes and the publication.
func (r *Repository) apply(owner string, endLeases bool, plan func(c *change, st *state) (func(), error)) error {
	if r.Failed() {
		return ErrUnavailable
	}
	coord := r.coord.Load()
	if coord == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	held, wrote := false, false
	defer func() {
		if held {
			r.mu.Unlock()
		}
	}()
	err := coord.Catalog(ctx, owner, func(tx lease.Tx) (func(), lease.Ending, error) {
		otx, ok := tx.(catalogdb.OwnerTx)
		if !ok || otx.CatalogOwner() != owner {
			return nil, lease.Ending{}, lease.ErrStorage
		}
		r.mu.Lock()
		held = true
		if r.st == nil {
			return nil, lease.Ending{}, ErrUnavailable
		}
		c := &change{tx: otx, rows: otx.CatalogRows(), boot: coord.BootID(), now: r.now()}
		publish, err := plan(c, r.st)
		if err != nil {
			return nil, lease.Ending{}, err
		}
		for _, e := range c.events {
			e.At = tx.Now()
			if err := tx.Event(e); err != nil {
				return nil, lease.Ending{}, err
			}
		}
		wrote = true
		return func() {
			if publish != nil {
				publish()
			}
			held = false
			r.mu.Unlock()
		}, lease.Ending{All: endLeases, Connector: c.end}, nil
	})
	if err != nil && wrote && !errors.Is(err, lease.ErrRolledBack) {
		// The writes ran; the commit may or may not have happened. A
		// transaction the store abandoned before COMMIT committed nothing, so
		// the view is still right and the catalog stays up.
		r.fail()
		return ErrUnavailable
	}
	return mapError(err)
}

func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, lease.ErrRolledBack), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Rolled back before COMMIT, or gave up before running.
		return ErrNotSaved
	case errors.Is(err, catalogdb.ErrConflict):
		return fmt.Errorf("catalog change conflicted with stored data")
	case errors.Is(err, ErrUnavailable), errors.Is(err, lease.ErrLocked), errors.Is(err, lease.ErrStorage), errors.Is(err, catalogdb.ErrStorage):
		return ErrUnavailable
	}
	return err
}

func (r *Repository) view() (*state, func()) {
	r.mu.RLock()
	if r.st == nil {
		r.mu.RUnlock()
		return newState(), func() {}
	}
	return r.st, r.mu.RUnlock
}

// ---- Connectors ----

func copyEntry(e catalog.Entry) catalog.Entry {
	out := e
	out.HeaderNames = slices.Clone(e.HeaderNames)
	return out
}

func (st *state) entry(owner, name string) (catalog.Entry, bool) {
	for _, e := range st.entries {
		if e.Owner == owner && e.Name == name {
			return e, true
		}
	}
	return catalog.Entry{}, false
}

func (r *Repository) List(owner string) []catalog.Entry {
	st, done := r.view()
	defer done()
	out := make([]catalog.Entry, 0)
	for _, e := range st.entries {
		if e.Owner == owner {
			out = append(out, copyEntry(e))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *Repository) Add(e catalog.Entry) error {
	if e.ID == "" {
		e.ID = identity.New()
	}
	if err := catalog.Validate(e); err != nil {
		return err
	}
	e = copyEntry(e)
	return r.apply(e.Owner, false, func(c *change, st *state) (func(), error) {
		if _, exists := st.entry(e.Owner, e.Name); exists {
			return nil, fmt.Errorf("upstream %s already exists", e.Name)
		}
		if _, exists := st.entries[e.ID]; exists {
			return nil, fmt.Errorf("upstream ID already exists")
		}
		if _, exists := st.tombstones[e.ID]; exists {
			return nil, fmt.Errorf("upstream ID already exists")
		}
		e.CreatedAt = c.now
		e.UpdatedAt = e.CreatedAt
		row, err := r.seal.connectorRow(e)
		if err != nil {
			return nil, err
		}
		if err := c.rows.PutConnector(row); err != nil {
			return nil, err
		}
		c.event("connector.created", e.ID)
		return func() { st.entries[e.ID] = e }, nil
	})
}

// Delete leaves a credential-free tombstone, removes cached tools and provider
// settings, and ends the owner's access windows in the same transaction.
func (r *Repository) Delete(owner, name string) error {
	return r.apply(owner, true, func(c *change, st *state) (func(), error) {
		e, exists := st.entry(owner, name)
		if !exists {
			return nil, fmt.Errorf("upstream %s does not exist", name)
		}
		deleted := e.Lifecycle
		deleted.DeletedAt = c.now
		deleted.UpdatedAt = deleted.DeletedAt
		row, err := r.seal.tombstoneRow(e.ID, owner, deleted)
		if err != nil {
			return nil, err
		}
		if err := c.rows.PutConnector(row); err != nil {
			return nil, err
		}
		if err := c.rows.DeleteDiscovery(owner, name); err != nil {
			return nil, err
		}
		if err := c.rows.DeleteVisibility(owner, name); err != nil {
			return nil, err
		}
		c.event("connector.deleted", e.ID)
		k := catalog.ProviderKey{Owner: owner, Provider: name}
		return func() {
			delete(st.entries, e.ID)
			st.tombstones[e.ID] = tombstone{owner: owner, life: deleted}
			delete(st.discovery, k)
			delete(st.visibility, k)
			delete(st.revisions, k)
		}, nil
	})
}

func (r *Repository) Visibility(owner, provider string) catalog.Visibility {
	st, done := r.view()
	defer done()
	setting, ok := st.visibility[catalog.ProviderKey{Owner: owner, Provider: provider}]
	if !ok {
		return catalog.Visibility{Mode: "all", Enabled: []string{}}
	}
	setting.Enabled = append([]string(nil), setting.Enabled...)
	if setting.Enabled == nil {
		setting.Enabled = []string{}
	}
	return setting
}

func (r *Repository) ToolVisible(owner, provider, tool string) bool {
	st, done := r.view()
	defer done()
	setting, ok := st.visibility[catalog.ProviderKey{Owner: owner, Provider: provider}]
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

func validProvider(owner, provider string) bool {
	return owner != "" && catalog.ValidName(provider)
}

func (st *state) connectorID(owner, provider string) string {
	if e, ok := st.entry(owner, provider); ok {
		return e.ID
	}
	return ""
}

// visibleSet is the part of a visibility setting that decides which tools a
// caller can use.
func visibleSet(v catalog.Visibility, exists bool) (string, []string) {
	if !exists || v.Mode == "all" {
		return "all", nil
	}
	return v.Mode, v.Enabled
}

// securityChange bumps the provider's security revision and ends the pending
// requests and windows of its connector in the same transaction. An old scope
// then no longer matches, even if the change is later undone.
func (c *change) securityChange(st *state, k catalog.ProviderKey) int64 {
	c.end = st.connectorID(k.Owner, k.Provider)
	return st.revisions[k] + 1
}

func (r *Repository) SetVisibility(owner, provider string, setting catalog.Visibility) error {
	if !validProvider(owner, provider) || setting.Mode != "all" && setting.Mode != "selected" {
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
	return r.apply(owner, false, func(c *change, st *state) (func(), error) {
		k := catalog.ProviderKey{Owner: owner, Provider: provider}
		old, exists := st.visibility[k]
		if exists && old.Mode == setting.Mode && slices.Equal(old.Enabled, setting.Enabled) {
			return nil, nil
		}
		setting.Disabled = old.Disabled
		setting.Lifecycle = old.Lifecycle
		touch(&setting.Lifecycle, c.now)
		revision := st.revisions[k]
		oldMode, oldTools := visibleSet(old, exists)
		newMode, newTools := visibleSet(setting, true)
		if oldMode != newMode || !slices.Equal(oldTools, newTools) {
			revision = c.securityChange(st, k)
		}
		row, err := r.seal.visibilityRow(k, setting, revision)
		if err != nil {
			return nil, err
		}
		if err := c.rows.PutVisibility(row); err != nil {
			return nil, err
		}
		c.event("connector.visibility_changed", st.connectorID(owner, provider))
		return func() { st.visibility[k] = setting; st.revisions[k] = revision }, nil
	})
}

func touch(l *catalog.Lifecycle, now time.Time) {
	if l.CreatedAt.IsZero() {
		l.CreatedAt = now
	}
	l.UpdatedAt = now
}

func copyDiscovery(d catalog.Discovery) catalog.Discovery {
	out := catalog.Discovery{UpdatedAt: d.UpdatedAt, Tools: make([]*mcp.Tool, 0, len(d.Tools))}
	for _, tool := range d.Tools {
		if tool == nil {
			continue
		}
		copyTool := *tool
		out.Tools = append(out.Tools, &copyTool)
	}
	return out
}

func (r *Repository) Discovery(owner, name string) (catalog.Discovery, bool) {
	st, done := r.view()
	defer done()
	d, ok := st.discovery[catalog.ProviderKey{Owner: owner, Provider: name}]
	if !ok {
		return catalog.Discovery{}, false
	}
	return copyDiscovery(d), true
}

func (r *Repository) SetDiscovery(owner, name string, tools []*mcp.Tool) error {
	if owner == "" || name == "" {
		return fmt.Errorf("invalid provider")
	}
	return r.apply(owner, false, func(c *change, st *state) (func(), error) {
		k := catalog.ProviderKey{Owner: owner, Provider: name}
		d := copyDiscovery(catalog.Discovery{Tools: tools, UpdatedAt: c.now})
		row, err := r.seal.discoveryRow(k, d)
		if err != nil {
			return nil, err
		}
		if err := c.rows.PutDiscovery(row); err != nil {
			return nil, err
		}
		return func() { st.discovery[k] = d }, nil
	})
}

func (r *Repository) SetProviderEnabled(owner, provider string, enabled bool) error {
	if !validProvider(owner, provider) {
		return fmt.Errorf("invalid provider")
	}
	return r.apply(owner, false, func(c *change, st *state) (func(), error) {
		k := catalog.ProviderKey{Owner: owner, Provider: provider}
		setting, exists := st.visibility[k]
		if setting.Disabled == !enabled {
			return nil, nil
		}
		if !exists {
			setting.Mode = "all"
		}
		setting.Enabled = append([]string(nil), setting.Enabled...)
		setting.Disabled = !enabled
		touch(&setting.Lifecycle, c.now)
		revision := c.securityChange(st, k)
		row, err := r.seal.visibilityRow(k, setting, revision)
		if err != nil {
			return nil, err
		}
		if err := c.rows.PutVisibility(row); err != nil {
			return nil, err
		}
		c.event("connector.availability_changed", st.connectorID(owner, provider))
		return func() { st.visibility[k] = setting; st.revisions[k] = revision }, nil
	})
}

// ConnectorSecurityRevision is the revision access scopes bind for a
// connector. It moves whenever the provider is disabled or enabled or its
// visible tools change.
func (r *Repository) ConnectorSecurityRevision(owner, connectorID string) string {
	st, done := r.view()
	defer done()
	e, ok := st.entries[connectorID]
	if !ok || e.Owner != owner {
		return "1"
	}
	return strconv.FormatInt(st.revisions[catalog.ProviderKey{Owner: owner, Provider: e.Name}]+1, 10)
}

// ---- Accounts ----

func (r *Repository) Account(username string) (catalog.Account, bool) {
	st, done := r.view()
	defer done()
	a, ok := st.accounts[username]
	a.Salt = append([]byte(nil), a.Salt...)
	a.PasswordHash = append([]byte(nil), a.PasswordHash...)
	return a, ok
}

func (r *Repository) AccountOwner(owner string) (catalog.Account, bool) {
	st, done := r.view()
	defer done()
	for _, a := range st.accounts {
		if a.ID == owner {
			return catalog.Account{ID: a.ID, Username: a.Username}, true
		}
	}
	return catalog.Account{}, false
}

func (r *Repository) AccountForToken(hash string) (catalog.Account, bool) {
	record, ok := r.AuthenticateAccess(hash, "api_key")
	if !ok {
		return catalog.Account{}, false
	}
	return r.AccountOwner(record.Owner)
}

func (r *Repository) AddAccount(a catalog.Account) error {
	if a.ID == "" || a.Username == "" {
		return fmt.Errorf("invalid account")
	}
	return r.apply(a.ID, false, func(c *change, st *state) (func(), error) {
		if _, exists := st.accounts[a.Username]; exists {
			return nil, fmt.Errorf("username unavailable")
		}
		for _, other := range st.accounts {
			if other.ID == a.ID {
				return nil, fmt.Errorf("username unavailable")
			}
		}
		a.CreatedAt = c.now
		a.UpdatedAt = a.CreatedAt
		row, err := r.seal.accountRow(a)
		if err != nil {
			return nil, err
		}
		if err := c.rows.PutAccount(row); err != nil {
			if errors.Is(err, catalogdb.ErrConflict) {
				return nil, fmt.Errorf("username unavailable")
			}
			return nil, err
		}
		c.event("account.created", a.ID)
		return func() { st.accounts[a.Username] = a }, nil
	})
}

// ChangePassword swaps the verifier and revokes the owner's other browser
// sessions in one transaction. It does not end access windows.
func (r *Repository) ChangePassword(username string, expected, salt, hash []byte, iterations int, keepSession string) ([]string, error) {
	var ids []string
	a, ok := r.Account(username)
	if !ok {
		return nil, fmt.Errorf("credentials changed")
	}
	err := r.apply(a.ID, false, func(c *change, st *state) (func(), error) {
		old, ok := st.accounts[username]
		if !ok || subtle.ConstantTimeCompare(old.PasswordHash, expected) != 1 {
			return nil, fmt.Errorf("credentials changed")
		}
		next := old
		next.Salt = append([]byte(nil), salt...)
		next.PasswordHash = append([]byte(nil), hash...)
		next.Iterations = iterations
		next.UpdatedAt = c.now
		row, err := r.seal.accountRow(next)
		if err != nil {
			return nil, err
		}
		if err := c.rows.PutAccount(row); err != nil {
			return nil, err
		}
		c.event("account.password_changed", next.ID)
		var publish []func()
		var revoked []string
		for id, record := range st.access {
			if record.Owner == old.ID && record.Kind == "browser" && id != keepSession && record.Active() {
				record.RevokedAt = next.UpdatedAt
				record.UpdatedAt = next.UpdatedAt
				p, err := r.putAccess(c, st, record, "access.revoked")
				if err != nil {
					return nil, err
				}
				publish = append(publish, p)
				revoked = append(revoked, id)
			}
		}
		return func() {
			st.accounts[username] = next
			for _, p := range publish {
				p()
			}
			ids = revoked
		}, nil
	})
	if err != nil {
		return nil, err
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}

// ---- Access records ----

func validAccess(a *catalog.AccessRecord) error {
	if a.Owner == "" || a.SecretHash == "" || len(strings.TrimSpace(a.Name)) == 0 || len(a.Name) > 100 || (a.Role != "admin" && a.Role != "client") || (a.Kind != "api_key" && a.Kind != "browser" && a.Kind != "oauth" && a.Kind != "mcp") {
		return fmt.Errorf("invalid access credential")
	}
	if a.ID == "" {
		a.ID = identity.New()
	}
	if a.Kind == "api_key" && a.PublicID == "" {
		a.PublicID = identity.NewPublicID()
	}
	if a.PublicID != "" && !identity.ValidPublicID(a.PublicID) {
		return fmt.Errorf("invalid access public ID")
	}
	return nil
}

func limitFor(kind string) (int, []string) {
	switch kind {
	case "api_key":
		return catalog.MaxAPIKeys, []string{"api_key"}
	case "mcp":
		return catalog.MaxMCPSessions, []string{"mcp"}
	default:
		return catalog.MaxLoginSessions, []string{"browser", "oauth"}
	}
}

// putAccess writes one access record and returns its publication.
func (r *Repository) putAccess(c *change, st *state, a catalog.AccessRecord, event string) (func(), error) {
	row, err := r.seal.accessRow(a)
	if err != nil {
		return nil, err
	}
	if err := c.rows.PutAccess(row); err != nil {
		return nil, err
	}
	if event != "" {
		c.event(event, a.ID)
	}
	return func() { st.access[a.ID] = a }, nil
}

// addAccess enforces uniqueness and the hard active limit in memory and in the
// owner transaction, then inserts the record. revoking names records this
// transaction already revoked; before publishes them.
func (r *Repository) addAccess(c *change, st *state, a catalog.AccessRecord, revoking map[string]bool, before []func()) (func(), error) {
	touch(&a.Lifecycle, c.now)
	if _, exists := st.access[a.ID]; exists {
		return nil, fmt.Errorf("credential already exists")
	}
	for _, old := range st.access {
		if old.SecretHash == a.SecretHash || a.PublicID != "" && old.PublicID == a.PublicID {
			return nil, fmt.Errorf("credential already exists")
		}
	}
	limit, kinds := limitFor(a.Kind)
	count := 0
	for _, old := range st.access {
		if old.Owner == a.Owner && contains(kinds, old.Kind) && old.Active() && !revoking[old.ID] {
			count++
		}
	}
	if count >= limit {
		return nil, fmt.Errorf("active %s limit reached (%d)", a.Kind, limit)
	}
	stored, err := c.rows.ActiveAccess(a.Owner, kinds, c.now)
	if err != nil {
		return nil, err
	}
	if stored >= limit {
		return nil, fmt.Errorf("active %s limit reached (%d)", a.Kind, limit)
	}
	p, err := r.putAccess(c, st, a, "access.created")
	if err != nil {
		if errors.Is(err, catalogdb.ErrConflict) {
			return nil, fmt.Errorf("credential already exists")
		}
		return nil, err
	}
	return func() {
		for _, b := range before {
			b()
		}
		p()
	}, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (r *Repository) AddAccess(a catalog.AccessRecord) error {
	if err := validAccess(&a); err != nil {
		return err
	}
	return r.apply(a.Owner, false, func(c *change, st *state) (func(), error) {
		return r.addAccess(c, st, a, nil, nil)
	})
}

func (r *Repository) AccessList(owner string) []catalog.AccessRecord {
	st, done := r.view()
	defer done()
	out := []catalog.AccessRecord{}
	for _, a := range st.access {
		if a.Owner == owner {
			a.SecretHash = ""
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (r *Repository) AccessByID(owner, id string) (catalog.AccessRecord, bool) {
	st, done := r.view()
	defer done()
	a, ok := st.access[id]
	a.SecretHash = ""
	if !ok || a.Owner != owner {
		return catalog.AccessRecord{}, false
	}
	return a, true
}

// AuthenticateAccess compares verifiers in constant time. Recording use at
// most once a minute is a committed write; if it fails, authentication fails.
func (r *Repository) AuthenticateAccess(hash, kind string) (catalog.AccessRecord, bool) {
	if r.Failed() {
		return catalog.AccessRecord{}, false
	}
	st, done := r.view()
	var found catalog.AccessRecord
	ok := false
	for _, a := range st.access {
		if subtle.ConstantTimeCompare([]byte(a.SecretHash), []byte(hash)) == 1 && a.Kind == kind && a.Active() {
			found, ok = a, true
			break
		}
	}
	done()
	if !ok {
		return catalog.AccessRecord{}, false
	}
	if time.Since(found.LastUsedAt) >= time.Minute {
		if err := r.touch(found.Owner, found.ID); err != nil {
			return catalog.AccessRecord{}, false
		}
		found, ok = r.AccessByID(found.Owner, found.ID)
		if !ok || !found.Active() {
			return catalog.AccessRecord{}, false
		}
	}
	found.SecretHash = ""
	return found, true
}

func (r *Repository) touch(owner, id string) error {
	return r.apply(owner, false, func(c *change, st *state) (func(), error) {
		a, ok := st.access[id]
		if !ok || a.Owner != owner || !a.Active() {
			return nil, fmt.Errorf("access revoked or expired")
		}
		if time.Since(a.LastUsedAt) < time.Minute {
			return nil, nil
		}
		a.LastUsedAt = c.now
		return r.putAccess(c, st, a, "")
	})
}

func (r *Repository) RevokeAccess(owner, id string) error {
	st, done := r.view()
	a, ok := st.access[id]
	done()
	if !ok || a.Owner != owner {
		return fmt.Errorf("credential not found")
	}
	if !a.RevokedAt.IsZero() {
		return nil
	}
	// Revoking an API key ends the owner's access windows in the same commit.
	return r.apply(owner, a.Kind == "api_key", func(c *change, st *state) (func(), error) {
		a, ok := st.access[id]
		if !ok || a.Owner != owner {
			return nil, fmt.Errorf("credential not found")
		}
		if !a.RevokedAt.IsZero() {
			return nil, nil
		}
		a.RevokedAt = c.now
		a.UpdatedAt = a.RevokedAt
		return r.putAccess(c, st, a, "access.revoked")
	})
}

// ObserveOAuth records tokens already validated by the external issuer.
func (r *Repository) ObserveOAuth(owner, hash, role string, expires time.Time, device ...string) (catalog.AccessRecord, error) {
	var out catalog.AccessRecord
	err := r.apply(owner, false, func(c *change, st *state) (func(), error) {
		for _, a := range st.access {
			if a.Kind != "oauth" || a.SecretHash != hash {
				continue
			}
			if a.Owner != owner || !a.Active() {
				return nil, fmt.Errorf("OAuth access revoked")
			}
			old := a
			a.Role = role
			a.ExpiresAt = expires
			out = a
			out.SecretHash = ""
			if time.Since(a.LastUsedAt) >= time.Minute || a.Role != old.Role {
				a.LastUsedAt = c.now
				a.UpdatedAt = a.LastUsedAt
				out = a
				out.SecretHash = ""
				return r.putAccess(c, st, a, "")
			}
			return nil, nil
		}
		a := catalog.AccessRecord{ID: identity.New(), Owner: owner, Name: "OAuth access", Kind: "oauth", Role: role, SecretHash: hash, ExpiresAt: expires}
		if len(device) > 0 {
			a.Device = device[0]
			if len(a.Device) > 300 {
				a.Device = a.Device[:300]
			}
		}
		a.CreatedAt = c.now
		a.UpdatedAt = c.now
		a.LastUsedAt = a.CreatedAt
		out = a
		out.SecretHash = ""
		return r.addAccess(c, st, a, nil, nil)
	})
	if err != nil {
		return catalog.AccessRecord{}, err
	}
	return out, nil
}

func (r *Repository) UpdateAccess(owner, id, name string, end bool) error {
	if len(name) > 100 {
		return fmt.Errorf("name too long")
	}
	return r.apply(owner, false, func(c *change, st *state) (func(), error) {
		a, ok := st.access[id]
		if !ok || a.Owner != owner {
			return nil, fmt.Errorf("session not found")
		}
		event := "access.renamed"
		if name != "" {
			a.Name = name
		}
		if end {
			a.EndedAt = c.now
			event = "access.ended"
		}
		a.UpdatedAt = c.now
		return r.putAccess(c, st, a, event)
	})
}

// EndStaleSessions ends every open MCP session record, one owner transaction
// per affected owner with an access.ended event each. No MCP session survives
// a restart, so it runs after Load and Attach and before the listener opens,
// as the file store does when it opens.
func (r *Repository) EndStaleSessions() error {
	st, done := r.view()
	open := map[string][]string{}
	for id, a := range st.access {
		if a.Kind == "mcp" && a.EndedAt.IsZero() {
			open[a.Owner] = append(open[a.Owner], id)
		}
	}
	done()
	owners := make([]string, 0, len(open))
	for owner := range open {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		ids := open[owner]
		sort.Strings(ids)
		err := r.apply(owner, false, func(c *change, st *state) (func(), error) {
			var publish []func()
			for _, id := range ids {
				a, ok := st.access[id]
				if !ok || a.Owner != owner || !a.EndedAt.IsZero() {
					continue
				}
				a.EndedAt, a.UpdatedAt = c.now, c.now
				p, err := r.putAccess(c, st, a, "access.ended")
				if err != nil {
					return nil, err
				}
				publish = append(publish, p)
			}
			return func() {
				for _, p := range publish {
					p()
				}
			}, nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) TouchAccess(owner, id string) error {
	st, done := r.view()
	a, ok := st.access[id]
	done()
	if !ok || a.Owner != owner || !a.Active() {
		return fmt.Errorf("access revoked or expired")
	}
	if time.Since(a.LastUsedAt) < time.Minute {
		return nil
	}
	return r.touch(owner, id)
}
