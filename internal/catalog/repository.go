package catalog

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Repository is the persistence boundary for user-owned gateway state.
//
// Implementations must be safe for concurrent use, preserve owner isolation,
// return defensive copies from read methods, and make each mutation durable
// before returning success. Secret-bearing fields (password material and access
// hashes) must be protected at rest and must never be logged. Connector
// credentials are never stored here; they live in the owner's vault.
// Implementations backed by a transactional database should enforce uniqueness
// and active-access limits in the same transaction as the corresponding write.
//
// Read methods intentionally do not return storage errors because some are used
// in synchronous MCP visibility callbacks. A remote-database implementation
// must therefore load a coherent view before it is made available, serve reads
// from that view, and return connectivity/commit failures from mutations. It
// must not translate database read failures into empty or cross-owner results.
//
// Close releases backend resources. It must be safe to call once after all
// users of the repository have stopped.
type Repository interface {
	Close() error

	List(owner string) []Entry
	Add(Entry) error
	Delete(owner, name string) error
	Visibility(owner, provider string) Visibility
	ToolVisible(owner, provider, tool string) bool
	SetVisibility(owner, provider string, setting Visibility) error
	Discovery(owner, name string) (Discovery, bool)
	SetDiscovery(owner, name string, tools []*mcp.Tool) error
	SetProviderEnabled(owner, provider string, enabled bool) error

	Account(username string) (Account, bool)
	AccountOwner(owner string) (Account, bool)
	AccountForToken(hash string) (Account, bool)
	AddAccount(Account) error
	ChangePassword(username string, expected, salt, hash []byte, iterations int, keepSession string) ([]string, error)

	AddAccess(AccessRecord) error
	AccessList(owner string) []AccessRecord
	AccessByID(owner, id string) (AccessRecord, bool)
	AuthenticateAccess(hash, kind string) (AccessRecord, bool)
	RevokeAccess(owner, id string) error
	ObserveOAuth(owner, hash, role string, expires time.Time, device ...string) (AccessRecord, error)
	UpdateAccess(owner, id, name string, end bool) error
	TouchAccess(owner, id string) error
}
