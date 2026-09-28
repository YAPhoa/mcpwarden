package pgcatalog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/catalog/dbcatalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
)

// Sources are the file backend's catalog and history. Import only reads them;
// rollback replaces them with reconciled copies. An empty HistoryPath means the
// file gateway kept no history file.
type Sources struct {
	CatalogPath string
	CatalogKey  string
	HistoryPath string
}

// Options exist for tests: AfterBatch runs after each committed history batch
// and can stop the import to simulate an interruption.
type Options struct {
	BatchLines int
	AfterBatch func(lines int64) error
}

// Manifest summarizes what was imported and verified. It holds counts, IDs,
// paths and digests only, never secrets.
type Manifest struct {
	ImportID            string             `json:"import_id"`
	Snapshot            string             `json:"snapshot"`
	SourceCatalogSHA256 string             `json:"source_catalog_sha256"`
	SourceHistorySHA256 string             `json:"source_history_sha256"`
	SourceHistoryBytes  int64              `json:"source_history_bytes"`
	CatalogDigest       string             `json:"catalog_digest"`
	Normalized          catalog.Normalized `json:"normalized"`
	Accounts            int                `json:"accounts"`
	Access              map[string]int     `json:"access"`
	Connectors          int                `json:"connectors"`
	Tombstones          int                `json:"tombstones"`
	Discovery           int                `json:"discovery"`
	Visibility          int                `json:"visibility"`
	Owners              map[string]Counts  `json:"owners"`
	HistoryLines        int64              `json:"history_lines"`
	HistoryVersions     map[string]int64   `json:"history_versions"`
	HistoryOwners       map[string]int64   `json:"history_owners"`
	VerifiedAt          time.Time          `json:"verified_at"`
}

type Counts struct {
	Access     int `json:"access"`
	Connectors int `json:"connectors"`
	Providers  int `json:"providers"`
}

// RollbackManifest describes a rollback. Reauthorize stays empty: connectors
// no longer hold upstream OAuth grants.
type RollbackManifest struct {
	RollbackID      string    `json:"rollback_id"`
	ImportID        string    `json:"import_id"`
	StaleRequests   int       `json:"stale_requests"`
	SuspendedLeases int       `json:"suspended_leases"`
	CatalogDigest   string    `json:"catalog_digest,omitempty"`
	Reauthorize     []string  `json:"reauthorize_connectors,omitempty"`
	EndedMCP        int       `json:"ended_mcp_sessions"`
	LegacyHistory   int64     `json:"legacy_history_lines"`
	LiveHistory     int64     `json:"live_history_lines"`
	HistorySHA256   string    `json:"history_sha256,omitempty"`
	HistoryBytes    int64     `json:"history_bytes"`
	CompletedAt     time.Time `json:"completed_at,omitzero"`
}

var (
	ErrLocked      = errors.New("a gateway or another migration is running: stop every gateway first")
	ErrState       = errors.New("the catalog is in the wrong state for this step")
	ErrSourceMoved = errors.New("a source file changed since the import started; stop every gateway, run abort, then import again")
	ErrNotEmpty    = errors.New("the target database already has catalog or history rows")
	ErrVerify      = errors.New("verification failed")
	ErrReplaced    = errors.New("a catalog or history file changed after cutover; move it aside (it is not used) and run rollback again")
	ErrMarker      = errors.New("the catalog marker belongs to a migration in another database; run this step against the database that owns it")
	ErrNotExport   = errors.New("the catalog file is not the one the PostgreSQL rollback wrote; restore that file (an older copy could revive revoked access)")
)

const maxLine = 1 << 20

// locks takes the executor advisory lock, so no PostgreSQL gateway runs, and
// the exclusive catalog file lock, so no file gateway runs.
func locks(ctx context.Context, conn *pgx.Conn, src Sources) (func(), error) {
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", postgres.ExecutorLock).Scan(&ok); err != nil {
		return nil, catalogdb.ErrStorage
	}
	if !ok {
		return nil, ErrLocked
	}
	unlockDB := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(cleanup, "SELECT pg_advisory_unlock($1)", postgres.ExecutorLock)
	}
	unlockFile, err := catalog.Lock(src.CatalogPath, true)
	if err != nil {
		unlockDB()
		if errors.Is(err, catalog.ErrCatalogBusy) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() { unlockFile(); unlockDB() }, nil
}

// ownMarker checks, under the exclusive catalog lock, that this database may
// replace the marker beside the catalog: it must be absent or carry this
// database's import (and rollback) ID. With allowPrevious a rolled_back marker
// from an earlier migration is also accepted, since the file is then
// authoritative; it is returned so an abandoned import can restore it. Any
// other marker guards another database's authority, and a new or empty target
// database does not make the file authoritative again.
func ownMarker(src Sources, importID, rollbackID string, allowPrevious bool) (*catalog.Marker, error) {
	m, ok, err := catalog.ReadMarker(src.CatalogPath)
	if err != nil || !ok {
		return nil, err
	}
	if importID != "" && m.ImportID == importID && (m.RollbackID == "" || m.RollbackID == rollbackID) {
		return m.Previous, nil
	}
	if allowPrevious && m.State == "rolled_back" {
		return &m, nil
	}
	return nil, ErrMarker
}

// rollbackExport refuses a catalog that a rolled_back marker does not admit.
// After a rollback only the exported file is authoritative, exactly as
// catalog.Open requires; an older copy could revive revoked access.
func rollbackExport(snap catalog.Snapshot, previous *catalog.Marker) error {
	if previous != nil && snap.Rollback != previous.RollbackID {
		return ErrNotExport
	}
	return nil
}

func prepare(ctx context.Context, conn *pgx.Conn, src Sources) (*dbcatalog.Codec, func(), error) {
	if src.CatalogPath == "" {
		return nil, nil, fmt.Errorf("managed_upstreams.path is required")
	}
	seal, err := dbcatalog.NewCodec(src.CatalogKey)
	if err != nil {
		return nil, nil, err
	}
	unlock, err := locks(ctx, conn, src)
	if err != nil {
		return nil, nil, err
	}
	if err := postgres.CheckSchema(ctx, conn); err != nil {
		unlock()
		return nil, nil, err
	}
	return seal, unlock, nil
}

func inTx(ctx context.Context, conn *pgx.Conn, fn func(pgx.Tx) error) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return catalogdb.ErrStorage
	}
	defer tx.Rollback(context.Background())
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return catalogdb.ErrStorage
	}
	return nil
}

// protected rejects files other users could read or write.
func protected(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be a regular file readable only by its owner (mode 0600)", filepath.Base(path))
	}
	return nil
}

func fileHash(path string) (string, int64, error) {
	var f *os.File
	var err error
	if path != "" {
		f, err = os.Open(path)
	}
	if path == "" || os.IsNotExist(err) {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type sourceHashes struct {
	catalog, history string
	historyBytes     int64
}

func hashFiles(catalogPath, historyPath string) (sourceHashes, error) {
	var h sourceHashes
	for _, p := range []string{catalogPath, historyPath} {
		if err := protected(p); err != nil {
			return h, err
		}
	}
	var err error
	if h.catalog, _, err = fileHash(catalogPath); err != nil {
		return h, err
	}
	h.history, h.historyBytes, err = fileHash(historyPath)
	return h, err
}

func (h sourceHashes) match(st postgres.CatalogState) bool {
	return h.catalog == st.SourceCatalogSHA256 && h.history == st.SourceHistorySHA256 && h.historyBytes == st.SourceHistoryBytes
}

// The protected snapshot is a 0700 directory beside the catalog holding exact
// copies of both source files, taken under the exclusive catalog lock and
// checked against the pinned hashes. Import reads only the copies, and the
// rollback rebuilds history from them. It is kept after the migration.

// SnapshotDir returns the snapshot directory for an import.
func SnapshotDir(src Sources, importID string) string {
	return filepath.Join(filepath.Dir(src.CatalogPath), ".mcpwarden-import-"+importID)
}

func snapshotSources(src Sources, importID string) Sources {
	dir := SnapshotDir(src, importID)
	return Sources{CatalogPath: filepath.Join(dir, "catalog"), CatalogKey: src.CatalogKey, HistoryPath: filepath.Join(dir, "history.jsonl")}
}

// copyFile atomically writes a synced 0600 copy of from (empty if missing).
func copyFile(from, to string) error {
	var in io.Reader = bytes.NewReader(nil)
	if from != "" {
		f, err := os.Open(from)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			defer f.Close()
			in = f
		}
	}
	return writeAtomic(to, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	})
}

func writeAtomic(path string, fill func(io.Writer) error) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".mcpwarden-migrate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = f.Chmod(0600)
	if err == nil {
		err = fill(f)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err == nil {
		err = syncDir(dir)
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// takeSnapshot creates or rechecks the protected snapshot for st.
func takeSnapshot(src Sources, st postgres.CatalogState) (Sources, error) {
	snap := snapshotSources(src, st.ImportID)
	dir := filepath.Dir(snap.CatalogPath)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return snap, err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return snap, fmt.Errorf("snapshot directory must be a 0700 directory")
	}
	if h, err := hashFiles(snap.CatalogPath, snap.HistoryPath); err == nil && h.match(st) {
		return snap, nil
	}
	if err := copyFile(src.CatalogPath, snap.CatalogPath); err != nil {
		return snap, err
	}
	if err := copyFile(src.HistoryPath, snap.HistoryPath); err != nil {
		return snap, err
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return snap, err
	}
	h, err := hashFiles(snap.CatalogPath, snap.HistoryPath)
	if err != nil {
		return snap, err
	}
	if !h.match(st) {
		return snap, ErrSourceMoved
	}
	return snap, nil
}

func empty(ctx context.Context, db postgres.DB) (bool, error) {
	var any bool
	err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mcpwarden_security.catalog_accounts) OR EXISTS (SELECT 1 FROM mcpwarden_security.catalog_access)
        OR EXISTS (SELECT 1 FROM mcpwarden_security.catalog_connectors) OR EXISTS (SELECT 1 FROM mcpwarden_security.catalog_legacy_tombstones)
        OR EXISTS (SELECT 1 FROM mcpwarden_security.catalog_discovery) OR EXISTS (SELECT 1 FROM mcpwarden_security.catalog_visibility)
        OR EXISTS (SELECT 1 FROM mcpwarden_security.history_events) OR EXISTS (SELECT 1 FROM mcpwarden_security.history_tools)
        OR EXISTS (SELECT 1 FROM mcpwarden_security.history_open)`).Scan(&any)
	if err != nil {
		return false, catalogdb.ErrStorage
	}
	return !any, nil
}

// Import copies the file catalog and history into an empty, migrated database
// and verifies the result. It holds the executor lock and the exclusive catalog
// lock, refuses a marker that belongs to another database, pins both source
// files by SHA-256 and reads only a protected snapshot of them. The importing
// marker is written once the import is recorded in this database. The catalog
// is imported in one transaction and history in checkpointed batches: an
// interrupted run resumes from its last committed batch, and a completed one
// only re-verifies.
func Import(ctx context.Context, conn *pgx.Conn, src Sources, opts Options) (Manifest, error) {
	seal, unlock, err := prepare(ctx, conn, src)
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	hashes, err := hashFiles(src.CatalogPath, src.HistoryPath)
	if err != nil {
		return Manifest{}, err
	}
	st, exists, err := postgres.ReadState(ctx, conn, false)
	if err != nil {
		return Manifest{}, err
	}
	if exists {
		if st.State != "importing" && st.State != "imported" {
			return Manifest{}, ErrState
		}
		previous, err := ownMarker(src, st.ImportID, "", true)
		if err != nil {
			return Manifest{}, err
		}
		if !hashes.match(st) {
			return Manifest{}, ErrSourceMoved
		}
		if previous != nil {
			// The pinned source is the file the first run checked; check it
			// again, since a rolled_back marker may still be on disk.
			snap, _, err := catalog.ReadSnapshot(src.CatalogPath, src.CatalogKey, st.StartedAt)
			if err != nil {
				return Manifest{}, err
			}
			if err := rollbackExport(snap, previous); err != nil {
				return Manifest{}, err
			}
		}
		if err := catalog.WriteMarker(src.CatalogPath, catalog.Marker{State: "importing", ImportID: st.ImportID, Previous: previous}); err != nil {
			return Manifest{}, err
		}
		if st.State == "imported" {
			return verify(ctx, conn, seal, src, st)
		}
		if _, err := takeSnapshot(src, st); err != nil {
			return Manifest{}, err
		}
	} else {
		previous, err := ownMarker(src, "", "", true)
		if err != nil {
			return Manifest{}, err
		}
		ok, err := empty(ctx, conn)
		if err != nil {
			return Manifest{}, err
		}
		if !ok {
			return Manifest{}, ErrNotEmpty
		}
		if _, err := os.Stat(src.CatalogPath); err != nil {
			return Manifest{}, fmt.Errorf("catalog file not found")
		}
		st = postgres.CatalogState{State: "importing", ImportID: identity.New(), SourceCatalogSHA256: hashes.catalog, SourceHistorySHA256: hashes.history,
			SourceHistoryBytes: hashes.historyBytes, StartedAt: time.Now().UTC().Truncate(time.Microsecond)}
		snapSrc, err := takeSnapshot(src, st)
		if err != nil {
			return Manifest{}, err
		}
		snap, _, err := catalog.ReadSnapshot(snapSrc.CatalogPath, src.CatalogKey, st.StartedAt)
		if err != nil {
			return Manifest{}, err
		}
		if err := rollbackExport(snap, previous); err != nil {
			return Manifest{}, err
		}
		h := sha256.New()
		if st.HistoryHashState, err = h.(encoding.BinaryMarshaler).MarshalBinary(); err != nil {
			return Manifest{}, err
		}
		if err := inTx(ctx, conn, func(tx pgx.Tx) error {
			if err := postgres.PutState(ctx, tx, st); err != nil {
				return err
			}
			return writeSnapshot(ctx, tx, seal, snap)
		}); err != nil {
			return Manifest{}, err
		}
		// Reload so StartedAt and ChangedAt are exactly what PutState compares.
		if st, _, err = postgres.ReadState(ctx, conn, false); err != nil {
			return Manifest{}, err
		}
		// The marker follows the commit, so an importing marker without state in
		// its database is never this tool's own. The file stays authoritative
		// until cutover: a file gateway that starts after an interruption only
		// makes the resumed import fail its source hash check.
		if err := catalog.WriteMarker(src.CatalogPath, catalog.Marker{State: "importing", ImportID: st.ImportID, Previous: previous}); err != nil {
			return Manifest{}, err
		}
	}
	if err := importHistory(ctx, conn, snapshotSources(src, st.ImportID), &st, opts); err != nil {
		return Manifest{}, err
	}
	m, err := verify(ctx, conn, seal, src, st)
	if err != nil {
		return Manifest{}, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, err
	}
	st.State, st.Manifest = "imported", raw
	if err := postgres.PutState(ctx, conn, st); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func writeSnapshot(ctx context.Context, db postgres.DB, seal *dbcatalog.Codec, snap catalog.Snapshot) error {
	owners := map[string]bool{}
	for _, a := range snap.Accounts {
		owners[a.ID] = true
	}
	for _, r := range snap.Access {
		owners[r.Owner] = true
	}
	for _, e := range snap.Entries {
		owners[e.Owner] = true
	}
	for k := range snap.Discovery {
		owners[k.Owner] = true
	}
	for k := range snap.Visibility {
		owners[k.Owner] = true
	}
	for owner := range owners {
		if err := postgres.EnsureOwner(ctx, db, owner); err != nil {
			return err
		}
	}
	for _, a := range snap.Accounts {
		row, err := seal.AccountRow(a)
		if err == nil {
			err = postgres.PutAccount(ctx, db, row)
		}
		if err != nil {
			return err
		}
	}
	for _, r := range snap.Access {
		row, err := seal.AccessRow(r)
		if err == nil {
			err = postgres.PutAccess(ctx, db, row)
		}
		if err != nil {
			return err
		}
	}
	for _, e := range snap.Entries {
		row, err := seal.ConnectorRow(e)
		if err == nil {
			err = postgres.PutConnector(ctx, db, row)
		}
		if err != nil {
			return err
		}
	}
	for id, life := range snap.Deleted {
		row, err := seal.LegacyTombstoneRow(id, life)
		if err == nil {
			err = postgres.PutTombstone(ctx, db, row)
		}
		if err != nil {
			return err
		}
	}
	for k, d := range snap.Discovery {
		row, err := seal.DiscoveryRow(k, d)
		if err == nil {
			err = postgres.PutDiscovery(ctx, db, row)
		}
		if err != nil {
			return err
		}
	}
	for k, v := range snap.Visibility {
		row, err := seal.VisibilityRow(k, v)
		if err == nil {
			err = postgres.PutVisibility(ctx, db, row)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// lineReader splits JSONL exactly as bufio.ScanLines does (a trailing \r is
// dropped) while tracking byte offsets. Lines over 1 MiB fail, as the reader
// fails. The final line must be terminated, as audit.Open requires.
type lineReader struct {
	r   *bufio.Reader
	off int64
}

func (l *lineReader) next() ([]byte, bool, error) {
	raw, err := l.r.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return nil, false, fmt.Errorf("history line exceeds 1 MiB")
	}
	if err == io.EOF {
		if len(raw) != 0 {
			return nil, false, fmt.Errorf("history has an unterminated final record")
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	l.off += int64(len(raw))
	line := raw[:len(raw)-1]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return bytes.Clone(line), true, nil
}

func openLines(path string, offset int64) (*os.File, *lineReader, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, &lineReader{r: bufio.NewReader(bytes.NewReader(nil))}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, &lineReader{r: bufio.NewReaderSize(f, maxLine+2), off: offset}, nil
}

func importHistory(ctx context.Context, conn *pgx.Conn, snap Sources, st *postgres.CatalogState, opts Options) error {
	batch := opts.BatchLines
	if batch <= 0 {
		batch = 2000
	}
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(st.HistoryHashState); err != nil {
		return ErrState
	}
	f, lines, err := openLines(snap.HistoryPath, st.HistoryBytes)
	if err != nil {
		return err
	}
	if f != nil {
		defer f.Close()
	}
	for {
		var rows []catalogdb.HistoryRow
		start := lines.off
		for len(rows) < batch {
			raw, ok, err := lines.next()
			if err != nil {
				return err
			}
			if !ok {
				break
			}
			n := st.HistoryLines + int64(len(rows)) + 1
			r, err := audit.ParseLine(int(n), raw)
			if err != nil {
				return err
			}
			row := dbcatalog.HistoryRow(r, string(raw))
			row.Source, row.SourceLine = "legacy", n
			rows = append(rows, row)
		}
		if len(rows) == 0 {
			break
		}
		if err := hashRange(h, snap.HistoryPath, start, lines.off); err != nil {
			return err
		}
		next := *st
		next.HistoryLines += int64(len(rows))
		next.HistoryBytes = lines.off
		if next.HistoryHashState, err = h.(encoding.BinaryMarshaler).MarshalBinary(); err != nil {
			return err
		}
		err := inTx(ctx, conn, func(tx pgx.Tx) error {
			for _, row := range rows {
				if err := postgres.InsertHistory(ctx, tx, row); err != nil {
					if errors.Is(err, catalogdb.ErrConflict) {
						return fmt.Errorf("history line %d repeats an event or invocation ID", row.SourceLine)
					}
					return err
				}
			}
			return postgres.PutState(ctx, tx, next)
		})
		if err != nil {
			return err
		}
		*st = next
		if opts.AfterBatch != nil {
			if err := opts.AfterBatch(st.HistoryLines); err != nil {
				return err
			}
		}
	}
	if st.HistoryBytes != st.SourceHistoryBytes || hex.EncodeToString(h.Sum(nil)) != st.SourceHistorySHA256 {
		return ErrSourceMoved
	}
	return nil
}

func hashRange(h hash.Hash, path string, from, to int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return err
	}
	_, err = io.CopyN(h, f, to-from)
	return err
}

// verify compares every imported value with a fresh read of the protected
// snapshot, after checking that it and the original files still match the
// pinned hashes: the whole catalog field by field (ownership, verifiers,
// roles, expiry, timestamps, tombstones, OAuth grants and their revisions) and
// every history line byte for byte with its line number, event ID and order.
func verify(ctx context.Context, conn *pgx.Conn, seal *dbcatalog.Codec, src Sources, st postgres.CatalogState) (Manifest, error) {
	fail := func(format string, args ...any) (Manifest, error) {
		return Manifest{}, fmt.Errorf("%w: %s", ErrVerify, fmt.Sprintf(format, args...))
	}
	snapSrc := snapshotSources(src, st.ImportID)
	unchanged := func() error {
		for _, s := range []Sources{src, snapSrc} {
			h, err := hashFiles(s.CatalogPath, s.HistoryPath)
			if err != nil {
				return err
			}
			if !h.match(st) {
				return ErrSourceMoved
			}
		}
		return nil
	}
	if err := unchanged(); err != nil {
		return Manifest{}, err
	}
	source, normalized, err := catalog.ReadSnapshot(snapSrc.CatalogPath, src.CatalogKey, st.StartedAt)
	if err != nil {
		return Manifest{}, err
	}
	var decoded dbcatalog.Decoded
	m := Manifest{ImportID: st.ImportID, Snapshot: filepath.Dir(snapSrc.CatalogPath), SourceCatalogSHA256: st.SourceCatalogSHA256,
		SourceHistorySHA256: st.SourceHistorySHA256, SourceHistoryBytes: st.SourceHistoryBytes, Normalized: normalized,
		Access: map[string]int{}, Owners: map[string]Counts{}, HistoryVersions: map[string]int64{}, HistoryOwners: map[string]int64{}}
	err = inTx(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil {
			return catalogdb.ErrStorage
		}
		rows, err := postgres.Load(ctx, tx)
		if err != nil {
			return err
		}
		if decoded, err = seal.Decode(rows); err != nil {
			return err
		}
		for _, c := range rows.Connectors {
			if c.GrantRevision != 0 || !c.DeletedAt.IsZero() {
				return fmt.Errorf("%w: connector rows changed after import", ErrVerify)
			}
		}
		f, lines, err := openLines(snapSrc.HistoryPath, 0)
		if err != nil {
			return err
		}
		if f != nil {
			defer f.Close()
		}
		var n int64
		err = postgres.LegacyHistory(ctx, tx, func(got catalogdb.HistoryRow) error {
			raw, ok, err := lines.next()
			if err != nil {
				return err
			}
			n++
			if !ok || got.SourceLine != n || got.Record != string(raw) {
				return fmt.Errorf("%w: history line %d differs", ErrVerify, n)
			}
			r, err := audit.ParseLine(int(n), raw)
			if err != nil {
				return err
			}
			// Queries read the derived columns, not the record: owner, event ID
			// (derived for v0 lines), filters, ordering and timing must all be
			// what the JSONL reader derives from this line.
			want := dbcatalog.HistoryRow(r, string(raw))
			want.Source, want.SourceLine = "legacy", n
			if got != want {
				return fmt.Errorf("%w: history line %d columns differ", ErrVerify, n)
			}
			m.HistoryVersions[fmt.Sprint(r.SchemaVersion)]++
			m.HistoryOwners[r.Owner]++
			return nil
		})
		if err != nil {
			return err
		}
		if _, more, err := lines.next(); err != nil || more {
			return fmt.Errorf("%w: history has lines that were not imported", ErrVerify)
		}
		var live int64
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM mcpwarden_security.history_events WHERE source='live'").Scan(&live); err != nil {
			return catalogdb.ErrStorage
		}
		if n != st.HistoryLines || live != 0 {
			return fmt.Errorf("%w: history row count", ErrVerify)
		}
		m.HistoryLines = n
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	if decoded.Tombstones != 0 {
		return fail("unexpected connector tombstones")
	}
	if decoded.Revisions != 0 {
		return fail("unexpected provider security revisions")
	}
	same, err := dbcatalog.SameSnapshot(source, decoded.Snapshot)
	if err != nil {
		return Manifest{}, err
	}
	if !same {
		return fail("catalog records differ from the source file")
	}
	if m.CatalogDigest, err = snapshotDigest(seal, source); err != nil {
		return Manifest{}, err
	}
	m.Accounts, m.Connectors, m.Tombstones = len(source.Accounts), len(source.Entries), len(source.Deleted)
	m.Discovery, m.Visibility = len(source.Discovery), len(source.Visibility)
	for _, r := range source.Access {
		m.Access[r.Kind]++
		c := m.Owners[r.Owner]
		c.Access++
		m.Owners[r.Owner] = c
	}
	for _, e := range source.Entries {
		c := m.Owners[e.Owner]
		c.Connectors++
		m.Owners[e.Owner] = c
	}
	for k := range source.Visibility {
		c := m.Owners[k.Owner]
		c.Providers++
		m.Owners[k.Owner] = c
	}
	if err := unchanged(); err != nil {
		return Manifest{}, err
	}
	m.VerifiedAt = time.Now().UTC()
	return m, nil
}

// snapshotDigest is a keyed digest of the whole catalog, so the manifest can
// pin it without being a guessable hash of verifiers.
func snapshotDigest(seal *dbcatalog.Codec, snap catalog.Snapshot) (string, error) {
	raw, err := snap.Canonical()
	if err != nil {
		return "", err
	}
	defer clear(raw)
	h := hmac.New(sha256.New, seal.MAC())
	h.Write([]byte("snapshot\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Status returns the current state and its manifests.
func Status(ctx context.Context, conn *pgx.Conn) (postgres.CatalogState, bool, error) {
	return postgres.ReadState(ctx, conn, false)
}

// Cutover makes PostgreSQL authoritative. It re-verifies the import against
// the untouched sources and snapshot, marks the database active, then writes
// the active marker. Repeating it after success only rewrites the marker.
func Cutover(ctx context.Context, conn *pgx.Conn, src Sources) (Manifest, error) {
	seal, unlock, err := prepare(ctx, conn, src)
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	st, exists, err := postgres.ReadState(ctx, conn, false)
	if err != nil {
		return Manifest{}, err
	}
	if !exists {
		return Manifest{}, ErrState
	}
	if _, err := ownMarker(src, st.ImportID, "", false); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	switch st.State {
	case "imported":
		if m, err = verify(ctx, conn, seal, src, st); err != nil {
			return Manifest{}, err
		}
		var recorded Manifest
		if json.Unmarshal(st.Manifest, &recorded) != nil || recorded.CatalogDigest != m.CatalogDigest || recorded.HistoryLines != m.HistoryLines {
			return Manifest{}, fmt.Errorf("%w: manifest differs from the imported rows", ErrVerify)
		}
		st.State = "active"
		if err := postgres.PutState(ctx, conn, st); err != nil {
			return Manifest{}, err
		}
	case "active":
		if json.Unmarshal(st.Manifest, &m) != nil {
			return Manifest{}, ErrState
		}
	default:
		return Manifest{}, ErrState
	}
	if err := catalog.WriteMarker(src.CatalogPath, catalog.Marker{State: "active", ImportID: st.ImportID}); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Abort abandons an import that was never cut over: it deletes the imported
// rows, restores the marker the import replaced (or removes its own), then
// deletes the state. The state row stays, marked aborting, until the marker is
// cleaned up, so an interrupted abort is finished by running it again and a
// marker is only ever cleaned up by the database that owns it. The protected
// snapshot is kept.
func Abort(ctx context.Context, conn *pgx.Conn, src Sources) error {
	_, unlock, err := prepare(ctx, conn, src)
	if err != nil {
		return err
	}
	defer unlock()
	st, exists, err := postgres.ReadState(ctx, conn, false)
	if err != nil {
		return err
	}
	if !exists {
		// Rows without state cannot be an import this tool started, and a
		// marker here is not this database's.
		if clean, err := empty(ctx, conn); err != nil {
			return err
		} else if !clean {
			return ErrNotEmpty
		}
		if _, err := ownMarker(src, "", "", true); err != nil {
			return err
		}
		return nil
	}
	if st.State != "importing" && st.State != "imported" && st.State != "aborting" {
		return ErrState
	}
	if _, err := ownMarker(src, st.ImportID, "", true); err != nil {
		return err
	}
	marker, ours, err := catalog.ReadMarker(src.CatalogPath)
	if err != nil {
		return err
	}
	err = inTx(ctx, conn, func(tx pgx.Tx) error {
		for _, table := range []string{"history_events", "history_tools", "history_open", "catalog_discovery", "catalog_visibility", "catalog_legacy_tombstones", "catalog_connectors", "catalog_access", "catalog_accounts"} {
			if _, err := tx.Exec(ctx, "DELETE FROM mcpwarden_security."+table); err != nil {
				return catalogdb.ErrStorage
			}
		}
		st.State = "aborting"
		return postgres.PutState(ctx, tx, st)
	})
	if err != nil {
		return err
	}
	// Without its own marker the import was interrupted before writing one, or
	// an earlier abort already cleaned it up; any marker in place is then the
	// earlier rolled_back one.
	if ours && marker.ImportID == st.ImportID {
		if marker.Previous != nil {
			err = catalog.WriteMarker(src.CatalogPath, *marker.Previous)
		} else {
			err = catalog.RemoveMarker(src.CatalogPath)
		}
		if err != nil {
			return err
		}
	}
	if _, err := conn.Exec(ctx, "DELETE FROM mcpwarden_security.catalog_state WHERE import_id=$1", st.ImportID); err != nil {
		return catalogdb.ErrStorage
	}
	return nil
}
