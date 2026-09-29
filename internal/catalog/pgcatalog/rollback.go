package pgcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/catalog/dbcatalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
	"github.com/yaphoa/mcpwarden/internal/lease/postgres"
)

// Rollback returns authority to the file backend after a cutover without
// reviving anything PostgreSQL revoked. With every gateway stopped (it holds
// the executor lock and the exclusive catalog lock) it:
//
//  1. marks the database rolling_back, so no PostgreSQL gateway can load it,
//     and in the same transaction makes pending requests stale and suspends
//     active leases, with security events under the rollback ID;
//  2. exports the current PostgreSQL catalog, not the pre-cutover file:
//     revoked keys, ended sessions and changed passwords stay that way, and
//     MCP sessions are ended;
//  3. rebuilds history as the verified pre-cutover bytes followed by every
//     record written after cutover, in commit order;
//  4. reads both files back and compares them with the database;
//  5. marks the database rolled_back, then writes the rolled_back marker that
//     lets only this exported file start.
//
// An interrupted rollback is resumed by running it again; a finished one only
// re-verifies the files and rewrites the marker.
func Rollback(ctx context.Context, conn *pgx.Conn, src Sources) (RollbackManifest, error) {
	seal, unlock, err := prepare(ctx, conn, src)
	if err != nil {
		return RollbackManifest{}, err
	}
	defer unlock()
	st, exists, err := postgres.ReadState(ctx, conn, false)
	if err != nil {
		return RollbackManifest{}, err
	}
	if !exists {
		return RollbackManifest{}, ErrState
	}
	if _, err := ownMarker(src, st.ImportID, st.RollbackID, false); err != nil {
		return RollbackManifest{}, err
	}
	switch st.State {
	case "active":
		if st, err = beginRollback(ctx, conn, st); err != nil {
			return RollbackManifest{}, err
		}
	case "rolling_back":
	case "rolled_back":
		return finishedRollback(src, st)
	default:
		return RollbackManifest{}, ErrState
	}
	if err := catalog.WriteMarker(src.CatalogPath, catalog.Marker{State: "rolling_back", ImportID: st.ImportID, RollbackID: st.RollbackID}); err != nil {
		return RollbackManifest{}, err
	}
	var m RollbackManifest
	if json.Unmarshal(st.RollbackManifest, &m) != nil || m.RollbackID != st.RollbackID {
		return RollbackManifest{}, ErrState
	}
	if err := export(ctx, conn, seal, src, st, &m); err != nil {
		return RollbackManifest{}, err
	}
	m.CompletedAt = time.Now().UTC()
	raw, err := json.Marshal(m)
	if err != nil {
		return RollbackManifest{}, err
	}
	st.State, st.RollbackManifest = "rolled_back", raw
	if err := postgres.PutState(ctx, conn, st); err != nil {
		return RollbackManifest{}, err
	}
	if err := catalog.WriteMarker(src.CatalogPath, catalog.Marker{State: "rolled_back", ImportID: st.ImportID, RollbackID: st.RollbackID}); err != nil {
		return RollbackManifest{}, err
	}
	return m, nil
}

func beginRollback(ctx context.Context, conn *pgx.Conn, st postgres.CatalogState) (postgres.CatalogState, error) {
	id := identity.New()
	err := inTx(ctx, conn, func(tx pgx.Tx) error {
		current, ok, err := postgres.ReadState(ctx, tx, true)
		if err != nil {
			return err
		}
		if !ok || current.State != "active" || current.ImportID != st.ImportID {
			return ErrState
		}
		stale, suspended, err := postgres.Quiesce(ctx, tx, id)
		if err != nil {
			return catalogdb.ErrStorage
		}
		raw, err := json.Marshal(RollbackManifest{RollbackID: id, ImportID: st.ImportID, StaleRequests: stale, SuspendedLeases: suspended})
		if err != nil {
			return err
		}
		current.State, current.RollbackID, current.RollbackManifest = "rolling_back", id, raw
		return postgres.PutState(ctx, tx, current)
	})
	if err != nil {
		return st, err
	}
	st, _, err = postgres.ReadState(ctx, conn, false)
	return st, err
}

// base returns the pre-cutover history: the protected snapshot copy, or the
// original file if the copy is gone, whichever still matches the pinned hash.
func base(src Sources, st postgres.CatalogState) (string, error) {
	for _, path := range []string{snapshotSources(src, st.ImportID).HistoryPath, src.HistoryPath} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if protected(path) != nil {
			continue
		}
		sum, n, err := fileHash(path)
		if err == nil && sum == st.SourceHistorySHA256 && n == st.SourceHistoryBytes {
			return path, nil
		}
	}
	if st.SourceHistoryBytes == 0 {
		return "", nil
	}
	return "", fmt.Errorf("the pre-cutover history is gone: restore %s from the protected backup", SnapshotDir(src, st.ImportID))
}

// replaceable reports whether an existing target may be overwritten: it is
// missing, still the pre-cutover source, or a file this rollback wrote.
func replaceable(path, sourceSHA string, sourceBytes int64, ours func(string) bool) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	if err := protected(path); err != nil {
		return err
	}
	sum, n, err := fileHash(path)
	if err != nil {
		return err
	}
	if sum == sourceSHA && (sourceBytes < 0 || n == sourceBytes) || ours(sum) {
		return nil
	}
	return ErrReplaced
}

func export(ctx context.Context, conn *pgx.Conn, seal *dbcatalog.Codec, src Sources, st postgres.CatalogState, m *RollbackManifest) error {
	if src.HistoryPath == "" {
		return fmt.Errorf("audit.path must name the history file to roll back into")
	}
	basePath, err := base(src, st)
	if err != nil {
		return err
	}
	at := st.ChangedAt.Truncate(time.Microsecond)
	var snap catalog.Snapshot
	var legacy, live int64
	var tail []string
	err = inTx(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil {
			return catalogdb.ErrStorage
		}
		rows, err := postgres.Load(ctx, tx)
		if err != nil {
			return err
		}
		decoded, err := seal.Decode(rows)
		if err != nil {
			return err
		}
		snap = decoded.Snapshot
		// Connectors hold no upstream OAuth grants any more, so none needs
		// reauthorization.
		m.Reauthorize, m.EndedMCP = nil, 0
		for i, a := range snap.Access {
			if a.Kind == "mcp" && a.EndedAt.IsZero() {
				a.EndedAt, a.UpdatedAt = at, at
				snap.Access[i] = a
				m.EndedMCP++
			}
		}
		snap.Rollback = st.RollbackID
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM mcpwarden_security.history_events WHERE source='legacy'").Scan(&legacy); err != nil {
			return catalogdb.ErrStorage
		}
		return postgres.LiveHistory(ctx, tx, func(seq int64, raw string) error {
			live++
			if _, err := audit.ParseLine(int(legacy+live), []byte(raw)); err != nil {
				return fmt.Errorf("%w: stored history record %d is invalid", ErrVerify, seq)
			}
			tail = append(tail, raw)
			return nil
		})
	})
	if err != nil {
		return err
	}
	if legacy != st.HistoryLines {
		return fmt.Errorf("%w: imported history rows changed", ErrVerify)
	}
	m.LegacyHistory, m.LiveHistory = legacy, live
	expected, err := snap.Canonical()
	if err != nil {
		return err
	}
	defer clear(expected)
	if m.CatalogDigest, err = snapshotDigest(seal, snap); err != nil {
		return err
	}

	// Catalog: overwrite only the pre-cutover file or an earlier export of
	// this same rollback, so a file someone put back is never silently lost.
	ours := func(string) bool {
		existing, _, err := catalog.ReadSnapshot(src.CatalogPath, src.CatalogKey, at)
		return err == nil && existing.Rollback == st.RollbackID
	}
	if err := replaceable(src.CatalogPath, st.SourceCatalogSHA256, -1, ours); err != nil {
		return err
	}
	if err := catalog.WriteSnapshot(src.CatalogPath, src.CatalogKey, snap); err != nil {
		return err
	}

	// History: the pinned bytes, then every post-cutover record.
	h := sha256.New()
	var written int64
	fill := func(w io.Writer) error {
		out := io.MultiWriter(w, h)
		if basePath != "" {
			f, err := os.Open(basePath)
			if err != nil {
				return err
			}
			defer f.Close()
			check := sha256.New()
			n, err := io.Copy(io.MultiWriter(out, check), f)
			if err != nil {
				return err
			}
			if n != st.SourceHistoryBytes || hex.EncodeToString(check.Sum(nil)) != st.SourceHistorySHA256 {
				return ErrSourceMoved
			}
			written += n
		}
		for _, raw := range tail {
			n, err := io.WriteString(out, raw+"\n")
			if err != nil {
				return err
			}
			written += int64(n)
		}
		return nil
	}
	sum, err := expectedHistory(basePath, tail)
	if err != nil {
		return err
	}
	if err := replaceable(src.HistoryPath, st.SourceHistorySHA256, st.SourceHistoryBytes, func(s string) bool { return s == sum }); err != nil {
		return err
	}
	if err := writeAtomic(src.HistoryPath, fill); err != nil {
		return err
	}
	m.HistorySHA256, m.HistoryBytes = hex.EncodeToString(h.Sum(nil)), written
	if m.HistorySHA256 != sum {
		return fmt.Errorf("%w: history export changed while written", ErrVerify)
	}
	return checkExport(src, st, expected, m)
}

func expectedHistory(basePath string, tail []string) (string, error) {
	h := sha256.New()
	if basePath != "" {
		if err := copyInto(h, basePath); err != nil {
			return "", err
		}
	}
	for _, raw := range tail {
		io.WriteString(h, raw+"\n")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyInto(h hash.Hash, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(h, f)
	return err
}

// checkExport reads both files back the way a file gateway will.
func checkExport(src Sources, st postgres.CatalogState, expected []byte, m *RollbackManifest) error {
	read, normalized, err := catalog.ReadSnapshot(src.CatalogPath, src.CatalogKey, st.ChangedAt)
	if err != nil {
		return err
	}
	if read.Rollback != st.RollbackID || normalized.EndedMCPSessions != 0 {
		return fmt.Errorf("%w: exported catalog", ErrVerify)
	}
	got, err := read.Canonical()
	if err != nil {
		return err
	}
	defer clear(got)
	if string(got) != string(expected) {
		return fmt.Errorf("%w: exported catalog differs from PostgreSQL", ErrVerify)
	}
	sum, n, err := fileHash(src.HistoryPath)
	if err != nil {
		return err
	}
	if sum != m.HistorySHA256 || n != m.HistoryBytes {
		return fmt.Errorf("%w: exported history", ErrVerify)
	}
	// audit.Open parses every line and refuses duplicates or a torn tail.
	w, err := audit.Open(src.HistoryPath)
	if err != nil {
		return fmt.Errorf("%w: exported history: %v", ErrVerify, err)
	}
	return w.Close()
}

// finishedRollback confirms the catalog file is the rollback export (the file
// gateway may have changed its contents since) and rewrites the marker.
func finishedRollback(src Sources, st postgres.CatalogState) (RollbackManifest, error) {
	var m RollbackManifest
	if json.Unmarshal(st.RollbackManifest, &m) != nil {
		return m, ErrState
	}
	read, _, err := catalog.ReadSnapshot(src.CatalogPath, src.CatalogKey, time.Now().UTC())
	if err != nil {
		return m, err
	}
	if read.Rollback != st.RollbackID {
		return m, errors.New("the catalog file is not the rollback export; restore the file the rollback wrote")
	}
	if err := catalog.WriteMarker(src.CatalogPath, catalog.Marker{State: "rolled_back", ImportID: st.ImportID, RollbackID: st.RollbackID}); err != nil {
		return m, err
	}
	return m, nil
}
