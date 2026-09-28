package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
)

// CatalogState is the single catalog_state row: which store is authoritative, and the
// import's source identity and history checkpoint.
type CatalogState struct {
	State               string
	ImportID            string
	SourceCatalogSHA256 string
	SourceHistorySHA256 string
	SourceHistoryBytes  int64
	HistoryLines        int64
	HistoryBytes        int64
	HistoryHashState    []byte
	Manifest            []byte
	RollbackID          string
	RollbackManifest    []byte
	StartedAt           time.Time
	ChangedAt           time.Time
}

// ReadState returns ok=false when no import has started.
func ReadState(ctx context.Context, db DB, lock bool) (CatalogState, bool, error) {
	var s CatalogState
	var rollback *string
	sql := `SELECT state,import_id::text,source_catalog_sha256,source_history_sha256,source_history_bytes,history_lines,history_bytes,
        history_sha256_state,manifest,rollback_id::text,rollback_manifest,started_at,changed_at FROM mcpwarden_security.catalog_state`
	if lock {
		sql += " FOR UPDATE"
	}
	err := db.QueryRow(ctx, sql).Scan(&s.State, &s.ImportID, &s.SourceCatalogSHA256, &s.SourceHistorySHA256, &s.SourceHistoryBytes,
		&s.HistoryLines, &s.HistoryBytes, &s.HistoryHashState, &s.Manifest, &rollback, &s.RollbackManifest, &s.StartedAt, &s.ChangedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CatalogState{}, false, nil
	}
	if err != nil {
		return CatalogState{}, false, catalogdb.ErrStorage
	}
	if rollback != nil {
		s.RollbackID = *rollback
	}
	s.StartedAt, s.ChangedAt = s.StartedAt.UTC(), s.ChangedAt.UTC()
	return s, true, nil
}

// PutState writes the whole row. Only the migration role may call it.
func PutState(ctx context.Context, db DB, s CatalogState) error {
	var manifest, rollbackManifest, hashState any
	if s.Manifest != nil {
		manifest = s.Manifest
	}
	if s.RollbackManifest != nil {
		rollbackManifest = s.RollbackManifest
	}
	if s.HistoryHashState != nil {
		hashState = s.HistoryHashState
	}
	tag, err := db.Exec(ctx, `INSERT INTO mcpwarden_security.catalog_state
        (singleton,state,import_id,source_catalog_sha256,source_history_sha256,source_history_bytes,history_lines,history_bytes,
         history_sha256_state,manifest,rollback_id,rollback_manifest,started_at,changed_at)
        VALUES (true,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp())
        ON CONFLICT (singleton) DO UPDATE SET state=excluded.state,import_id=excluded.import_id,
        source_catalog_sha256=excluded.source_catalog_sha256,source_history_sha256=excluded.source_history_sha256,
        source_history_bytes=excluded.source_history_bytes,history_lines=excluded.history_lines,history_bytes=excluded.history_bytes,
        history_sha256_state=excluded.history_sha256_state,manifest=excluded.manifest,rollback_id=excluded.rollback_id,
        rollback_manifest=excluded.rollback_manifest,changed_at=excluded.changed_at
        WHERE catalog_state.import_id=excluded.import_id AND catalog_state.started_at=excluded.started_at`,
		s.State, s.ImportID, s.SourceCatalogSHA256, s.SourceHistorySHA256, s.SourceHistoryBytes, s.HistoryLines, s.HistoryBytes,
		hashState, manifest, text(s.RollbackID), rollbackManifest, s.StartedAt)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() != 1 {
		return catalogdb.ErrConflict
	}
	return nil
}

// ReadCatalogState reads the state row on the executor session.
func (s *Store) ReadCatalogState(ctx context.Context) (CatalogState, bool, error) {
	var st CatalogState
	var ok bool
	err := s.run(ctx, ownerDeadline, func(ctx context.Context, db DB) error {
		var err error
		st, ok, err = ReadState(ctx, db, false)
		return err
	})
	return st, ok, err
}
