package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// tx wraps one executor transaction and reproduces PostgreSQL's aborted
// transaction rule: after the first statement error, every later statement
// fails without running, and COMMIT is refused. A guard violation that a
// caller mishandles therefore never commits the rest of the change, and no
// statement runs in autocommit after SQLite has silently ended the
// transaction.
type tx struct {
	ctx context.Context
	tx  *sql.Tx
	err error // the first statement error
}

func (t *tx) fail(err error) error {
	if t.err == nil {
		t.err = err
	}
	return err
}

func (t *tx) exec(query string, args ...any) (int64, error) {
	if t.err != nil {
		return 0, errPoisoned
	}
	r, err := t.tx.ExecContext(t.ctx, query, args...)
	if err != nil {
		return 0, t.fail(err)
	}
	n, err := r.RowsAffected()
	if err != nil {
		return 0, t.fail(err)
	}
	return n, nil
}

// queryRow scans one row. sql.ErrNoRows is returned as is and is not a
// statement error, as in PostgreSQL.
func (t *tx) queryRow(query string, args []any, dest ...any) error {
	if t.err != nil {
		return errPoisoned
	}
	err := t.tx.QueryRowContext(t.ctx, query, args...).Scan(dest...)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return t.fail(err)
	}
	return err
}

// query calls scan for each row.
func (t *tx) query(query string, args []any, scan func(*sql.Rows) error) error {
	if t.err != nil {
		return errPoisoned
	}
	rows, err := t.tx.QueryContext(t.ctx, query, args...)
	if err != nil {
		return t.fail(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return t.fail(err)
		}
	}
	if err := rows.Err(); err != nil {
		return t.fail(err)
	}
	if err := rows.Close(); err != nil {
		return t.fail(err)
	}
	return nil
}

// Timestamps are INTEGER Unix microseconds, PostgreSQL's precision.

func micros(t time.Time) int64 { return t.UnixMicro() }

func optMicros(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMicro()
}

func fromMicros(v int64) time.Time { return time.UnixMicro(v).UTC() }

func fromOptMicros(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return fromMicros(v.Int64)
}

func optText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
