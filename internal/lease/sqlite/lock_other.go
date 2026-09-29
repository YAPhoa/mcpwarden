//go:build !unix && !windows

package sqlite

import (
	"errors"
	"os"
)

// Other platforms have no process lock mcpwarden trusts, so the store refuses
// to start there.
type lockFile struct{}

func openLock(string) (*lockFile, error) {
	return nil, errors.New("SQLite storage needs a Unix or Windows host")
}

func (l *lockFile) try(bool) error             { return errors.New("unsupported platform") }
func (l *lockFile) unlock() error              { return nil }
func (l *lockFile) close() error               { return nil }
func (l *lockFile) stat() (os.FileInfo, error) { return nil, errors.New("unsupported platform") }
