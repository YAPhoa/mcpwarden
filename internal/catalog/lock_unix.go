//go:build unix

package catalog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ErrCatalogBusy means another process holds the catalog lock in a
// conflicting mode: a migration while a gateway starts, or a gateway while a
// migration starts.
var ErrCatalogBusy = errors.New("catalog is in use by another process")

// LockPath is the lock file beside the catalog. File gateways hold it shared
// for their lifetime; catalog migration holds it exclusively.
func LockPath(path string) string { return path + ".lock" }

// Lock takes the catalog lock without waiting. The returned function releases it.
func Lock(path string, exclusive bool) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create managed upstream directory: %w", err)
	}
	f, err := os.OpenFile(LockPath(path), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("open catalog lock: %w", err)
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrCatalogBusy
		}
		return nil, fmt.Errorf("lock catalog: %w", err)
	}
	return func() { f.Close() }, nil
}
