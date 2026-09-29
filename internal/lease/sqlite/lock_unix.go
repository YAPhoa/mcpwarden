//go:build unix

package sqlite

import (
	"errors"
	"os"
	"syscall"
)

// lockFile holds an flock on <path>.lock. The kernel releases it when the
// process exits, so a crash never leaves a stale lock.
type lockFile struct{ f *os.File }

func openLock(path string) (*lockFile, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return &lockFile{f: f}, nil
}

// try takes the lock without waiting. It returns errBusy when another
// process holds it in a conflicting mode.
func (l *lockFile) try(exclusive bool) error {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	err := syscall.Flock(int(l.f.Fd()), how|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return errBusy
	}
	return err
}

// unlock releases the lock and keeps the descriptor open.
func (l *lockFile) unlock() error { return syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN) }

func (l *lockFile) close() error { return l.f.Close() }

func (l *lockFile) stat() (os.FileInfo, error) { return l.f.Stat() }
