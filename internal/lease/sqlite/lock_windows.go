//go:build windows

package sqlite

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// lockFile holds a LockFileEx byte-range lock on <path>.lock, released when
// the handle closes or the process exits.
type lockFile struct {
	f    *os.File
	held bool
}

func openLock(path string) (*lockFile, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("lock file is a symbolic link")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	return &lockFile{f: f}, nil
}

func (l *lockFile) try(exclusive bool) error {
	if l.held {
		// LockFileEx does not convert a lock; release it first.
		ol := new(windows.Overlapped)
		_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, ol)
		l.held = false
	}
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(l.f.Fd()), flags, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errBusy
	}
	if err == nil {
		l.held = true
	}
	return err
}

func (l *lockFile) close() error { return l.f.Close() }

func (l *lockFile) stat() (os.FileInfo, error) { return l.f.Stat() }
