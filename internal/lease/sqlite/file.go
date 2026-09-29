package sqlite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type fsKind int

const (
	fsUnknown fsKind = iota
	fsLocal
	fsRemote
)

var errBusy = errors.New("lock held by another process")

// checkPath refuses paths the driver would read as a URI or options, and a
// database on a network or FUSE filesystem. It creates the parent directory
// 0700. warn receives a note about an unrecognized filesystem.
func checkPath(path string, warn func(string)) (string, error) {
	if path == "" || strings.ContainsAny(path, "?#") || strings.HasPrefix(path, "file:") || path == ":memory:" {
		return "", errors.New("storage.path must be a plain file path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("storage.path is invalid")
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", errors.New("storage directory could not be created")
	}
	name, kind, err := filesystem(dir)
	if err != nil {
		return "", errors.New("storage directory filesystem could not be checked")
	}
	switch kind {
	case fsRemote:
		return "", fmt.Errorf("storage.path is on a %s filesystem; SQLite needs a local filesystem", name)
	case fsUnknown:
		if warn != nil {
			warn("storage.path is on an unrecognized filesystem; SQLite needs a local filesystem with working file locks")
		}
	}
	return abs, nil
}

// prepareFile creates a missing database 0600 with O_EXCL before the driver
// opens it, and refuses a symbolic link, a non-regular file or one that group
// or other users can access. The creating descriptor is closed before the
// driver opens the file, and nothing else in mcpwarden opens the database
// files: closing any other descriptor for them would drop SQLite's POSIX
// locks.
func prepareFile(path string) (os.FileInfo, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, errors.New("storage database could not be created")
		}
		if err := f.Close(); err != nil {
			return nil, errors.New("storage database could not be created")
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("storage database could not be read")
	}
	if err := safeFile(info); err != nil {
		return nil, err
	}
	return info, nil
}

func safeFile(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("storage.path is a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return errors.New("storage.path is not a regular file")
	}
	// Windows reports synthetic permission bits; its ACLs are the boundary.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("storage database must not be accessible to group or other users (chmod 600)")
	}
	return nil
}

// sameFile reports whether path still names the file that was opened.
func sameFile(path string, opened os.FileInfo) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && os.SameFile(info, opened)
}
