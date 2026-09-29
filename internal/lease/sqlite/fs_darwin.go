//go:build darwin

package sqlite

import (
	"strings"

	"golang.org/x/sys/unix"
)

func filesystem(dir string) (string, fsKind, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return "", fsUnknown, err
	}
	name := unix.ByteSliceToString(st.Fstypename[:])
	k := classifyName(name)
	return name, k, nil
}

func classifyName(name string) fsKind {
	switch {
	case name == "nfs" || name == "smbfs" || name == "afpfs" || name == "webdav" || strings.Contains(name, "fuse"):
		return fsRemote
	case name == "apfs" || name == "hfs":
		return fsLocal
	}
	return fsUnknown
}
