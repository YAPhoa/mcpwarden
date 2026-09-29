//go:build windows

package sqlite

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func filesystem(dir string) (string, fsKind, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fsUnknown, err
	}
	root := filepath.VolumeName(abs) + `\`
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return "", fsUnknown, err
	}
	switch windows.GetDriveType(p) {
	case windows.DRIVE_REMOTE:
		return "remote drive", fsRemote, nil
	case windows.DRIVE_FIXED:
		return "", fsLocal, nil
	}
	return "", fsUnknown, nil
}
