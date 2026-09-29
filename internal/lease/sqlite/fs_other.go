//go:build !linux && !darwin && !windows

package sqlite

func filesystem(string) (string, fsKind, error) { return "", fsUnknown, nil }
