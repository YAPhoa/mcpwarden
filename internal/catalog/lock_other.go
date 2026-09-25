//go:build !unix

package catalog

import "errors"

var ErrCatalogBusy = errors.New("catalog is in use by another process")

func LockPath(path string) string { return path + ".lock" }

// Lock is unavailable on this platform, so catalog migration refuses to run.
func Lock(path string, exclusive bool) (func(), error) {
	if exclusive {
		return nil, errors.New("catalog migration requires a Unix host")
	}
	return func() {}, nil
}
