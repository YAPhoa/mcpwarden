package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yaphoa/mcpwarden/internal/identity"
)

// Marker records, beside the catalog file, that PostgreSQL took over the
// catalog. The file backend refuses to start while it exists, except with the
// exact file a completed rollback wrote. Deleting the marker removes this
// protection; restore it from backup instead.
type Marker struct {
	State      string `json:"state"` // importing, active, rolling_back, rolled_back
	ImportID   string `json:"import_id"`
	RollbackID string `json:"rollback_id,omitempty"`
	// Previous is the rolled_back marker of an earlier migration that an
	// importing marker replaced. Abandoning the import restores it.
	Previous *Marker `json:"previous,omitempty"`
}

func MarkerPath(path string) string { return path + ".state" }

// ReadMarker returns ok=false when no marker exists.
func ReadMarker(path string) (Marker, bool, error) {
	data, err := os.ReadFile(MarkerPath(path))
	if os.IsNotExist(err) {
		return Marker{}, false, nil
	}
	if err != nil {
		return Marker{}, false, fmt.Errorf("read catalog marker: %w", err)
	}
	var m Marker
	if len(data) > 4096 || json.Unmarshal(data, &m) != nil || !m.valid() {
		return Marker{}, false, fmt.Errorf("catalog marker is invalid")
	}
	if m.Previous != nil && (m.State != "importing" || m.Previous.State != "rolled_back" || m.Previous.Previous != nil || !m.Previous.valid()) {
		return Marker{}, false, fmt.Errorf("catalog marker is invalid")
	}
	return m, true, nil
}

func (m Marker) valid() bool {
	if !identity.Valid(m.ImportID) {
		return false
	}
	switch m.State {
	case "importing", "active":
		return m.RollbackID == ""
	case "rolling_back", "rolled_back":
		return identity.Valid(m.RollbackID)
	}
	return false
}

// WriteMarker atomically replaces the marker and syncs its directory.
func WriteMarker(path string, m Marker) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".mcpwarden-marker-*")
	if err != nil {
		return fmt.Errorf("write catalog marker: %w", err)
	}
	defer os.Remove(f.Name())
	err = f.Chmod(0600)
	if err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), MarkerPath(path))
	}
	if err == nil {
		err = syncDir(dir)
	}
	if err != nil {
		return fmt.Errorf("write catalog marker: %w", err)
	}
	return nil
}

// RemoveMarker deletes the marker (used only when an import that replaced no
// earlier marker is abandoned before cutover) and syncs the directory.
func RemoveMarker(path string) error {
	if err := os.Remove(MarkerPath(path)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove catalog marker: %w", err)
	}
	return syncDir(filepath.Dir(path))
}

func checkMarker(path, rollback string) error {
	m, ok, err := ReadMarker(path)
	if err != nil || !ok {
		return err
	}
	if m.State != "rolled_back" {
		return fmt.Errorf("the catalog is managed by PostgreSQL (marker state %s); the file backend must not start", m.State)
	}
	if rollback != m.RollbackID {
		return fmt.Errorf("this catalog file is not the one the PostgreSQL rollback wrote; an older copy could revive revoked access")
	}
	return nil
}
