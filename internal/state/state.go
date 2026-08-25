package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"hidpass/internal/model"
)

const CurrentVersion = 1

type File struct {
	Version int                   `json:"version"`
	Devices []model.AllowedDevice `json:"devices"`
}

type Store struct{ Path string }

func DefaultStore() Store { return Store{Path: "/etc/hidpass/devices.json"} }

func (s Store) Load() (File, error) {
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return File{Version: CurrentVersion, Devices: []model.AllowedDevice{}}, nil
	}
	if err != nil {
		return File{}, fmt.Errorf("read state %s: %w", s.Path, err)
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("parse state %s: %w", s.Path, err)
	}
	if f.Version != CurrentVersion {
		return File{}, fmt.Errorf("unsupported state version %d in %s (this binary supports %d)", f.Version, s.Path, CurrentVersion)
	}
	if f.Devices == nil {
		f.Devices = []model.AllowedDevice{}
	}
	if err := Validate(&f); err != nil {
		return File{}, fmt.Errorf("validate state %s: %w", s.Path, err)
	}
	return f, nil
}

func (s Store) Save(f File) error {
	if f.Version == 0 {
		f.Version = CurrentVersion
	}
	if err := Validate(&f); err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create state directory %s: %w", dir, err)
	}
	// MkdirAll applies the caller's umask; `list` and `doctor` run unprivileged
	// and must still be able to read what the root helper wrote.
	if err := os.Chmod(dir, 0755); err != nil {
		return fmt.Errorf("set permissions on %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(dir, ".devices.json.*")
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0644); err == nil {
		_, err = tmp.Write(b)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("install state %s: %w", s.Path, err)
	}
	return nil
}

func Validate(f *File) error {
	if f.Version != CurrentVersion {
		return fmt.Errorf("state version must be %d", CurrentVersion)
	}
	seen := make(map[string]bool)
	for i := range f.Devices {
		vid, pid, err := model.NormalizePair(f.Devices[i].VID, f.Devices[i].PID)
		if err != nil {
			return fmt.Errorf("device %d: %w", i, err)
		}
		f.Devices[i].VID, f.Devices[i].PID = vid, pid
		if seen[f.Devices[i].ID()] {
			return fmt.Errorf("duplicate device %s", f.Devices[i].ID())
		}
		seen[f.Devices[i].ID()] = true
	}
	sort.Slice(f.Devices, func(i, j int) bool { return f.Devices[i].ID() < f.Devices[j].ID() })
	return nil
}

func Add(f *File, d model.AllowedDevice) bool {
	for i := range f.Devices {
		if f.Devices[i].ID() == d.ID() {
			// Refresh descriptive metadata but retain the original timestamp and
			// whatever the new record does not know: `allow` of a disconnected
			// device carries no name or category.
			d.AddedAt = f.Devices[i].AddedAt
			if d.Name == "" {
				d.Name = f.Devices[i].Name
			}
			if d.Category == "" {
				d.Category = f.Devices[i].Category
			}
			f.Devices[i] = d
			return false
		}
	}
	if d.AddedAt.IsZero() {
		d.AddedAt = time.Now().UTC()
	}
	f.Devices = append(f.Devices, d)
	return true
}

func Remove(f *File, id string) bool {
	for i := range f.Devices {
		if f.Devices[i].ID() == id {
			f.Devices = append(f.Devices[:i], f.Devices[i+1:]...)
			return true
		}
	}
	return false
}
