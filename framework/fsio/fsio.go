// Package fsio is the tool's file I/O: read a data file, and write one atomically
// so a published DB is never left half-written if the process dies mid-write. It
// is pure infrastructure — it handles bytes and paths and knows nothing about
// fingerprints, so it never imports a domain package under modules/.
package fsio

import (
	"fmt"
	"os"
	"path/filepath"
)

// Read returns the file's bytes, wrapping the error with the path.
func Read(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fsio: read %q: %w", path, err)
	}
	return b, nil
}

// WriteAtomic writes data to a temp file in the same directory and renames it over
// path, so a reader sees either the old file or the whole new one, never a partial
// write. The rename is atomic within one filesystem.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sigforge-*.tmp")
	if err != nil {
		return fmt.Errorf("fsio: temp in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("fsio: write %q: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fsio: close %q: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("fsio: chmod %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("fsio: rename to %q: %w", path, err)
	}
	return nil
}
