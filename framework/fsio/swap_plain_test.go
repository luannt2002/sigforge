package fsio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSwapped runs WriteAtomic of "data" over a db.json holding "old", with swap put at the given step, and returns
// what db.json holds after (gone: nothing there) and its error.
func writeSwapped(t *testing.T, at *func(string, string), swap func(dir, tmp string)) (after string, gone bool, err error) {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	for name, body := range map[string]string{"db.json": "old", "other": "theirs"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer func(orig func(string, string)) { *at = orig }(*at)
	*at = func(d, tmp string) {
		if strings.HasSuffix(tmp, ".tmp") {
			swap(d, tmp)
		}
	}
	err = WriteAtomic(db, []byte("data"), 0o644)
	b, rerr := os.ReadFile(db)
	return string(b), os.IsNotExist(rerr), err
}

// A plain file another user renames over the temporary file while it is written is refused before the rename: the file
// at the name stays as it was.
func TestWriteAtomicKeepsTheFileWhenItsTemporaryFileIsSwapped(t *testing.T) {
	after, _, err := writeSwapped(t, &afterWrite, func(d, tmp string) {
		if err := os.Rename(filepath.Join(d, "other"), filepath.Join(d, tmp)); err != nil {
			t.Error(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "replaced while it was written") || after != "old" {
		t.Errorf("WriteAtomic with its temporary file swapped for a plain file = %v, the name holding %q; want it refused and %q kept", err, after, "old")
	}
}

// A temporary file another user removes while it is written is refused before the rename: the file at the name stays.
func TestWriteAtomicKeepsTheFileWhenItsTemporaryFileIsRemoved(t *testing.T) {
	after, _, err := writeSwapped(t, &afterWrite, func(d, tmp string) {
		if err := os.Remove(filepath.Join(d, tmp)); err != nil {
			t.Error(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "replaced while it was written") || after != "old" {
		t.Errorf("WriteAtomic with its temporary file removed = %v, the name holding %q; want it refused and %q kept", err, after, "old")
	}
}

// A plain file another user renames over the closed temporary file in the instant before the rename lands, and is
// removed: the write fails and leaves nothing at the name.
func TestWriteAtomicRemovesAPlainFileSwappedInAtTheRename(t *testing.T) {
	after, gone, err := writeSwapped(t, &beforeRename, func(d, tmp string) {
		if err := os.Rename(filepath.Join(d, "other"), filepath.Join(d, tmp)); err != nil {
			t.Error(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "not this write's") || !gone {
		t.Errorf("WriteAtomic with a plain file swapped in at the rename = %v, the name holding %q; want it refused and nothing left there", err, after)
	}
}
