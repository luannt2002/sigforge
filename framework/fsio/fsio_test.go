package fsio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicThenRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.json")
	want := []byte(`{"ok":true}`)
	if err := WriteAtomic(path, want, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("perm = %v", info.Mode().Perm())
	}
}

func TestReadMissing(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestWriteAtomicLeavesNoTempOnSuccess(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAtomic(filepath.Join(dir, "db.json"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the final file, got %d entries", len(entries))
	}
}
