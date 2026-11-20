// Package fsio is the tool's file I/O: read a data file, and write one atomically
// so a published DB is never left half-written if the process dies mid-write. It
// is pure infrastructure — it handles bytes and paths and knows nothing about
// fingerprints, so it never imports a domain package under modules/.
package fsio

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
)

// Read returns the file's bytes, wrapping the error with the path.
func Read(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fsio: read %q: %w", path, err)
	}
	return b, nil
}

// afterWrite runs once the data is written, before the file's mode is set and it is renamed: a test puts another
// user's move there (the temporary file swapped for a link).
var afterWrite = func(dir, tmpName string) {}

// beforeRename runs between the check that the temporary file is still this write's and the rename: a test swaps it
// there, in the instant no check can close.
var beforeRename = func(dir, tmpName string) {}

// WriteAtomic writes data to a temporary file in path's directory and renames it over path, so a reader sees either
// the old file or the whole new one, never a partial write. The rename is atomic within one filesystem.
//
// Every step acts on what this call opened — the directory (an os.Root), the temporary file it created (O_EXCL) — and
// never on a name looked up again: the mode is set on the open file, the rename is refused if the temporary file was
// replaced meanwhile, and the write fails if what landed at path is not the file it wrote (a swap in the instant
// between that check and the rename). In a directory another user can write, that user can still replace path
// afterwards — as they could anyway — but never makes this write change, read or create any other file.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("fsio: open %q: %w", dir, err)
	}
	defer root.Close()
	return WriteAtomicIn(root, filepath.Base(path), data, perm)
}

// WriteAtomicIn is WriteAtomic for the file name of root's directory.
func WriteAtomicIn(root *os.Root, name string, data []byte, perm os.FileMode) error {
	var tmp *os.File
	var tmpName string
	var err error
	for range 100 {
		tmpName = ".sigforge-" + strconv.FormatUint(rand.Uint64(), 36) + ".tmp"
		if tmp, err = root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("fsio: temp in %q: %w", root.Name(), err)
	}
	renamed := false
	defer func() {
		if !renamed {
			root.Remove(tmpName) // the entry by that name: this file, or whatever was put in its place
		}
	}()
	shown := filepath.Join(root.Name(), tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("fsio: write %q: %w", shown, err)
	}
	afterWrite(root.Name(), tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("fsio: chmod %q: %w", shown, err)
	}
	mine, serr := tmp.Stat()
	if err := errors.Join(serr, tmp.Close()); err != nil {
		return fmt.Errorf("fsio: close %q: %w", shown, err)
	}
	if now, err := root.Lstat(tmpName); err != nil || !os.SameFile(mine, now) {
		return fmt.Errorf("fsio: %q was replaced while it was written: refused", shown)
	}
	beforeRename(root.Name(), tmpName)
	if err := root.Rename(tmpName, name); err != nil {
		return fmt.Errorf("fsio: rename to %q: %w", filepath.Join(root.Name(), name), err)
	}
	renamed = true
	if now, err := root.Lstat(name); err != nil || !os.SameFile(mine, now) {
		return fmt.Errorf("fsio: %q was replaced as it was renamed into place: what is there is not this write's", filepath.Join(root.Name(), name))
	}
	return nil
}

// SymlinkAtomicIn makes name, in root's directory, a link to target, replacing whatever name was: the link is made
// under a fresh name and renamed into place, so name never goes missing.
func SymlinkAtomicIn(root *os.Root, name, target string) error {
	tmp, err := "", fs.ErrExist
	for i := 0; errors.Is(err, fs.ErrExist) && i < 100; i++ { // a name taken already: draw another
		tmp = ".sigforge-" + strconv.FormatUint(rand.Uint64(), 36) + ".link"
		err = root.Symlink(target, tmp)
	}
	if err == nil {
		if err = root.Rename(tmp, name); err != nil {
			root.Remove(tmp)
		}
	}
	if err != nil {
		return fmt.Errorf("fsio: link %q: %w", filepath.Join(root.Name(), name), err)
	}
	return nil
}
