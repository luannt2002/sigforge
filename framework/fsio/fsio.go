// Package fsio is the tool's file I/O: read a data file, and write one atomically
// so a published DB is never left half-written if the process dies mid-write. It
// is pure infrastructure — it handles bytes and paths and knows nothing about
// fingerprints, so it never imports a domain package under modules/.
package fsio

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
)

// Read returns the file's bytes, wrapping the error with the path — an input the operator names (a DB, a merge
// source), read as they name it: through a link, and from a pipe such as a shell's <(…). A file sigforge wrote itself
// is read with ReadOwn instead.
func Read(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fsio: read %q: %w", path, err)
	}
	return b, nil
}

// ReadPlain returns the bytes of the plain file at path, read through a link if path is one, and never waits: a FIFO
// or a directory there is refused. It is for a file read only to be checked — rollback's archived DB and checksum,
// which may be links the archive kept — never published as it is.
func ReadPlain(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|nonBlock, 0)
	if err == nil {
		defer f.Close()
		var st os.FileInfo
		if st, err = f.Stat(); err == nil && !st.Mode().IsRegular() {
			err = errors.New("not a plain file")
		}
	}
	var b []byte
	if err == nil {
		b, err = io.ReadAll(f)
	}
	if err != nil {
		return nil, fmt.Errorf("fsio: read %q: %w", path, err)
	}
	return b, nil
}

// OpenOwn opens a plain file sigforge wrote itself — in the store, the publish directory, a state file — never
// through a link: in a directory another user can write, they may have put one in its place, and what is read is
// often written back (docs/snapshot-governance.md §6). A link, a FIFO or a directory there is refused, never waited on.
func OpenOwn(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := ownFile(path, before); err != nil {
		return nil, err
	}
	ownLooked(path)
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	if now, err := f.Stat(); err != nil || !os.SameFile(before, now) {
		f.Close()
		return nil, fmt.Errorf("fsio: %q was replaced while it was opened", path)
	}
	return f, nil
}

// OpenOwnIn is OpenOwn for the file name of root's directory.
func OpenOwnIn(root *os.Root, name string) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	shown := filepath.Join(root.Name(), name)
	if err := ownFile(shown, before); err != nil {
		return nil, err
	}
	ownLooked(shown)
	f, err := root.OpenFile(name, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	if now, err := f.Stat(); err != nil || !os.SameFile(before, now) {
		f.Close()
		return nil, fmt.Errorf("fsio: %q was replaced while it was opened", shown)
	}
	return f, nil
}

// ReadOwn returns the bytes of a plain file sigforge wrote itself, never read through a link (see OpenOwn).
func ReadOwn(path string) ([]byte, error) {
	f, err := OpenOwn(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ReadOwnIn is ReadOwn for the file name of root's directory.
func ReadOwnIn(root *os.Root, name string) ([]byte, error) {
	f, err := OpenOwnIn(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ownFile refuses what a file sigforge wrote can never be: a link, or anything but a plain file.
func ownFile(shown string, st os.FileInfo) error {
	switch {
	case st.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("fsio: %q is a link: a file sigforge wrote is never read through one", shown)
	case !st.Mode().IsRegular():
		return fmt.Errorf("fsio: %q is not a plain file", shown)
	}
	return nil
}

// afterWrite runs once the data is written, before the file's mode is set and it is renamed: a test puts another
// user's move there (the temporary file swapped for a link).
var afterWrite = func(dir, tmpName string) {}

// ownLooked runs between looking at a file sigforge wrote and opening it: a test swaps the file there.
var ownLooked = func(shown string) {}

// tmpSuffix draws the random part of a temporary name: a test makes the first draw a name taken already.
var tmpSuffix = func() string { return strconv.FormatUint(rand.Uint64(), 36) }

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
	tmp, err := CreateIn(root)
	if err != nil {
		return err
	}
	if _, err := tmp.File.Write(data); err != nil {
		tmp.Abort()
		return fmt.Errorf("fsio: write %q: %w", tmp.Path(), err)
	}
	return tmp.Commit(name, perm)
}

// Temp is a temporary file made in a root's directory for a write that streams: the caller writes File, then Commit
// puts it at a name with every check WriteAtomicIn makes, or Abort removes it. Keep the root open until then.
type Temp struct {
	File *os.File
	root *os.Root
	name string
}

// CreateIn makes a temporary file in root's directory under a fresh name, created there (O_EXCL) — never a name
// that exists, so never through a link someone put there.
func CreateIn(root *os.Root) (*Temp, error) {
	var f *os.File
	var name string
	var err error
	for range 100 {
		name = ".sigforge-" + tmpSuffix() + ".tmp"
		if f, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("fsio: temp in %q: %w", root.Name(), err)
	}
	return &Temp{File: f, root: root, name: name}, nil
}

// Path is where the temporary file is (root's directory and its name), for a check that reads it before the commit.
func (t *Temp) Path() string { return filepath.Join(t.root.Name(), t.name) }

// Close closes the file and keeps it at Path, for a caller that hands the file on instead of committing it; Abort
// removes it later.
func (t *Temp) Close() error { return t.File.Close() }

// Abort closes the file and removes the entry by its name: this file, or whatever was put in its place.
func (t *Temp) Abort() {
	t.File.Close()
	t.root.Remove(t.name)
}

// Commit sets perm on the open file, closes it and renames it over name in root's directory. Every step acts on what
// this write opened: the rename is refused if the temporary file was replaced meanwhile, and the commit fails if what
// landed at name is not this file (a swap in the instant between that check and the rename) — and removes what landed,
// as RenameIn does. A failed commit removes the temporary entry.
func (t *Temp) Commit(name string, perm os.FileMode) error {
	shown := t.Path()
	renamed := false
	defer func() {
		if !renamed {
			t.root.Remove(t.name) // the entry by that name: this file, or whatever was put in its place
		}
	}()
	afterWrite(t.root.Name(), t.name)
	if err := t.File.Chmod(perm); err != nil {
		t.File.Close()
		return fmt.Errorf("fsio: chmod %q: %w", shown, err)
	}
	mine, serr := t.File.Stat()
	if err := errors.Join(serr, t.File.Close()); err != nil {
		return fmt.Errorf("fsio: close %q: %w", shown, err)
	}
	if now, err := t.root.Lstat(t.name); err != nil || !os.SameFile(mine, now) {
		return fmt.Errorf("fsio: %q was replaced while it was written: refused", shown)
	}
	beforeRename(t.root.Name(), t.name)
	if err := t.root.Rename(t.name, name); err != nil {
		return fmt.Errorf("fsio: rename to %q: %w", filepath.Join(t.root.Name(), name), err)
	}
	renamed = true
	if now, err := t.root.Lstat(name); err != nil || !os.SameFile(mine, now) {
		t.root.Remove(name) // what landed is not this write's: never left at the name, as RenameIn
		return fmt.Errorf("fsio: %q was replaced as it was renamed into place: what landed is not this write's, removed",
			filepath.Join(t.root.Name(), name))
	}
	return nil
}

// RenameIn moves the plain file from to the name to, both in root's directory, checked as a commit is: anything but a
// plain file at from is refused, and what lands at to must be the file looked at — otherwise it is removed and the
// move fails.
func RenameIn(root *os.Root, from, to string) error {
	st, err := root.Lstat(from)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("fsio: %q is not a plain file", filepath.Join(root.Name(), from))
	}
	beforeRename(root.Name(), from)
	if err := root.Rename(from, to); err != nil {
		return err
	}
	if now, err := root.Lstat(to); err != nil || !os.SameFile(st, now) {
		root.Remove(to)
		return fmt.Errorf("fsio: %q was replaced as it was moved: removed", filepath.Join(root.Name(), to))
	}
	return nil
}

// SymlinkAtomicIn makes name, in root's directory, a link to target, replacing whatever name was: the link is made
// under a fresh name and renamed into place, so name never goes missing.
func SymlinkAtomicIn(root *os.Root, name, target string) error {
	tmp, err := "", fs.ErrExist
	for i := 0; errors.Is(err, fs.ErrExist) && i < 100; i++ { // a name taken already: draw another
		tmp = ".sigforge-" + tmpSuffix() + ".link"
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
