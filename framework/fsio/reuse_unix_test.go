//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package fsio

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// remakeUnderNumber removes path and remakes it with remake until what is there has the inode number the removed file
// had — what another user's remove-and-create can get — and reports whether it got it. What takes another number is
// kept under another name, so the removed file's number becomes the lowest free one, the one ext4 gives next.
func remakeUnderNumber(path string, remake func() error) (bool, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	want := uint64(st.Sys().(*syscall.Stat_t).Ino)
	if err := os.Remove(path); err != nil {
		return false, err
	}
	for i := range 500 {
		if err := remake(); err != nil {
			return false, err
		}
		if now, err := os.Lstat(path); err == nil && uint64(now.Sys().(*syscall.Stat_t).Ino) == want {
			return true, nil
		}
		if err := os.Rename(path, path+".fill"+strconv.Itoa(i)); err != nil {
			return false, err
		}
	}
	return false, nil
}

// A FIFO another user makes where a file sigforge wrote was, under the number that file had, passes a number check:
// the open refuses it as not a plain file, never reading it or waiting on it.
func TestOwnReadRefusesAFIFOUnderTheLookedAtNumber(t *testing.T) {
	dir := t.TempDir()
	own := filepath.Join(dir, "own")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	reused := true
	defer func(orig func(string)) { ownLooked = orig }(ownLooked)
	ownLooked = func(string) {
		ok, err := remakeUnderNumber(own, func() error { return syscall.Mkfifo(own, 0o644) })
		if err != nil {
			t.Error(err)
		}
		reused = reused && ok
	}
	for name, read := range map[string]func() ([]byte, error){
		"ReadOwn":   func() ([]byte, error) { return ReadOwn(own) },
		"ReadOwnIn": func() ([]byte, error) { return ReadOwnIn(root, "own") },
	} {
		_ = os.Remove(own)
		if err := os.WriteFile(own, []byte("mine"), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := read()
		if !reused {
			t.Skip("this file system gave the removed file's number to nothing new: no swap passes a number check")
		}
		if err == nil || !strings.Contains(err.Error(), "not a plain file") {
			t.Errorf("%s of a FIFO under the looked-at number = %q, %v; want it refused as not a plain file", name, b, err)
		}
	}
}

// A hard link another user puts where a file sigforge wrote is, to a file they cannot read, is that file: every check
// on the name passes, so the open refuses a file with another name and never reads it.
func TestOwnReadRefusesAHardLink(t *testing.T) {
	dir := t.TempDir()
	secret, own := filepath.Join(dir, "secret"), filepath.Join(dir, "own")
	if err := os.WriteFile(secret, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, own); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, read := range map[string]func() ([]byte, error){
		"ReadOwn":   func() ([]byte, error) { return ReadOwn(own) },
		"ReadOwnIn": func() ([]byte, error) { return ReadOwnIn(root, "own") },
	} {
		if b, err := read(); err == nil || !strings.Contains(err.Error(), "another name") || strings.Contains(string(b), "SECRET") {
			t.Errorf("%s of a hard link = %q, %v; want it refused as a file with another name", name, b, err)
		}
	}
	f, err := OpenPlainIn(root, "own")
	if err == nil {
		f.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "another name") {
		t.Errorf("OpenPlainIn of a hard link = %v; want it refused as a file with another name", err)
	}
}

// OpenPlainIn opens a plain file and never waits: a FIFO is refused as not a plain file.
func TestOpenPlainInRefusesAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if f, err := OpenPlainIn(root, "fifo"); err == nil || !strings.Contains(err.Error(), "not a plain file") {
		if f != nil {
			f.Close()
		}
		t.Errorf("OpenPlainIn of a FIFO = %v; want it refused as not a plain file", err)
	}
	f, err := OpenPlainIn(root, "plain")
	if err != nil {
		t.Fatalf("OpenPlainIn of a plain file = %v", err)
	}
	f.Close()
}

// A link another user makes in place of the closed temporary file, under its number, passes a number check: the commit
// refuses what lands and leaves nothing at the name.
func TestCommitRefusesALinkUnderTheTemporaryNumber(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "victim"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	reused := false
	defer func(orig func(string, string)) { beforeRename = orig }(beforeRename)
	beforeRename = func(d, name string) {
		p := filepath.Join(d, name)
		ok, err := remakeUnderNumber(p, func() error { return os.Symlink("victim", p) })
		if err != nil {
			t.Error(err)
		}
		reused = ok
	}
	err = WriteAtomicIn(root, "db.json", []byte("mine"), 0o644)
	if !reused {
		t.Skip("this file system gave the removed file's number to nothing new: no swap passes a number check")
	}
	if _, lerr := os.Lstat(filepath.Join(dir, "db.json")); err == nil || lerr == nil {
		t.Errorf("a commit with its temporary file remade as a link under its number = %v (at the name: %v); want it refused and nothing there", err, lerr)
	}
}

// A link another user makes in place of RenameIn's source, under its number, passes a number check: the move refuses
// what lands and leaves nothing at the destination.
func TestRenameInRefusesALinkUnderTheSourceNumber(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"from": "mine", "victim": "SECRET"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	reused := false
	defer func(orig func(string, string)) { beforeRename = orig }(beforeRename)
	beforeRename = func(d, name string) {
		p := filepath.Join(d, name)
		ok, err := remakeUnderNumber(p, func() error { return os.Symlink("victim", p) })
		if err != nil {
			t.Error(err)
		}
		reused = ok
	}
	err = RenameIn(root, "from", "to")
	if !reused {
		t.Skip("this file system gave the removed file's number to nothing new: no swap passes a number check")
	}
	if _, lerr := os.Lstat(filepath.Join(dir, "to")); err == nil || lerr == nil {
		t.Errorf("RenameIn with its source remade as a link under its number = %v (at the destination: %v); want it refused and nothing there", err, lerr)
	}
}
