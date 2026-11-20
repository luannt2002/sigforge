//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package fsio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A write through a root lands in the directory the root was opened on, even once that directory's path names
// another: nothing is created or renamed by path.
func TestWriteAtomicInStaysInTheDirectoryOpened(t *testing.T) {
	dir := t.TempDir()
	d, moved, other := filepath.Join(dir, "d"), filepath.Join(dir, "moved"), filepath.Join(dir, "other")
	for _, p := range []string{d, other} {
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(d)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(d, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, d); err != nil { // the path now names another directory
		t.Fatal(err)
	}
	if err := WriteAtomicIn(root, "f", []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteAtomicIn = %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(moved, "f")); err != nil || string(b) != "data" {
		t.Errorf("the directory opened holds %q, %v; want the data", b, err)
	}
	if entries, _ := os.ReadDir(other); len(entries) != 0 {
		t.Errorf("the directory the path names now got %d entries; want none", len(entries))
	}
}

// A temporary name somebody took already — a link to their file — is never opened: another name is drawn, and their
// file is left as it was.
func TestWriteAtomicNeverOpensANameTakenAlready(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, ".sigforge-taken.tmp")); err != nil {
		t.Fatal(err)
	}
	defer func(orig func() string) { tmpSuffix = orig }(tmpSuffix)
	var draws atomic.Int32
	orig := tmpSuffix
	tmpSuffix = func() string {
		if draws.Add(1) == 1 {
			return "taken"
		}
		return orig()
	}
	if err := WriteAtomic(filepath.Join(dir, "f"), []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteAtomic with its first temporary name taken = %v, want another name drawn", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "SECRET" {
		t.Errorf("the file the taken name links to now holds %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "f")); string(b) != "data" {
		t.Errorf("f holds %q, want the data", b)
	}
}

// A link put in place of the temporary file — even to a second name of that very file — is refused before the rename:
// what was at the name stays as it was.
func TestWriteAtomicRefusesALinkToItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "f")
	if err := os.WriteFile(name, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer func(orig func(string, string)) { afterWrite = orig }(afterWrite)
	afterWrite = func(d, tmp string) {
		p, hard := filepath.Join(d, tmp), filepath.Join(d, "hard")
		if err := errors.Join(os.Link(p, hard), os.Remove(p), os.Symlink("hard", p)); err != nil { // relative: a root follows it
			t.Error(err)
		}
	}
	err := WriteAtomic(name, []byte("new"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "while it was written") {
		t.Errorf("WriteAtomic = %v, want it refused before the rename", err)
	}
	if st, lerr := os.Lstat(name); lerr != nil || !st.Mode().IsRegular() {
		t.Fatalf("the name is now %v, %v; want the plain file it was", st, lerr)
	}
	if b, _ := os.ReadFile(name); string(b) != "old" {
		t.Errorf("the name holds %q, want what it held", b)
	}
}

// While the link is replaced again and again, the name is never missing for a reader looking at it.
func TestSymlinkAtomicInNeverLeavesTheNameMissing(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := SymlinkAtomicIn(root, "l", "a"); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var missing atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if _, err := root.Lstat("l"); errors.Is(err, fs.ErrNotExist) {
				missing.Add(1)
			}
		}
	}()
	for i := range 3000 {
		if err := SymlinkAtomicIn(root, "l", string(rune('a'+i%2))); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if n := missing.Load(); n != 0 {
		t.Errorf("the name was missing %d time(s) while it was replaced", n)
	}
}

// A plain file put in place of one sigforge wrote, between the look and the open, is refused: what is read is the file
// looked at, or nothing.
func TestOwnFileSwappedWhileOpenedIsRefused(t *testing.T) {
	dir := t.TempDir()
	own, other := filepath.Join(dir, "own"), filepath.Join(dir, "other")
	defer func(orig func(string)) { ownLooked = orig }(ownLooked)
	ownLooked = func(string) {
		if err := os.Rename(other, own); err != nil {
			t.Error(err)
		}
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
		for p, body := range map[string]string{own: "mine", other: "theirs"} {
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if b, err := read(); err == nil || !strings.Contains(err.Error(), "replaced") {
			t.Errorf("%s with the file swapped while opened = %q, %v; want it refused", name, b, err)
		}
	}
}

// Read is an operator's input, read as v0.5.0 read it: through a link, and from a pipe (a shell's <(…), /dev/stdin).
func TestReadTakesAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() { _, _ = w.Write([]byte("piped")); w.Close() }()
	if b, err := Read("/dev/fd/" + strconv.Itoa(int(r.Fd()))); err != nil || string(b) != "piped" {
		t.Errorf("Read of a pipe = %q, %v; want what was written", b, err)
	}
}

// ReadPlain follows a link but never waits on a FIFO and never takes one for an empty file.
func TestReadPlainRefusesAFIFO(t *testing.T) {
	dir := t.TempDir()
	p, link := filepath.Join(dir, "fifo"), filepath.Join(dir, "link")
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("fifo", link); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadPlain(link); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a plain file") {
			t.Errorf("ReadPlain(link to a FIFO) = %v, want it refused as not a plain file", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPlain waited on the FIFO")
	}
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("plain", filepath.Join(dir, "plainlink")); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadPlain(filepath.Join(dir, "plainlink")); err != nil || string(b) != "x" {
		t.Errorf("ReadPlain through a link to a plain file = %q, %v", b, err)
	}
}

// A streamed write (CreateIn, write, Commit) makes the same checks as WriteAtomicIn: it lands in the directory the root
// was opened on, with the mode asked, and a temporary file swapped for a link before the commit is refused, its target
// left as it was; Abort leaves nothing behind.
func TestStreamedWriteInARoot(t *testing.T) {
	dir := t.TempDir()
	d, moved, other := filepath.Join(dir, "d"), filepath.Join(dir, "moved"), filepath.Join(dir, "other")
	for _, p := range []string{d, other} {
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(d)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := errors.Join(os.Rename(d, moved), os.Symlink(other, d)); err != nil {
		t.Fatal(err)
	}
	tmp, err := CreateIn(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.File.Write([]byte("streamed")); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Commit("f", 0o640); err != nil {
		t.Fatalf("Commit = %v", err)
	}
	if st, err := os.Lstat(filepath.Join(moved, "f")); err != nil || st.Mode().Perm() != 0o640 {
		t.Errorf("the directory opened holds %v, %v; want f with mode 0640", st, err)
	}
	if entries, _ := os.ReadDir(other); len(entries) != 0 {
		t.Errorf("the directory the path names now got %d entries", len(entries))
	}

	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp, err = CreateIn(root)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(moved, filepath.Base(tmp.Path()))
	if err := errors.Join(os.Remove(p), os.Symlink(victim, p)); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Commit("g", 0o644); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Errorf("Commit of a temporary file swapped for a link = %v, want it refused", err)
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o600 {
		t.Errorf("the link's target is now %v", st.Mode().Perm())
	}
	if _, err := os.Lstat(filepath.Join(moved, "g")); !os.IsNotExist(err) {
		t.Errorf("g exists after a refused commit: %v", err)
	}

	tmp, err = CreateIn(root)
	if err != nil {
		t.Fatal(err)
	}
	tmp.Abort()
	if entries, _ := os.ReadDir(moved); len(entries) != 1 {
		t.Errorf("after Abort the directory holds %d entries, want only f", len(entries))
	}
}

// A FIFO put in place of a file sigforge wrote, between the look and the open, is refused without waiting on it.
func TestOwnFileSwappedForAFIFOIsRefusedAtOnce(t *testing.T) {
	dir := t.TempDir()
	own, fifo := filepath.Join(dir, "own"), filepath.Join(dir, "fifo")
	if err := os.WriteFile(own, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	defer func(orig func(string)) { ownLooked = orig }(ownLooked)
	ownLooked = func(string) {
		if err := os.Rename(fifo, own); err != nil {
			t.Error(err)
		}
	}
	done := make(chan error, 1)
	go func() { _, err := ReadOwn(own); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("ReadOwn of a file swapped for a FIFO read it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadOwn waited on the FIFO swapped in")
	}
}

// A link put in place of a file sigforge wrote, between the look and the open, is never opened — even one to a second
// name of that very file, which the check after the open could not tell from it.
func TestOwnFileSwappedForALinkToItselfIsNeverOpened(t *testing.T) {
	dir := t.TempDir()
	own, hard := filepath.Join(dir, "own"), filepath.Join(dir, "hard")
	if err := os.WriteFile(own, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(orig func(string)) { ownLooked = orig }(ownLooked)
	ownLooked = func(string) {
		if err := errors.Join(os.Link(own, hard), os.Remove(own), os.Symlink("hard", own)); err != nil {
			t.Error(err)
		}
	}
	if b, err := ReadOwn(own); err == nil {
		t.Errorf("ReadOwn through a link swapped in = %q, want it refused", b)
	}
}

// OpenOwnIn, as OpenOwn: a FIFO put in place of the file, between the look and the open, is refused without waiting.
func TestOwnFileInARootSwappedForAFIFOIsRefusedAtOnce(t *testing.T) {
	dir := t.TempDir()
	own, fifo := filepath.Join(dir, "own"), filepath.Join(dir, "fifo")
	if err := os.WriteFile(own, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	defer func(orig func(string)) { ownLooked = orig }(ownLooked)
	ownLooked = func(string) {
		if err := os.Rename(fifo, own); err != nil {
			t.Error(err)
		}
	}
	done := make(chan error, 1)
	go func() { _, err := ReadOwnIn(root, "own"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("ReadOwnIn of a file swapped for a FIFO read it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadOwnIn waited on the FIFO swapped in")
	}
}

// RenameIn moves only a plain file, and only the one it looked at: a link at the source is refused, and a file
// swapped in as it is moved is removed from the destination, never left there.
func TestRenameInMovesOnlyThePlainFileLookedAt(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gone := func(name string) bool { _, err := os.Lstat(filepath.Join(dir, name)); return os.IsNotExist(err) }
	if err := RenameIn(root, "missing", "to"); err == nil || !gone("to") {
		t.Errorf("RenameIn of nothing = %v", err)
	}
	write("victim", "SECRET")
	if err := os.Symlink("victim", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := RenameIn(root, "link", "to"); err == nil || !gone("to") {
		t.Errorf("RenameIn of a link = %v; want it refused and nothing at to", err)
	}
	write("from", "mine")
	write("other", "theirs")
	defer func(orig func(string, string)) { beforeRename = orig }(beforeRename)
	beforeRename = func(d, name string) {
		if name == "from" {
			_ = os.Rename(filepath.Join(dir, "other"), filepath.Join(dir, "from"))
		}
	}
	if err := RenameIn(root, "from", "to"); err == nil || !gone("to") {
		t.Errorf("RenameIn of a file swapped as it was moved = %v; want it refused and nothing at to", err)
	}
	beforeRename = func(string, string) {}
	write("from", "mine")
	if err := RenameIn(root, "from", "to"); err != nil || gone("to") || !gone("from") {
		t.Errorf("RenameIn of a plain file = %v", err)
	}
}

// A link at RenameIn's source is refused before anything moves: the link stays where it was, nothing lands at the
// destination, and the move never reaches its rename.
func TestRenameInRefusesALinkBeforeMoving(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(filepath.Join(dir, "victim"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("victim", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	defer func(orig func(string, string)) { beforeRename = orig }(beforeRename)
	reached := false
	beforeRename = func(string, string) { reached = true }
	if err := RenameIn(root, "link", "to"); err == nil || !strings.Contains(err.Error(), "not a plain file") {
		t.Errorf("RenameIn of a link = %v, want it refused as not a plain file", err)
	}
	if st, err := os.Lstat(filepath.Join(dir, "link")); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link at the source was moved or changed: %v, %v", st, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "to")); !os.IsNotExist(err) || reached {
		t.Errorf("a refused move reached its rename (%v) or left something at the destination (%v)", reached, err)
	}
}
