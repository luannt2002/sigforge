//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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

// runWithin runs cmd and returns its error, or fails the test once wait has passed — after opening fifo for writing,
// which lets a run stuck opening it go.
func runWithin(t *testing.T, wait time.Duration, fifo string, cmd func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		var err error
		captureStdout(t, func() { err = cmd() })
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(wait):
		if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
			w.Close()
		}
		<-done
		t.Fatalf("the run waited on the FIFO at %s for %s, holding the publish lock", fifo, wait)
		return nil
	}
}

// A FIFO another user makes where the DB was, under the number the DB had, passes the archive's number check: the
// archive refuses it as not a plain file instead of waiting for a writer while it holds the publish lock.
func TestArchiveRefusesAFIFOUnderTheDBNumber(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	src, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "db.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, db, "the DB that was looked at")
	reused, remakeErr := false, error(nil)
	defer func(orig func(*os.Root, string)) { archiveLooked = orig }(archiveLooked)
	archiveLooked = func(root *os.Root, name string) {
		if name == "db.json" {
			reused, remakeErr = remakeUnderNumber(db, func() error { return syscall.Mkfifo(db, 0o644) })
		}
	}
	err := runWithin(t, 5*time.Second, db, func() error {
		return cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
	})
	if remakeErr != nil {
		t.Fatal(remakeErr)
	}
	if !reused {
		t.Skip("this file system gave the removed DB's number to nothing new: no swap passes a number check")
	}
	if err == nil || !strings.Contains(err.Error(), "not a plain file") {
		t.Errorf("merge with a FIFO made under the DB's number = %v, want it refused as not a plain file", err)
	}
}

// A hard link another user puts at the DB's name, to a file they cannot read, is that file: archiving it would copy it
// into <DB>.prev, mode 0644. The archive refuses a file with another name.
func TestArchiveRefusesAHardLinkedDB(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	src, db, secret := filepath.Join(dir, "a.json"), filepath.Join(dir, "db.json"), filepath.Join(dir, "secret")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	if err := os.WriteFile(secret, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, db); err != nil {
		t.Fatal(err)
	}
	var err error
	captureStdout(t, func() {
		err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
	})
	if err == nil || !strings.Contains(err.Error(), "another name") {
		t.Errorf("merge over a hard-linked DB = %v, want it refused as a file with another name", err)
	}
	if b, rerr := os.ReadFile(db + ".prev"); rerr == nil && strings.Contains(string(b), "SECRET") {
		t.Errorf("the hard-linked file was archived")
	}
}

// What is at --out and is no plain file — a FIFO, a device — is no live DB: refresh refuses it, never waiting for a
// writer or reading without end while it holds the publish lock.
func TestRefreshRefusesWhatIsNotAPlainFileAtOut(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	src, man := filepath.Join(dir, "a.json"), filepath.Join(dir, "m.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	fifo, dev := filepath.Join(dir, "fifo.json"), filepath.Join(dir, "dev.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.DevNull, dev); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{fifo, dev} {
		err := runWithin(t, 5*time.Second, fifo, func() error {
			return cmdRefresh([]string{"--out", out, "--manifest", man, "--source", "a=" + src})
		})
		if err == nil || !strings.Contains(err.Error(), "not a plain file") {
			t.Errorf("refresh --out %s = %v, want it refused as not a plain file", filepath.Base(out), err)
		}
	}
}
