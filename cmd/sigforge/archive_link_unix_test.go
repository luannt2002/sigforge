//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A DB name that is neither a file nor a link — a FIFO another user put there — is refused when archived, never
// opened: opening a FIFO waits for a writer that may never come.
func TestArchiveRefusesWhatIsNotAPlainFile(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	src, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "db.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	if err := syscall.Mkfifo(db, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var err error
		captureStdout(t, func() {
			err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a plain file") {
			t.Errorf("merge over a FIFO = %v, want it refused as not a plain file", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("merge hung opening the FIFO")
	}
}

// A file swapped between the look and the open — for another file of the directory — is refused, not archived.
func TestArchiveRefusesAFileSwappedWhileArchived(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	src, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "db.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, db, "the DB that was looked at")
	writeFile(t, filepath.Join(dir, "other"), "another file of the directory")
	defer func(orig func(*os.Root, string)) { archiveLooked = orig }(archiveLooked)
	archiveLooked = func(root *os.Root, name string) {
		if name == "db.json" {
			_ = os.Rename(filepath.Join(dir, "other"), db)
		}
	}
	var err error
	captureStdout(t, func() {
		err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
	})
	if err == nil || !strings.Contains(err.Error(), "replaced while it was archived") {
		t.Errorf("merge with the DB swapped while archived = %v, want it refused", err)
	}
	if b, rerr := os.ReadFile(db + ".prev"); rerr == nil && strings.Contains(string(b), "another file") {
		t.Errorf("the swapped-in file was archived")
	}
}
