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

// The lock file is readable by every user that may publish the DB, whatever the umask of the run that made it: a run
// under another user locks it through a read-only descriptor, which a file only its owner can read would refuse.
func TestLockFileIsReadableByOthers(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	db := filepath.Join(t.TempDir(), "db.json")
	release := mustLock(t, db)
	defer release()
	st, err := os.Stat(db + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("lock file made under umask 077: %v — want mode 0644", st.Mode().Perm())
	}
}

// Anything but a plain file at <out>.lock is refused, never followed nor waited on: a symbolic link — to a file a
// root run would otherwise change, or to a path it would create — a directory, a FIFO. The run publishes nothing and
// the link's target is left as it was.
func TestLockFileThatIsNotAPlainFileIsRefused(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "a.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "SECRET-DATA-KEEP-ME\n")
	if err := os.Chmod(victim, 0o600); err != nil {
		t.Fatal(err)
	}
	merge := func(db string) error {
		var err error
		captureStdout(t, func() {
			err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
		})
		return err
	}
	cases := map[string]func(lock string) error{
		"symlink to a file":  func(lock string) error { return os.Symlink(victim, lock) },
		"symlink to nothing": func(lock string) error { return os.Symlink(filepath.Join(dir, "made-by-the-run"), lock) },
		"directory":          func(lock string) error { return os.Mkdir(lock, 0o755) },
		"FIFO (would block)": func(lock string) error { return syscall.Mkfifo(lock, 0o644) },
	}
	for name, make := range cases {
		db := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := make(db + ".lock"); err != nil {
			t.Fatal(err)
		}
		done := make2(func() error { return merge(db) })
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), db+".lock") ||
				(strings.HasPrefix(name, "symlink") && !strings.Contains(err.Error(), "symbolic link, never followed")) {
				t.Errorf("%s: merge = %v, want a refusal naming the lock file (and, for a link, saying so)", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: merge hung on the lock file", name)
		}
		if _, err := os.Stat(db); !os.IsNotExist(err) {
			t.Errorf("%s: merge published without the lock: %v", name, err)
		}
	}
	if st, err := os.Stat(victim); err != nil || st.Mode().Perm() != 0o600 || st.Size() != int64(len("SECRET-DATA-KEEP-ME\n")) {
		t.Errorf("the symlink's target was changed: %v, %v — want it 0600 with its content", st, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "made-by-the-run")); !os.IsNotExist(err) {
		t.Errorf("a dangling symlink made the run create its target: %v", err)
	}
}

// make2 runs f in a goroutine and hands back its error.
func make2(f func() error) <-chan error {
	c := make(chan error, 1)
	go func() { c <- f() }()
	return c
}

// A directory the run cannot write, holding no lock file yet, is refused with the system's own reason.
func TestLockInADirectoryThatCannotBeWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file modes do not bind root")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	if _, err := lockPublish(filepath.Join(dir, "db.json")); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("lock in a read-only directory: err = %v, want the system's permission denied", err)
	}
}
