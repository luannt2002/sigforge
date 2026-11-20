//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Anything but a plain file or a link in place of an archived file — a FIFO, a directory — is refused at once, named
// as such, never waited on; a refused rollback writes nothing: the DB, its sidecar and its manifest keep every byte.
func TestRollbackRefusesWhatIsNotAPlainFileAndWritesNothing(t *testing.T) {
	offline(t)
	for _, archived := range []string{".prev", ".prev.sha256", ".prev.manifest.json"} {
		for _, kind := range []string{"fifo", "dir"} {
			dir := t.TempDir()
			a, b, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "db.json")
			writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
			writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
			for _, src := range []string{a, b} {
				captureStdout(t, func() {
					if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + src}); err != nil {
						t.Fatal(err)
					}
				})
			}
			if err := os.Remove(db + archived); err != nil {
				t.Fatal(err)
			}
			if kind == "fifo" {
				if err := syscall.Mkfifo(db+archived, 0o644); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(db+archived, 0o755); err != nil {
				t.Fatal(err)
			}
			before := map[string]string{}
			for _, ext := range []string{"", ".sha256", ".manifest.json"} {
				b, _ := os.ReadFile(db + ext)
				before[ext] = string(b)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				captureStdout(t, func() { err = cmdRollback([]string{db}) })
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a plain file") {
					t.Errorf("rollback with %s a %s = %v, want it refused as not a plain file", archived, kind, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("rollback waited on %s, a %s", archived, kind)
			}
			for ext, was := range before {
				if b, _ := os.ReadFile(db + ext); string(b) != was {
					t.Errorf("rollback refused over %s (%s) still changed db.json%s", archived, kind, ext)
				}
			}
		}
	}
}

// An operator names a DB, a merge source or a diff side as a pipe — a shell's <(…) — and it is read as v0.5.0 read it.
func TestOperatorInputsMayBePipes(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	content := `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`
	writeFile(t, db, content)
	pipe := func() string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close() })
		go func() { _, _ = w.Write([]byte(content)); w.Close() }()
		return "/dev/fd/" + strconv.Itoa(int(r.Fd()))
	}
	for name, run := range map[string]func() error{
		"inspect --db": func() error { return cmdInspect([]string{"--db", pipe(), "ProbeA"}) },
		"merge --source": func() error {
			return cmdMerge([]string{"--out", filepath.Join(dir, "out.json"), "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + pipe()})
		},
		"diff": func() error { return cmdDiff([]string{pipe(), db}) },
	} {
		var err error
		captureStdout(t, func() { err = run() })
		if err != nil {
			t.Errorf("%s from a pipe = %v, want it read", name, err)
		}
	}
}

// An archived manifest is never checked, so a link the archive kept for it is restored as it is — never read, never
// waited on, even when it points at a FIFO or at nothing.
func TestRollbackRestoresAManifestLinkUnread(t *testing.T) {
	offline(t)
	for _, target := range []string{"fifo", "gone"} {
		dir := t.TempDir()
		a, b, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "db.json")
		writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
		writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
		for _, src := range []string{a, b} {
			captureStdout(t, func() {
				if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + src}); err != nil {
					t.Fatal(err)
				}
			})
		}
		if target == "fifo" {
			if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Remove(db + ".prev.manifest.json"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, db+".prev.manifest.json"); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			var err error
			captureStdout(t, func() { err = cmdRollback([]string{db}) })
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("rollback with the archived manifest a link to %s = %v, want it restored unread", target, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("rollback waited on the archived manifest's link to %s", target)
		}
		if got, err := os.Readlink(db + ".manifest.json"); err != nil || got != target {
			t.Errorf("the manifest links to %q (%v), want %q as archived", got, err, target)
		}
	}
}

// A plain archived file swapped for a link between the look and the read is never read through it: rollback refuses,
// and no file it writes holds what the link points to.
func TestRollbackNeverReadsAnArchivedFileSwappedForALink(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	a, b, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "db.json")
	writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
	for _, src := range []string{a, b} {
		captureStdout(t, func() {
			if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + src}); err != nil {
				t.Fatal(err)
			}
		})
	}
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "TOP-SECRET\n")
	defer func(orig func(*os.Root, string)) { archivedLooked = orig }(archivedLooked)
	archivedLooked = func(_ *os.Root, name string) {
		if name == "db.json.prev.manifest.json" {
			p := filepath.Join(dir, name)
			if err := errors.Join(os.Remove(p), os.Symlink(victim, p)); err != nil {
				t.Error(err)
			}
		}
	}
	var err error
	captureStdout(t, func() { err = cmdRollback([]string{db}) })
	if err == nil {
		t.Errorf("rollback over an archived manifest swapped for a link succeeded")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() || p == victim {
			continue
		}
		if b, _ := os.ReadFile(p); strings.Contains(string(b), "TOP-SECRET") {
			t.Errorf("%s, a plain file, holds what the swapped-in link points to", e.Name())
		}
	}
}

// A restored plain DB, sidecar and manifest are readable by every user, as merge writes them.
func TestRollbackRestoresPlainFilesReadable(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	a, b, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "db.json")
	writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
	for _, src := range []string{a, b} {
		captureStdout(t, func() {
			if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + src}); err != nil {
				t.Fatal(err)
			}
		})
	}
	captureStdout(t, func() {
		if err := cmdRollback([]string{db}); err != nil {
			t.Fatal(err)
		}
	})
	for _, ext := range []string{"", ".sha256", ".manifest.json"} {
		if st, err := os.Lstat(db + ext); err != nil || st.Mode().Perm() != 0o644 {
			t.Errorf("db.json%s after rollback: %v, %v; want a plain file, mode 0644", ext, st, err)
		}
	}
}
