package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A merge over a DB whose name is a link never copies what the link points to: the link is archived as the same
// link, unread. In a directory another user can write, the DB, its sidecar or its manifest may be their link to a
// file this run must not copy out (0644) — and an operator's own link to a versioned DB still rolls back.
func TestArchiveNeverCopiesWhatALinkPointsTo(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	srcA, srcB := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	writeFile(t, srcA, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, srcB, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
	merge := func(db, src string) error {
		var err error
		captureStdout(t, func() {
			err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + src})
		})
		return err
	}

	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "SECRET-DATA-KEEP-ME\n")
	if err := os.Chmod(victim, 0o600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "db.json")
	for _, name := range []string{db, db + ".sha256", db + ".manifest.json"} {
		if err := os.Symlink(victim, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := merge(db, srcA); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{db + ".prev", db + ".prev.sha256", db + ".prev.manifest.json"} {
		st, err := os.Lstat(name)
		if err != nil || st.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("%s: %v, %v — want the link archived as a link", filepath.Base(name), st, err)
			continue
		}
		if target, _ := os.Readlink(name); target != victim {
			t.Errorf("%s points to %q, want the archived link's own target %q", filepath.Base(name), target, victim)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil && e.Name() != "victim" && e.Type().IsRegular() &&
			strings.Contains(string(b), "SECRET-DATA") {
			t.Errorf("%s holds a copy of what the link pointed to", e.Name())
		}
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o600 {
		t.Errorf("the link's target changed mode to %v", st.Mode().Perm())
	}

	// an operator's link to a versioned DB: archived as the link, rolled back to that DB's content
	db2 := filepath.Join(dir, "live.json")
	if err := merge(db2, srcA); err != nil {
		t.Fatal(err)
	}
	v1 := filepath.Join(dir, "v1.json")
	if err := os.Rename(db2, v1); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(v1, db2); err != nil {
		t.Fatal(err)
	}
	if err := merge(db2, srcB); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		if err := cmdRollback([]string{db2}); err != nil {
			t.Fatalf("rollback to the linked DB: %v", err)
		}
	})
	if got, want := readFile(t, db2), readFile(t, v1); got != want {
		t.Errorf("rollback restored %d bytes, want the linked DB's %d", len(got), len(want))
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
