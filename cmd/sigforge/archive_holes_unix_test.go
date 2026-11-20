//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// An older DB with no sidecar or manifest is archived with what it has: the merge goes on, .prev holds the old DB,
// and no archived checksum is made up for it.
func TestArchiveOfADBWithoutSidecar(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	src, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "db.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	old := `{"schema_version":"1.0.0","fingerprints":{"Old":{"html":["old"]}}}`
	writeFile(t, db, old)
	var err error
	captureStdout(t, func() {
		err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
	})
	if err != nil {
		t.Fatalf("merge over a DB without sidecar = %v", err)
	}
	if b, _ := os.ReadFile(db + ".prev"); string(b) != old {
		t.Errorf(".prev holds %q, want the old DB", b)
	}
	for _, p := range []string{db + ".prev.sha256", db + ".prev.manifest.json"} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s exists (%v); the old DB had none to archive", filepath.Base(p), err)
		}
	}
}

// A relative link at out is archived as the same link, its target kept as it was written — not resolved against the
// directory — so the archive points where the operator's link pointed.
func TestArchiveKeepsARelativeLinkTargetVerbatim(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	src, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "db.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	if err := os.Mkdir(filepath.Join(dir, "releases"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "releases", "v1.json"), `{"schema_version":"1.0.0","fingerprints":{"Old":{"html":["old"]}}}`)
	if err := os.Symlink("releases/v1.json", db); err != nil {
		t.Fatal(err)
	}
	var err error
	captureStdout(t, func() {
		err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(db + ".prev"); err != nil || got != "releases/v1.json" {
		t.Errorf(".prev links to %q (%v), want the link's own target releases/v1.json", got, err)
	}
}
