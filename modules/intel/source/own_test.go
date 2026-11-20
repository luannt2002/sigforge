package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The manifest sync keeps is its own file: a link in its place is refused, never read and written back.
func TestManifestIsNeverReadThroughALink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.json")
	if err := os.WriteFile(victim, []byte(`{"generated_at":"TOPSECRET"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("LoadManifest of a link = %v, want it refused naming the link", err)
	}
}
