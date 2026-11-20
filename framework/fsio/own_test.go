package fsio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OpenOwn reads only a plain file, never through a link; Read follows a link; ReadPlain follows one to a plain file but
// reads no directory.
func TestOwnFilesAreNeverReadThroughALink(t *testing.T) {
	dir := t.TempDir()
	plain, victim, link := filepath.Join(dir, "plain"), filepath.Join(dir, "victim"), filepath.Join(dir, "link")
	for _, p := range []string{plain, victim} {
		if err := os.WriteFile(p, []byte(filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadOwn(plain); err != nil || string(b) != "plain" {
		t.Errorf("ReadOwn(plain) = %q, %v", b, err)
	}
	if _, err := ReadOwn(link); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("ReadOwn(link) = %v, want it refused as a link", err)
	}
	if _, err := ReadOwn(dir); err == nil || !strings.Contains(err.Error(), "not a plain file") {
		t.Errorf("ReadOwn(dir) = %v, want it refused", err)
	}
	if b, err := Read(link); err != nil || string(b) != "victim" {
		t.Errorf("Read(link) = %q, %v — an operator's input is read through its link", b, err)
	}
	if _, err := ReadPlain(dir); err == nil {
		t.Errorf("ReadPlain(dir) must fail")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if b, err := ReadOwnIn(root, "plain"); err != nil || string(b) != "plain" {
		t.Errorf("ReadOwnIn(plain) = %q, %v", b, err)
	}
	if _, err := ReadOwnIn(root, "link"); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("ReadOwnIn(link) = %v, want it refused as a link", err)
	}
}
