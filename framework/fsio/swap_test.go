package fsio

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Another user who can write the directory swaps the temporary file for a link to a file of their choice while the
// data is written. The write never changes that file's mode — the mode is set on the file this write created — and
// it reports the swap instead of renaming the link into place as if it were the data.
func TestWriteAtomicSetsTheModeOnItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(orig func(string, string)) { afterWrite = orig }(afterWrite)
	afterWrite = func(d, tmp string) {
		link := filepath.Join(d, tmp+".link")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(link, filepath.Join(d, tmp)); err != nil { // atomic: the name never goes missing
			t.Fatal(err)
		}
	}
	err := WriteAtomic(filepath.Join(dir, "db.json"), []byte("data"), 0o644)
	if st, serr := os.Stat(victim); serr != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the link's target changed mode: %v, %v — want it left 0600", st.Mode().Perm(), serr)
	}
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Errorf("WriteAtomic with its temporary file swapped = %v, want the swap reported", err)
	}
	if st, serr := os.Lstat(filepath.Join(dir, "db.json")); serr == nil && st.Mode()&fs.ModeSymlink != 0 {
		t.Errorf("the swapped-in link was renamed into place as the data")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".sigforge-*")); len(left) != 0 {
		t.Errorf("a refused write left %v behind", left)
	}
}

// SymlinkAtomicIn replaces whatever the name was with the link, and leaves no link of its own behind when it cannot.
func TestSymlinkAtomicIn(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(filepath.Join(dir, "db.json.prev"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SymlinkAtomicIn(root, "db.json.prev", "v1.json"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(filepath.Join(dir, "db.json.prev")); err != nil || got != "v1.json" {
		t.Errorf("db.json.prev = %q, %v — want the link to v1.json in place of the file", got, err)
	}
	if err := os.Mkdir(filepath.Join(dir, "busy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "busy", "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SymlinkAtomicIn(root, "busy", "v1.json"); err == nil {
		t.Errorf("a link renamed over a non-empty directory must fail")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".sigforge-*")); len(left) != 0 {
		t.Errorf("a failed link left %v behind", left)
	}
}

// A swap in the instant between that check and the rename cannot be stopped, but it is never silent: the write fails
// when what landed at the path is not the file it wrote, and the link's target is left as it was.
func TestWriteAtomicReportsASwapAtTheRename(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(orig func(string, string)) { beforeRename = orig }(beforeRename)
	beforeRename = func(d, tmp string) {
		link := filepath.Join(d, tmp+".link")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(link, filepath.Join(d, tmp)); err != nil {
			t.Fatal(err)
		}
	}
	err := WriteAtomic(filepath.Join(dir, "db.json"), []byte("data"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "not this write's") {
		t.Errorf("WriteAtomic with its file swapped at the rename = %v, want the swap reported", err)
	}
	if st, serr := os.Stat(victim); serr != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the link's target changed: %v, %v", st, serr)
	}
}

// No code outside tests changes a file's mode or owner by path: a path is looked up again when used, and in a
// directory another user can write it may by then name a file of theirs choosing. Modes are set on a file this
// process opened (*os.File.Chmod). A call by path anywhere in the module fails here.
func TestNoModeChangeByPath(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") && path != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" && (sel.Sel.Name == "Chmod" || sel.Sel.Name == "Chown" || sel.Sel.Name == "Lchown") {
				t.Errorf("%s: os.%s by path — set it on the open file instead", strings.TrimPrefix(path, root+"/"), sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
