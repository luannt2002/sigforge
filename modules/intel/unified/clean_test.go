package unified

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Clean never answers not_affected: every combination of evidence is a named gap. The four
// cases are the whole truth table, so with TestOnlyCleanProducesNotAffected no path is left.
func TestCleanNeedsEvidence(t *testing.T) {
	cases := []struct {
		ev   Evidence
		want State
	}{
		{Evidence{FullData: true, Positioned: true}, StateNotChecked},
		{Evidence{FullData: false, Positioned: true}, StateNotChecked},
		{Evidence{FullData: true, Positioned: false}, StateUnknownVersion},
		{Evidence{}, StateNotChecked},
	}
	for _, c := range cases {
		got, why := Clean(c.ev)
		if got != c.want || why == "" {
			t.Errorf("Clean(%+v) = %v %q, want %v with a reason", c.ev, got, why, c.want)
		}
	}
}

// notAffectedOffenders reports every place a file produces a not_affected_by_advisory state
// without unified.Clean: the identifier used anywhere but in an ==/!= comparison or a case
// list, a conversion to State, arithmetic on a State constant, or ++/-- on a State field.
// Positional elements are allowed only in the list of every state (allowlisted by path).
func notAffectedOffenders(fset *token.FileSet, f *ast.File, allowList bool) []string {
	var out []string
	report := func(n ast.Node, what string) {
		out = append(out, fset.Position(n.Pos()).String()+": "+what)
	}
	isStateConst := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && strings.HasPrefix(sel.Sel.Name, "State") && sel.Sel.Name != "State"
	}
	var walk func(n ast.Node, parent ast.Node)
	walk = func(n ast.Node, parent ast.Node) {
		if n == nil {
			return
		}
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == "StateNotAffectedByAdvisory" {
				ok := false
				switch p := parent.(type) {
				case *ast.BinaryExpr:
					ok = p.Op == token.EQL || p.Op == token.NEQ
				case *ast.CaseClause:
					ok = true
				case *ast.CompositeLit:
					ok = allowList
				}
				if !ok {
					report(x, "not_affected produced outside unified.Clean")
				}
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "State" {
				report(x, "conversion to unified.State")
			}
		case *ast.BinaryExpr:
			if x.Op != token.EQL && x.Op != token.NEQ && x.Op != token.LAND && x.Op != token.LOR && (isStateConst(x.X) || isStateConst(x.Y)) {
				report(x, "arithmetic on a State constant")
			}
		case *ast.IncDecStmt:
			if sel, ok := x.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "State" {
				report(x, "++/-- on a State field")
			}
		}
		ast.Inspect(n, func(c ast.Node) bool {
			if c == n {
				return true
			}
			if c != nil {
				walk(c, n)
			}
			return false
		})
	}
	walk(f, nil)
	return out
}

// The detector itself is held to the forms it must catch and the ones it must let through.
func TestNotAffectedDetectorCatchesEveryForm(t *testing.T) {
	bad := []string{
		`u.State = unified.StateNotAffectedByAdvisory`,
		`return unified.StateNotAffectedByAdvisory`,
		`f(unified.StateNotAffectedByAdvisory)`,
		`r := unified.Result{State: unified.StateNotAffectedByAdvisory}`,
		`s := []unified.State{unified.StateNotAffectedByAdvisory}[0]`,
		`u.State = (unified.StateNotAffectedByAdvisory)`,
		`u.State = unified.State(6)`,
		`u.State = unified.StateAffectedByAdvisory + 1`,
		`u.State++`,
	}
	good := []string{
		`if u.State == unified.StateNotAffectedByAdvisory { x() }`,
		`if u.State != unified.StateNotAffectedByAdvisory && ok { x() }`,
		`switch u.State { case unified.StateNotAffectedByAdvisory: x() }`,
	}
	parse := func(stmt string) (*token.FileSet, *ast.File) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package x\nfunc _() {\n"+stmt+"\n}\n", 0)
		if err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
		return fset, f
	}
	for _, b := range bad {
		if fset, f := parse(b); len(notAffectedOffenders(fset, f, false)) == 0 {
			t.Errorf("not caught: %s", b)
		}
	}
	for _, g := range good {
		if fset, f := parse(g); len(notAffectedOffenders(fset, f, false)) != 0 {
			t.Errorf("wrongly caught: %s", g)
		}
	}
}

// The one way to say "not affected" is Clean: no code outside this package may produce the
// state itself — assign it, return it, pass it or put it in a field. Comparing with it and
// listing it among all states stay allowed. A source states its evidence to Clean (which in
// v0.4 never answers "clean"); this test is what keeps every new path from going around it.
func TestOnlyCleanProducesNotAffected(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == ".cache" || n == "testdata" || path == "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || filepath.Dir(path) == "." {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		// the list of every state, in coverage, is the one place the constant may stand alone
		offenders = append(offenders, notAffectedOffenders(fset, f, filepath.ToSlash(path) == "../../../modules/intel/coverage/coverage.go")...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("not_affected_by_advisory produced outside unified.Clean in: %v", offenders)
	}
}
