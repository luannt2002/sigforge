package fsio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The module's file and request rules, held DENY BY DEFAULT within a stated boundary. What is type-checked covers
// what can be built: every Go file a build of the module compiles for linux, windows, darwin and plan9 (as
// `go list -deps -export` gives them) is type-checked whole; refused outright are a Go file none of those builds takes
// outside what the go tool leaves out of ./... (testdata, a directory named with . or _, a nested module: a directory
// holding its own go.mod file), a file the go tool compiles or links that is not Go (for any system or architecture),
// a //go: directive but build, embed and generate, a //line directive, a godebug line in go.mod, and a package of
// another module under the module's directory that a build imports.
// Outside framework/fsio (the file system) and framework/fetch (the network):
//   - a package may import only the standard packages listed pure below, those whose objects are judged one by
//     one (os, syscall, net, net/http, reflect) and packages of the module itself, as go list names the module;
//     any other import needs a reason;
//   - an object of a judged package that is not listed safe needs a reason, on each call; taken as a value it is
//     refused outright;
//   - a use of an interface's method — called, as a method value or expression, through a type parameter's
//     constraint or an embedded field — is refused outright when a type the module holds a value of has a judged
//     method of that name whose signature matches, aliases resolved and type parameters matching anything (see
//     resolve);
//   - a value that carries a judged method used outside the uses that keep its type (see launders), or given as a
//     type argument, is refused outright: it may flow into the standard library, whose calls the scan never reads.
// A reason is a comment "fsio-exempt <what>: <why>" naming what it lets through, on its line or the line after its own
// comment block, for one use. What the scan cannot decide — whether an exempted call is given a path inside a
// directory another user can write — the reason states, and review and the behaviour tests hold.

// pure are the standard packages any package may import: they reach neither the file system by path nor the network.
var pure = map[string]bool{}

func init() {
	for _, p := range strings.Fields(`archive/zip bufio bytes cmp compress/gzip container/heap container/list context
		crypto/sha256 embed encoding/base64 encoding/binary encoding/gob encoding/hex encoding/json errors flag fmt hash
		hash/fnv html io io/fs iter log maps math math/bits math/rand math/rand/v2 net/url path path/filepath regexp slices
		sort strconv strings sync sync/atomic text/tabwriter time unicode unicode/utf16 unicode/utf8`) {
		pure[p] = true
	}
}

// owners are the packages free to use a judged package: fsio for the file system, fetch for the network — those
// packages exactly, not packages under them.
var owners = map[string]string{
	"os": "framework/fsio", "syscall": "framework/fsio", "reflect": "framework/fsio",
	"net": "framework/fetch", "net/http": "framework/fetch",
}

// safe lists, per judged package, what may be used anywhere: names that touch no file by path and send nothing.
// A method is matched as "Type.Method" by its receiver's type name; a struct field is always safe — a value that
// carries a judged method is held where it leaves the uses that keep its type (see launders) and where the method
// is called.
var safe = map[string]*regexp.Regexp{
	// os: the process, the standard streams, errors and types, metadata (Lstat, Stat), and what an open file or an
	// os.Root does inside the directory it opened without following a link at its last name.
	"os": regexp.MustCompile(`^(Args|Getenv|LookupEnv|Environ|Exit|Stdin|Stdout|Stderr|File|FileInfo|FileMode|DirEntry|` +
		`Root|PathError|LinkError|SyscallError|Err[A-Z]\w*|Is(NotExist|Exist|Permission|Timeout)|SameFile|Lstat|Stat|` +
		`TempDir|Getpid|Getuid|Geteuid|Interrupt|Kill|Signal|PathSeparator|PathListSeparator|DevNull|O_\w+|Mode\w+|` +
		`File\.\w+|FileMode\.\w+|PathError\.\w+|LinkError\.\w+|SyscallError\.\w+|` +
		`Root\.(Close|Name|Lstat|Stat|Readlink|Remove|RemoveAll|Mkdir|OpenRoot))$`),
	// syscall: types, constants and calls on an open descriptor.
	"syscall": regexp.MustCompile(`^(Stat_t|Errno|Signal|WaitStatus|Handle|Overlapped|Flock|E[A-Z0-9]+|O_\w+|SIG\w+|` +
		`LOCK_\w+|S_I\w+|Errno\.\w+|Signal\.\w+|WaitStatus\.\w+)$`),
	// net/http: building a request and reading an answer — sending one is fetch's.
	"net/http": regexp.MustCompile(`^(Request|Response|Header|Cookie|NewRequest|NewRequestWithContext|StatusText|` +
		`ParseTime|CanonicalHeaderKey|DetectContentType|TimeFormat|NoBody|Status\w+|Method\w+|Err\w+|` +
		`Header\.(Get|Set|Add|Del|Values|Clone|Write|WriteSubset)|Cookie\.(String|Valid)|noBody\.\w+|Request\.(Context|WithContext)|Response\.Location)$`),
	// net: parsing addresses only.
	"net": regexp.MustCompile(`^(IP|IPNet|IPMask|ParseIP|ParseCIDR|SplitHostPort|JoinHostPort|IPv4|IPv4Mask|CIDRMask|` +
		`(IP|IPNet|IPMask)\.\w+)$`),
	// reflect: comparing values, never calling through them.
	"reflect": regexp.MustCompile(`^(DeepEqual|Value\.String)$`),
}

// byPath lists what pure packages offer to read a file by its path or to walk a directory: these need a reason too.
var byPath = map[string]*regexp.Regexp{
	"archive/zip":   regexp.MustCompile(`^OpenReader$`),
	"path/filepath": regexp.MustCompile(`^(Walk|WalkDir|Glob|EvalSymlinks)$`),
	"time":          regexp.MustCompile(`^LoadLocation$`), // reads $ZONEINFO or the system's zoneinfo by name
}

// fsioSafe is what of framework/fsio may be used anywhere: the calls that work inside a directory already opened (an
// os.Root). Its calls by path — and any it gains — need a reason: the directory part of the path must be one the
// operator gave.
var fsioSafe = regexp.MustCompile(`^(WriteAtomicIn|SymlinkAtomicIn|RenameIn|OpenOwnIn|ReadOwnIn|CreateIn|Temp|Temp\.\w+)$`)

// judge returns the name to report a use of obj by, in the package at rel, when that use needs a reason; "" when not.
func judge(obj types.Object, rel, modulePath string) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		return ""
	}
	p := obj.Pkg().Path()
	key, label := obj.Name(), obj.Pkg().Name()+"."+obj.Name()
	if fn, ok := obj.(*types.Func); ok {
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			t := sig.Recv().Type()
			if ptr, ok := t.(*types.Pointer); ok {
				t = ptr.Elem()
			}
			if named, ok := t.(*types.Named); ok {
				key = named.Obj().Name() + "." + obj.Name()
			}
			label = "(" + types.TypeString(sig.Recv().Type(), func(p *types.Package) string { return p.Name() }) + ")." + obj.Name()
		}
	}
	switch local, ok := strings.CutPrefix(p, modulePath+"/"); {
	case ok:
		if local == "framework/fsio" && rel != local && !fsioSafe.MatchString(key) {
			return label
		}
	case p == "golang.org/x/sys" || strings.HasPrefix(p, "golang.org/x/sys/"):
		if rel != "framework/fsio" {
			return label
		}
	case safe[p] != nil:
		if rel != owners[p] && !safe[p].MatchString(key) {
			return label
		}
	case byPath[p] != nil && byPath[p].MatchString(key):
		return label
	}
	return ""
}

// importLabel is the name to report an import of path by, in the package at rel; "" when the import is allowed. own
// says the package imported belongs to the module scanned — as `go list` says, never by its path's prefix: a module
// nested under the same path is another module.
func importLabel(path, rel string, own bool) string {
	switch {
	case own, pure[path], safe[path] != nil, owners[path] == rel,
		strings.HasPrefix(path, "golang.org/x/sys") && rel == "framework/fsio":
		return ""
	}
	return "import(" + path + ")"
}

// exemption is one "fsio-exempt <what>: <why>" comment: the use it names (as the scan reports it) and its own line.
type exemption struct {
	label string
	at    int
}

var exemptRe = regexp.MustCompile(`fsio-exempt ([^\s:]+):(.*)`)

// exemptions maps each line a "fsio-exempt <what>: <why>" comment speaks for to what it names there. A comment with
// code before or after it on its line speaks for that line; a comment block on lines of its own, for the line after
// it. A comment naming nothing, or with nothing after the colon, speaks for nothing.
func exemptions(fset *token.FileSet, f *ast.File, src []byte) map[int][]exemption {
	out := map[int][]exemption{}
	bounds := func(off int) (start, end int) {
		start, end = off, off
		for start > 0 && src[start-1] != '\n' {
			start--
		}
		for end < len(src) && src[end] != '\n' {
			end++
		}
		return start, end
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			m := exemptRe.FindStringSubmatch(c.Text)
			if m == nil || strings.TrimSpace(strings.TrimSuffix(m[2], "*/")) == "" {
				continue
			}
			from, to := fset.PositionFor(c.Pos(), false), fset.PositionFor(c.End(), false)
			s, _ := bounds(from.Offset)
			_, e := bounds(to.Offset)
			line := fset.PositionFor(cg.End(), false).Line + 1
			if strings.TrimSpace(string(src[s:from.Offset])) != "" || strings.TrimSpace(string(src[to.Offset:e])) != "" {
				line = from.Line
			}
			out[line] = append(out[line], exemption{m[1], from.Line})
		}
	}
	return out
}

// finding is one report: where, and what.
type finding struct {
	pass, file string
	line       int
	label      string
	fixed      bool // refused outright: no exemption lets it through
}

// checker type-checks one package's files for one system and reports what they use that needs a reason.
type checker struct {
	modOf   map[string]string // import path → the module `go list` puts it in
	fset    *token.FileSet
	imp     types.Importer
	root    string
	modPath string
	pass    string
	out     []finding
	bearing map[bearingKey]string
	present []types.Type // the types carrying a judged method that the module's own code holds a value of (this system)
	calls   []ifaceCall  // the module's calls through an interface, judged once every package is checked (resolve)
}

// bearingKey caches carries by the type itself: two types of one name (local types in two functions) are two keys.
type bearingKey struct {
	rel string
	t   types.Type
}

// ifaceCall is one use of an interface's method — a call, a method value or a method expression — outside its owner.
type ifaceCall struct {
	rel, file string
	line      int
	name      string      // the interface, as shown
	method    *types.Func // its signature may name the interface's type parameters
}

// carries returns the judged method a value of type t lets its holder call — the reason converting it to an interface
// or a type parameter hides that call from the scan — or "" when none.
func (c *checker) carries(t types.Type, rel string) string {
	if t == nil {
		return ""
	}
	key := bearingKey{rel, t}
	if l, ok := c.bearing[key]; ok {
		return l
	}
	c.bearing[key] = ""
	sets := []*types.MethodSet{types.NewMethodSet(t)}
	if _, isPtr := t.(*types.Pointer); !isPtr && !types.IsInterface(t) {
		sets = append(sets, types.NewMethodSet(types.NewPointer(t)))
	}
	for _, ms := range sets {
		for i := 0; i < ms.Len(); i++ {
			if !ms.At(i).Obj().Exported() {
				continue // an interface declared elsewhere cannot name it
			}
			if l := judge(ms.At(i).Obj(), rel, c.modPath); l != "" {
				c.bearing[key] = l
				return l
			}
		}
	}
	return ""
}

// hold records t (each part of a tuple) as held by the module when, judged at rel, it carries a judged method.
func (c *checker) hold(t types.Type, rel string) {
	if tup, ok := t.(*types.Tuple); ok {
		for i := 0; i < tup.Len(); i++ {
			c.hold(tup.At(i).Type(), rel)
		}
		return
	}
	if c.carries(t, rel) == "" || slices.ContainsFunc(c.present, func(p types.Type) bool { return types.Identical(p, t) }) {
		return
	}
	c.present = append(c.present, t)
}

// unifies is whether a method of signature a — an interface's, whose types may be its type parameters, each matching
// any type — can be answered by one of signature b.
func unifies(a, b types.Type) bool {
	a, b = types.Unalias(a), types.Unalias(b)
	if _, ok := a.(*types.TypeParam); ok {
		return true
	}
	switch a := a.(type) {
	case *types.Signature:
		b, ok := b.(*types.Signature)
		return ok && unifies(a.Params(), b.Params()) && unifies(a.Results(), b.Results()) // no judged method is variadic
	case *types.Tuple:
		b, ok := b.(*types.Tuple)
		if !ok || a.Len() != b.Len() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !unifies(a.At(i).Type(), b.At(i).Type()) {
				return false
			}
		}
		return true
	case *types.Pointer:
		b, ok := b.(*types.Pointer)
		return ok && unifies(a.Elem(), b.Elem())
	case *types.Slice:
		b, ok := b.(*types.Slice)
		return ok && unifies(a.Elem(), b.Elem())
	case *types.Named: // a named type is only itself: an instance matches one of the same generic type
		b, ok := b.(*types.Named)
		if !ok || a.Origin() != b.Origin() || a.TypeArgs().Len() != b.TypeArgs().Len() {
			return false
		}
		for i := 0; i < a.TypeArgs().Len(); i++ {
			if !unifies(a.TypeArgs().At(i), b.TypeArgs().At(i)) {
				return false
			}
		}
		return true
	}
	// Any other kind that holds a type parameter (an array, a map, a channel, a struct…) is not compared part by part:
	// it matches, refused rather than missed.
	return mentionsTypeParam(a) || types.Identical(a, b)
}

// mentionsTypeParam is whether t names a type parameter anywhere in it.
func mentionsTypeParam(t types.Type) bool {
	switch t := types.Unalias(t).(type) {
	case *types.TypeParam:
		return true
	case *types.Pointer:
		return mentionsTypeParam(t.Elem())
	case *types.Slice:
		return mentionsTypeParam(t.Elem())
	case *types.Array:
		return mentionsTypeParam(t.Elem())
	case *types.Map:
		return mentionsTypeParam(t.Key()) || mentionsTypeParam(t.Elem())
	case *types.Chan:
		return mentionsTypeParam(t.Elem())
	case *types.Signature:
		return mentionsTypeParam(t.Params()) || mentionsTypeParam(t.Results())
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if mentionsTypeParam(t.At(i).Type()) {
				return true
			}
		}
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if mentionsTypeParam(t.Field(i).Type()) {
				return true
			}
		}
	case *types.Interface:
		for i := 0; i < t.NumMethods(); i++ {
			if mentionsTypeParam(t.Method(i).Type()) {
				return true
			}
		}
	case *types.Named:
		for i := 0; i < t.TypeArgs().Len(); i++ {
			if mentionsTypeParam(t.TypeArgs().At(i)) {
				return true
			}
		}
	}
	return false
}

// resolve refuses each use of an interface's method that one of the types the module holds could answer with a judged
// method — of the same name, its signature matching (see unifies). It is the call that is checked, against every type
// held, so the path a value took to the interface (a tuple, a variadic, unsafe, a generic wrapper) does not matter. A
// type held only by its owner (net.Conn in framework/fetch) carries nothing there and is not held.
func (c *checker) resolve() {
	sort.Slice(c.present, func(i, j int) bool {
		return types.TypeString(c.present[i], nil) < types.TypeString(c.present[j], nil)
	})
	for _, call := range c.calls {
		for _, t := range c.present {
			obj, _, _ := types.LookupFieldOrMethod(t, true, call.method.Pkg(), call.method.Name())
			m, ok := obj.(*types.Func)
			if !ok || !unifies(call.method.Type(), m.Type()) {
				continue
			}
			if l := judge(m, call.rel, c.modPath); l != "" {
				label := "(" + call.name + ")." + call.method.Name() + ": " + l
				c.out = append(c.out, finding{c.pass, call.file, call.line, label, true})
				break
			}
		}
	}
}

// launders reports, through bad, each place in f where a value whose type carries a judged method (see carries)
// is used other than in the closed set of uses that keep its type: the operand of a selector (a field, a method),
// of & or *; assigned, declared, passed, returned, put in a composite literal or sent where the type is the
// identical one; compared with nil or a value of the identical type; a statement on its own; the blank
// identifier. Anything else — converted to an interface or another type, asserted, switched on, ranged into
// another type, a tuple element of a call or a comma-ok read landing in another type — is refused. Within the
// module, resolve catches the call wherever the value went; this keeps it from code the scan does not read.
func launders(f *ast.File, info *types.Info, carries func(types.Type) bool, bad func(pos token.Pos, t types.Type)) {
	same := func(a, b types.Type) bool { return a != nil && b != nil && types.Identical(a, b) }
	// parts is what an expression yields: a call's results, a comma-ok read's value and flag (go/types records
	// both as a tuple), or itself.
	parts := func(e ast.Expr) []types.Type {
		t := info.TypeOf(e)
		if tup, ok := t.(*types.Tuple); ok {
			out := make([]types.Type, tup.Len())
			for i := range out {
				out[i] = tup.At(i).Type()
			}
			return out
		}
		return []types.Type{t}
	}
	// into checks one tuple-valued expression (a call's results, a comma-ok read) landing in targets; a nil target is
	// the blank identifier, which discards the value.
	// A variable a := declares takes the type of its part, so it needs no case of its own.
	into := func(values []ast.Expr, targets []types.Type) {
		if len(values) == 1 && len(targets) > 1 {
			for i, t := range parts(values[0]) {
				if i < len(targets) && targets[i] != nil && carries(t) && !same(t, targets[i]) {
					bad(values[0].Pos(), t)
				}
			}
		}
	}
	var stack []ast.Node
	var results []*types.Tuple // the result types of the enclosing functions
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		if n == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if _, ok := top.(*ast.FuncLit); ok {
				results = results[:len(results)-1]
			} else if fd, ok := top.(*ast.FuncDecl); ok && fd.Body != nil {
				results = results[:len(results)-1]
			}
			return true
		}
		stack = append(stack, n)
		switch n := n.(type) {
		case *ast.FuncDecl:
			if n.Body != nil {
				sig, _ := info.Defs[n.Name].Type().(*types.Signature)
				results = append(results, sig.Results())
			}
		case *ast.FuncLit:
			sig, _ := info.TypeOf(n).(*types.Signature)
			results = append(results, sig.Results())
		case *ast.AssignStmt:
			var targets []types.Type
			for _, l := range n.Lhs {
				if id, ok := l.(*ast.Ident); ok && id.Name == "_" {
					targets = append(targets, nil) // discarded
					continue
				}
				targets = append(targets, info.TypeOf(l))
			}
			into(n.Rhs, targets)
		case *ast.ValueSpec:
			if n.Type != nil {
				targets := make([]types.Type, len(n.Names))
				for i := range targets {
					targets[i] = info.TypeOf(n.Type)
				}
				into(n.Values, targets)
			}
		case *ast.ReturnStmt:
			if len(results) > 0 && results[len(results)-1] != nil {
				r := results[len(results)-1]
				targets := make([]types.Type, r.Len())
				for i := range targets {
					targets[i] = r.At(i).Type()
				}
				into(n.Results, targets)
			}
		case *ast.CallExpr:
			tup, isTuple := info.TypeOf(firstArg(n)).(*types.Tuple)
			sig, ok := underlying(info.TypeOf(n.Fun)).(*types.Signature)
			if isTuple && len(n.Args) == 1 && !ok { // a type parameter's function: what it takes is not known here
				for i := 0; i < tup.Len(); i++ {
					if carries(tup.At(i).Type()) {
						bad(n.Args[0].Pos(), tup.At(i).Type())
					}
				}
			}
			if ok && isTuple && len(n.Args) == 1 {
				params := sig.Params()
				targets := make([]types.Type, tup.Len())
				for i := range targets {
					switch {
					case sig.Variadic() && i >= params.Len()-1: // the variadic parameter takes this part and every one after it
						targets[i] = params.At(params.Len() - 1).Type().(*types.Slice).Elem()
					case i < params.Len():
						targets[i] = params.At(i).Type()
					}
				}
				into(n.Args, targets)
			}
		case *ast.RangeStmt:
			if n.Tok == token.ASSIGN {
				key, val := rangeTypes(info.TypeOf(n.X))
				for _, kv := range []struct {
					e ast.Expr
					t types.Type
				}{{n.Key, key}, {n.Value, val}} {
					if kv.e != nil && kv.t != nil && carries(kv.t) && !same(kv.t, info.TypeOf(kv.e)) {
						bad(kv.e.Pos(), kv.t)
					}
				}
			}
		}
		e, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		tv, ok := info.Types[e]
		if !ok || tv.IsType() || tv.Type == nil {
			return true
		}
		if !carries(tv.Type) {
			return true // a tuple carries no method itself: its parts are checked where they land (into)
		}
		// the nearest ancestor that is not a parenthesis, and the child of it this value is
		child, i := ast.Node(e), len(stack)-2
		for ; i >= 0; i-- {
			if p, ok := stack[i].(*ast.ParenExpr); ok {
				child = p
				continue
			}
			break
		}
		if i < 0 {
			return true
		}
		if !allowedUse(stack[:i+1], child, tv.Type, info, results, same) {
			bad(e.Pos(), tv.Type)
		}
		return true
	}
	ast.Inspect(f, walk)
}

// underlying is t's underlying type — a named function type's or an alias's signature — nil for nil.
func underlying(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return t.Underlying()
}

// firstArg is a call's first argument, nil when it has none.
func firstArg(call *ast.CallExpr) ast.Expr {
	if len(call.Args) == 0 {
		return nil
	}
	return call.Args[0]
}

// rangeTypes is what ranging over a value of type t yields: key and value types, nil where there is none.
func rangeTypes(t types.Type) (key, val types.Type) {
	if t == nil {
		return nil, nil
	}
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	switch u := t.Underlying().(type) {
	case *types.Slice:
		return types.Typ[types.Int], u.Elem()
	case *types.Array:
		return types.Typ[types.Int], u.Elem()
	case *types.Map:
		return u.Key(), u.Elem()
	case *types.Chan:
		return u.Elem(), nil
	case *types.Basic:
		return types.Typ[types.Int], types.Typ[types.Rune]
	case *types.Signature: // range over a function: the yield function's parameters
		if u.Params().Len() == 1 {
			if y, ok := u.Params().At(0).Type().Underlying().(*types.Signature); ok {
				ps := y.Params()
				switch ps.Len() {
				case 1:
					return ps.At(0).Type(), nil
				case 2:
					return ps.At(0).Type(), ps.At(1).Type()
				}
			}
		}
	}
	return nil, nil
}

// allowedUse is whether a value of type t, the child of the last of ancestors, is used in one of the ways that keep its
// type.
func allowedUse(ancestors []ast.Node, child ast.Node, t types.Type, info *types.Info, results []*types.Tuple,
	same func(a, b types.Type) bool) bool {
	parent := ancestors[len(ancestors)-1]
	isNil := func(e ast.Expr) bool {
		tv, ok := info.Types[e]
		return ok && tv.IsNil()
	}
	switch p := parent.(type) {
	case *ast.SelectorExpr:
		return p.X == child
	case *ast.StarExpr:
		return p.X == child
	case *ast.UnaryExpr:
		return p.Op == token.AND
	case *ast.ExprStmt:
		return true
	case *ast.BinaryExpr:
		other := p.X
		if p.X == child {
			other = p.Y
		}
		return (p.Op == token.EQL || p.Op == token.NEQ) && (isNil(other) || same(t, info.TypeOf(other)))
	case *ast.AssignStmt:
		for i, r := range p.Rhs {
			if r != child {
				continue
			}
			lhs := p.Lhs[min(i, len(p.Lhs)-1)]
			if id, ok := lhs.(*ast.Ident); ok && id.Name == "_" {
				return true // discarded; a variable := declares has the value's own type
			}
			return same(t, info.TypeOf(lhs))
		}
		return true // a place assigned to
	case *ast.ValueSpec:
		for _, n := range p.Names {
			if n.Name != "_" {
				return p.Type == nil || same(t, info.TypeOf(p.Type))
			}
		}
		return true // var _ I = v: discarded, as a check that v implements I
	case *ast.ReturnStmt:
		if len(results) == 0 || results[len(results)-1] == nil {
			return false
		}
		r := results[len(results)-1]
		for i, e := range p.Results {
			if e == child && i < r.Len() {
				return same(t, r.At(i).Type())
			}
		}
		return false
	case *ast.SendStmt:
		if p.Value != child {
			return false
		}
		ch, ok := info.TypeOf(p.Chan).Underlying().(*types.Chan)
		return ok && same(t, ch.Elem())
	case *ast.CallExpr:
		if p.Fun == child {
			return false
		}
		if tv, ok := info.Types[p.Fun]; ok && tv.IsType() {
			return same(t, tv.Type) // a conversion: only to the identical type
		}
		sig, ok := underlying(info.TypeOf(p.Fun)).(*types.Signature)
		if !ok {
			return false // a type parameter's function: what it takes is not known here
		}
		for i, a := range p.Args {
			if a != child {
				continue
			}
			params := sig.Params()
			switch {
			case sig.Variadic() && i >= params.Len()-1 && !p.Ellipsis.IsValid():
				s, ok := params.At(params.Len() - 1).Type().(*types.Slice)
				return ok && same(t, s.Elem())
			case i < params.Len():
				return same(t, params.At(i).Type())
			}
		}
		return false
	case *ast.IndexExpr:
		m, ok := info.TypeOf(p.X).Underlying().(*types.Map)
		return ok && p.Index == child && same(t, m.Key()) // a map key of the identical type
	case *ast.CompositeLit:
		return sameInLiteral(p, nil, child, t, info, same)
	case *ast.KeyValueExpr:
		if len(ancestors) < 2 {
			return false
		}
		lit, ok := ancestors[len(ancestors)-2].(*ast.CompositeLit)
		return ok && sameInLiteral(lit, p, child, t, info, same)
	}
	return false
}

// sameInLiteral is whether a value placed in the composite literal lit — positionally, or as the key or the value of
// kv — lands in the identical type.
func sameInLiteral(lit *ast.CompositeLit, kv *ast.KeyValueExpr, child ast.Node, t types.Type, info *types.Info,
	same func(a, b types.Type) bool) bool {
	lt := info.TypeOf(lit)
	if lt == nil {
		return false
	}
	if ptr, ok := lt.Underlying().(*types.Pointer); ok { // an element of a []*T literal with its & left out
		lt = ptr.Elem()
	}
	switch u := lt.Underlying().(type) {
	case *types.Struct:
		if kv != nil {
			id, ok := kv.Key.(*ast.Ident)
			if !ok || kv.Value != child {
				return false
			}
			for i := 0; i < u.NumFields(); i++ {
				if u.Field(i).Name() == id.Name {
					return same(t, u.Field(i).Type())
				}
			}
			return false
		}
		for i, el := range lit.Elts {
			if el == child && i < u.NumFields() {
				return same(t, u.Field(i).Type())
			}
		}
	case *types.Map:
		if kv != nil && kv.Key == child {
			return same(t, u.Key())
		}
		return kv != nil && kv.Value == child && same(t, u.Elem())
	case *types.Slice:
		return (kv == nil || kv.Value == child) && same(t, u.Elem())
	case *types.Array:
		return (kv == nil || kv.Value == child) && same(t, u.Elem())
	}
	return false
}

// check type-checks one package (files, absolute) of the module at rel and records its findings. Any type error fails
// the scan: what was not typed was not judged.
func (c *checker) check(rel, pkgPath string, names []string) error {
	var files []*ast.File
	srcs := map[*ast.File][]byte{}
	for _, name := range names {
		src, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(c.fset, name, src, parser.ParseComments)
		if err != nil {
			return err
		}
		files, srcs[f] = append(files, f), src
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{},
		Types: map[ast.Expr]types.TypeAndValue{}, Instances: map[*ast.Ident]types.Instance{},
		Selections: map[*ast.SelectorExpr]*types.Selection{}}
	if _, err := (&types.Config{Importer: c.imp}).Check(pkgPath, c.fset, files, info); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	// What this package holds a value of that carries a judged method: a value reaches an interface only through an
	// expression, and every expression's type is here.
	for _, tv := range info.Types {
		c.hold(tv.Type, rel)
	}
	// Every use of an interface's method — called, taken as a value or as a method expression, through a type
	// parameter's constraint or promoted through an embedded field — judged in resolve, once the whole module is held.
	for e, sel := range info.Selections {
		m, ok := sel.Obj().(*types.Func) // a field's Obj is a *types.Var
		if !ok {
			continue
		}
		recv := m.Type().(*types.Signature).Recv()
		if recv == nil || !types.IsInterface(recv.Type()) {
			continue
		}
		pos := c.fset.PositionFor(e.Sel.Pos(), false)
		shown, _ := filepath.Rel(c.root, pos.Filename)
		c.calls = append(c.calls, ifaceCall{rel, filepath.ToSlash(shown), pos.Line,
			types.TypeString(recv.Type(), func(p *types.Package) string { return p.Name() }), m})
	}
	type use struct {
		line  int
		label string
		fixed bool
	}
	per := map[string][]use{}
	// A //line directive moves nothing: positions are the file's own.
	at := func(pos token.Pos) token.Position { return c.fset.PositionFor(pos, false) }
	add := func(pos token.Pos, label string, fixed bool) {
		p := at(pos)
		per[p.Filename] = append(per[p.Filename], use{p.Line, label, fixed})
	}
	called := map[*ast.Ident]bool{}
	for _, f := range files {
		for _, im := range f.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			if l := importLabel(path, rel, c.modOf[path] == c.modPath); l != "" {
				add(im.Pos(), l, false)
			}
		}
		for _, cg := range f.Comments {
			for _, cm := range cg.List {
				switch {
				case strings.HasPrefix(cm.Text, "//go:"):
					name, _, _ := strings.Cut(strings.TrimPrefix(cm.Text, "//go:"), " ")
					if !directives[name] {
						add(cm.Pos(), "go:"+name+" directive", true)
					}
				case strings.HasPrefix(cm.Text, "//line ") || strings.HasPrefix(cm.Text, "/*line "):
					add(cm.Pos(), "line directive", true)
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				fun := call.Fun
				for {
					switch e := fun.(type) {
					case *ast.ParenExpr:
						fun = e.X
						continue
					case *ast.IndexExpr:
						fun = e.X
						continue
					case *ast.IndexListExpr:
						fun = e.X
						continue
					case *ast.SelectorExpr:
						called[e.Sel] = true
					case *ast.Ident:
						called[e] = true
					}
					break
				}
			}
			return true
		})
		launders(f, info, func(t types.Type) bool { return c.carries(t, rel) != "" }, func(pos token.Pos, t types.Type) {
			add(pos, "launder("+types.TypeString(t, func(p *types.Package) string { return p.Name() })+")", true)
		})
	}
	for id, obj := range info.Uses {
		if l := judge(obj, rel, c.modPath); l != "" {
			if _, isFunc := obj.(*types.Func); isFunc && !called[id] {
				add(id.Pos(), l+" taken as a value", true)
			} else {
				add(id.Pos(), l, false)
			}
		}
	}
	for id, inst := range info.Instances {
		for i := 0; i < inst.TypeArgs.Len(); i++ {
			if t := inst.TypeArgs.At(i); c.carries(t, rel) != "" {
				add(id.Pos(), "typearg("+types.TypeString(t, func(p *types.Package) string { return p.Name() })+")", true)
			}
		}
	}
	for _, f := range files {
		file := at(f.Pos()).Filename
		shown, _ := filepath.Rel(c.root, file)
		shown = filepath.ToSlash(shown)
		uses := per[file]
		ex := exemptions(c.fset, f, srcs[f])
		count := map[use]int{}
		for _, u := range uses {
			count[use{u.line, u.label, false}]++
		}
		named := func(line int, label string) bool {
			return slices.ContainsFunc(ex[line], func(e exemption) bool { return e.label == label })
		}
		for _, u := range uses {
			switch {
			case u.fixed || !named(u.line, u.label):
				c.out = append(c.out, finding{c.pass, shown, u.line, u.label, u.fixed})
			case count[use{u.line, u.label, false}] > 1:
				c.out = append(c.out, finding{c.pass, shown, u.line, u.label + " (one exemption, several uses)", false})
			}
		}
		for line, es := range ex {
			for _, e := range es {
				if count[use{line, e.label, false}] == 0 {
					c.out = append(c.out, finding{c.pass, shown, e.at, "fsio-exempt " + e.label + " with nothing to exempt", false})
				}
			}
		}
	}
	return nil
}

// listed is what `go list -json` says of one package.
type listed struct {
	ImportPath, Dir, Export string
	GoFiles, IgnoredGoFiles []string
	Module                  *struct{ Path string }
	Error                   *struct{ Err string }
}

// goList lists the packages a build of root's module for goos compiles — its own and every one they import —
// with the export data the compiler wrote for each.
func goList(root, goos string) ([]listed, error) {
	cmd := exec.Command("go", "list", "-e", "-export", "-deps",
		"-json=ImportPath,Dir,Export,GoFiles,IgnoredGoFiles,Module,Error", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list for %s: %w: %s", goos, err, stderr.String())
	}
	var pkgs []listed
	for dec := json.NewDecoder(bytes.NewReader(out)); ; {
		var p listed
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			return pkgs, nil
		} else if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
}

// systems are those the scan builds the module for; a file none of them compiles is refused.
// directives are the //go: directives allowed: what files a build takes, what it embeds, what go generate runs. Any
// other — go:linkname, go:cgo_import_dynamic, go:wasmimport… — reaches past the type checker, so it is refused.
var directives = map[string]bool{"build": true, "embed": true, "generate": true}

// built are the file kinds the go tool compiles or links into a package beside its Go files, whatever the system.
var built = map[string]bool{".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".m": true, ".h": true, ".hh": true,
	".hpp": true, ".hxx": true, ".f": true, ".F": true, ".for": true, ".f90": true, ".s": true, ".S": true, ".sx": true,
	".swig": true, ".swigcxx": true, ".syso": true}

var systems = []string{"linux", "windows", "darwin", "plan9"}

// scanModule checks every Go file the module compiles for each of systems, each finding reported once, by the first
// system that compiles it, then refuses each file of the module's packages none of them compiles.
func scanModule(root, modulePath string) ([]string, error) {
	// go list reports directories cleaned and with links resolved: so must the root they are compared with be
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	// checked are the Go files a pass type-checked; buildable, every Go file some build of the module may take. A
	// buildable file no pass checked is reported: what is type-checked covers what can be built.
	checked, buildable := map[string]bool{}, map[string]bool{}
	var all []finding
	// Every file the go tool would compile or link beside Go source — for any system or architecture, in any directory
	// (go list sorts them by the one build it describes, and with cgo off drops .c files altogether): none is
	// type-checked, so none may be in the module. Every Go file outside what ./... leaves out (testdata, a directory
	// named with . or _, a module nested inside) may be built by some system or architecture: go list names none of a
	// package whose every file is for a system or architecture no pass builds.
	notBuilt := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			mod, modErr := os.Stat(filepath.Join(path, "go.mod")) // a module only when a file, as the go tool has it
			if path != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") ||
				strings.HasPrefix(d.Name(), "_") || (modErr == nil && !mod.IsDir()) || notBuilt[filepath.Dir(path)]) {
				notBuilt[path] = true
			}
			return nil
		}
		switch {
		case built[filepath.Ext(path)]:
			shown, _ := filepath.Rel(root, path)
			all = append(all, finding{"any", filepath.ToSlash(shown), 0, "not Go source: never type-checked", true})
		case strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") && !notBuilt[filepath.Dir(path)]:
			buildable[path] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// A godebug line in go.mod sets what //go:debug would, which is refused: so is it.
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	for i, line := range strings.Split(string(mod), "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(f[0], "godebug") {
			all = append(all, finding{"any", "go.mod", i + 1, "godebug directive", true})
		}
	}
	for _, goos := range systems {
		pkgs, err := goList(root, goos)
		if err != nil {
			return nil, err
		}
		export, modOf := map[string]string{}, map[string]string{}
		for _, p := range pkgs {
			export[p.ImportPath] = p.Export
			if p.Module != nil {
				modOf[p.ImportPath] = p.Module.Path
			}
		}
		c := &checker{fset: token.NewFileSet(), root: root, modPath: modulePath, pass: goos, bearing: map[bearingKey]string{},
			modOf: modOf}
		c.imp = importer.ForCompiler(c.fset, "gc", func(path string) (io.ReadCloser, error) {
			if export[path] == "" {
				return nil, fmt.Errorf("no export data for %s", path)
			}
			return os.Open(export[path])
		})
		for _, p := range pkgs {
			under := p.Dir == root || strings.HasPrefix(p.Dir, root+string(filepath.Separator))
			if under && (p.Module == nil || p.Module.Path != modulePath) { // code under the repo the scan does not own
				shown, _ := filepath.Rel(root, p.Dir)
				all = append(all, finding{goos, filepath.ToSlash(shown), 0, "a package of another module: " + p.ImportPath, true})
				continue
			}
			if p.Module == nil || p.Module.Path != modulePath {
				continue
			}
			if p.Error != nil {
				return nil, fmt.Errorf("%s: %s: %s", goos, p.ImportPath, p.Error.Err)
			}
			rel := strings.TrimPrefix(strings.TrimPrefix(p.ImportPath, modulePath), "/")
			var names []string
			for _, n := range p.GoFiles {
				names = append(names, filepath.Join(p.Dir, n))
				checked[filepath.Join(p.Dir, n)] = true
			}
			for _, n := range p.IgnoredGoFiles { // an imported testdata package's too
				if !strings.HasSuffix(n, "_test.go") {
					buildable[filepath.Join(p.Dir, n)] = true
				}
			}
			if len(names) > 0 {
				if err := c.check(rel, p.ImportPath, names); err != nil {
					return nil, fmt.Errorf("%s: %w", goos, err)
				}
			}
		}
		c.resolve()
		all = append(all, c.out...)
	}
	for f := range buildable {
		if !checked[f] {
			shown, _ := filepath.Rel(root, f)
			all = append(all, finding{"none", filepath.ToSlash(shown), 0, "built by none of " + strings.Join(systems, ", "), true})
		}
	}
	rank := map[string]int{"any": -1, "none": len(systems)}
	for i, s := range systems {
		rank[s] = i
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.pass != b.pass {
			return rank[a.pass] < rank[b.pass]
		}
		if a.file != b.file {
			return a.file < b.file
		}
		if a.line != b.line {
			return a.line < b.line
		}
		return a.label < b.label
	})
	var out []string
	seen := map[string]bool{}
	for _, f := range all {
		where := f.file + ":" + strconv.Itoa(f.line)
		if f.line == 0 {
			where = f.file
		}
		key := where + ": " + f.label
		if !seen[key] {
			seen[key] = true
			out = append(out, f.pass+": "+key)
		}
	}
	return out, nil
}

// Two local types of one name are two types: what one carries is never taken for the other's (a cache keyed by the
// type's name once let a type embedding *os.Root pass as the one before it, which carries nothing).
func TestCarriesTellsTypesOfOneNameApart(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module example.com/z\n\ngo 1.26\n",
		"main.go": "package main\n\nimport \"os\"\n\nfunc a() {\n\ttype T struct{}\n\t_ = T{}\n}\n\n" +
			"func b(r *os.Root) {\n\ttype T struct{ *os.Root }\n\t_ = T{r}\n}\n\nfunc main() { a(); b(nil) }\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkgs, err := goList(root, "linux")
	if err != nil {
		t.Fatal(err)
	}
	export := map[string]string{}
	for _, p := range pkgs {
		export[p.ImportPath] = p.Export
	}
	c := &checker{fset: token.NewFileSet(), root: root, modPath: "example.com/z", pass: "linux", bearing: map[bearingKey]string{}}
	c.imp = importer.ForCompiler(c.fset, "gc", func(path string) (io.ReadCloser, error) { return os.Open(export[path]) })
	f, err := parser.ParseFile(c.fset, filepath.Join(root, "main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}}
	if _, err := (&types.Config{Importer: c.imp}).Check("example.com/z", c.fset, []*ast.File{f}, info); err != nil {
		t.Fatal(err)
	}
	var ts []*types.TypeName
	for _, obj := range info.Defs {
		if tn, ok := obj.(*types.TypeName); ok && tn.Name() == "T" {
			ts = append(ts, tn)
		}
	}
	slices.SortFunc(ts, func(x, y *types.TypeName) int { return int(x.Pos() - y.Pos()) })
	if len(ts) != 2 {
		t.Fatalf("want two local types T, got %d", len(ts))
	}
	if l := c.carries(ts[0].Type(), ""); l != "" {
		t.Errorf("the first T, an empty struct, carries %q", l)
	}
	if l := c.carries(ts[1].Type(), ""); l == "" {
		t.Errorf("the second T, embedding *os.Root, carries nothing: taken for the first one")
	}
}

// A type the module holds only inside a tuple — a result passed straight on — is held all the same: a call through an
// interface it answers is refused.
func TestScanHoldsATypeSeenOnlyInATuple(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module example.com/y\n\ngo 1.26\n",
		"main.go": "package main\n\nimport \"os\"\n\ntype w interface{ WriteFile(string, []byte, os.FileMode) error }\n\n" +
			"func put(x w, err error) error {\n\tif err != nil {\n\t\treturn err\n\t}\n\treturn x.WriteFile(\"p\", nil, 0o644)\n}\n\n" +
			"func main() { _ = put(os.OpenRoot(\".\")) } // fsio-exempt os.OpenRoot: a sample\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := scanModule(root, "example.com/y")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"linux: main.go:11: (main.w).WriteFile: (*os.Root).WriteFile", "linux: main.go:14: launder(*os.Root)"}
	if !slices.Equal(got, want) {
		t.Errorf("scan found\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// The module keeps its file and request rules, in every Go file a build of it compiles.
func TestRepoKeepsItsFileAndRequestRules(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	got, err := scanModule(root, "github.com/luannt2002/sigforge")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range got {
		t.Errorf("%s", v)
	}
}

// golang.org/x/sys reaches the file system as syscall does: outside fsio a use needs a reason, inside it does not.
func TestScanJudgesGolangOrgXSys(t *testing.T) {
	unix := types.NewPackage("golang.org/x/sys/unix", "unix")
	open := types.NewFunc(token.NoPos, unix, "Open", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	if got := judge(open, "cmd/sigforge", "example.com/x"); got != "unix.Open" {
		t.Errorf("judge(unix.Open) outside fsio = %q, want unix.Open", got)
	}
	if got := judge(open, "framework/fsio", "example.com/x"); got != "" {
		t.Errorf("judge(unix.Open) inside fsio = %q, want nothing", got)
	}
	if got := importLabel("golang.org/x/sys/unix", "cmd/sigforge", false); got != "import(golang.org/x/sys/unix)" {
		t.Errorf("importLabel(golang.org/x/sys/unix) outside fsio = %q", got)
	}
}

// The scan finds each use that needs a reason however it is reached — a call, a value, a method expression, a dot
// import, a type, a conversion to an interface or a type parameter, a package not listed pure, a file only one system
// compiles or none does, a package under testdata, a package under fsio, a //line or //go:linkname directive — and
// holds an exemption to one named use. It lets through what is safe, and fsio's and fetch's own uses.
func TestRepoScanFindsEachBreach(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/x\n\ngo 1.26\n\nrequire example.com/x/framework/evil v0.0.0\n\n"+
		"replace example.com/x/framework/evil => ./framework/evil\n\ngodebug zipinsecurepath=1\n")
	write("app/w.go", `package app

import (
	"net/http"
	"os"
	"time"

	"example.com/x/framework/evil"
	"example.com/x/framework/fetch"
)

type doer interface{ Do(*http.Request) (*http.Response, error) }

type holder struct{ W writer }

func pass(r *os.Root) (*os.Root, error) { return r, nil }

func pass2(r *os.Root) (*os.Root, *os.Root) { return r, r }

func asWriter(r *os.Root) (writer, error) { return pass(r) }

func use(writer, error) {}

func forms(r *os.Root, c *fetch.Client, req *http.Request, x any) {
	var w writer
	var err error
	w, err = pass(r)
	var a, b writer = pass2(r)
	use(pass(r))
	m := map[string]*os.Root{"a": r}
	w, ok := m["a"]
	ch := make(chan *os.Root, 1)
	ch <- r
	w, ok = <-ch
	for _, w = range []*os.Root{r} {
	}
	tr := c.HTTP.Transport
	if d, ok := tr.(doer); ok {
		_ = d
	}
	switch tr.(type) {
	case doer:
	}
	hs := []*holder{{W: r}}
	var i any = r
	_ = x == r
	same, same2 := pass2(r)
	_ = r == nil || same == same2
	_ = req.ParseMultipartForm(0)
	_, _ = time.LoadLocation("x")
	evil.W()
	var j any = (r)
	wc := make(chan writer, 1)
	wc <- r
	use2(r)
	usev(r)
	_ = holder{r}
	_ = map[string]writer{"a": r}
	_ = []writer{r}
	_ = any(r)
	pp := &r
	_ = *pp == r
	keep(r)
	_, _, _, _, _, _, _, _ = w, err, a, b, ok, hs, i, j
}

func use2(writer) {}

func usev(...writer) {}

func keep(*os.Root) {}

func asWriter2(r *os.Root) writer { return r }

type hold2 struct{ R *os.Root }

func mk() *os.Root { return nil }

func forms2(r *os.Root, m map[string]*os.Root, ch chan *os.Root, a [1]*os.Root, seq func(func(*os.Root) bool),
	seq2 func(func(int, *os.Root) bool)) {
	var w writer
	var err error
	var r1, r2 *os.Root
	r1, r2 = pass2(r)
	_, err = pass(r)
	mk()
	_ = (*r).Name()
	_ = []*hold2{{R: r}}
	_ = map[writer]int{r: 1}
	_ = [1]writer{r}
	for _, w = range m {
	}
	for w = range ch {
	}
	for _, w = range a {
	}
	for _, w = range &a {
	}
	for w = range seq {
	}
	for _, w = range seq2 {
	}
	_ = any(*r)
	var _ writer = r
	_ = r
	_, _, _, _ = w, err, r1, r2
}

func asW3(r *os.Root) writer {
	f := func() *os.Root { return r }
	return f()
}

func assign(r *os.Root) {
	var w writer
	w = r
	_ = w
}
`)
	write("app/asm.go", "package app\n\nfunc asmf()\n")
	write("app/asm_amd64.s", "#include \"textflag.h\"\n\nTEXT ·asmf(SB),NOSPLIT,$0-0\n\tRET\n")
	write("app/x.syso", "not an object, never linked by go list")
	write("app/v.go", `package app

import (
	"io"
	"net"
	"net/http"
	"os"
	"unsafe" // fsio-exempt import(unsafe): a sample of an interface built through unsafe
)

type zzWriter interface{ WriteFile(string, []byte, os.FileMode) error }

type zzDoer interface{ Do(*http.Request) (*http.Response, error) }

type zzReg interface{ RegisterProtocol(string, http.RoundTripper) }

func zzWriteAll(ws ...zzWriter) error { return ws[0].WriteFile("zz", nil, 0o644) }

func zzA(r *os.Root) error { return zzWriteAll(pass2(r)) }

func zzLocalA() { type T struct{}; _ = T{} }

func zzLocalB(r *os.Root) error {
	type T struct{ *os.Root }
	var w zzWriter = T{r}
	return w.WriteFile("zz2", nil, 0o644)
}

func zzUnsafe() error {
	var a any = 1
	w := *(*zzWriter)(unsafe.Pointer(&a))
	return w.WriteFile("zz3", nil, 0o644)
}

func zzGen[W zzWriter](w W) error { return w.WriteFile("zz4", nil, 0o644) }

func zzSend(d zzDoer, req *http.Request) { _, _ = d.Do(req) }

func zzValue(w zzWriter) { f := w.WriteFile; _ = f }

func zzExpr() { _ = zzWriter.WriteFile }

func zzOK(w io.Writer, g zzReg) { _, _ = w.Write(nil); g.RegisterProtocol("x", nil) }

func zzNe(r *os.Root) bool { return r != nil }

func zzIP(ip net.IP, m map[*os.Root]int, r *os.Root, req *http.Request) {
	for range ip {
	}
	_, _ = ip[0], m[r]
	for k := range req.Header {
		_ = k
	}
}

func zzFixed(r *os.Root) {
	var i any = (*os.Root)(nil) // fsio-exempt launder(*os.Root): a sample, not exemptible
	_ = zzGen(r)                // fsio-exempt typearg(*os.Root): a sample, not exemptible
	_ = i
}

type zzOther interface{ WriteFile(string) error }

func zzO(o zzOther) { _ = o.WriteFile("x") }

func zzRoots(...*os.Root) {}

func zzR(r *os.Root) { zzRoots(pass2(r)) }
`)
	write("app/x_linux_arm64.syso", "an object for another architecture: never linked on amd64")
	write("app/y_arm64.s", "TEXT ·zzArm(SB),0,$0-0\n\tRET\n")
	write("app/z.c", "int zz(void) { return 0; }\n")
	write("app/z.h", "int zz(void);\n")
	write("app/u.go", `package app

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

type zzGW[M any] interface{ WriteFile(string, []byte, M) error }

func zzGen2[M any](w zzGW[M], m M) error { return w.WriteFile("g", nil, m) }

type zzBox[M any] struct{ zzGW[M] }

func zzBoxed[M any](b zzBox[M], m M) error { return b.WriteFile("b", nil, m) }

type zzGD[R any] interface{ Do(R) (*http.Response, error) }

func zzGSend[R any](d zzGD[R], r R) { _, _ = d.Do(r) }

type zzFn func(zzWriter, error) error

type zzAlias = func(zzWriter, error) error

func zzOpen(r *os.Root) (*os.Root, error) { return r, nil }

func zzVia(f zzFn, r *os.Root) error { return f(zzOpen(r)) }

func zzViaAlias(f zzAlias, r *os.Root) error { return f(zzOpen(r)) }

func zzViaTP[F func(zzWriter, error) error](f F, r *os.Root) error { return f(zzOpen(r)) }

type zzS struct{ zzWriter }

func zzEmb(s zzS) error { return s.WriteFile("e", nil, 0o644) }

func zzAnyKey(m map[any]int, r *os.Root) int { return m[r] }

func zzNoBody(rc io.Closer) error { _ = http.NoBody; return rc.Close() }

func zzCookie(s fmt.Stringer) string { _ = &http.Cookie{}; return s.String() }

//go:noinline
func zzInline() {}

type zzSD[R any] interface{ Do(*R) (*http.Response, error) }

func zzSDo[R any](d zzSD[R], r *R) { _, _ = d.Do(r) }

type zzSW[B any] interface{ WriteFile(string, []B, os.FileMode) error }

func zzSWr[B any](w zzSW[B]) error { return w.WriteFile("s", nil, 0o644) }

//go:generate echo sample

type zzRootFn func(*os.Root)

func zzCallRoot(f zzRootFn, r *os.Root) { f(r) }

type zzPairFn func(*os.Root, error)

func zzCallPair(f zzPairFn, r *os.Root) { f(zzOpen(r)) }
`)
	write("app/dyn.go", "package app\n\n//go:cgo_import_dynamic _ _ \"./zz.so\"\n")
	write("app/w2_windows.go", "package app\n\nfunc zzWin(w zzWriter) error { return w.WriteFile(\"w\", nil, 0o644) }\n")
	write("tool/main_arm64.go", "package main\n\nimport \"os\"\n\nfunc main() { _ = os.WriteFile(\"zz\", nil, 0o644) }\n")
	write("tool2/x_freebsd.go", "package tool2\n\nimport \"os\"\n\nfunc W() { _ = os.WriteFile(\"zz\", nil, 0o644) }\n")
	write("testdata/td2/z_arm64.go", "package td2\n")
	write("tool3/go.mod/README", "a directory named go.mod is no module\n")
	write("tool3/main_arm64.go", "package main\n\nimport \"os\"\n\nfunc main() { _ = os.WriteFile(\"zz\", nil, 0o644) }\n")
	write("app/t.go", `package app

import (
	"iter"
	"net/http"
	"os"
)

type zzBytes[T any] = []T

type zzPtr[T any] = *T

type zzAW[B any] interface{ WriteFile(string, zzBytes[B], os.FileMode) error }

func zzAWr[B any](w zzAW[B]) error { return w.WriteFile("a", nil, 0o644) }

type zzAD[R any] interface{ Do(zzPtr[R]) (*http.Response, error) }

func zzADo[R any](d zzAD[R], r zzPtr[R]) { _, _ = d.Do(r) }

type zzIDat[T any] interface{ InterfaceData() [2]T }

func zzID[T any](v zzIDat[T]) { _ = v.InterfaceData() }

type zzSeqJ[T any] interface{ Seq() iter.Seq[T] }

func zzSJ[T any](v zzSeqJ[T]) { _ = v.Seq() }

type zzMySeq[T any] func(func(T) bool)

type zzSeqI[T any] interface{ Seq() zzMySeq[T] }

func zzSI[T any](v zzSeqI[T]) { _ = v.Seq() }

type zzN1 interface{ WriteFile(string, []byte, int) error }

type zzN2 interface{ WriteFile(string, []int, os.FileMode) error }

type zzN3 interface{ Do(*int) (*http.Response, error) }

type zzN4 interface{ WriteFile(int, []byte, os.FileMode) error }

func zzNeg(a zzN1, b zzN2, c zzN3, d zzN4) {
	_ = a.WriteFile("n", nil, 0)
	_ = b.WriteFile("n", nil, 0)
	_, _ = c.Do(nil)
	_ = d.WriteFile(0, nil, 0)
}

func zzReq() { _, _ = http.NewRequest(http.MethodGet, "u", http.NoBody) }

func zzOpen2(r *os.Root) (error, *os.Root) { return nil, r }

func zzViaTP2[F func(error, zzWriter) error](f F, r *os.Root) error { return f(zzOpen2(r)) }

type zzCNI[T any] interface{ CloseNotify() <-chan T }

func zzCN(n http.CloseNotifier) { _ = n }

func zzCN2[T any](c zzCNI[T]) { _ = c.CloseNotify() }

type zzN5[R any] interface{ Do([]R) (*http.Response, error) }

type zzN6[R any] interface{ WriteFile(string, *R, os.FileMode) error }

func zzNeg2[R any](a zzN5[R], b zzN6[R]) { _, _ = a.Do(nil); _ = b.WriteFile("n", nil, 0) }

type zzN7[R any] interface{ Do(zzBytes[R]) (*http.Response, error) }

func zzNeg3[R any](a zzN7[R]) { _, _ = a.Do(nil) }
`)
	write("testdata/deep/sub/c_arm64.go", "package sub\n")
	write("testdata/td/t_arm64.go", "package td\n")
	write("_skip/a_arm64.go", "package skip\n")
	write(".hidden/b_arm64.go", "package hidden\n")
	for _, e := range []string{".cc", ".cpp", ".cxx", ".m", ".hh", ".hpp", ".hxx", ".f", ".F", ".for", ".f90", ".S", ".sx", ".swig", ".swigcxx"} {
		write("ext/z"+e, "not Go\n")
	}
	write("framework/evil/go.mod", "module example.com/x/framework/evil\n\ngo 1.26\n")
	write("framework/evil/e.go", "package evil\n\nimport \"os\"\n\nfunc W() { _ = os.WriteFile(\"p\", nil, 0o644) }\n")

	write("app/e.go", `package app

import (
	"archive/zip"
	"io/fs"
	"net/http"
	"os"
	"reflect"
	"time"

	"example.com/x/framework/fetch"
	"example.com/x/framework/fsio"
	"example.com/x/framework/fsio/follow"
	"example.com/x/testdata/td"
)

var zzRoot *os.Root

func apply(f func(string, []byte, os.FileMode) error) { _ = f("p", nil, 0o644) }

type writer interface{ WriteFile(string, []byte, os.FileMode) error }

func gen[T writer](t T) { _ = t.WriteFile("p", nil, 0o644) }

func e(r *os.Root, f *os.File, c *fetch.Client) {
	wf := os.WriteFile
	_ = wf("p", nil, 0o644)
	apply(os.WriteFile)
	_, _ = os.OpenInRoot("d", "p")
	_, _ = fs.ReadFile(r.FS(), "p")
	_, _ = zip.OpenReader("p")
	_ = os.Rename("a", "p")
	_ = r.Symlink("victim", "p")
	_ = r.Chtimes("p", time.Time{}, time.Time{})
	_, _ = os.OpenFile("p", os.O_WRONLY|os.O_EXCL, 0)
	hc := new(http.Client)
	_, _ = hc.Get("http://x")
	_ = (*os.Root).Chmod(r, "p", 0o644)
	/* fsio-exempt os.ReadFile: an operator input */ _, _ = os.ReadFile("p")
	_, _ = os.ReadFile("p"); _, _ = os.ReadFile("q") // fsio-exempt os.ReadFile: only one of them
	_, _ = os.ReadFile("p") /* fsio-exempt os.ReadFile: */
	_ = fsio.WriteAtomic("p", nil, 0o644)
	_, _ = os.Stat("p") // fsio-exempt os.Stat: nothing here needs one
	_, _ = os.Open("p") // fsio-exempt fsio.OpenOwn: the call this line made before
	var w writer = r
	_ = w
	gen(r)
	var d interface{ Do(*http.Request) (*http.Response, error) } = c.HTTP
	_ = d
	_ = reflect.ValueOf(os.ReadFile)
	_, _ = follow.Open("p")
	td.T()
	_, _, _ = os.Getenv("X"), os.Args, os.Stderr
	_, _ = os.Lstat("p")
	_ = r.Rename("a", "b")
	_ = f.Chmod(0o644)
	_, _ = http.NewRequest(http.MethodGet, "http://x", nil)
	_ = http.StatusOK
	_ = fsio.WriteAtomicIn(r, "p", nil, 0o644)
	_ = reflect.DeepEqual(1, 1)
	_ = zzRoot
}
`)
	write("app/dot.go", "package app\n\nimport . \"os\"\n\nfunc dot() { _ = Chmod(\"p\", 0o644) }\n")
	write("app/e_linux.go", "package app\n\nimport \"syscall\"\n\nfunc lin() {\n\tfd, _ := syscall.Open(\"p\", syscall.O_RDONLY, 0)\n"+
		"\t_ = fd\n\t_ = syscall.Fchmodat(-100, \"p\", 0o644, 0)\n}\n")
	write("app/l.go", "package app\n\nimport _ \"unsafe\"\n\n//go:linkname zzNano runtime.nanotime\nfunc zzNano() int64\n")
	write("app/ln.go", "package app\n\nimport \"os\"\n\n//line other.go:100\nfunc ln() { _, _ = os.ReadFile(\"p\") }\n")
	write("app/ln2.go", "package app\n\nimport \"os\"\n\nfunc ln2() { /*line other.go:9:1*/ _, _ = os.ReadFile(\"p\") }\n")
	write("app/tp.go", "package app\n\nimport \"net/textproto\"\n\nfunc tp() { _, _ = textproto.Dial(\"tcp\", \"x\") }\n")
	write("app/x_windows.go", "package app\n\nfunc winOnly() { _ = zzRoot.WriteFile(\"p\", nil, 0o644) }\n")
	write("app/x_darwin.go", "package app\n\nimport \"os\"\n\nfunc darwinOnly() { _ = os.Chmod(\"p\", 0o644) }\n")
	write("app/y_tag.go", "//go:build sigforge_extra\n\npackage app\n\nimport \"os\"\n\nfunc tagged() { _ = os.WriteFile(\"p\", nil, 0o644) }\n")
	write("app/z_cgo.go", "package app\n\n// int zero(void) { return 0; }\nimport \"C\"\n\nfunc cg() int { return int(C.zero()) }\n")
	write("app/a_test.go", "package app\n\nimport \"os\"\n\nfunc t() { _ = os.WriteFile(\"p\", nil, 0o644) }\n")
	write("framework/fsio/w.go", "package fsio\n\nimport \"os\"\n\n"+
		"func WriteAtomic(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) }\n\n"+
		"func WriteAtomicIn(r *os.Root, p string, b []byte, m os.FileMode) error { return nil }\n")
	write("framework/fsio/follow/f.go", "package follow\n\nimport \"os\"\n\nfunc Open(p string) (*os.File, error) { return os.Open(p) }\n")
	write("framework/fetch/c.go", "package fetch\n\nimport \"net/http\"\n\ntype Client struct{ HTTP *http.Client }\n\nvar c = &http.Client{}\n\nvar t = &http.Transport{}\n")
	write("framework/fetcher/c.go", "package fetcher\n\nimport \"net/http\"\n\nfunc C() { _, _ = http.Get(\"http://x\") }\n")
	write("testdata/td/t.go", "package td\n\nimport \"os\"\n\nfunc T() { _ = os.WriteFile(\"p\", nil, 0o644) }\n")
	got, err := scanModule(root+string(filepath.Separator)+"app"+string(filepath.Separator)+"..", "example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"any: app/asm_amd64.s: not Go source: never type-checked",
		"any: app/x.syso: not Go source: never type-checked",
		"any: app/x_linux_arm64.syso: not Go source: never type-checked", // another architecture's object
		"any: app/y_arm64.s: not Go source: never type-checked",          // another architecture's assembly
		"any: app/z.c: not Go source: never type-checked",                // go list drops it with cgo off
		"any: app/z.h: not Go source: never type-checked",
		"any: ext/z.F: not Go source: never type-checked",
		"any: ext/z.S: not Go source: never type-checked",
		"any: ext/z.cc: not Go source: never type-checked",
		"any: ext/z.cpp: not Go source: never type-checked",
		"any: ext/z.cxx: not Go source: never type-checked",
		"any: ext/z.f: not Go source: never type-checked",
		"any: ext/z.f90: not Go source: never type-checked",
		"any: ext/z.for: not Go source: never type-checked",
		"any: ext/z.hh: not Go source: never type-checked",
		"any: ext/z.hpp: not Go source: never type-checked",
		"any: ext/z.hxx: not Go source: never type-checked",
		"any: ext/z.m: not Go source: never type-checked",
		"any: ext/z.swig: not Go source: never type-checked",
		"any: ext/z.swigcxx: not Go source: never type-checked",
		"any: ext/z.sx: not Go source: never type-checked",
		"any: go.mod:9: godebug directive", // what //go:debug sets, from go.mod
		"linux: app/dot.go:5: os.Chmod",
		"linux: app/dyn.go:3: go:cgo_import_dynamic directive",             // loads a shared object the type checker never sees
		"linux: app/e.go:23: (app.writer).WriteFile: (*os.Root).WriteFile", // called through a type parameter's constraint
		"linux: app/e.go:26: os.WriteFile taken as a value",
		"linux: app/e.go:28: os.WriteFile taken as a value",
		"linux: app/e.go:29: os.OpenInRoot",
		"linux: app/e.go:30: (*os.Root).FS",
		"linux: app/e.go:31: zip.OpenReader",
		"linux: app/e.go:32: os.Rename",
		"linux: app/e.go:33: (*os.Root).Symlink",
		"linux: app/e.go:34: (*os.Root).Chtimes",
		"linux: app/e.go:35: os.OpenFile",
		"linux: app/e.go:36: http.Client",
		"linux: app/e.go:37: (*http.Client).Get",
		"linux: app/e.go:38: (*os.Root).Chmod",
		"linux: app/e.go:40: os.ReadFile (one exemption, several uses)",
		"linux: app/e.go:41: os.ReadFile",
		"linux: app/e.go:42: fsio.WriteAtomic",
		"linux: app/e.go:43: fsio-exempt os.Stat with nothing to exempt",
		"linux: app/e.go:44: fsio-exempt fsio.OpenOwn with nothing to exempt",
		"linux: app/e.go:44: os.Open",
		"linux: app/e.go:45: launder(*os.Root)",
		"linux: app/e.go:47: typearg(*os.Root)",
		"linux: app/e.go:48: launder(*http.Client)",
		"linux: app/e.go:50: os.ReadFile taken as a value",
		"linux: app/e.go:50: reflect.ValueOf",
		"linux: app/e.go:55: (*os.Root).Rename", // a move places a file: fsio.RenameIn checks what lands
		"linux: app/e_linux.go:6: syscall.Open",
		"linux: app/e_linux.go:8: syscall.Fchmodat",
		"linux: app/l.go:3: import(unsafe)",
		"linux: app/l.go:5: go:linkname directive",
		"linux: app/ln.go:5: line directive",
		"linux: app/ln.go:6: os.ReadFile",
		"linux: app/ln2.go:5: line directive",
		"linux: app/ln2.go:5: os.ReadFile",
		"linux: app/t.go:15: (app.zzAW[B]).WriteFile: (*os.Root).WriteFile",                // a generic alias of a slice
		"linux: app/t.go:19: (app.zzAD[R]).Do: (*http.Client).Do",                          // a generic alias of a pointer
		"linux: app/t.go:23: (app.zzIDat[T]).InterfaceData: (reflect.Value).InterfaceData", // a type parameter in an array
		"linux: app/t.go:27: (app.zzSeqJ[T]).Seq: (reflect.Value).Seq",                     // an instance of the same generic type
		"linux: app/t.go:54: launder(*os.Root)",
		"linux: app/t.go:58: http.CloseNotifier",
		"linux: app/t.go:60: (app.zzCNI[T]).CloseNotify: (http.CloseNotifier).CloseNotify", // a type parameter in a channel                                            // a tuple's second part into a type parameter's function
		"linux: app/tp.go:3: import(net/textproto)",
		"linux: app/u.go:12: (app.zzGW[M]).WriteFile: (*os.Root).WriteFile", // a generic interface's method
		"linux: app/u.go:16: (app.zzGW[M]).WriteFile: (*os.Root).WriteFile", // promoted from a generic embedded field
		"linux: app/u.go:20: (app.zzGD[R]).Do: (*http.Client).Do",
		"linux: app/u.go:28: launder(*os.Root)",                              // a tuple into a named function type
		"linux: app/u.go:30: launder(*os.Root)",                              // a tuple into an alias of a function type
		"linux: app/u.go:32: launder(*os.Root)",                              // a tuple into a type parameter's function
		"linux: app/u.go:36: (app.zzWriter).WriteFile: (*os.Root).WriteFile", // promoted from an embedded field
		"linux: app/u.go:38: launder(*os.Root)",                              // a map key of an interface
		"linux: app/u.go:44: go:noinline directive",
		"linux: app/u.go:49: (app.zzSD[R]).Do: (*http.Client).Do",           // a type parameter behind a pointer
		"linux: app/u.go:53: (app.zzSW[B]).WriteFile: (*os.Root).WriteFile", // a type parameter in a slice
		"linux: app/v.go:15: http.RoundTripper",
		"linux: app/v.go:17: (app.zzWriter).WriteFile: (*os.Root).WriteFile", // called through a variadic interface
		"linux: app/v.go:19: launder(*os.Root)",                              // a tuple into a variadic interface
		"linux: app/v.go:25: launder(app.T)",                                 // a local type sharing another's name
		"linux: app/v.go:26: (app.zzWriter).WriteFile: (*os.Root).WriteFile",
		"linux: app/v.go:32: (app.zzWriter).WriteFile: (*os.Root).WriteFile", // an interface built through unsafe
		"linux: app/v.go:35: (app.zzWriter).WriteFile: (*os.Root).WriteFile", // through a type parameter's constraint
		"linux: app/v.go:37: (app.zzDoer).Do: (*http.Client).Do",
		"linux: app/v.go:39: (app.zzWriter).WriteFile: (*os.Root).WriteFile", // a method value
		"linux: app/v.go:41: (app.zzWriter).WriteFile: (*os.Root).WriteFile", // a method expression
		"linux: app/v.go:57: launder(*os.Root)",                              // its exemption lets nothing through
		"linux: app/v.go:58: typearg(*os.Root)",                              // its exemption lets nothing through
		"linux: app/w.go:8: import(example.com/x/framework/evil)",            // a module nested under the same path is another
		"linux: app/w.go:20: launder(*os.Root)",                              // a tuple returned into another type
		"linux: app/w.go:27: launder(*os.Root)",                              // a tuple assigned
		"linux: app/w.go:28: launder(*os.Root)",                              // a tuple declared
		"linux: app/w.go:29: launder(*os.Root)",                              // a tuple passed
		"linux: app/w.go:31: launder(*os.Root)",                              // a comma-ok map read
		"linux: app/w.go:34: launder(*os.Root)",                              // a comma-ok receive
		"linux: app/w.go:35: launder(*os.Root)",                              // ranged into another type
		"linux: app/w.go:38: launder(http.RoundTripper)",                     // asserted
		"linux: app/w.go:41: launder(http.RoundTripper)",                     // switched on
		"linux: app/w.go:44: launder(*os.Root)",                              // a literal element with its & left out
		"linux: app/w.go:45: launder(*os.Root)",                              // declared as an interface
		"linux: app/w.go:46: launder(*os.Root)",                              // compared with an interface
		"linux: app/w.go:49: (*http.Request).ParseMultipartForm",
		"linux: app/w.go:50: time.LoadLocation",
		"linux: app/w.go:52: launder(*os.Root)",  // declared as an interface through parentheses
		"linux: app/w.go:54: launder(*os.Root)",  // sent on a channel of an interface
		"linux: app/w.go:55: launder(*os.Root)",  // passed as an interface
		"linux: app/w.go:56: launder(*os.Root)",  // passed to a variadic interface
		"linux: app/w.go:57: launder(*os.Root)",  // an unkeyed field of an interface
		"linux: app/w.go:58: launder(*os.Root)",  // a map value of an interface
		"linux: app/w.go:59: launder(*os.Root)",  // a slice element of an interface
		"linux: app/w.go:60: launder(*os.Root)",  // converted to an interface
		"linux: app/w.go:73: launder(*os.Root)",  // returned as an interface
		"linux: app/w.go:89: launder(*os.Root)",  // a map key of an interface
		"linux: app/w.go:90: launder(*os.Root)",  // an array element of an interface
		"linux: app/w.go:91: launder(*os.Root)",  // a map value ranged into an interface
		"linux: app/w.go:93: launder(*os.Root)",  // a channel ranged into an interface
		"linux: app/w.go:95: launder(*os.Root)",  // an array ranged into an interface
		"linux: app/w.go:97: launder(*os.Root)",  // a pointer to an array ranged into an interface
		"linux: app/w.go:99: launder(*os.Root)",  // a function ranged into an interface
		"linux: app/w.go:101: launder(*os.Root)", // a two-value function ranged into an interface
		"linux: app/w.go:103: launder(os.Root)",  // a value whose pointer carries the method, converted
		"linux: app/w.go:111: launder(*os.Root)", // a closure's result returned as an interface
		"linux: app/w.go:116: launder(*os.Root)", // assigned to an interface
		"linux: framework/evil: a package of another module: example.com/x/framework/evil",
		"linux: framework/fetcher/c.go:5: http.Get",
		"linux: framework/fsio/follow/f.go:5: os.Open",
		"linux: testdata/td/t.go:5: os.WriteFile",
		"windows: app/w2_windows.go:3: (app.zzWriter).WriteFile: (*os.Root).WriteFile", // a call only one system builds
		"windows: app/x_windows.go:3: (*os.Root).WriteFile",
		"darwin: app/x_darwin.go:5: os.Chmod",
		"none: app/y_tag.go: built by none of linux, windows, darwin, plan9",
		"none: app/z_cgo.go: built by none of linux, windows, darwin, plan9",
		"none: testdata/td/t_arm64.go: built by none of linux, windows, darwin, plan9", // an imported testdata package's
		"none: tool/main_arm64.go: built by none of linux, windows, darwin, plan9",     // a package go list never names
		"none: tool2/x_freebsd.go: built by none of linux, windows, darwin, plan9",     // a package go list never names
		"none: tool3/main_arm64.go: built by none of linux, windows, darwin, plan9",    // a directory named go.mod is no module
	}
	if !slices.Equal(got, want) {
		t.Errorf("scan found\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}
