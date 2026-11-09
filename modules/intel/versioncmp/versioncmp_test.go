package versioncmp

import "testing"

// TestPEP440 pins the PyPI ordering that the shared "semver-ish" comparator got wrong — the
// pre-release / post / dev / epoch rules of PEP 440. The 1.0a1 < 1.0 row is the audit case.
func TestPEP440(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0a1", "1.0", -1},      // a pre-release is BELOW the final release (the audit bug)
		{"1.0a1", "1.0b1", -1},    // a < b
		{"1.0b1", "1.0rc1", -1},   // b < rc
		{"1.0rc1", "1.0", -1},     // rc < final
		{"1.0.post1", "1.0", 1},   // .post is ABOVE the release
		{"1.0", "1.0.post1", -1},  // symmetry
		{"1.0.dev1", "1.0a1", -1}, // a dev release is below any pre-release on the same base
		{"1.0.dev1", "1.0", -1},   // dev below final
		{"1!1.0", "2.0", 1},       // epoch dominates the release
		{"1!1.0", "1!1.0", 0},     // equal epoch+release
		{"1.0", "1.0.0", 0},       // trailing-zero release equality
		{"1.2.3", "1.2.4", -1},
		{"1.0a2", "1.0a1", 1},
		{"1.0.post2", "1.0.post1", 1},
	}
	for _, c := range cases {
		got, ok := Compare("pypi", c.a, c.b)
		if !ok {
			t.Errorf("Compare(pypi,%q,%q) ok=false; both must parse", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(pypi,%q,%q) = %d; want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestSemver pins the npm/Go/crates.io ordering and the empty-ecosystem default.
func TestSemver(t *testing.T) {
	cases := []struct {
		eco, a, b string
		want      int
	}{
		{"npm", "1.2.3", "1.2.3", 0},
		{"npm", "1.2", "1.2.0", 0},
		{"npm", "v1.2.3", "1.2.3", 0},
		{"npm", "1.2.3", "1.2.4", -1},
		{"npm", "1.10.0", "1.9.0", 1},      // numeric, not lexical
		{"npm", "1.0.0-rc.1", "1.0.0", -1}, // pre-release below release
		{"npm", "1.0.0-alpha", "1.0.0-beta", -1},
		{"npm", "1.0.0-alpha.1", "1.0.0-alpha", 1},  // more identifiers wins
		{"npm", "4.17.21+build", "4.17.21", 0},      // build metadata ignored
		{"", "20230101120000", "20230101119999", 1}, // long numeric, empty eco uses semver default
		{"crates.io", "0.1.0", "0.2.0", -1},
	}
	for _, c := range cases {
		got, ok := Compare(c.eco, c.a, c.b)
		if !ok {
			t.Errorf("Compare(%q,%q,%q) ok=false; both must parse", c.eco, c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q,%q) = %d; want %d", c.eco, c.a, c.b, got, c.want)
		}
	}
}

// TestUnparseableReturnsNotOK is the honesty contract: a form the scheme cannot position
// returns ok=false so the caller keeps the version UNKNOWN rather than guessing.
func TestUnparseableReturnsNotOK(t *testing.T) {
	cases := []struct{ eco, a, b string }{
		{"npm", "trunk", "1.0.0"},        // not a version
		{"npm", "1.0.0", ""},             // empty operand
		{"go", "deadbeef", "1.0.0"},      // a bare git hash is not a semver/Go version
		{"pypi", "not-a-version", "1.0"}, //
		{"debian", "deadbeef", "1.0"},    // Debian upstream must start with a digit (Policy §5.6.12)
		{"rubygems", "cafebabe", "1.0"},  // Gem::Version must start with a digit
		{"rpm", "...", "1.0"},            // no alphanumeric content to order
		{"maven", "", "1.0"},             // empty operand
	}
	for _, c := range cases {
		if _, ok := Compare(c.eco, c.a, c.b); ok {
			t.Errorf("Compare(%q,%q,%q) ok=true; an unparseable form must be ok=false", c.eco, c.a, c.b)
		}
	}
}

// TestDebian pins dpkg's ordering (cases from deb-version(7) and dpkg's verrevcmp testsuite).
func TestDebian(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1:1.0~rc1", "1:1.0", -1}, // a tilde sorts before the empty string
		{"1.0", "1.0-1", -1},       // a revision raises the version above the bare upstream
		{"1.0~beta1", "1.0", -1},   // tilde pre-release below the release
		{"1.0-1", "1.0-2", -1},     // revision compared like the upstream
		{"1:1.0", "2.0", 1},        // epoch dominates the upstream
		{"1.0", "0:1.0", 0},        // a missing epoch equals epoch 0
		{"1.0+deb1", "1.0", 1},     // '+' sorts after the end of string
		{"2.0", "2.0", 0},
	}
	runCmp(t, "debian", cases)
}

// TestRPM pins rpmvercmp (cases from rpm's lib/rpmvercmp.at).
func TestRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0~beta", "1.0", -1}, // tilde sorts before everything
		{"1.0", "1.0.1", -1},
		{"1.0", "1.1", -1},
		{"1.a", "1.0", -1}, // an alpha run is older than a numeric one
		{"1.0", "1.a", 1},  // and a numeric run is newer (both sides of the type-mismatch rule)
		{"1.0^", "1.0", 1}, // caret sorts after a version that ends
		{"1.01", "1.1", 0}, // leading zeros ignored inside a numeric run
		{"2", "1", 1},
		{"1.0-1", "1.0-1", 0}, // the same version-release
	}
	runCmp(t, "rpm", cases)
}

// TestMaven pins ComparableVersion (cases from Maven's ComparableVersionTest).
func TestMaven(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0-alpha", "1.0", -1}, // alpha qualifier below the release
		{"1.0", "1.0-sp", -1},    // sp (service pack) above the release
		{"1.0-rc1", "1.0", -1},   // rc below the release
		{"1.0-alpha1", "1.0-alpha2", -1},
		{"1.0-alpha1", "1.0-beta1", -1}, // alpha < beta
		{"1.0-milestone1", "1.0-rc1", -1},
		{"1.0-cr1", "1.0-rc1", 0}, // cr is an alias of rc
		{"1.0.RELEASE", "1.0", 0}, // RELEASE is an alias of the plain release
		{"1", "1.1", -1},
		{"1.0-snapshot", "1.0", -1}, // snapshot below the release
	}
	runCmp(t, "maven", cases)
}

// TestGo pins Go module ordering, which is semver 2.0.0 — pseudo-versions and "+incompatible"
// included (cases from Go's cmd/go/internal/modfetch pseudo-version semantics).
func TestGo(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.0.0-20200101000000-aaaaaaaaaaaa", "v0.0.0-20200102000000-bbbbbbbbbbbb", -1}, // earlier pseudo-version timestamp is lower
		{"v0.0.0-20200102000000-bbbbbbbbbbbb", "v1.0.0", -1},                             // any pseudo-version below a tagged release
		{"v2.0.0+incompatible", "v2.0.0", 0},                                             // build metadata ignored
		{"v1.2.3", "v1.2.4", -1},
		{"v1.2.3-pre", "v1.2.3", -1}, // a pre-release below the release
	}
	runCmp(t, "go", cases)
}

// TestRubyGems pins Gem::Version (cases from RubyGems' version_test.rb).
func TestRubyGems(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0.pre", "1.0.0", -1}, // a letter segment marks a pre-release below its release
		{"1.0.a", "1.0", -1},
		{"1.0.0.rc1", "1.0.0", -1},
		{"1.0.0.beta", "1.0.0.rc1", -1}, // beta < rc lexically
		{"1.1", "1.0", 1},
		{"1.0.0", "1.0.0.0", 0}, // trailing zero segment is equal
		{"1.0-1", "1.0", -1},    // '-' becomes ".pre." → a pre-release
	}
	runCmp(t, "rubygems", cases)
}

func runCmp(t *testing.T, eco string, cases []struct {
	a, b string
	want int
}) {
	t.Helper()
	for _, c := range cases {
		got, ok := Compare(eco, c.a, c.b)
		if !ok {
			t.Errorf("Compare(%q,%q,%q) ok=false; both must parse", eco, c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q,%q) = %d; want %d", eco, c.a, c.b, got, c.want)
		}
	}
}
