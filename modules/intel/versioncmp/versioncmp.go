// Package versioncmp compares two version strings UNDER THE RULES OF A SPECIFIC
// ECOSYSTEM. A single "semver-ish" comparator sorts PEP 440 and OS-package versions
// wrong at the edges (a Python "1.0a1" is a pre-release BELOW "1.0", not above it),
// so every caller that positions a pinned version inside an advisory range must route
// through here with the record's ecosystem.
//
// HONESTY (§2). Compare returns ok=false when it cannot parse BOTH operands under the
// chosen scheme. The caller MUST then keep the version UNKNOWN — it must never turn an
// unparseable comparison into a "vulnerable" or "no-vuln" verdict by guessing a result.
//
// ECOSYSTEM COVERAGE (each ordered by that ecosystem's OWN algorithm, so a pinned version is
// positioned the way its package manager would position it):
//
//	PyPI    (pypi/pip/python/poetry) — PEP 440: epoch "N!", release, pre-release a<b<rc<release,
//	        ".postN" (> release), ".devN" (< everything on the same base).
//	SemVer  (npm, crates.io, Go, Hex, SwiftURL, Bitnami, ConanCenter, …, and the DEFAULT for an
//	        EMPTY ecosystem) — MAJOR.MINOR.PATCH, "-pre" sorts below the release, "+build" ignored.
//	        Go pseudo-versions (v0.0.0-<yyyymmddhhmmss>-<hash>) and "+incompatible" included.
//	NuGet   — semver with up to four numeric parts, pre-release labels compared case-insensitively.
//	Pub     — semver, but "+build" orders (1.0.0+1 > 1.0.0).
//	Debian  (Debian/Ubuntu/Echo) — dpkg's epoch:upstream-revision ordering, tilde before all else.
//	RPM     (Red Hat/Rocky Linux/AlmaLinux/SUSE/openSUSE/Mageia/openEuler) — rpmvercmp.
//	apk     (Alpine/Wolfi/Chainguard/MinimOS/…) — apk-tools: numbers, letter, _suffix, -rN.
//	Maven   — ComparableVersion qualifier order alpha<beta<milestone<rc<snapshot<""<sp.
//	RubyGems— Gem::Version: a letter segment marks a pre-release below its release.
//	Packagist — Composer / PHP version_compare: dev < alpha < beta < RC < release < patch.
//	Hackage, CRAN — numeric component lists; a longer list ranks above its own prefix.
//
// Ecosystem names are OSV's (a release suffix such as "Debian:12" or "Alpine:v3.18" is ignored
// here), and each maps to the ordering OSV itself applies to that ecosystem. An ecosystem with no
// ordering here returns ok=false — it is never guessed as semver. A form that still cannot be
// positioned under its scheme (a bare git hash, an empty operand) returns ok=false too, and the
// caller MUST keep the version UNKNOWN rather than guess a result.
package versioncmp

import (
	"regexp"
	"strings"
)

// Compare returns -1/0/1 for a<b / a==b / a>b under ecosystem's scheme, and ok=true only
// when BOTH operands parsed. ok=false ⇒ cmp is meaningless, keep the version unknown.
func Compare(ecosystem, a, b string) (cmp int, ok bool) {
	switch k := scheme(ecosystem); k {
	case schemePEP440:
		x, okx := parsePEP440(a)
		y, oky := parsePEP440(b)
		if !okx || !oky {
			return 0, false
		}
		return cmpPEP440(x, y), true
	case schemeDebian:
		xe, xu, xr, okx := parseDebian(a)
		ye, yu, yr, oky := parseDebian(b)
		if !okx || !oky {
			return 0, false
		}
		return cmpDebian(xe, xu, xr, ye, yu, yr), true
	case schemeRPM:
		if !rpmParseable(a) || !rpmParseable(b) {
			return 0, false
		}
		return cmpRPMEVR(a, b)
	case schemeMaven:
		x, okx := parseMaven(a)
		y, oky := parseMaven(b)
		if !okx || !oky {
			return 0, false
		}
		return sign(x.compare(y)), true
	case schemeRubyGems:
		x, okx := parseGem(a)
		y, oky := parseGem(b)
		if !okx || !oky {
			return 0, false
		}
		return cmpGem(x, y), true
	case schemeAPK:
		x, okx := parseAPK(a)
		y, oky := parseAPK(b)
		if !okx || !oky {
			return 0, false
		}
		return cmpAPK(x, y), true
	case schemePackagist:
		x, okx := parsePackagist(a)
		y, oky := parsePackagist(b)
		if !okx || !oky {
			return 0, false
		}
		return cmpPackagist(x, y), true
	case schemeHackage, schemeCRAN:
		x, okx := parseNumList(a, k == schemeCRAN)
		y, oky := parseNumList(b, k == schemeCRAN)
		if !okx || !oky {
			return 0, false
		}
		return cmpNumList(x, y), true
	case schemeUnknown:
		return 0, false
	case schemeNuGet:
		a, b = strings.ToLower(a), strings.ToLower(b)
		fallthrough
	default:
		x, okx := parseSemver(a)
		y, oky := parseSemver(b)
		if !okx || !oky {
			return 0, false
		}
		if c := cmpSemver(x, y); c != 0 || k != schemePub {
			return c, true
		}
		xb, yb := semverBuild(a), semverBuild(b)
		if len(xb) == 0 || len(yb) == 0 {
			return cmpInt(len(xb), len(yb)), true // no build ranks below any build
		}
		return cmpPre(xb, yb), true
	}
}

type schemeKind int

const (
	schemeSemver schemeKind = iota
	schemePEP440
	schemeDebian
	schemeRPM
	schemeMaven
	schemeRubyGems
	schemeAPK
	schemeNuGet
	schemePub
	schemePackagist
	schemeHackage
	schemeCRAN
	schemeUnknown
)

// scheme maps an OSV ecosystem name (release suffix ignored) to its ordering, following the
// mapping OSV's own version library uses; anything unlisted is schemeUnknown, never semver.
func scheme(eco string) schemeKind {
	base, _, _ := strings.Cut(strings.TrimSpace(eco), ":")
	switch strings.ToLower(base) {
	case "pypi", "pip", "python", "poetry":
		return schemePEP440
	case "deb", "debian", "ubuntu", "echo":
		return schemeDebian
	case "rpm", "redhat", "red hat", "fedora", "rocky linux", "almalinux", "suse", "opensuse", "mageia", "openeuler":
		return schemeRPM
	case "maven":
		return schemeMaven
	case "rubygems", "gem":
		return schemeRubyGems
	case "alpine", "wolfi", "chainguard", "minimos", "alpaquita", "bellsoft hardened containers":
		return schemeAPK
	case "nuget":
		return schemeNuGet
	case "pub":
		return schemePub
	case "packagist", "composer":
		return schemePackagist
	case "hackage":
		return schemeHackage
	case "cran":
		return schemeCRAN
	case "", "npm", "crates.io", "go", "gomod", "golang", "hex", "swifturl", "bitnami", "conancenter",
		"julia", "ghc", "bioconductor", "docker hardened images":
		return schemeSemver // the empty ecosystem keeps the documented semver default
	}
	return schemeUnknown
}

// ---------------------------------------------------------------------------
// SemVer (and the generic default)
// ---------------------------------------------------------------------------

type semver struct {
	release []string // numeric core segments (as strings, so a long build-date does not overflow)
	pre     []string // dot-separated pre-release identifiers; nil means a final release
}

// parseSemver strips a v prefix and "+build" metadata, splits the pre-release at the first
// "-", and requires every core segment to be numeric. A non-numeric core segment (a Maven
// "RELEASE", a Debian "1:2" colon) is NOT confidently a semver, so ok=false.
func parseSemver(s string) (semver, bool) {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var pre []string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		if p := v[i+1:]; p != "" {
			pre = strings.Split(p, ".")
		}
		v = v[:i]
	}
	if v == "" {
		return semver{}, false
	}
	core := strings.Split(v, ".")
	for _, seg := range core {
		if !isNum(seg) {
			return semver{}, false
		}
	}
	return semver{release: core, pre: pre}, true
}

func cmpSemver(x, y semver) int {
	n := len(x.release)
	if len(y.release) > n {
		n = len(y.release)
	}
	for i := 0; i < n; i++ {
		xs, ys := "0", "0" // a missing segment is 0, so 1.2 == 1.2.0
		if i < len(x.release) {
			xs = x.release[i]
		}
		if i < len(y.release) {
			ys = y.release[i]
		}
		if c := cmpNumStr(xs, ys); c != 0 {
			return c
		}
	}
	return cmpPre(x.pre, y.pre)
}

// cmpPre applies the semver pre-release rule: a version WITH a pre-release is lower than one
// without (1.0.0-rc < 1.0.0); numeric identifiers rank below alphanumeric and compare
// numerically; a longer identifier set wins when every shared identifier is equal.
func cmpPre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		an, bn := isNum(a[i]), isNum(b[i])
		switch {
		case an && bn:
			if c := cmpNumStr(a[i], b[i]); c != 0 {
				return c
			}
		case an:
			return -1 // numeric identifier < alphanumeric identifier
		case bn:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// PEP 440 (PyPI)
// ---------------------------------------------------------------------------

type pep440 struct {
	epoch   int
	release []string // numeric release segments
	pre     *preRel  // nil ⇒ no pre-release
	post    *int     // nil ⇒ no post
	dev     *int     // nil ⇒ no dev
}

type preRel struct {
	letter int // a=0, b=1, rc/c/pre/preview=2
	num    int
}

// pep440Re is a pragmatic subset of the PEP 440 grammar: epoch, dotted release, one
// a/b/rc pre-release, a .post (or implicit "-N") release, and a .dev release. +local
// metadata is stripped before matching. A version that does not match is reported
// unparseable (ok=false), never guessed.
var pep440Re = regexp.MustCompile(`^(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[._-]?(a|b|c|rc|alpha|beta|pre|preview)[._-]?(\d*))?` +
	`(?:(?:[._-]?(?:post|rev|r)[._-]?(\d*))|-(\d+))?` +
	`(?:[._-]?dev[._-]?(\d*))?$`)

func parsePEP440(s string) (pep440, bool) {
	v := strings.ToLower(strings.TrimSpace(s))
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 { // local metadata is ignored for ordering
		v = v[:i]
	}
	m := pep440Re.FindStringSubmatch(v)
	if m == nil {
		return pep440{}, false
	}
	out := pep440{epoch: atoiOr(m[1], 0), release: strings.Split(m[2], ".")}
	if m[3] != "" {
		out.pre = &preRel{letter: preLetter(m[3]), num: atoiOr(m[4], 0)}
	}
	if m[5] != "" || m[6] != "" { // ".postN" or implicit "-N"
		p := atoiOr(m[5], 0)
		if m[6] != "" {
			p = atoiOr(m[6], 0)
		}
		out.post = &p
	}
	if strings.Contains(v, "dev") { // local stripped above, so "dev" only appears in a real dev segment
		d := atoiOr(m[7], 0)
		out.dev = &d
	}
	return out, true
}

func preLetter(s string) int {
	switch s {
	case "a", "alpha":
		return 0
	case "b", "beta":
		return 1
	default: // c, rc, pre, preview
		return 2
	}
}

// cmpPEP440 follows the PEP 440 ordering: epoch, release (trailing zeros ignored), then
// the pre/post/dev stages with their sentinel rules (dev-only sorts lowest, a bare release
// sorts above any pre-release, a post sorts above the release).
func cmpPEP440(x, y pep440) int {
	if c := cmpInt(x.epoch, y.epoch); c != 0 {
		return c
	}
	if c := cmpReleaseTrim(x.release, y.release); c != 0 {
		return c
	}
	if c := cmpPreStage(x, y); c != 0 {
		return c
	}
	if c := cmpOpt(x.post, y.post, false); c != 0 { // absent post sorts BELOW present
		return c
	}
	return cmpOpt(x.dev, y.dev, true) // absent dev sorts ABOVE present
}

// cmpPreStage ranks the pre-release stage: a dev-only version (no pre, no post) is lowest;
// an actual pre-release is in the middle ordered by letter then number; a version with no
// pre-release is highest.
func cmpPreStage(x, y pep440) int {
	xk, xl, xn := preStageKey(x)
	yk, yl, yn := preStageKey(y)
	if c := cmpInt(xk, yk); c != 0 {
		return c
	}
	if c := cmpInt(xl, yl); c != 0 {
		return c
	}
	return cmpInt(xn, yn)
}

func preStageKey(v pep440) (kind, letter, num int) {
	switch {
	case v.pre == nil && v.post == nil && v.dev != nil:
		return 0, 0, 0 // dev release with no pre/post sorts below everything
	case v.pre == nil:
		return 2, 0, 0 // no pre-release sorts above any pre-release
	default:
		return 1, v.pre.letter, v.pre.num
	}
}

// cmpOpt compares two optional integers. absentHigh=false ⇒ a nil sorts below a present
// value (post semantics); absentHigh=true ⇒ a nil sorts above (dev semantics).
func cmpOpt(x, y *int, absentHigh bool) int {
	xr, xv := optRank(x, absentHigh)
	yr, yv := optRank(y, absentHigh)
	if c := cmpInt(xr, yr); c != 0 {
		return c
	}
	return cmpInt(xv, yv)
}

func optRank(p *int, absentHigh bool) (rank, val int) {
	if p == nil {
		if absentHigh {
			return 1, 0
		}
		return 0, 0
	}
	if absentHigh {
		return 0, *p
	}
	return 1, *p
}

// cmpReleaseTrim compares two release segment lists with trailing-zero segments ignored, so
// "1.0" and "1.0.0" are equal (the PEP 440 / semver 1.2==1.2.0 rule).
func cmpReleaseTrim(a, b []string) int {
	a, b = trimZeros(a), trimZeros(b)
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpNumStr(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func trimZeros(seg []string) []string {
	n := len(seg)
	for n > 1 && isZero(seg[n-1]) {
		n--
	}
	return seg[:n]
}

func isZero(s string) bool { return strings.TrimLeft(s, "0") == "" }

// ---------------------------------------------------------------------------
// shared numeric helpers (string-based, so a 14-digit build date never overflows)
// ---------------------------------------------------------------------------

func isNum(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cmpNumStr compares two all-digit strings by numeric value regardless of length.
func cmpNumStr(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return def
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }
func isAlphaByte(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnumByte(c byte) bool { return isDigitByte(c) || isAlphaByte(c) }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Debian — deb-version(7): [epoch:]upstream[-revision]
// ---------------------------------------------------------------------------

// parseDebian splits a Debian version into epoch (absent ⇒ "0"), upstream and revision (the
// text after the LAST hyphen). It accepts only the characters dpkg permits and requires the
// upstream to start with a digit (Debian Policy §5.6.12), so a bare git hash stays ok=false
// rather than being positioned as if it were a version.
func parseDebian(s string) (epoch, upstream, revision string, ok bool) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", "", "", false
	}
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e := v[:i]; isNum(e) {
			epoch, v = e, v[i+1:]
		} else {
			return "", "", "", false
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		revision, v = v[i+1:], v[:i]
	}
	upstream = v
	if upstream == "" || !isDigitByte(upstream[0]) {
		return "", "", "", false
	}
	for i := 0; i < len(upstream); i++ {
		if !debianChar(upstream[i]) {
			return "", "", "", false
		}
	}
	for i := 0; i < len(revision); i++ {
		if !debianChar(revision[i]) {
			return "", "", "", false
		}
	}
	return epoch, upstream, revision, true
}

func debianChar(c byte) bool {
	return isAlnumByte(c) || c == '.' || c == '+' || c == '~' || c == '-'
}

func cmpDebian(xe, xu, xr, ye, yu, yr string) int {
	if c := cmpNumStr(xe, ye); c != 0 {
		return c
	}
	if c := debianVerrevcmp(xu, yu); c != 0 {
		return c
	}
	return debianVerrevcmp(xr, yr)
}

// debianVerrevcmp is dpkg's version-segment comparison, ported from verrevcmp: it alternates
// non-digit runs (ordered by debianOrder, so a tilde sorts before everything including the end
// of the string) and digit runs (compared by numeric value), until a difference is found.
func debianVerrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigitByte(a[i])) || (j < len(b) && !isDigitByte(b[j])) {
			if c := debianOrder(a, i) - debianOrder(b, j); c != 0 {
				return sign(c)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigitByte(a[i]) && j < len(b) && isDigitByte(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigitByte(a[i]) {
			return 1
		}
		if j < len(b) && isDigitByte(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

// debianOrder is dpkg's per-character sort weight: digits and end-of-string are 0, a letter
// keeps its byte value, a tilde is -1 (before everything), any other character sorts after
// the letters.
func debianOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigitByte(c):
		return 0
	case isAlphaByte(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// ---------------------------------------------------------------------------
// RPM — rpmvercmp
// ---------------------------------------------------------------------------

func rpmParseable(s string) bool {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); i++ {
		if isAlnumByte(s[i]) {
			return true
		}
	}
	return false
}

// splitEVR splits an RPM [epoch:]version[-release]: a missing epoch is "0", and the
// release is what follows the LAST "-".
func splitEVR(s string) (epoch, version, release string) {
	s, epoch = strings.TrimSpace(s), "0"
	if i := strings.IndexByte(s, ':'); i > 0 && isNum(s[:i]) {
		epoch, s = s[:i], s[i+1:]
	}
	version = s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		version, release = s[:i], s[i+1:]
	}
	return epoch, version, release
}

// cmpRPMEVR is rpm's order: epoch as a number, then version, then release, each compared on
// its own with rpmvercmp. With the rest equal, a release on one side only cannot be ordered.
func cmpRPMEVR(a, b string) (int, bool) {
	ae, av, ar := splitEVR(a)
	be, bv, br := splitEVR(b)
	if c := cmpNumStr(ae, be); c != 0 {
		return c, true
	}
	if c := cmpRPM(av, bv); c != 0 {
		return c, true
	}
	if (ar == "") != (br == "") {
		return 0, false
	}
	return cmpRPM(ar, br), true
}

// cmpRPM is a port of rpm's rpmvercmp: separators are skipped, a tilde sorts before any other
// content (even the empty string) and a caret sorts after a version that ends, then equal-type
// runs (all-digit or all-alpha) are compared, a numeric run outranking an alphabetic one.
func cmpRPM(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnumByte(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnumByte(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if (i < len(a) && a[i] == '^') || (j < len(b) && b[j] == '^') {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		startI, startJ := i, j
		isNumSeg := isDigitByte(a[i])
		if isNumSeg {
			for i < len(a) && isDigitByte(a[i]) {
				i++
			}
			for j < len(b) && isDigitByte(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlphaByte(a[i]) {
				i++
			}
			for j < len(b) && isAlphaByte(b[j]) {
				j++
			}
		}
		segA, segB := a[startI:i], b[startJ:j]
		if segB == "" { // the two runs are different types; a numeric run is newer than an alpha one
			if isNumSeg {
				return 1
			}
			return -1
		}
		if isNumSeg {
			if c := cmpNumStr(segA, segB); c != 0 {
				return c
			}
		} else if c := strings.Compare(segA, segB); c != 0 {
			return sign(c)
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

// ---------------------------------------------------------------------------
// Maven — ComparableVersion
// ---------------------------------------------------------------------------

type mvnItem interface {
	compare(mvnItem) int
	isNull() bool
}

type mvnInt struct{ v string } // digit string, leading zeros stripped ("0" ⇒ zero)

func (x mvnInt) isNull() bool { return isZero(x.v) }
func (x mvnInt) compare(o mvnItem) int {
	switch y := o.(type) {
	case nil:
		if isZero(x.v) { // 1.0 == 1 (a trailing zero equals the absent item)
			return 0
		}
		return 1
	case mvnInt:
		return cmpNumStr(x.v, y.v)
	default: // a number outranks a string or a list
		return 1
	}
}

type mvnStr struct{ q string } // qualifier with aliases already applied

func (x mvnStr) isNull() bool { return mavenQualifier(x.q) == mavenReleaseRank }
func (x mvnStr) compare(o mvnItem) int {
	switch y := o.(type) {
	case nil:
		return sign(strings.Compare(mavenQualifier(x.q), mavenReleaseRank))
	case mvnStr:
		return sign(strings.Compare(mavenQualifier(x.q), mavenQualifier(y.q)))
	default: // a string sorts below a number and below a list
		return -1
	}
}

type mvnList struct{ items []mvnItem }

func (l *mvnList) isNull() bool   { return len(l.items) == 0 }
func (l *mvnList) add(it mvnItem) { l.items = append(l.items, it) }
func (l *mvnList) compare(o mvnItem) int {
	switch y := o.(type) {
	case nil:
		if len(l.items) == 0 {
			return 0
		}
		return l.items[0].compare(nil)
	case mvnInt:
		return -1 // a list sorts below a number
	case mvnStr:
		return 1 // a list sorts above a string
	case *mvnList:
		n := len(l.items)
		if len(y.items) > n {
			n = len(y.items)
		}
		for i := 0; i < n; i++ {
			var li, ri mvnItem
			if i < len(l.items) {
				li = l.items[i]
			}
			if i < len(y.items) {
				ri = y.items[i]
			}
			var r int
			if li == nil { // left ran out: compare the right item against the absent item and invert
				r = -ri.compare(nil)
			} else {
				r = li.compare(ri)
			}
			if r != 0 {
				return sign(r)
			}
		}
		return 0
	}
	return 0
}

// normalize strips trailing "null" items (a zero, a release-equivalent qualifier, an empty
// list) from a parsed list, so 1.0.0 and 1.0 and 1-ga compare equal.
func (l *mvnList) normalize() {
	for i := len(l.items) - 1; i >= 0; i-- {
		if l.items[i].isNull() {
			l.items = append(l.items[:i], l.items[i+1:]...)
		} else if _, isList := l.items[i].(*mvnList); !isList {
			break
		}
	}
}

// mavenQualifier maps a qualifier to its comparable rank string: a known qualifier to its index
// 0..6, an unknown one to "7-"+q so it sorts after every known qualifier and alphabetically
// among its own kind.
var mavenQualifierRank = map[string]int{
	"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4, "": 5, "sp": 6,
}

const mavenReleaseRank = "5" // rank of the release qualifier "" — the boundary between pre- and post-release

func mavenQualifier(q string) string {
	if i, ok := mavenQualifierRank[q]; ok {
		return string(rune('0' + i))
	}
	return "7-" + q
}

func parseMaven(version string) (*mvnList, bool) {
	v := strings.ToLower(strings.TrimSpace(version))
	if v == "" {
		return nil, false
	}
	root := &mvnList{}
	stack := []*mvnList{root}
	cur := root
	isDigit := false
	start := 0
	descend := func() {
		nl := &mvnList{}
		cur.add(nl)
		cur = nl
		stack = append(stack, nl)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.':
			if i == start {
				cur.add(mvnInt{"0"})
			} else {
				cur.add(mavenItem(isDigit, v[start:i]))
			}
			start = i + 1
		case c == '-':
			if i == start {
				cur.add(mvnInt{"0"})
			} else {
				cur.add(mavenItem(isDigit, v[start:i]))
			}
			start = i + 1
			descend()
		case isDigitByte(c):
			if !isDigit && i > start { // a letter run abutting a digit run starts a new list
				cur.add(mavenStr(v[start:i], true))
				start = i
				descend()
			}
			isDigit = true
		default:
			if isDigit && i > start { // a digit run abutting a letter run starts a new list
				cur.add(mavenItem(true, v[start:i]))
				start = i
				descend()
			}
			isDigit = false
		}
	}
	if len(v) > start {
		cur.add(mavenItem(isDigit, v[start:]))
	}
	for i := len(stack) - 1; i >= 0; i-- { // innermost lists first, so an outer list sees them empty
		stack[i].normalize()
	}
	return root, true
}

func mavenItem(isDigit bool, buf string) mvnItem {
	if isDigit {
		b := strings.TrimLeft(buf, "0")
		if b == "" {
			b = "0"
		}
		return mvnInt{b}
	}
	return mavenStr(buf, false)
}

func mavenStr(value string, followedByDigit bool) mvnStr {
	if followedByDigit && len(value) == 1 { // a1 = alpha1, b1 = beta1, m1 = milestone1
		switch value {
		case "a":
			value = "alpha"
		case "b":
			value = "beta"
		case "m":
			value = "milestone"
		}
	}
	switch value { // aliases that mean the plain release
	case "ga", "final", "release":
		value = ""
	case "cr":
		value = "rc"
	}
	return mvnStr{value}
}

// ---------------------------------------------------------------------------
// RubyGems — Gem::Version
// ---------------------------------------------------------------------------

type gemSeg struct {
	num   string // numeric value, leading zeros stripped (isNum)
	str   string // letter run (!isNum)
	isNum bool
}

// parseGem scans a Gem version into numeric and letter segments. A hyphen is a pre-release
// marker (Ruby rewrites "-" to ".pre."). The version must start with a digit (Gem::Version's
// own validity rule), so a bare git hash stays ok=false.
func parseGem(s string) ([]gemSeg, bool) {
	v := strings.TrimSpace(s)
	if v == "" || !isDigitByte(v[0]) {
		return nil, false
	}
	for i := 0; i < len(v); i++ {
		if !(isAlnumByte(v[i]) || v[i] == '.' || v[i] == '-') {
			return nil, false
		}
	}
	v = strings.ReplaceAll(v, "-", ".pre.")
	var segs []gemSeg
	for i := 0; i < len(v); {
		switch {
		case isDigitByte(v[i]):
			j := i
			for j < len(v) && isDigitByte(v[j]) {
				j++
			}
			n := strings.TrimLeft(v[i:j], "0")
			if n == "" {
				n = "0"
			}
			segs = append(segs, gemSeg{num: n, isNum: true})
			i = j
		case isAlphaByte(v[i]):
			j := i
			for j < len(v) && isAlphaByte(v[j]) {
				j++
			}
			segs = append(segs, gemSeg{str: v[i:j]})
			i = j
		default:
			i++
		}
	}
	return gemCanonical(segs), true
}

// gemCanonical drops trailing zeros from the release part and the pre-release part separately,
// as Gem::Version#canonical_segments does, so 2.0.0.rc1 orders as 2.rc1.
func gemCanonical(segs []gemSeg) []gemSeg {
	cut := len(segs)
	for i, s := range segs {
		if !s.isNum {
			cut = i
			break
		}
	}
	trim := func(p []gemSeg) []gemSeg {
		for len(p) > 0 && p[len(p)-1].isNum && p[len(p)-1].num == "0" {
			p = p[:len(p)-1]
		}
		return p
	}
	return append(trim(append([]gemSeg(nil), segs[:cut]...)), trim(segs[cut:])...)
}

// cmpGem compares Gem segments pairwise; a missing segment counts as numeric 0, and a letter
// segment sorts below a numeric one (so 1.0.0.pre < 1.0.0).
func cmpGem(a, b []gemSeg) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x := gemSeg{num: "0", isNum: true}
		y := gemSeg{num: "0", isNum: true}
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x.isNum && y.isNum:
			if c := cmpNumStr(x.num, y.num); c != 0 {
				return c
			}
		case !x.isNum && y.isNum:
			return -1
		case x.isNum && !y.isNum:
			return 1
		default:
			if c := strings.Compare(x.str, y.str); c != 0 {
				return sign(c)
			}
		}
	}
	return 0
}

// semverBuild returns the dot-separated "+build" identifiers, nil when there are none.
func semverBuild(s string) []string {
	_, build, _ := strings.Cut(strings.TrimSpace(s), "+")
	if build == "" {
		return nil
	}
	return strings.Split(build, ".")
}

// ---------------------------------------------------------------------------
// apk (Alpine family) — number{.number}[letter]{_suffix[N]}[~hash][-rN]
// ---------------------------------------------------------------------------

type apkSuffix struct {
	rank int
	num  string
}

type apkVersion struct {
	nums    []string
	letter  byte
	suffix  []apkSuffix
	release string
}

var apkSuffixRank = map[string]int{"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}

// apkMissingSuffix is what a shorter suffix list is padded with (OSV's Alpine ordering): above
// every pre-release suffix, level with _cvs (rank 5), below the other post-release ones.
var apkMissingSuffix = apkSuffix{rank: 5}

func parseAPK(s string) (apkVersion, bool) {
	v, i := strings.TrimSpace(s), 0
	var out apkVersion
	for {
		j := i
		for j < len(v) && isDigitByte(v[j]) {
			j++
		}
		if j == i {
			return apkVersion{}, false
		}
		out.nums = append(out.nums, v[i:j])
		i = j
		if i+1 < len(v) && v[i] == '.' && isDigitByte(v[i+1]) {
			i++
			continue
		}
		break
	}
	if i < len(v) && v[i] >= 'a' && v[i] <= 'z' {
		out.letter = v[i]
		i++
	}
	for i < len(v) && v[i] == '_' {
		j := i + 1
		for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
			j++
		}
		rank, ok := apkSuffixRank[v[i+1:j]]
		if !ok {
			return apkVersion{}, false
		}
		k := j
		for k < len(v) && isDigitByte(v[k]) {
			k++
		}
		out.suffix = append(out.suffix, apkSuffix{rank: rank, num: v[j:k]})
		i = k
	}
	if i < len(v) && v[i] == '~' {
		i++
		for i < len(v) && (isDigitByte(v[i]) || (v[i] >= 'a' && v[i] <= 'f')) {
			i++
		}
	}
	if strings.HasPrefix(v[i:], "-r") {
		j := i + 2
		for j < len(v) && isDigitByte(v[j]) {
			j++
		}
		out.release, i = v[i+2:j], j
	}
	if i != len(v) {
		return apkVersion{}, false
	}
	return out, true
}

func cmpAPK(x, y apkVersion) int {
	for i := 0; i < len(x.nums) || i < len(y.nums); i++ {
		if i >= len(x.nums) || i >= len(y.nums) {
			xs, ys := "0", "0" // a missing component is numeric 0, so 1.0 == 1
			if i < len(x.nums) {
				xs = x.nums[i]
			}
			if i < len(y.nums) {
				ys = y.nums[i]
			}
			if c := cmpNumStr(xs, ys); c != 0 {
				return c
			}
			continue
		}
		xs, ys := x.nums[i], y.nums[i]
		c := cmpNumStr(xs, ys)
		if i > 0 && (xs[0] == '0' || ys[0] == '0') {
			c = strings.Compare(xs, ys) // apk: a leading zero after the first component compares as text
		}
		if c != 0 {
			return c
		}
	}
	if c := cmpInt(int(x.letter), int(y.letter)); c != 0 {
		return c
	}
	for i := 0; i < len(x.suffix) || i < len(y.suffix); i++ {
		xs, ys := apkMissingSuffix, apkMissingSuffix
		if i < len(x.suffix) {
			xs = x.suffix[i]
		}
		if i < len(y.suffix) {
			ys = y.suffix[i]
		}
		if c := cmpInt(xs.rank, ys.rank); c != 0 {
			return c
		}
		if c := cmpNumStr(xs.num, ys.num); c != 0 {
			return c
		}
	}
	return cmpNumStr(x.release, y.release)
}

// ---------------------------------------------------------------------------
// Packagist — Composer compares with PHP's version_compare
// ---------------------------------------------------------------------------

// parsePackagist canonicalizes like version_compare: one leading v/V dropped, "-_+" become ".",
// and a "." is inserted between letters and digits. A branch ("dev-master") is not a version.
func parsePackagist(s string) ([]string, bool) {
	v := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "v"), "V")
	var b strings.Builder
	var prev byte
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '-' || c == '_' || c == '+' {
			c = '.'
		}
		if prev != 0 && prev != '.' && c != '.' && isDigitByte(prev) != isDigitByte(c) {
			b.WriteByte('.')
		}
		b.WriteByte(c)
		prev = c
	}
	parts := strings.Split(b.String(), ".")
	if !isNum(parts[0]) {
		return nil, false
	}
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
	}
	return parts, true
}

// phpSpecialForms is version_compare's order; a part matches by prefix ("patch" is "p").
var phpSpecialForms = []struct {
	prefix string
	order  int
}{{"dev", 0}, {"alpha", 1}, {"a", 1}, {"beta", 2}, {"b", 2}, {"RC", 3}, {"rc", 3}, {"#", 4}, {"pl", 5}, {"p", 5}}

// phpNumberOrder is where a numeric part sits among the special forms.
const phpNumberOrder = 4

func phpOrder(part string) int {
	if isNum(part) {
		return phpNumberOrder
	}
	for _, f := range phpSpecialForms {
		if strings.HasPrefix(part, f.prefix) {
			return f.order
		}
	}
	return -1 // an unknown word sorts below dev
}

func cmpPackagist(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		var c int
		if isNum(a[i]) && isNum(b[i]) {
			c = cmpNumStr(a[i], b[i])
		} else {
			c = cmpInt(phpOrder(a[i]), phpOrder(b[i]))
		}
		if c != 0 {
			return c
		}
	}
	// The longer version's next part decides: a number or patch ranks it above, a pre-release below.
	tail := func(next string) int {
		if isNum(next) {
			return 1
		}
		return sign(phpOrder(next) - phpNumberOrder)
	}
	switch {
	case len(a) > len(b):
		return tail(a[len(b)])
	case len(b) > len(a):
		return -tail(b[len(a)])
	}
	return 0
}

// ---------------------------------------------------------------------------
// Hackage (PVP) and CRAN — lists of non-negative integers
// ---------------------------------------------------------------------------

// parseNumList splits on "." (and also "-" for CRAN, where both separate components) and
// requires every component to be numeric.
func parseNumList(s string, dashToo bool) ([]string, bool) {
	v := strings.TrimSpace(s)
	if dashToo {
		v = strings.ReplaceAll(v, "-", ".")
	}
	parts := strings.Split(v, ".")
	for _, p := range parts {
		if !isNum(p) {
			return nil, false
		}
	}
	return parts, true
}

func cmpNumList(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := cmpNumStr(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}
