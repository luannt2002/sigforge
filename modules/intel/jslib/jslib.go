// Package jslib resolves a detected front-end JavaScript library (name + version)
// to its KNOWN vulnerabilities using the Retire.js repository. It is a NEW intel
// domain alongside cve/kev/wpcve, and it owns ONLY half of what Retire.js does:
//
//	Retire.js ships (a) fingerprints that recognize which library a script is, and
//	(b) a library+version → known-vulnerability table. sigforge's matcher already
//	performs (a), so this package deliberately does ONLY (b): given a (library,
//	version) the matcher produced, it returns the published vulnerabilities (CVE ids,
//	severity, affected range). The Retire.js `extractors` (the fingerprint half) are
//	ignored on decode — part (a) is not rebuilt here.
//
// One source, supplied by the operator as a URL (never hardcoded, off by default):
//
//	RETIREJS — the Retire.js jsrepository JSON. Supplied via
//	           SIGFORGE_SOURCE_RETIREJS_URL. When unset (or the feed is dead/junk)
//	           the package falls back to a small embedded snapshot so an air-gapped
//	           run still recognizes the most notorious library CVEs instead of going
//	           fully blind.
//
// HONESTY (§2, the controlled part). Three outcomes are kept distinct and never
// collapsed into "safe":
//
//	HasCVE          — the feed knows the library AND the installed version falls in a
//	                  published vulnerable range ⇒ Resolved=true with Vulns.
//	NoKnownVuln     — the feed knows the library and the version matched no range ⇒
//	                  Resolved=true, empty Vulns (clean PER THIS SOURCE).
//	UNKNOWN         — the feed is off/dead/unparseable, OR the library is not listed
//	                  (KnownLib=false), OR a version was detected but is not
//	                  semver-comparable (UnparsedVersion=true) ⇒ Resolved=false. The
//	                  caller MUST render this as not-measured, NEVER as clean.
//
// Every match is a LEAD, not a proven exploit: the version comes from a banner/body
// the target controls and can spoof, so Confidence is always "heuristic". Severity
// is passed through from the feed only — never invented; absent ⇒ "". Everything
// touching the network is FAIL-OPEN. Decode and range-matching are PURE (no network).
//
// LICENSE (§4). The Retire.js repository (github.com/RetireJS/retire.js) is licensed
// Apache-2.0 — permissive, so a small point-in-time snapshot is embedded (go:embed)
// as an air-gap baseline and recorded in NOTICE, exactly as the public-domain CISA
// KEV snapshot is. The operator's SIGFORGE_SOURCE_RETIREJS_URL upgrades it to the
// full live repository.
package jslib

import (
	"context"
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// EnvRetireJSURL is the environment variable the operator uses to supply the
// Retire.js repository URL. It mirrors the other intel adapters' SIGFORGE_SOURCE_*_URL
// naming and is off by default, so nothing goes to the network when it is unset.
const EnvRetireJSURL = "SIGFORGE_SOURCE_RETIREJS_URL"

// RetireJSLicense records the source's provenance so a caller can tag output. Unlike
// the encumbered WP feed, Retire.js is Apache-2.0, so the snapshot IS embeddable.
const RetireJSLicense = "Retire.js jsrepository (github.com/RetireJS/retire.js) — Apache-2.0; permissive, embeddable snapshot + NOTICE"

// Confidence is the same for every finding here: a version-range match on a
// target-controlled (spoofable) version banner is a LEAD, never a proven exploit.
const Confidence = "heuristic"

//go:embed data/retirejs-snapshot.json
var repoSnapshot []byte

// Range is one published vulnerable version window, normalized from either the
// classic flat Retire.js shape or the newer nested `ranges` shape. Bounds are
// optional; an empty bound means that side is open. Excludes lists versions inside
// the window that were back-patched and are therefore NOT vulnerable.
type Range struct {
	AtOrAbove string   // lower bound, inclusive (ge)
	Above     string   // lower bound, exclusive (gt)
	Below     string   // upper bound, exclusive (lt) — "fixed_in" semantics
	AtOrBelow string   // upper bound, inclusive (le)
	Excludes  []string // versions inside the window that are patched (not affected)
}

// Lead is one vulnerability Retire.js reports for a library whose installed version
// falls in a published range. A LEAD (version-range match), not a confirmed exploit.
// Severity is passed through from the feed's own qualitative level (low/medium/high)
// and is "" when the feed gives none — never invented.
type Lead struct {
	ID         string   // a stable id: first CVE, else githubID/issue/bug/retid, else ""
	CVE        []string // every CVE the advisory maps, UPPER-cased (may be empty)
	Summary    string   // short human description from the feed
	Severity   string   // low|medium|high (feed's own level), or "" when absent
	CWE        []string // CWE ids the advisory lists
	Info       []string // reference URLs
	Ranges     []Range  // the published vulnerable window(s) this lead covers
	Confidence string   // always Confidence ("heuristic")
}

// Result is the full answer for one library at one version.
//
// Resolved=false means UNKNOWN and MUST be rendered as not-measured, never clean:
// the feed was off/dead/unparseable (KnownLib=false), the library is not listed
// (KnownLib=false), or a version WAS detected but is not semver-comparable
// (UnparsedVersion=true). Resolved=true with an empty Vulns means the feed KNOWS the
// library and the installed version matched none of its ranges — clean per Retire.js.
type Result struct {
	Library         string
	Version         string
	Vulns           []Lead // version-range LEADs (empty + Resolved=true ⇒ clean per the feed)
	KnownLib        bool   // the feed lists this library (its vuln history is known)
	Resolved        bool   // false ⇒ UNKNOWN ⇒ not-measured (never "safe")
	UnparsedVersion bool   // a version was detected but is not comparable ⇒ distinct UNKNOWN
}

// Adapter resolves library vulnerabilities from the operator-supplied Retire.js URL,
// falling back to the embedded Apache-2.0 snapshot when the URL is empty or the feed
// is unusable. The zero value is not ready; use New. Stateless per call (no cache),
// matching the kev/wpcve adapters.
type Adapter struct {
	url    string
	client *fetch.Client
}

// New builds an adapter bound to the operator-supplied Retire.js URL and client. An
// empty URL simply uses the embedded snapshot (no network).
func New(retireURL string, client *fetch.Client) *Adapter {
	return &Adapter{url: strings.TrimSpace(retireURL), client: client}
}

// LookupOne resolves one library at one version. It loads the repository (live or
// snapshot) and returns the honest tri-state Result.
func (a *Adapter) LookupOne(ctx context.Context, library, version string) Result {
	return resolve(a.loadRepo(ctx), library, version)
}

// Lookup resolves MANY libraries in one shot, loading the repository ONCE — the
// natural shape for a JS-bundle detector that found several libraries. libs maps a
// library name to its detected version; the result is keyed by the SAME names the
// caller passed (so a caller's casing/aliasing is preserved).
func (a *Adapter) Lookup(ctx context.Context, libs map[string]string) map[string]Result {
	out := make(map[string]Result, len(libs))
	if len(libs) == 0 {
		return out
	}
	repo := a.loadRepo(ctx)
	for name, ver := range libs {
		out[name] = resolve(repo, name, ver)
	}
	return out
}

// loadRepo returns the library→entry lookup map. It prefers the live repository from
// the operator's URL but fails open to the embedded Apache-2.0 snapshot on an empty
// URL, a fetch error, or junk content (a proxy serving HTML). It never returns nil.
func (a *Adapter) loadRepo(ctx context.Context) map[string]libEntry {
	snap, _ := ParseRepo(repoSnapshot)
	if a.url == "" || a.client == nil {
		return snap
	}
	raw, err := a.client.Get(ctx, a.url)
	if err != nil {
		return snap
	}
	m, err := ParseRepo(raw)
	if err != nil || len(m) == 0 {
		return snap
	}
	return m
}

// repoRange is the wire shape of a nested `ranges[]` entry (newer Retire.js master).
type repoRange struct {
	AtOrAbove string   `json:"atOrAbove"`
	Above     string   `json:"above"`
	Below     string   `json:"below"`
	AtOrBelow string   `json:"atOrBelow"`
	Excludes  []string `json:"excludes"`
}

// repoVuln is one Retire.js vulnerability. The version bounds appear EITHER flat on
// this object (the classic, widely-mirrored jsrepository shape) OR nested under
// `ranges` (the newer master shape); both are decoded and unified by vulnRanges.
// `summary` moved from inside `identifiers` to the top level across versions, so both
// are read.
type repoVuln struct {
	AtOrAbove   string      `json:"atOrAbove"`
	Above       string      `json:"above"`
	Below       string      `json:"below"`
	AtOrBelow   string      `json:"atOrBelow"`
	Ranges      []repoRange `json:"ranges"`
	Severity    string      `json:"severity"`
	CWE         []string    `json:"cwe"`
	Summary     string      `json:"summary"`
	Info        []string    `json:"info"`
	Identifiers struct {
		CVE      []string `json:"CVE"`
		Summary  string   `json:"summary"`
		GithubID string   `json:"githubID"`
		Issue    string   `json:"issue"`
		Bug      string   `json:"bug"`
		Retid    string   `json:"retid"`
	} `json:"identifiers"`
}

// libEntry is one library's record. Only `vulnerabilities` is decoded; the Retire.js
// `extractors` (the fingerprint half, part (a)) are intentionally ignored here.
type libEntry struct {
	Vulnerabilities []repoVuln `json:"vulnerabilities"`
}

// ParseRepo is the PURE decode of a Retire.js repository body into a lookup map keyed
// by LOWER-cased library name (Retire.js keys vary in case), so lookups are
// case-insensitive. No network.
func ParseRepo(b []byte) (map[string]libEntry, error) {
	var raw map[string]libEntry
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]libEntry, len(raw))
	for name, e := range raw {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		out[key] = e
	}
	return out, nil
}

// resolve applies the honest tri-state rule for one (library, version) against an
// already-loaded repository. PURE (no network).
func resolve(repo map[string]libEntry, library, version string) Result {
	res := Result{Library: library, Version: strings.TrimSpace(version)}
	key := strings.ToLower(strings.TrimSpace(library))
	if key == "" {
		return res // nothing to look up ⇒ UNKNOWN
	}
	entry, ok := repo[key]
	if !ok {
		return res // library not in the feed ⇒ UNKNOWN (never "safe")
	}
	res.KnownLib = true

	// A version string PRESENT but not semver-comparable (a git hash, "trunk", a bare
	// build number) cannot be positioned inside any published range. Honest-verdict:
	// that is UNKNOWN coverage, never clean.
	if res.Version != "" && !parseableVersion(res.Version) {
		res.UnparsedVersion = true
		return res
	}
	res.Resolved = true

	for i := range entry.Vulnerabilities {
		v := &entry.Vulnerabilities[i]
		if res.Version != "" && !versionAffected(res.Version, v) {
			continue
		}
		res.Vulns = append(res.Vulns, leadFrom(v))
	}
	return res
}

// versionAffected reports whether `installed` falls in ANY of the vuln's published
// ranges. The classic flat shape is treated as a single range synthesized from the
// top-level bounds. An empty installed version can't be excluded ⇒ true (a LEAD,
// honest "can't pin"). Pure.
func versionAffected(installed string, v *repoVuln) bool {
	installed = strings.TrimSpace(installed)
	if installed == "" {
		return true
	}
	for i := range v.Ranges {
		if inRange(installed, &v.Ranges[i]) {
			return true
		}
	}
	if len(v.Ranges) == 0 {
		// classic flat shape ⇒ one range from the top-level bounds
		return inRange(installed, &repoRange{AtOrAbove: v.AtOrAbove, Above: v.Above, Below: v.Below, AtOrBelow: v.AtOrBelow})
	}
	return false
}

// inRange tests one window. An explicitly excluded (back-patched) version is NOT
// affected. A window with no bounds at all means the whole version space is
// vulnerable ⇒ reported as a LEAD rather than silently dropped. Pure.
func inRange(installed string, r *repoRange) bool {
	for _, ex := range r.Excludes {
		if ex = strings.TrimSpace(ex); ex != "" && cmpVer(installed, ex) == 0 {
			return false
		}
	}
	if a := strings.TrimSpace(r.Above); a != "" && cmpVer(installed, a) <= 0 {
		return false
	}
	if a := strings.TrimSpace(r.AtOrAbove); a != "" && cmpVer(installed, a) < 0 {
		return false
	}
	if b := strings.TrimSpace(r.Below); b != "" && cmpVer(installed, b) >= 0 {
		return false
	}
	if b := strings.TrimSpace(r.AtOrBelow); b != "" && cmpVer(installed, b) > 0 {
		return false
	}
	return true
}

// leadFrom maps a wire vuln to a Lead, unifying flat and nested ranges and passing
// severity through honestly (never invented).
func leadFrom(v *repoVuln) Lead {
	summary := strings.TrimSpace(v.Summary)
	if summary == "" {
		summary = strings.TrimSpace(v.Identifiers.Summary)
	}
	cve := normalizeCVEs(v.Identifiers.CVE)

	var ranges []Range
	for i := range v.Ranges {
		r := &v.Ranges[i]
		ranges = append(ranges, Range{
			AtOrAbove: strings.TrimSpace(r.AtOrAbove),
			Above:     strings.TrimSpace(r.Above),
			Below:     strings.TrimSpace(r.Below),
			AtOrBelow: strings.TrimSpace(r.AtOrBelow),
			Excludes:  trimAll(r.Excludes),
		})
	}
	if len(ranges) == 0 {
		ranges = []Range{{
			AtOrAbove: strings.TrimSpace(v.AtOrAbove),
			Above:     strings.TrimSpace(v.Above),
			Below:     strings.TrimSpace(v.Below),
			AtOrBelow: strings.TrimSpace(v.AtOrBelow),
		}}
	}

	return Lead{
		ID:         leadID(v, cve),
		CVE:        cve,
		Summary:    summary,
		Severity:   strings.ToLower(strings.TrimSpace(v.Severity)),
		CWE:        trimAll(v.CWE),
		Info:       trimAll(v.Info),
		Ranges:     ranges,
		Confidence: Confidence,
	}
}

// leadID picks a stable identifier for a lead, preferring a CVE and degrading to the
// feed's other ids so a lead is never anonymous when any id exists.
func leadID(v *repoVuln, cve []string) string {
	if len(cve) > 0 {
		return cve[0]
	}
	for _, id := range []string{v.Identifiers.GithubID, v.Identifiers.Issue, v.Identifiers.Bug, v.Identifiers.Retid} {
		if id = strings.TrimSpace(id); id != "" {
			return id
		}
	}
	return ""
}

// parseableVersion reports whether a DETECTED version has a comparable dotted-integer
// core ("1.0", "1.2.3", "v2.3", "1.0-beta" core "1.0"). A git hash, "trunk", or a
// bare build number has none ⇒ false, so it is kept OUT of range comparison (⇒
// UnparsedVersion UNKNOWN, never false-clean). Pure.
func parseableVersion(s string) bool {
	s = strings.TrimLeft(strings.TrimSpace(s), "vV")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(strings.TrimSpace(p)); err != nil {
			return false
		}
	}
	return true
}

// cmpVer compares dotted numeric versions group-by-group. A leading v/V and
// non-numeric tails are tolerated. Pure.
func cmpVer(a, b string) int {
	pa, pb := parseVer(a), parseVer(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVer(s string) []int {
	s = strings.TrimLeft(strings.TrimSpace(s), "vV")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, _ := strconv.Atoi(strings.TrimSpace(p))
		out[i] = n
	}
	return out
}

// normalizeCVEs UPPER-cases, trims and dedupes CVE ids in first-appearance order,
// dropping blanks. Deterministic. Pure.
func normalizeCVEs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// trimAll trims each entry and drops blanks, keeping order. Pure.
func trimAll(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
