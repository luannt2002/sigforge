// Package jslib resolves a detected front-end JavaScript library (name + version)
// to its KNOWN vulnerabilities using the Retire.js repository. It is a NEW intel
// domain alongside cve/kev/wpcve, and it owns ONLY half of what Retire.js does:
//
//	Retire.js ships (a) fingerprints — `extractors` — that recognize which library a
//	script is, and (b) a library+version → known-vulnerability table. Lookup does (b):
//	given a (library, version), it returns the published vulnerabilities (CVE ids,
//	severity, affected range). Identify does (a) with the repository's own extractors
//	over a script's URL, file name and content, so the libraries recognized grow with
//	the data instead of with hand-written patterns.
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
//	                  Resolved=true, empty Vulns (a miss, not a clearance: ToUnified
//	                  answers not_checked).
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
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/versioncmp"
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
// library and the installed version matched none of its ranges — a miss, which ToUnified
// reports as not_checked, never as clean.
type Result struct {
	Library         string
	Version         string
	Vulns           []Lead // version-range LEADs (empty + Resolved=true ⇒ no range matched)
	KnownLib        bool   // the feed lists this library (its vuln history is known)
	Resolved        bool   // false ⇒ UNKNOWN ⇒ not-measured (never "safe")
	UnparsedVersion bool   // a version was detected but is not comparable ⇒ distinct UNKNOWN
	Unpositioned    bool   // Vulns are advisories whose bounds could not be compared with Version: they may not apply
	Live            bool   // the repo behind this result came from the operator's live URL, not the embedded snapshot
	Stale           bool   // the source failed, so the repo is the last synced copy from the local store
	Sample          bool   // the repo is the embedded sample, not the repository: a miss in it is not an answer
	Err             string // why the configured repository could not be fetched now (Stale: the last synced copy is in use); "" otherwise
	// Unplaced is every advisory whose bounds could not place Version, whether or not another matched: Vulns
	// never holds one beside a match (with none matched it holds the same ones, Unpositioned, as it always has).
	Unplaced []Lead
}

// Adapter resolves library vulnerabilities from the operator-supplied Retire.js URL,
// falling back to the embedded Apache-2.0 snapshot when the URL is empty or the feed
// is unusable. The zero value is not ready; use New.
type Adapter struct {
	url    string
	client *fetch.Client

	// shortcut: the repository loads once per Adapter (the kev adapter does the same),
	// so build one Adapter per scan; a long-lived Adapter keeps its first repository.
	once   sync.Once
	repo   map[string]libEntry
	live   bool
	stale  bool
	sample bool // the repo is the embedded sample
	err    string
}

// New builds an adapter bound to the operator-supplied Retire.js URL and client. An
// empty URL simply uses the embedded snapshot (no network).
func New(retireURL string, client *fetch.Client) *Adapter {
	return &Adapter{url: strings.TrimSpace(retireURL), client: client}
}

// LookupOne resolves one library at one version. It loads the repository (live or
// snapshot) and returns the honest tri-state Result.
func (a *Adapter) LookupOne(ctx context.Context, library, version string) Result {
	repo, live, stale := a.loadRepo(ctx)
	res := resolve(repo, library, version)
	res.Live, res.Stale, res.Sample, res.Err = live, stale, a.sample, a.err
	return res
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
	repo, live, stale := a.loadRepo(ctx)
	for name, ver := range libs {
		res := resolve(repo, name, ver)
		res.Live, res.Stale, res.Sample, res.Err = live, stale, a.sample, a.err
		out[name] = res
	}
	return out
}

// loadRepo returns the library→entry lookup map and whether it came LIVE from the
// operator's URL (true) or fell open to the embedded Apache-2.0 snapshot (false) on an
// empty URL, a fetch error, or junk content (a proxy serving HTML). It never returns a
// nil map. The live flag is what lets the adapter report freshness honestly instead of
// hardcoding snapshot. It is fetched once per Adapter: enrich's JS hook resolves one
// library per call, and re-downloading the repository per library would be waste.
func (a *Adapter) loadRepo(ctx context.Context) (map[string]libEntry, bool, bool) {
	a.once.Do(func() { a.repo, a.live, a.stale, a.sample, a.err = a.fetchRepo(ctx) })
	return a.repo, a.live, a.stale
}

func (a *Adapter) fetchRepo(ctx context.Context) (repo map[string]libEntry, live, stale, sample bool, why string) {
	snap, _ := ParseRepo(repoSnapshot)
	if a.url == "" || a.client == nil {
		return snap, false, false, true, ""
	}
	// a new repository enters the store only once it is usable; a stored copy served without asking is checked below
	raw, meta, err := a.client.GetMetaChecked(ctx, a.url, func(b []byte) error { return usableRepo(ParseRepo(b)) })
	if err != nil {
		return snap, false, false, true, err.Error()
	}
	m, err := ParseRepo(raw)
	if err := usableRepo(m, err); err != nil {
		return snap, false, false, true, err.Error()
	}
	return m, !meta.Cached, meta.Stale, false, meta.Err // a locally synced copy is a snapshot, never live
}

// usableRepo says why a decoded repository cannot be used — the parser refused it, or it lists no
// library (the rule sync applies too) — or nil.
func usableRepo(m map[string]libEntry, err error) error {
	if err != nil {
		return fmt.Errorf("Retire.js repository unparseable: %w", err)
	}
	if len(m) == 0 {
		return errors.New("Retire.js repository lists no libraries")
	}
	return nil
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

// libEntry is one library's record: its vulnerabilities, and the extractors that recognize it
// (the static kinds; `func` and `hashes` need a JavaScript runtime or the exact file and are not used).
type libEntry struct {
	Vulnerabilities []repoVuln `json:"vulnerabilities"`
	Extractors      struct {
		URI         []string `json:"uri"`
		Filename    []string `json:"filename"`
		FileContent []string `json:"filecontent"`
	} `json:"extractors"`
	match [3][]*regexp.Regexp // compiled uri, filename, filecontent extractors
}

// extractorKinds names the compiled extractor kinds in libEntry.match order.
var extractorKinds = [3]string{"uri", "filename", "filecontent"}

// retireVersion is what Retire.js puts in place of §§version§§ in an extractor.
const retireVersion = `[0-9][0-9.a-z_\-]+`

// compileExtractors builds a library's extractors; one Go cannot compile (a JavaScript-only
// construct such as a look-ahead) is skipped, never failing the repository.
func (e *libEntry) compileExtractors() {
	for i, pats := range [3][]string{e.Extractors.URI, e.Extractors.Filename, e.Extractors.FileContent} {
		for _, p := range pats {
			if re, err := regexp.Compile(strings.ReplaceAll(p, "§§version§§", retireVersion)); err == nil && re.NumSubexp() > 0 {
				e.match[i] = append(e.match[i], re)
			}
		}
	}
}

// Found is a library a script reveals to the repository's extractors.
type Found struct {
	Library string // the repository's name for it
	Version string
	Via     string // "uri", "filename" or "filecontent"
}

// Identify names the libraries — with their versions — a script reveals to the repository's own
// extractors: its URL, its file name, or its content (content may be "", not fetched). Each library
// is named once, from the first way that shows it. The repository is loaded once per Adapter, as for
// Lookup; past that it is pure.
func (a *Adapter) Identify(ctx context.Context, scriptURL, content string) []Found {
	repo, _, _ := a.loadRepo(ctx)
	return identify(repo, scriptURL, content)
}

func identify(repo map[string]libEntry, scriptURL, content string) []Found {
	file := scriptURL
	if u, err := url.Parse(scriptURL); err == nil && u.Path != "" {
		file = path.Base(u.Path)
	}
	names := make([]string, 0, len(repo))
	for name := range repo {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Found
	for _, name := range names {
		e := repo[name]
	kinds:
		for i, input := range [3]string{scriptURL, file, content} {
			if input == "" {
				continue
			}
			for _, re := range e.match[i] {
				if m := re.FindStringSubmatch(input); m != nil {
					if v := cleanFoundVersion(m[1]); v != "" {
						out = append(out, Found{Library: name, Version: v, Via: extractorKinds[i]})
						break kinds
					}
				}
			}
		}
	}
	return out
}

// cleanFoundVersion drops what the version pattern can swallow past the version: a ".min"/"-min"
// suffix of a minified file name, and trailing separators.
func cleanFoundVersion(v string) string {
	v = strings.TrimSuffix(strings.TrimSuffix(v, ".min"), "-min")
	return strings.TrimRight(v, ".-_")
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
		e.compileExtractors()
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
		entry, ok = repo[strings.TrimSuffix(key, ".js")] // a detected "Vue.js" is the repository's "vue"
	}
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

	var unpositioned []Lead
	for i := range entry.Vulnerabilities {
		v := &entry.Vulnerabilities[i]
		switch affected, determinate := versionAffected(res.Version, v); {
		case affected:
			res.Vulns = append(res.Vulns, leadFrom(v))
		case !determinate:
			unpositioned = append(unpositioned, leadFrom(v))
		}
	}
	if len(res.Vulns) == 0 && len(unpositioned) > 0 {
		res.Vulns, res.Unpositioned = unpositioned, true
	}
	res.Unplaced = unpositioned
	return res
}

// versionAffected reports whether `installed` falls in ANY of the vuln's published
// ranges. The classic flat shape is treated as a single range synthesized from the
// top-level bounds. An empty installed version can't be excluded ⇒ true (a LEAD,
// honest "can't pin"). determinate=false: a bound could not be compared, so whether
// the vuln applies is unknown. Pure.
func versionAffected(installed string, v *repoVuln) (affected, determinate bool) {
	installed = strings.TrimSpace(installed)
	if installed == "" {
		return true, true
	}
	if len(v.Ranges) == 0 {
		// classic flat shape ⇒ one range from the top-level bounds
		return inRange(installed, &repoRange{AtOrAbove: v.AtOrAbove, Above: v.Above, Below: v.Below, AtOrBelow: v.AtOrBelow})
	}
	determinate = true
	for i := range v.Ranges {
		in, ok := inRange(installed, &v.Ranges[i])
		if in {
			return true, true
		}
		determinate = determinate && ok
	}
	return false, determinate
}

// inRange tests one window under npm's semver order. An explicitly excluded (back-patched)
// version is NOT affected. A window with no bounds at all means the whole version space is
// vulnerable ⇒ reported as a LEAD rather than silently dropped. A bound (or the installed
// version) the order cannot read is never taken as equal: unless another bound already puts
// the version outside, membership is indeterminate. Pure.
func inRange(installed string, r *repoRange) (in, determinate bool) {
	determinate = true
	outside := func(bound string, out func(c int) bool) bool {
		b := strings.TrimSpace(bound)
		if b == "" {
			return false
		}
		c, ok := versioncmp.Compare("npm", installed, b)
		if !ok {
			determinate = false
			return false
		}
		return out(c)
	}
	for _, ex := range r.Excludes {
		if outside(ex, func(c int) bool { return c == 0 }) {
			return false, true
		}
	}
	if outside(r.Above, func(c int) bool { return c <= 0 }) || outside(r.AtOrAbove, func(c int) bool { return c < 0 }) ||
		outside(r.Below, func(c int) bool { return c >= 0 }) || outside(r.AtOrBelow, func(c int) bool { return c > 0 }) {
		return false, true
	}
	return determinate, determinate
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
