// Package osv adds ecosystem→CVE intelligence for lockfile / dependency SCA. It is a NEW intel
// domain alongside cve: the cve adapter is CPE-keyed for web technologies ("nginx 1.18 → CVE-X"),
// whereas osv is ECOSYSTEM-keyed for packages ("npm lodash@4.17.11 → CVE-Y / GHSA-Z"), answering
// the question a dependency lock file asks.
//
// SOURCE (operator-supplied, never hardcoded, off by default). OSV publishes per-ecosystem bulk
// dumps as a zip of hundreds of thousands of advisories (npm alone is ~205MB). The operator points
// SIGFORGE_SOURCE_OSV_URL at the dump root; the adapter downloads one ecosystem's all.zip to a temp
// file, reduces it to a compact in-RAM index (reduce.go), DELETES the temp dump within the same
// call, and serves lookups from RAM. An empty env means the source is off — no network.
//
// LICENSE (§4). The aggregated OSV data is NOT under one permissive license: it merges source
// databases carrying CC-BY-4.0, CC0, MIT, Apache-2.0, CC-BY-SA-4.0 AND CC-BY-NC-ND-4.0
// (NonCommercial-NoDerivatives). A NonCommercial-NoDerivatives record cannot be redistributed in a
// vendored snapshot, and the dumps are large regardless, so OSV data is OPERATOR-FETCH-ONLY: it is
// NEVER vendored or embedded here, and the operator owns the fetched output under OSV's own terms.
//
// HONESTY (tri-state, the controlled part). A lookup is never turned into a bare "safe":
//
//	StatusUnknown     — no usable index (source off, dump dead/empty) OR the package is absent from
//	                    the index. "Cannot look up / never saw this package" ≠ "no vulnerability".
//	StatusVulnerable  — the version falls inside at least one affected range → the matching vuln ids.
//	StatusNoKnownVuln — the index WAS consulted and the package IS known, but no advisory touches this
//	                    specific version. This is a genuine RESOLVED "no known vuln for this version".
//
// LoadIndex returns an error (not a panic, not a blocked scan) when it cannot build an index, and
// Index.Lookup, BuildIndex, reduceRecord and the version comparison are pure (no network) for tests.
package osv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/versioncmp"
)

// EnvOSVURL is the environment variable the operator uses to supply the OSV bulk-dump root (the
// per-ecosystem all.zip lives at <root>/<Ecosystem>/all.zip). It mirrors the other intel adapters'
// SIGFORGE_SOURCE_*_URL naming and is off by default, so nothing hits the network when it is unset.
const EnvOSVURL = "SIGFORGE_SOURCE_OSV_URL"

// OSVLicense records the source's provenance for a caller that tags its output (see the package doc, §4).
const OSVLicense = "OSV.dev aggregate — mixed source licenses incl. CC-BY-NC-ND-4.0; operator-fetch-only, never vendored"

// osvWebResolver is the display resolver link for humans, NOT a fetch endpoint (the source dump is
// env-configured via EnvOSVURL); only Vuln.URL uses it, so it is not a hardcoded data source.
const osvWebResolver = "https://osv.dev/vulnerability/"

const (
	// downloadLimit bounds one dump download end to end; npm (~205MB) over a slow link still fits.
	downloadLimit = 12 * time.Minute
	// maxZipBytes caps the downloaded dump on disk (Chainguard's ~1.1GB and Ubuntu's ~0.8GB are the
	// largest known), guarding the disk against a hostile or runaway endpoint. The dump streams to
	// a file and is reduced entry by entry, so this is a disk ceiling, not a memory one.
	maxZipBytes int64 = 2 << 30
)

var (
	errEmptyDump    = errors.New("osv: empty dump")
	errUnknownEco   = errors.New("osv: unsupported ecosystem")
	errSourceOff    = errors.New("osv: SIGFORGE_SOURCE_OSV_URL is empty, source off")
	errBuiltNothing = errors.New("osv: dump produced no advisories")
)

// ecosystemNames maps friendly aliases (lockfile / language names) to the EXACT directory name on
// the dump bucket — wrong case is a 404, so this is the OSV data taxonomy, not a convenience. These
// are package-ecosystem names (schema), not a provider endpoint; the endpoint itself is in env.
var ecosystemNames = map[string]string{
	"npm": "npm", "yarn": "npm", "pnpm": "npm", "node": "npm", "javascript": "npm", "js": "npm",
	"pypi": "PyPI", "pip": "PyPI", "python": "PyPI", "poetry": "PyPI",
	"go": "Go", "gomod": "Go", "golang": "Go",
	"packagist": "Packagist", "composer": "Packagist", "php": "Packagist",
	"maven": "Maven", "gradle": "Maven", "java": "Maven",
	"rubygems": "RubyGems", "gem": "RubyGems", "bundler": "RubyGems", "ruby": "RubyGems",
	"crates.io": "crates.io", "crates": "crates.io", "cargo": "crates.io", "rust": "crates.io",
	"nuget": "NuGet", "dotnet": "NuGet", "csharp": "NuGet", ".net": "NuGet",
	"hex": "Hex", "pub": "Pub", "swift": "SwiftURL", "swifturl": "SwiftURL", "cran": "CRAN", "hackage": "Hackage",
	"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine", "wolfi": "Wolfi", "chainguard": "Chainguard",
	"rocky linux": "Rocky Linux", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
}

// releaseScoped ecosystems keep a separate advisory set per distro release ("Debian:12"): a
// version is comparable only against its own release's records, so a lookup must name one.
var releaseScoped = map[string]bool{"Debian": true, "Ubuntu": true, "Alpine": true, "Rocky Linux": true, "AlmaLinux": true}

// Ecosystem maps an alias, or an OSV ecosystem name with a release suffix ("Debian:12"), to the
// ecosystem's dump directory; ok is false when outside the whitelist.
func Ecosystem(name string) (eco string, ok bool) {
	v, ok := ecosystemNames[strings.ToLower(trimEcosystem(name))]
	return v, ok
}

// sameEcosystem compares two ecosystem names ignoring the distro suffix OSV appends
// ("Alpine:v3.16", "Debian:11") — only the part before ":" identifies the package ecosystem.
func sameEcosystem(a, b string) bool { return strings.EqualFold(trimEcosystem(a), trimEcosystem(b)) }

func trimEcosystem(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i > 0 {
		return s[:i]
	}
	return s
}

// Status is the honest tri-state of a lookup (see the package doc).
type Status int

const (
	StatusUnknown     Status = iota // no usable index, or package not indexed — never read as "safe"
	StatusVulnerable                // the version falls inside an affected range
	StatusNoKnownVuln               // index consulted, package known, no advisory matches this version
)

func (s Status) String() string {
	switch s {
	case StatusVulnerable:
		return "vulnerable"
	case StatusNoKnownVuln:
		return "no-known-vuln"
	default:
		return "unknown"
	}
}

// Vuln is one advisory touching the looked-up package@version.
type Vuln struct {
	ID       string  // native OSV id (GHSA-/GO-/PYSEC-…), the stable key
	CVE      string  // CVE alias if any, UPPER-cased
	Severity string  // upstream text label mapped (low|medium|high|critical), or "" if unscored
	Summary  string  // rebuilt from recorded facts (the fixed version), never fabricated
	URL      string  // https://osv.dev/vulnerability/<ID>
	Score    float64 // CVSS v3 base score computed from the record's vector, when Scored
	Scored   bool    // the record has a v3 vector; a value keeps Vuln comparable by content
	Vector   string  // that CVSS v3 vector, as the record gives it
	CWE      string  // the weakness ids the record names, comma-separated (a string keeps Vuln comparable)
	// OutsideListed (a platform's release only): the advisory reaches the version only through its
	// "introduced 0" range while the version is older than every version the package's advisories
	// name and older than this advisory's own list — it may not be one of this package's releases.
	OutsideListed bool
	// Published is when the record was published, as it gives it.
	Published string
}

func deref(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

// Ref is the display id, preferring the CVE (readers recognize it) and falling back to the OSV id.
func (v Vuln) Ref() string {
	if v.CVE != "" {
		return v.CVE
	}
	return v.ID
}

// Result is a lookup outcome: the tri-state status plus any matching vulns (nil unless Vulnerable).
//
// PackageKnown and VersionPinned let an adapter recover the honest sub-cases a bare Status folds: a
// StatusUnknown with PackageKnown is "advisories exist for the package but its version can't be
// positioned" (a potential affect), without it is a package absent from the index (unknown product);
// a StatusVulnerable with VersionPinned is an in-range match on a concrete version, without it is an
// unpinnable version surfacing every advisory for the package (potential, not confirmed).
type Result struct {
	Status        Status
	Vulns         []Vuln
	PackageKnown  bool // the package appears in the index (advisories exist for it)
	VersionPinned bool // a concrete version was supplied for range matching (not empty / a manifest range)
	Partial       bool // the dump had entries that could not be read: no answer from it is provably whole
	// BelowListed (a platform's release only): the version is older than every version the package's
	// advisories name; the advisories it reaches only "from the start" are marked OutsideListed.
	BelowListed bool
}

// Index is a reduced OSV index for ONE ecosystem, looked up by package name. It is read-only after
// BuildIndex returns, so it is safe to share across goroutines. Build it once per ecosystem and
// reuse it across every package in the lock file — do not rebuild per package (each rebuild is a
// fresh ~205MB download).
type Index struct {
	Ecosystem string
	BuiltAt   time.Time
	byName    map[string][]record
	count     int
	skipped   int        // dump entries that could not be read: the index is not provably whole
	fetched   fetch.Meta // where LoadIndex got the dump: the source now, the store (Cached), or a stale store copy
}

// Len is the number of advisory rows (one advisory touching n packages counts as n).
func (idx *Index) Len() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

// Packages is the number of distinct packages, used to tell an empty index from a populated one.
func (idx *Index) Packages() int {
	if idx == nil {
		return 0
	}
	return len(idx.byName)
}

func (idx *Index) add(r *record) {
	k := idx.key(r.pkg)
	if k == "" {
		return
	}
	idx.byName[k] = append(idx.byName[k], *r)
	idx.count++
}

// pkgKey is the lookup key, lower-cased: npm/PyPI/Packagist are case-insensitive at install time and
// Go/Maven names still match exactly after lowering, so real-world collisions do not occur.
func pkgKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// pep503Run is a run of the characters PEP 503 folds into one "-".
var pep503Run = regexp.MustCompile(`[-_.]+`)

// key is a package's lookup key in this index: PyPI names normalized as PEP 503 says (pip treats
// python_jose and Python.Jose as python-jose), every other ecosystem lower-cased only.
func (idx *Index) key(name string) string {
	if idx.Ecosystem == "PyPI" {
		return pep503Run.ReplaceAllString(pkgKey(name), "-")
	}
	return pkgKey(name)
}

// Lookup returns the tri-state result for name@version (see the package doc for the states).
//
// A pinned version is matched against affected ranges (and the concrete-version list). An EMPTY or
// RANGE version ("^4.17.0") cannot pin the running instance, so every advisory for the package is
// returned as Vulnerable and the caller must treat it as "potentially affected, version not pinned"
// rather than confirmed — surfacing the facts beats staying silent.
func (idx *Index) Lookup(name, version string) Result { return idx.LookupIn("", name, version) }

// LookupIn is Lookup within one distro release: with a release suffix ("Debian:12") only that
// release's records (and release-less ones) count, so another release's fix never decides.
func (idx *Index) LookupIn(ecosystem, name, version string) Result {
	return idx.lookup(ecosystem, name, version, false)
}

// lookup answers LookupIn; with release the version names a detected platform's release, which the
// package may not hold (Shopware 5 looked up in a package of Shopware 6).
func (idx *Index) lookup(ecosystem, name, version string, release bool) Result {
	r := idx.lookupIn(ecosystem, name, version, release)
	r.Partial = idx != nil && idx.skipped > 0
	return r
}

func (idx *Index) lookupIn(ecosystem, name, version string, release bool) Result {
	if idx == nil {
		return Result{Status: StatusUnknown}
	}
	recs := idx.byName[idx.key(name)]
	if strings.Contains(ecosystem, ":") {
		recs = sameRelease(recs, ecosystem)
	}
	if len(recs) == 0 {
		// The package never appears in the index: it may be unaffected, but it may also be a name /
		// ecosystem mismatch or a coverage gap, so this is not asserted as "no vulnerability".
		return Result{Status: StatusUnknown}
	}
	ver := CleanVersion(version)
	pinned := ver != ""
	below := release && pinned && belowNamedVersions(recs, ver)
	seen, seenUnplaced := make(map[string]bool, len(recs)*2), map[string]bool{}
	out := make([]Vuln, 0, 4)
	var unplaced []Vuln // advisories the version could not be placed against
	add := func(dst *[]Vuln, r *record, seen map[string]bool) {
		id := r.id
		if id == "" {
			id = r.cve
		}
		if id == "" || seenVuln(seen, r.vulnKeys) {
			return
		}
		*dst = append(*dst, Vuln{
			ID:        r.id,
			CVE:       r.cve,
			Severity:  r.severity,
			Score:     deref(r.score),
			Scored:    r.score != nil,
			Vector:    r.vector,
			CWE:       strings.Join(r.cwe, ","),
			Published: r.published,
			Summary:   summary(r),
			URL:       osvWebResolver + url.PathEscape(id),
		})
	}
	indeterminate := false
	var outside []*record // reached only "from the start" below the named versions: reported, marked, after the rest
	for i := range recs {
		r := &recs[i]
		if ver != "" {
			matched, determinate := recordMatches(r, ver, below && r.listed)
			if !matched && below && r.listed {
				// OSV's own rule decides the rest: a version it cannot place stays unknown with its lead, as for a package
				if matched, determinate = recordMatches(r, ver, false); matched {
					outside = append(outside, r)
					continue
				}
			}
			if !matched {
				if !determinate {
					indeterminate = true
					add(&unplaced, r, seenUnplaced)
				}
				continue
			}
		}
		add(&out, r, seen)
	}
	for _, r := range outside {
		n := len(out)
		add(&out, r, seen) // an advisory another record already reached stays unmarked
		if len(out) > n {
			out[n].OutsideListed = true
		}
	}
	if len(out) == 0 {
		if indeterminate {
			// The version could not be positioned under this ecosystem's rules (versioncmp ok=false):
			// an honest unknown, NOT a resolved "no known vuln for this version". The package IS known,
			// so an adapter reads this as potentially-affected, not unknown-product; the advisories it
			// could not be placed against are returned as the ones to look at.
			return Result{Status: StatusUnknown, Vulns: unplaced, PackageKnown: true, VersionPinned: pinned, BelowListed: below}
		}
		// The package IS known to the index but no advisory touches this version: a real resolved
		// "no known vulnerability for this version", distinct from the unknown cases above.
		return Result{Status: StatusNoKnownVuln, PackageKnown: true, VersionPinned: pinned, BelowListed: below}
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) > severityRank(out[j].Severity) })
	return Result{Status: StatusVulnerable, Vulns: out, PackageKnown: true, VersionPinned: pinned, BelowListed: below}
}

// listsRegistryReleases are the ecosystems whose advisories list the registry's releases in a range.
// shortcut: measured on the Packagist, Maven and NuGet dumps (09/11/2026); add another after
// measuring its dump. npm lists scattered versions (malicious-package records), not the registry's
// releases; distros list their own archive's versions — both keep OSV's rule.
var listsRegistryReleases = map[string]bool{"Packagist": true, "Maven": true, "NuGet": true}

// belowNamedVersions reports whether a platform's release is older than every version the package's
// advisories name (listed, or a range bound): a Shopware 5 version looked up in a package whose data
// begins at 6. An advisory that lists the package's releases then shows the version is not one of
// them: what its "introduced 0" range reaches is still reported, marked OutsideListed; one that
// lists none keeps OSV's rule; one whose ranges cannot place the version is unplaced, as for
// a package.
func belowNamedVersions(recs []record, ver string) bool {
	floor, eco := "", ""
	for i := range recs {
		r := &recs[i]
		if r.floor == "" || !listsRegistryReleases[r.ecosystem] {
			continue
		}
		floor, eco = lower(r.ecosystem, floor, r.floor), r.ecosystem
	}
	if floor == "" {
		return false
	}
	c, ok := versioncmp.Compare(eco, ver, floor)
	return ok && c < 0
}

func sameRelease(recs []record, ecosystem string) []record {
	keep := releaseRows(ecosystem)
	var out []record
	for i := range recs {
		if keep(&recs[i]) {
			out = append(out, recs[i])
		}
	}
	return out
}

// seenVuln folds one logical vuln reported under several ids: it reports whether any of this
// record's keys was already emitted, and otherwise marks them all so a cross-source duplicate
// (same flaw as a GHSA and a GO/PYSEC id sharing a CVE alias) is counted once.
func seenVuln(seen map[string]bool, keys []string) bool {
	for _, k := range keys {
		if seen[k] {
			return true
		}
	}
	for _, k := range keys {
		seen[k] = true
	}
	return false
}

// recordMatches reports whether a pinned version is touched by this record (a version range or,
// when only commit ranges or none were given, the concrete-version list). determinate=false means
// the version could not be placed — a bound not comparable under the record's ecosystem, commit
// ranges with no versions list, or a version list cut off — so the caller keeps the lookup
// unknown rather than counting it as a clean miss.
func recordMatches(r *record, ver string, notARelease bool) (matched, determinate bool) {
	determinate = true
	for i := range r.ranges {
		if r.ranges[i].typ == rangeGit {
			continue // commit bounds: the record's version ranges or its versions list answer instead
		}
		if notARelease && r.ranges[i].introduced == "0" {
			continue // the record's own list shows the version is not one of the package's releases
		}
		in, ok := versionInRange(ver, r.ranges[i], r.ecosystem)
		if !ok {
			determinate = false
			continue
		}
		if in {
			return true, true
		}
	}
	key := normVersionKey(ver)
	for _, v := range r.versions {
		// the ecosystem's own order decides equality ("1.0.0b1" is "1.0.0-beta1"); the spelling (a v prefix, git tags) matches too
		if c, ok := versioncmp.Compare(r.ecosystem, ver, v); (ok && c == 0) || normVersionKey(v) == key {
			return true, true
		}
	}
	if onlyCommitRanges(r.ranges) && len(r.versions) == 0 {
		return false, false // no version range and no versions list: nothing places the version
	}
	return false, determinate && !r.truncated
}

// summary is rebuilt from facts that exist in the reduced row (the reducer drops descriptions to
// keep the index small), never fabricating advisory content.
func summary(r *record) string {
	for _, rg := range r.ranges {
		if rg.fixed != "" {
			return fmt.Sprintf("%s: %s is vulnerable, fixed in %s (OSV)", r.ecosystem, r.pkg, rg.fixed)
		}
	}
	return fmt.Sprintf("%s: %s is vulnerable per OSV (no patch recorded yet)", r.ecosystem, r.pkg)
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// reConcreteVersion matches a single pinned version, OS-package forms included (epoch "1:",
// tilde, apk "_rc1"); a manifest RANGE ("^4.17.0", ">=1.2 <2", "1.2.*") does not.
var reConcreteVersion = regexp.MustCompile(`^[vV]?\d+(\.\d+)*([.\-+:~_][0-9A-Za-z.\-+:~_]+)?$`)

// CleanVersion returns a version usable for range matching, or "" when it is a range / undetermined
// (the caller then gets every advisory for the package — see Lookup).
func CleanVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" || !reConcreteVersion.MatchString(v) {
		return ""
	}
	return v
}

// Adapter builds per-ecosystem indexes from the operator-supplied OSV dump root. The zero value is
// not ready; use New. An empty base URL means the source is off and LoadIndex reports it.
type Adapter struct {
	baseURL string
	client  *fetch.Client

	mu    sync.Mutex
	dumps map[string]*storedDump // with a store: each dump fetched once per Adapter, read per release
}

type storedDump struct {
	once sync.Once
	path string
	meta fetch.Meta
	err  error
}

// New builds an adapter bound to the operator-supplied OSV dump root and client. An empty baseURL
// leaves the source off (LoadIndex returns an error, never a silent "no vuln").
func New(baseURL string, client *fetch.Client) *Adapter {
	return &Adapter{baseURL: strings.TrimSpace(strings.TrimRight(strings.TrimSpace(baseURL), "/")), client: client}
}

// LoadIndex downloads one ecosystem's dump, reduces it to a compact in-RAM index, and deletes the
// downloaded dump before returning. It never panics and never blocks indefinitely (the download is
// bounded); on any failure it returns an error so the caller keeps its honest "unknown" verdict
// rather than mistaking a dead source for "no vulnerability". Build the index ONCE and reuse it
// across the whole lock file — each call is a fresh download.
func (a *Adapter) LoadIndex(ctx context.Context, ecosystem string) (*Index, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	eco, ok := Ecosystem(ecosystem)
	if !ok {
		return nil, fmt.Errorf("%w: %q", errUnknownEco, ecosystem)
	}
	if a.baseURL == "" {
		return nil, errSourceOff
	}
	client := a.client
	if client == nil {
		client = fetch.New()
	}
	zipPath, meta, release, err := a.dump(ctx, client, eco)
	defer release()
	if err != nil {
		return nil, fmt.Errorf("osv %s: %w", eco, err)
	}
	st, err := os.Stat(zipPath)
	if err != nil {
		return nil, fmt.Errorf("osv %s: %w", eco, err)
	}
	if st.Size() == 0 {
		return nil, fmt.Errorf("osv %s: %w", eco, errEmptyDump)
	}
	idx, err := indexOf(ctx, eco, zipPath, st, releaseRows(ecosystem), client.CacheDir != "")
	if err != nil {
		return nil, fmt.Errorf("osv %s: %w", eco, err)
	}
	if idx.Len() == 0 && !strings.Contains(ecosystem, ":") {
		return nil, fmt.Errorf("osv %s: %w", eco, errBuiltNothing) // a release may hold no rows; a whole dump may not
	}
	idx.BuiltAt, idx.fetched = meta.FetchedAt, meta
	return idx, nil
}

// dump fetches eco's dump; with a store the stored copy is remembered, so loading several
// releases of one distro in a run asks the source once.
func (a *Adapter) dump(ctx context.Context, client *fetch.Client, eco string) (string, fetch.Meta, func(), error) {
	get := func() (string, fetch.Meta, func(), error) {
		dctx, cancel := context.WithTimeout(ctx, downloadLimit)
		defer cancel()
		return client.Download(dctx, a.baseURL+"/"+url.PathEscape(eco)+"/all.zip", maxZipBytes)
	}
	if client.CacheDir == "" {
		return get()
	}
	a.mu.Lock() // guards only the map, so two ecosystems download side by side
	d := a.dumps[eco]
	if d == nil {
		d = &storedDump{}
		if a.dumps == nil {
			a.dumps = map[string]*storedDump{}
		}
		a.dumps[eco] = d
	}
	a.mu.Unlock()
	d.once.Do(func() { d.path, d.meta, _, d.err = get() }) // a stored copy needs no release
	return d.path, d.meta, func() {}, d.err
}

// indexOf reads the dump's index file when it was cut from this very dump, and otherwise
// reduces the dump — cutting the file for later runs when the dump is in the store.
func indexOf(ctx context.Context, eco, zipPath string, st os.FileInfo, keep func(*record) bool, stored bool) (*Index, error) {
	idx, err := dumpIndex(ctx, eco, zipPath, st, keep, stored)
	if err == nil && stored {
		applyOverlay(idx, zipPath, st, eco, keep) // the records changed since the dump, from sync
	}
	return idx, err
}

func dumpIndex(ctx context.Context, eco, zipPath string, st os.FileInfo, keep func(*record) bool, stored bool) (*Index, error) {
	cachePath, stamp := "", dumpStamp(st)
	if stored {
		cachePath = zipPath + ".idx.gz"
		if idx, err := readIndexFile(cachePath, stamp, eco, keep); err == nil {
			return idx, nil
		}
	}
	zf, err := os.Open(zipPath)
	if err != nil {
		return nil, err
	}
	defer zf.Close()
	return buildIndex(ctx, eco, zf, st.Size(), keep, cachePath, stamp)
}

// Sync refreshes one ecosystem's dump in the client's store — with the client's MaxAge at 0
// it always asks the source, so an unchanged dump costs a 304 — cuts its index file when the
// dump changed, and returns the stored size. Later runs read that index. Sync replaces the
// stored dump only once the new one's index is cut from it and holds an advisory.
func (a *Adapter) Sync(ctx context.Context, ecosystem string) (int64, error) {
	eco, ok := Ecosystem(ecosystem)
	switch {
	case !ok:
		return 0, fmt.Errorf("%w: %q", errUnknownEco, ecosystem)
	case a.baseURL == "":
		return 0, errSourceOff
	case a.client == nil || a.client.CacheDir == "":
		return 0, errors.New("osv: sync needs the client's store (CacheDir)")
	}
	dumpURL := a.baseURL + "/" + url.PathEscape(eco) + "/all.zip"
	if stored, at, lastModified, ok := a.client.Stored(dumpURL); ok {
		if fi, err := os.Stat(stored); err == nil && time.Since(fi.ModTime()) < fullEvery {
			// no changed-records list (a mirror holding only dumps), or too many changes: the whole dump below
			done, err := a.syncChanged(ctx, eco, stored, lastModified, at)
			if err != nil {
				return 0, fmt.Errorf("osv %s: changed records: %w", eco, err)
			}
			if done {
				a.client.Confirm(dumpURL) // dump + overlay are current: a run within MaxAge reads them with no request
				return a.cutIndex(ctx, eco, stored)
			}
		}
	}
	dctx, cancel := context.WithTimeout(ctx, downloadLimit)
	defer cancel()
	var cut string // the new dump's index: rename keeps the dump's mtime, so moved beside it, it stays stamped for it
	path, meta, release, err := a.client.DownloadChecked(dctx, dumpURL, maxZipBytes, func(tmp string) error {
		st, err := os.Stat(tmp)
		if err != nil {
			return err
		}
		cut = tmp + ".idx.gz"
		rows := 0
		_, err = dumpIndex(ctx, eco, tmp, st, func(*record) bool { rows++; return false }, true)
		if err == nil && rows == 0 {
			err = errBuiltNothing // what LoadIndex refuses for a whole dump
		}
		return err
	})
	defer release()
	if err == nil && meta.Stale {
		err = errors.New(meta.Err) // the store kept its copy: the source did not answer, or the check refused its answer
	}
	if cut != "" && (err != nil || os.Rename(cut, path+".idx.gz") != nil) {
		os.Remove(cut)
	}
	if err != nil {
		return 0, fmt.Errorf("osv %s: %w", eco, err)
	}
	return a.cutIndex(ctx, eco, path)
}

// cutIndex makes sure the stored dump at path has its index file, and returns the dump's size.
func (a *Adapter) cutIndex(ctx context.Context, eco, path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("osv %s: %w", eco, err)
	}
	if f, err := os.Open(path + ".idx.gz"); err == nil {
		_, err = indexDecoder(f, dumpStamp(st))
		f.Close()
		if err == nil {
			return st.Size(), nil // already cut from this dump
		}
	}
	if _, err := dumpIndex(ctx, eco, path, st, func(*record) bool { return false }, true); err != nil {
		return 0, fmt.Errorf("osv %s: %w", eco, err)
	}
	return st.Size(), nil
}

// BuildIndex builds an in-RAM index from a zip dump (no network). r/size is an io.ReaderAt — the
// downloaded temp file at runtime, or a bytes.Reader in tests — so the dump is never held whole in
// RAM. eco is an alias or an OSV ecosystem name.
func BuildIndex(ctx context.Context, ecosystem string, r io.ReaderAt, size int64) (*Index, error) {
	eco, ok := Ecosystem(ecosystem)
	if !ok {
		eco = trimEcosystem(ecosystem)
	}
	if eco == "" {
		return nil, errUnknownEco
	}
	return buildIndex(ctx, eco, r, size, func(*record) bool { return true }, "", "")
}
