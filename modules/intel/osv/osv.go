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
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
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
	// maxZipBytes caps the downloaded dump on disk (npm's ~205MB is the largest known), guarding a
	// scarce disk against a hostile or runaway endpoint. It streams to a temp file, so this is a
	// disk ceiling, independent of the fetch client's in-memory ceiling.
	maxZipBytes int64 = 512 << 20
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
}

// Ecosystem maps an alias to its OSV ecosystem name; ok is false when outside the whitelist.
func Ecosystem(name string) (eco string, ok bool) {
	v, ok := ecosystemNames[strings.ToLower(strings.TrimSpace(name))]
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
	ID       string // native OSV id (GHSA-/GO-/PYSEC-…), the stable key
	CVE      string // CVE alias if any, UPPER-cased
	Severity string // upstream text label mapped (low|medium|high|critical), or "" if unscored
	Summary  string // rebuilt from recorded facts (the fixed version), never fabricated
	URL      string // https://osv.dev/vulnerability/<ID>
}

// Ref is the display id, preferring the CVE (readers recognize it) and falling back to the OSV id.
func (v Vuln) Ref() string {
	if v.CVE != "" {
		return v.CVE
	}
	return v.ID
}

// Result is a lookup outcome: the tri-state status plus any matching vulns (nil unless Vulnerable).
type Result struct {
	Status Status
	Vulns  []Vuln
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
	k := pkgKey(r.pkg)
	if k == "" {
		return
	}
	idx.byName[k] = append(idx.byName[k], *r)
	idx.count++
}

// pkgKey is the lookup key, lower-cased: npm/PyPI/Packagist are case-insensitive at install time and
// Go/Maven names still match exactly after lowering, so real-world collisions do not occur.
func pkgKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Lookup returns the tri-state result for name@version (see the package doc for the states).
//
// A pinned version is matched against affected ranges (and the concrete-version list). An EMPTY or
// RANGE version ("^4.17.0") cannot pin the running instance, so every advisory for the package is
// returned as Vulnerable and the caller must treat it as "potentially affected, version not pinned"
// rather than confirmed — surfacing the facts beats staying silent.
func (idx *Index) Lookup(name, version string) Result {
	if idx == nil {
		return Result{Status: StatusUnknown}
	}
	recs := idx.byName[pkgKey(name)]
	if len(recs) == 0 {
		// The package never appears in the index: it may be unaffected, but it may also be a name /
		// ecosystem mismatch or a coverage gap, so this is not asserted as "no vulnerability".
		return Result{Status: StatusUnknown}
	}
	ver := CleanVersion(version)
	seen := make(map[string]bool, len(recs))
	out := make([]Vuln, 0, 4)
	for i := range recs {
		r := &recs[i]
		if ver != "" && !recordMatches(r, ver) {
			continue
		}
		id := r.id
		if id == "" {
			id = r.cve
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Vuln{
			ID:       r.id,
			CVE:      r.cve,
			Severity: r.severity,
			Summary:  summary(r),
			URL:      osvWebResolver + url.PathEscape(id),
		})
	}
	if len(out) == 0 {
		// The package IS known to the index but no advisory touches this version: a real resolved
		// "no known vulnerability for this version", distinct from the unknown cases above.
		return Result{Status: StatusNoKnownVuln}
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) > severityRank(out[j].Severity) })
	return Result{Status: StatusVulnerable, Vulns: out}
}

// recordMatches reports whether a pinned version is touched by this record (a range or, when the
// advisory carried no range, the concrete-version list).
func recordMatches(r *record, ver string) bool {
	for i := range r.ranges {
		if VersionInRange(ver, r.ranges[i]) {
			return true
		}
	}
	key := normVersionKey(ver)
	for _, v := range r.versions {
		if normVersionKey(v) == key {
			return true
		}
	}
	return false
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

// reConcreteVersion matches a single pinned version; a manifest RANGE ("^4.17.0", ">=1.2 <2") does not.
var reConcreteVersion = regexp.MustCompile(`^[vV]?\d+(\.\d+)*([.\-+][0-9A-Za-z.\-+]+)?$`)

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
	zipPath, size, err := a.downloadDump(ctx, eco)
	if err != nil {
		return nil, fmt.Errorf("osv %s: %w", eco, err)
	}
	defer os.Remove(zipPath)

	zf, err := os.Open(zipPath)
	if err != nil {
		return nil, fmt.Errorf("osv %s: %w", eco, err)
	}
	defer zf.Close()

	idx, err := BuildIndex(ctx, eco, zf, size)
	if err != nil {
		return nil, fmt.Errorf("osv %s: %w", eco, err)
	}
	if idx.Len() == 0 {
		return nil, fmt.Errorf("osv %s: %w", eco, errBuiltNothing)
	}
	return idx, nil
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
	idx := &Index{Ecosystem: eco, BuiltAt: time.Now(), byName: make(map[string][]record, 4096)}
	err := reduceZip(ctx, r, size, eco, func(r *record) error {
		idx.add(r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return idx, nil
}

// downloadDump streams <base>/<eco>/all.zip to a temp file and returns its path + size; the caller
// deletes it. The dump is far larger than the fetch client's in-memory ceiling and archive/zip needs
// an io.ReaderAt, so it streams to disk here (bounded by maxZipBytes) rather than through fetch.Get,
// reusing only the operator's configured HTTP client.
func (a *Adapter) downloadDump(ctx context.Context, eco string) (string, int64, error) {
	u := a.baseURL + "/" + url.PathEscape(eco) + "/all.zip"
	cctx, cancel := context.WithTimeout(ctx, downloadLimit)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "sigforge-osv")

	hc := http.DefaultClient
	if a.client != nil && a.client.HTTP != nil {
		hc = a.client.HTTP
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("download %s: status %d", eco, resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "sigforge-osv-*.zip")
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxZipBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, err
	}
	if n > maxZipBytes {
		os.Remove(tmp.Name()) // over the ceiling means a truncated zip; keeping it only wastes disk
		return "", 0, fmt.Errorf("download %s exceeds the %d byte ceiling", eco, maxZipBytes)
	}
	if n == 0 {
		os.Remove(tmp.Name())
		return "", 0, errEmptyDump
	}
	return tmp.Name(), n, nil
}
