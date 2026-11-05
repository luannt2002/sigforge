// Package wpcve resolves a WordPress plugin/theme (slug + installed version) to
// its PROVENANCE and its known vulnerabilities, keeping the component-audit
// distinctions a bare "has CVE?" lookup throws away. It is a NEW intel domain
// alongside cve/kev/lifecycle: cve says "CVE-X applies", wpcve says "slug `acme`
// 1.2.0 sits inside a published vulnerable range (a LEAD), it IS in the free .org
// directory, and its runtime satisfies its requires-PHP".
//
// Two sources, each supplied by the operator as a URL (never hardcoded, off by
// default), each kept honest about what its silence means:
//
//	WPVULN — the community WordPress vulnerability feed, queried per slug. A 404,
//	         an off/unreachable feed, or a "found nothing" payload is UNKNOWN
//	         (Resolved=false), NEVER "0 CVEs / clean". Supplied via
//	         SIGFORGE_SOURCE_WPVULN_URL.
//	WPORG  — the official .org plugins/themes info endpoint, read for PROVENANCE.
//	         Here HTTP status carries meaning the vuln path flattens away: 200 ⇒
//	         in-directory (free), 404 ⇒ not-in-directory (a premium/custom/nulled
//	         CANDIDATE, NOT an error), anything else ⇒ UNKNOWN. Supplied via
//	         SIGFORGE_SOURCE_WPORG_URL.
//
// HONESTY (the controlled part, §2). Three states are kept distinct and never
// collapsed: HasCVE (feed had an opinion and the version matched a range),
// NoKnownCVE (feed had an opinion and nothing matched — Resolved=true, no vulns),
// and UNKNOWN (feed off/dead/404, or a version present but not semver-comparable —
// Resolved=false). The caller renders UNKNOWN as a not-measured finding, never as
// clean. Every match is a LEAD, not a proven exploit: a version-range overlap, so
// Confidence is always "heuristic". Severity is passed through from the feed's
// numeric CVSS only — never invented; with no numeric score it stays null.
// Everything touching the network is FAIL-OPEN: a dead or off source contributes
// nothing rather than erroring, and the pure functions take no network.
//
// LICENSE (§4). No vulnerability snapshot is embedded or vendored. The source is
// operator-chosen via env, and the prominent free community feed is encumbered
// (per-record attribution + hyperlink-back + separate MITRE license on CVE rows),
// so it cannot be redistributed in this Apache-2.0 repo. Both feeds are therefore
// OPERATOR-FETCH-ONLY, off by default, exactly as EPSS is in the kev package. See
// NOTICE.
package wpcve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// EnvWPVulnURL / EnvWPOrgURL are the environment variables the operator uses to
// supply each source's URL. They mirror the other intel adapters'
// SIGFORGE_SOURCE_*_URL naming; both are off by default, so nothing goes to the
// network when they are unset.
const (
	EnvWPVulnURL = "SIGFORGE_SOURCE_WPVULN_URL"
	EnvWPOrgURL  = "SIGFORGE_SOURCE_WPORG_URL"
)

// Licenses records each source's provenance so a caller can tag output. Both are
// operator-fetch-only: neither is ever vendored or embedded (see the package doc
// and §4/NOTICE).
const (
	WPVulnLicense = "community WordPress vulnerability feed — operator-chosen, encumbered (per-record attribution/link-back); operator-fetch-only, never vendored"
	WPOrgLicense  = "WordPress.org plugins/themes directory API — operator-fetch-only, never vendored"
)

// orgMaxBytes caps one .org info blob (a few KB); the ceiling guards against a
// swapped-in huge body on the status-reading path we drive ourselves.
const orgMaxBytes int64 = 512 << 10

// Tri is a three-state boolean. The absence of an answer is itself an answer:
// TriUnknown must never silently collapse into TriNo.
type Tri int

const (
	TriUnknown Tri = iota
	TriNo
	TriYes
)

func (t Tri) String() string {
	switch t {
	case TriYes:
		return "yes"
	case TriNo:
		return "no"
	default:
		return "unknown"
	}
}

// Provenance values for PluginResult.Provenance.
const (
	ProvFree     = "free"             // present in the official .org directory
	ProvNotInDir = "not_in_directory" // absent from .org ⇒ premium / custom / nulled CANDIDATE
	ProvUnknown  = "unknown"          // the .org source was off or unreachable
)

// Compat is a three-state compatibility verdict.
type Compat int

const (
	CompatUnknown      Compat = iota // not enough data to judge (never assume OK)
	CompatOK                         // every known dimension satisfies its requirement
	CompatIncompatible               // at least one dimension's runtime is below its requirement
)

func (c Compat) String() string {
	switch c {
	case CompatOK:
		return "ok"
	case CompatIncompatible:
		return "incompatible"
	default:
		return "unknown"
	}
}

// Lead is one vulnerability the feed reports for a slug whose installed version
// falls in the published range. A LEAD, not a confirmed exploit (version-range
// match, no PoC). Severity/Score are populated only when the feed carries a
// numeric CVSS; otherwise Severity is "" and Confidence is "heuristic".
type Lead struct {
	ID         string  // feed-local id of the advisory
	Title      string  // short human title from the feed
	CVE        string  // CVE id when the feed maps one; may be empty
	MinVersion string  // lower bound of the vulnerable range ("" = open below)
	MaxVersion string  // upper bound ("" = open above, see Unfixed)
	MinOp      string  // gt|ge (default ge)
	MaxOp      string  // lt|le (default lt — "fixed_in" semantics: vulnerable strictly below)
	Unfixed    bool    // no fixed release exists ⇒ anything at/above MinVersion stays vulnerable
	Severity   string  // low|medium|high|critical, or "" when the feed gives no numeric CVSS (null, never invented)
	Score      float64 // CVSS base score (0 = none/unknown)
	CVSS       string  // the raw CVSS vector when present (passed through; not scored here)
	Confidence string  // always "heuristic": method is version-range, not a proven exploit
}

// PluginResult is the full answer for one plugin/theme slug.
//
// Resolved=false means UNKNOWN: the vulnerability feed was off, unreachable,
// returned a "found nothing" shape for this slug, OR knew the slug but the
// installed version could not be parsed for range comparison
// (UnparsedVersion=true). The caller MUST render that as a not-measured finding,
// NOT as "clean". Resolved=true with an empty Vulns means the feed HAD an opinion
// and the installed version matched none of its ranges — clean per that source.
type PluginResult struct {
	Slug            string
	Version         string
	InDirectory     Tri    // tier-4 provenance, tri-state
	Provenance      string // ProvFree | ProvNotInDir | ProvUnknown
	LatestVersion   string // newest version per the .org directory (when known)
	RequiresPHP     string // minimum PHP per .org (when known)
	RequiresWP      string // minimum WP per .org (when known)
	Vulns           []Lead // version-range LEADs (empty + Resolved=true ⇒ clean per the feed)
	Compat          Compat // CompatUnknown unless a runtime was supplied via WithRuntime
	Resolved        bool   // false ⇒ UNKNOWN (feed gave no answer or version unparseable) ⇒ not-measured
	UnparsedVersion bool   // true ⇒ a version WAS detected but is not semver-comparable ⇒ distinct UNKNOWN, never clean
}

// Provider resolves provenance + vulnerabilities from the operator-supplied WPVULN
// and WPORG URLs. Either URL may be empty (that source stays OFF: no network). The
// zero value is not ready; use New. Stateless per call (no cache), matching the
// kev/cve adapters.
type Provider struct {
	vulnURL    string
	orgURL     string
	runtimePHP string
	runtimeWP  string
	client     *fetch.Client
}

// New builds a provider bound to the operator-supplied WPVULN and WPORG URLs and
// client. Both URLs may be empty (that source is simply off).
func New(vulnURL, orgURL string, client *fetch.Client) *Provider {
	return &Provider{
		vulnURL: strings.TrimSpace(vulnURL),
		orgURL:  strings.TrimSpace(orgURL),
		client:  client,
	}
}

// WithRuntime supplies the target's runtime PHP/WP so a lookup can fill Compat.
// Chainable. Empty values keep Compat at CompatUnknown (missing data is never OK).
func (p *Provider) WithRuntime(php, wp string) *Provider {
	p.runtimePHP, p.runtimeWP = strings.TrimSpace(php), strings.TrimSpace(wp)
	return p
}

// Enabled reports which of the two sources are configured, so a caller can label
// results honestly as not-measured when the vuln feed is off.
func (p *Provider) Enabled() (vuln bool, org bool) {
	return p.vulnURL != "", p.orgURL != ""
}

// LookupPlugin / LookupTheme resolve provenance + vulnerabilities for one slug at
// one version.
func (p *Provider) LookupPlugin(ctx context.Context, slug, version string) PluginResult {
	return p.lookup(ctx, slug, version, "plugin")
}

func (p *Provider) LookupTheme(ctx context.Context, slug, version string) PluginResult {
	return p.lookup(ctx, slug, version, "theme")
}

func (p *Provider) lookup(ctx context.Context, slug, version, kind string) PluginResult {
	res := PluginResult{
		Slug:        strings.TrimSpace(slug),
		Version:     strings.TrimSpace(version),
		InDirectory: TriUnknown,
		Provenance:  ProvUnknown,
		Compat:      CompatUnknown,
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if res.Slug == "" {
		return res // nothing to look up ⇒ UNKNOWN
	}

	// tier 4 — provenance via the .org directory. Off/unreachable ⇒ leave UNKNOWN.
	if info, err := p.orgLookup(ctx, res.Slug, kind); err == nil && info != nil {
		if info.InDirectory {
			res.InDirectory, res.Provenance = TriYes, ProvFree
			res.LatestVersion = info.LatestVersion
			res.RequiresPHP, res.RequiresWP = info.RequiresPHP, info.RequiresWP
			res.Compat = CheckCompatibility(info.RequiresPHP, info.RequiresWP, p.runtimePHP, p.runtimeWP)
		} else {
			res.InDirectory, res.Provenance = TriNo, ProvNotInDir
		}
	}

	// tier 2/3 — vulnerability feed. A nil entry (off / unreachable / 404 / "found
	// nothing") is UNKNOWN, never clean (the honest-verdict rule).
	entry, err := p.fetchVulns(ctx, res.Slug, kind)
	if err != nil || entry == nil {
		res.Resolved = false
		return res
	}
	res.Resolved = true

	// A version string PRESENT but not semver-comparable (a build-date, "trunk", a
	// bare build number) cannot be positioned inside any published range. Coercing
	// it to zero groups would land it below every lower bound ⇒ false-clean.
	// Honest-verdict: that is UNKNOWN coverage, never clean. No-version is a
	// separate case and stays on the all-vulns-are-leads path below.
	if res.Version != "" && !parseableVersion(res.Version) {
		res.UnparsedVersion = true
		res.Resolved = false
		return res
	}

	for i := range entry.Vulnerabilities {
		v := &entry.Vulnerabilities[i]
		if res.Version != "" && !versionAffected(res.Version, v) {
			continue
		}
		res.Vulns = append(res.Vulns, leadFrom(v))
	}
	return res
}

// feedEntry / feedVuln — the generic shape the community WP vulnerability feed is
// expected to deliver for a slug: either a bare entry ({"vulnerabilities":[...]})
// or an object keyed by slug ({"<slug>":{"vulnerabilities":[...]}}); parseVulns
// accepts both. No vendor field names beyond this generic shape are assumed — the
// operator points the env URL at a feed (or a mirror) that produces it.
type feedEntry struct {
	Vulnerabilities []feedVuln `json:"vulnerabilities"`
}

type feedVuln struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	CVE        string `json:"cve"`
	MinVersion string `json:"min_version"`
	MaxVersion string `json:"max_version"`
	MinOp      string `json:"min_operator"` // gt|ge
	MaxOp      string `json:"max_operator"` // lt|le
	Unfixed    bool   `json:"unfixed"`
	CVSSVector string `json:"cvss_vector"`
	CVSSScore  string `json:"cvss_score"`
}

// fetchVulns asks the operator's WPVULN URL about one slug via the stateless fetch
// client. OFF ⇒ (nil, nil) and no network. Fail-open: any fetch error (incl. a 404
// = slug absent) ⇒ (nil, err) ⇒ caller treats it as UNKNOWN, never clean. A non-nil
// entry (even with an empty Vulnerabilities list) means the feed KNOWS the slug.
func (p *Provider) fetchVulns(ctx context.Context, slug, kind string) (*feedEntry, error) {
	if p.vulnURL == "" || p.client == nil {
		return nil, nil
	}
	b, err := p.client.Get(ctx, buildURL(p.vulnURL, slug, kind))
	if err != nil || len(b) == 0 {
		return nil, err // unreachable / 404 / empty ⇒ UNKNOWN (NOT clean)
	}
	return parseVulns(b, slug)
}

// parseVulns turns a feed body into an entry, applying the honest-verdict rule. A
// null/empty "found nothing" payload, or a slug the feed does not list, yields
// (nil, nil) = UNKNOWN. An unparseable body yields an error = UNKNOWN (never a
// guessed clean). Pure (no network).
func parseVulns(b []byte, slug string) (*feedEntry, error) {
	switch strings.TrimSpace(string(b)) {
	case "", "null", "false", "{}", "[]":
		return nil, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("wpcve: vuln feed payload is not a JSON object")
	}
	if len(raw) == 0 {
		return nil, nil
	}
	for k, v := range raw { // keyed-by-slug shape
		if strings.EqualFold(k, slug) {
			var e feedEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return nil, err
			}
			return &e, nil
		}
	}
	if _, ok := raw["vulnerabilities"]; ok { // bare-entry shape
		var e feedEntry
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, nil // slug absent ⇒ UNKNOWN
}

// orgInfo is the .org directory's answer for one slug.
type orgInfo struct {
	InDirectory   bool
	LatestVersion string
	RequiresPHP   string
	RequiresWP    string
}

// orgLookup resolves provenance via the .org directory. (nil, nil) ⇒ source OFF;
// (info, nil) ⇒ resolved (in or not in directory); (nil, err) ⇒ unreachable.
func (p *Provider) orgLookup(ctx context.Context, slug, kind string) (*orgInfo, error) {
	if p.orgURL == "" || p.client == nil || p.client.HTTP == nil {
		return nil, nil // OFF ⇒ no network, provenance stays UNKNOWN
	}
	return p.orgFetch(ctx, buildURL(p.orgURL, slug, kind))
}

// orgFetch is one status-reading GET. The .org endpoint needs its own request —
// not fetch.Client.Get — because here status carries meaning: 200 ⇒ parse
// (in-directory, or a null/error body ⇒ not-in-directory); 404 ⇒ not-in-directory
// (clean negative, NOT an error); anything else / transport error ⇒ UNKNOWN. It
// reuses the client's configured *http.Client (timeout) rather than a second one.
func (p *Provider) orgFetch(ctx context.Context, u string) (*orgInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sigforge-fetch")
	res, err := p.client.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(res.Body, orgMaxBytes))
		if err != nil {
			return nil, err
		}
		return parseOrg(b)
	case http.StatusNotFound:
		return &orgInfo{InDirectory: false}, nil // not in the free directory ⇒ premium/custom candidate
	default:
		return nil, fmt.Errorf("wpcve: org feed HTTP %d", res.StatusCode)
	}
}

type orgDoc struct {
	Version     string `json:"version"`
	RequiresPHP string `json:"requires_php"`
	Requires    string `json:"requires"` // minimum WP version
	Error       string `json:"error"`
}

// parseOrg reads a 200 body. A null/false/empty/error/no-version body means the
// slug is not really in the directory (clean negative). An unparseable 200 is
// UNKNOWN (err) — never a pretended clean. Pure (no network).
func parseOrg(b []byte) (*orgInfo, error) {
	switch strings.TrimSpace(string(b)) {
	case "", "null", "false", "{}", "[]":
		return &orgInfo{InDirectory: false}, nil
	}
	var d orgDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("wpcve: org feed payload unparseable")
	}
	if strings.TrimSpace(d.Error) != "" || strings.TrimSpace(d.Version) == "" {
		return &orgInfo{InDirectory: false}, nil
	}
	return &orgInfo{
		InDirectory:   true,
		LatestVersion: strings.TrimSpace(d.Version),
		RequiresPHP:   strings.TrimSpace(d.RequiresPHP),
		RequiresWP:    strings.TrimSpace(d.Requires),
	}, nil
}

// buildURL places the slug into the operator's endpoint. The operator may use
// {slug}/{kind} placeholders (full, vendor-neutral control of the query shape);
// without a placeholder the slug is appended as a trailing path segment. The slug
// and kind are URL-escaped.
func buildURL(base, slug, kind string) string {
	s := url.PathEscape(slug)
	if strings.Contains(base, "{slug}") {
		r := strings.ReplaceAll(base, "{slug}", s)
		return strings.ReplaceAll(r, "{kind}", url.PathEscape(kind))
	}
	return strings.TrimRight(base, "/") + "/" + s
}

// versionAffected — does `installed` fall inside this record's published vulnerable
// range? The range is {MinVersion, MinOp(gt|ge)} .. {MaxVersion, MaxOp(lt|le)},
// plus Unfixed. Defaults are the honest ones: a lower bound with no operator is
// inclusive (ge); an upper bound with no operator is exclusive (lt), i.e.
// "fixed_in = X" means vulnerable strictly below X. Unfixed means no fix was ever
// published, so anything at/above the lower bound stays vulnerable. An empty
// installed version can't be excluded ⇒ true (treated as a LEAD; honest "can't
// pin"). Pure.
func versionAffected(installed string, rec *feedVuln) bool {
	installed = strings.TrimSpace(installed)
	if installed == "" {
		return true
	}

	if mv := strings.TrimSpace(rec.MinVersion); mv != "" {
		c := cmpVer(installed, mv)
		if strings.EqualFold(strings.TrimSpace(rec.MinOp), "gt") {
			if c <= 0 {
				return false
			}
		} else if c < 0 { // ge (default)
			return false
		}
	}

	if rec.Unfixed {
		return true // no fixed release ⇒ no upper bound
	}

	if xv := strings.TrimSpace(rec.MaxVersion); xv != "" {
		c := cmpVer(installed, xv)
		if strings.EqualFold(strings.TrimSpace(rec.MaxOp), "le") {
			return c <= 0
		}
		return c < 0 // lt (default): "fixed_in" ⇒ vulnerable strictly below
	}

	// only a lower bound given, no max ⇒ can't bound above; the lower bound already
	// matched, so report it as a LEAD rather than silently dropping it.
	return true
}

// CheckCompatibility compares required vs runtime for PHP and WP, three-state. A
// definite failure wins (CompatIncompatible); otherwise any missing dimension
// forces CompatUnknown — never OK while a requirement or a runtime is unknown.
// CompatOK only when BOTH sides of every dimension are known and satisfied. Pure.
func CheckCompatibility(requiresPHP, requiresWP, runtimePHP, runtimeWP string) Compat {
	php := compatDim(requiresPHP, runtimePHP)
	wp := compatDim(requiresWP, runtimeWP)
	if php == CompatIncompatible || wp == CompatIncompatible {
		return CompatIncompatible
	}
	if php == CompatUnknown || wp == CompatUnknown {
		return CompatUnknown
	}
	return CompatOK
}

func compatDim(required, runtime string) Compat {
	required, runtime = strings.TrimSpace(required), strings.TrimSpace(runtime)
	if required == "" || runtime == "" {
		return CompatUnknown
	}
	if cmpVer(runtime, required) < 0 {
		return CompatIncompatible
	}
	return CompatOK
}

// leadFrom maps a feed record to a Lead, passing CVSS through honestly. sigforge
// has no CVSS-vector scorer, so a bare vector is preserved as the raw CVSS string
// but is NOT turned into a severity (inventing one would violate §2); only an
// explicit numeric cvss_score sets Severity/Score.
func leadFrom(v *feedVuln) Lead {
	sev, score := leadSeverity(v)
	return Lead{
		ID:         strings.TrimSpace(v.ID),
		Title:      strings.TrimSpace(v.Title),
		CVE:        strings.TrimSpace(v.CVE),
		MinVersion: strings.TrimSpace(v.MinVersion),
		MaxVersion: strings.TrimSpace(v.MaxVersion),
		MinOp:      strings.TrimSpace(v.MinOp),
		MaxOp:      strings.TrimSpace(v.MaxOp),
		Unfixed:    v.Unfixed,
		Severity:   sev,
		Score:      score,
		CVSS:       strings.TrimSpace(v.CVSSVector),
		Confidence: "heuristic", // version-range match is a LEAD, never a proven exploit
	}
}

// leadSeverity passes an explicit numeric CVSS score through to a qualitative band.
// With no usable numeric score, severity is "" (null) — NEVER a default/invented
// level, even when a vector string is present (the vector is kept raw on the Lead).
func leadSeverity(v *feedVuln) (severity string, score float64) {
	if raw := strings.TrimSpace(v.CVSSScore); raw != "" {
		if s, err := strconv.ParseFloat(raw, 64); err == nil && s > 0 {
			return severityFromScore(s), s
		}
	}
	return "", 0
}

// severityFromScore maps a CVSS v3.1/v4.0 base score to its qualitative band.
// 0 ⇒ none ("" null severity).
func severityFromScore(score float64) string {
	switch {
	case score <= 0:
		return ""
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}

// parseableVersion reports whether a DETECTED version can be positioned inside a
// published vulnerable range: true only when its numeric core (before any
// pre-release/build tail) is a dotted group of integers ("1.0", "1.2.3", "v2.3",
// "1.0-beta" core "1.0"). A bare build-number or date ("20231101") or a
// non-numeric tag ("trunk") has no comparable dotted-semver core ⇒ false, so it is
// kept OUT of the range comparison (⇒ UnparsedVersion UNKNOWN, never false-clean).
// Pure.
func parseableVersion(s string) bool {
	s = strings.TrimLeft(strings.TrimSpace(s), "vV")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 { // no dot ⇒ a bare token/number, not a dotted version
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
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "vV")
	if i := strings.IndexAny(s, "-+ "); i >= 0 { // cut a pre-release/build tail so groups compare cleanly
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
