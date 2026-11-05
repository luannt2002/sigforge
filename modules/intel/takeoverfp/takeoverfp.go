// Package takeoverfp recognizes a DANGLING SUBDOMAIN — a DNS record still pointing
// at a third-party service (S3 bucket, Ghost blog, GitHub Pages…) whose underlying
// resource has been released and can be re-registered by anyone. It is a NEW intel
// domain alongside cve, kev and lifecycle: those answer "is this software version
// exploited", this answers "can this subdomain's CNAME target be re-claimed".
//
// A hardcoded provider table in .go goes stale the moment a provider appears or
// changes its "unclaimed resource" page, so the fingerprints are DATA supplied by
// the operator as a URL (never hardcoded, off by default) and only ever UPGRADE the
// embedded air-gap snapshot:
//
//	The community table at EdOverflow/can-i-take-over-xyz (fingerprints.json) is
//	released under CC-BY-4.0, which permits redistribution with attribution, so a
//	snapshot is embedded (go:embed) as the air-gap baseline and recorded in NOTICE.
//	The operator's SIGFORGE_SOURCE_TAKEOVER_URL upgrades it to the live table.
//
// HONESTY (the controlled part). A non-match is never turned into "safe": Match
// returning false means "no takeover evidence", not "this subdomain is clean". A
// dead or off source does NOT blind the scan — it falls open to the embedded
// snapshot — but it never fabricates a "not vulnerable" verdict either.
//
// FALSE-POSITIVE DISCIPLINE (why Match exists). A CNAME pointing to a PaaS provider
// is NORMAL ARCHITECTURE, not a vulnerability. Judging by the CNAME alone tags HIGH
// on every site using a PaaS; judging by the body alone matches any generic 404. So
// Match reports a hit only when ALL THREE hold: (1) the CNAME matches a provider's
// suffix ∧ (2) the body carries that provider's "unclaimed resource" signature ∧
// (3) upstream marks the provider vulnerable=true. ParseFingerprints, Match and
// Provider are PURE functions (no network) for deterministic tests.
package takeoverfp

import (
	"context"
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// EnvURL is the environment variable the operator uses to supply the live fingerprint
// table URL (e.g. the EdOverflow can-i-take-over-xyz fingerprints.json). It mirrors
// the other intel adapters' SIGFORGE_SOURCE_*_URL naming and is off by default, so
// nothing goes to the network when it is unset.
const EnvURL = "SIGFORGE_SOURCE_TAKEOVER_URL"

// License records the embedded snapshot's provenance so a caller can tag it (see the
// package doc and NOTICE). CC-BY-4.0 permits redistribution with attribution.
const License = "CC-BY-4.0 (EdOverflow/can-i-take-over-xyz fingerprints.json)"

// minFingerprint drops a signature too short to be evidence: a handful of characters
// matches harmless page text just as easily as an abandoned resource page.
const minFingerprint = 8

// FP is one provider normalized from the fingerprint table.
type FP struct {
	Service     string   // provider name, for explaining the finding
	CNAMEs      []string // CNAME suffixes identifying the provider (lowercased, trailing dot removed)
	Fingerprint string   // a string/regex that appears ONLY when the resource is abandoned
	Vulnerable  bool     // upstream confirms this provider is actually reclaimable
}

// fpRaw is the exact upstream schema; other fields (discussion, http_status…) are ignored.
type fpRaw struct {
	Service     string   `json:"service"`
	CNAME       []string `json:"cname"`
	Fingerprint string   `json:"fingerprint"`
	Vulnerable  bool     `json:"vulnerable"`
	Status      string   `json:"status"`
}

//go:embed data/fingerprints.json
var snapshot []byte

// Adapter loads the fingerprint table from the operator-supplied URL, falling open to
// the embedded CC-BY snapshot when the URL is empty, dead, or serving junk. The zero
// value is not ready; use New.
type Adapter struct {
	url    string
	client *fetch.Client
}

// New builds an adapter bound to the operator-supplied table URL and client. An empty
// URL means the embedded snapshot is used (air-gap baseline), never the network.
func New(url string, client *fetch.Client) *Adapter {
	return &Adapter{url: strings.TrimSpace(url), client: client}
}

// Load returns the full fingerprint table, keeping vulnerable=false entries too (Match
// filters them) so Provider can still name "this CNAME points to a third party, but
// that provider is not reclaimable". It prefers the live table from the operator's URL
// but fails open to the embedded snapshot on an empty URL, a fetch error, or junk
// content (a proxy serving HTML), so an air-gapped run still recognizes the notorious
// providers instead of going blind. It never returns nil — but a non-match from the
// returned table is still "no evidence", never "clean".
func (a *Adapter) Load(ctx context.Context) []FP {
	snap, _ := ParseFingerprints(snapshot)
	if a.url == "" {
		return snap
	}
	raw, err := a.client.Get(ctx, a.url)
	if err != nil {
		return snap
	}
	fps, err := ParseFingerprints(raw)
	if err != nil || len(fps) == 0 {
		return snap
	}
	return fps
}

// ParseFingerprints is the PURE decode of a fingerprint table (no network). A row
// without a service name is skipped.
func ParseFingerprints(b []byte) ([]FP, error) {
	var raw []fpRaw
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make([]FP, 0, len(raw))
	for _, r := range raw {
		svc := strings.TrimSpace(r.Service)
		if svc == "" {
			continue
		}
		cn := make([]string, 0, len(r.CNAME))
		for _, c := range r.CNAME {
			if c = normalize(c); c != "" {
				cn = append(cn, c)
			}
		}
		out = append(out, FP{
			Service:     svc,
			CNAMEs:      cn,
			Fingerprint: strings.TrimSpace(r.Fingerprint),
			// vulnerable=true while status says the opposite ("Not vulnerable" / "Edge
			// case") is self-contradictory data → treat as NOT exploitable, leaning to
			// fewer false positives. Don't test == "Vulnerable", so a reworded status
			// doesn't silently drop the whole table.
			Vulnerable: r.Vulnerable && !deniedStatus(r.Status),
		})
	}
	return out, nil
}

// Match returns the matching FP IF AND ONLY IF: fp.Vulnerable ∧ cname matches a suffix
// ∧ body contains the signature. Missing any term → (FP{}, false). That AND is exactly
// what blocks a false takeover report.
func Match(fps []FP, cname, body string) (FP, bool) {
	host := normalize(cname)
	if host == "" || body == "" {
		return FP{}, false
	}
	for _, fp := range fps {
		if !fp.Vulnerable || !bodySignature(fp.Fingerprint) {
			continue
		}
		if !cnameMatch(fp.CNAMEs, host) {
			continue
		}
		if bodyMatch(fp.Fingerprint, body) {
			return fp, true
		}
	}
	return FP{}, false
}

// Provider reports which provider a CNAME points to. It does NOT look at the body and
// does NOT filter vulnerable, so a caller can distinguish "inspected, still alive" from
// "could not inspect". NEVER build a Medium+ finding from Provider — a CNAME pointing
// to a PaaS is normal architecture; only Match carries enough evidence for High. A
// vulnerable entry is preferred so the name is closest to the actual risk.
func Provider(fps []FP, cname string) (FP, bool) {
	host := normalize(cname)
	if host == "" {
		return FP{}, false
	}
	var first FP
	found := false
	for _, fp := range fps {
		if !cnameMatch(fp.CNAMEs, host) {
			continue
		}
		if fp.Vulnerable {
			return fp, true
		}
		if !found {
			first, found = fp, true
		}
	}
	return first, found
}

// deniedStatus is an explicitly negative upstream status.
func deniedStatus(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return strings.HasPrefix(s, "not vulnerable") || strings.HasPrefix(s, "edge case")
}

// bodySignature reports whether a signature can be checked AGAINST THE BODY. Upstream
// uses a few values that are NOT page content: "NXDOMAIN" (a DNS-level signal) and
// "HTTP_STATUS=301/500" (a status-level signal). Comparing those to the body either
// never matches or matches bogusly, so they are rejected outright — better to miss
// than to build a HIGH with no page-content evidence.
func bodySignature(f string) bool {
	if len(f) < minFingerprint {
		return false
	}
	if strings.EqualFold(f, "NXDOMAIN") || strings.HasPrefix(f, "HTTP_STATUS=") {
		return false
	}
	return true
}

// cnameMatch is a suffix match on LABEL BOUNDARIES, not a bare HasSuffix, so
// "evilcdn.provider.example" does NOT count as matching "cdn.provider.example".
func cnameMatch(suffixes []string, host string) bool {
	for _, s := range suffixes {
		if s == "" {
			continue
		}
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

var (
	reMu   sync.Mutex
	reMemo = map[string]*regexp.Regexp{}
)

// bodyMatch matches a signature against the body. Upstream writes fingerprints as loose
// regex (they contain `.*`) and escapes the `|` alternation to `&#124;` in the JSON, so
// `&#124;` is restored to `|` and the pattern compiled case-insensitively; a compile
// failure (or a plain-text signature) falls back to a case-insensitive substring match.
// It never uses MustCompile — external data must not be able to panic the scan. Only
// `&#124;` is restored; other entities (`&rsquo;`…) stay verbatim as they appear in the
// abandoned page's HTML. Compiled patterns are memoized across calls (many subdomains
// may point to the same provider).
func bodyMatch(fingerprint, body string) bool {
	pat := strings.ReplaceAll(fingerprint, "&#124;", "|")

	reMu.Lock()
	re, seen := reMemo[pat]
	if !seen {
		re, _ = regexp.Compile("(?i)" + pat) // error → re == nil → plain-substring branch
		reMemo[pat] = re
	}
	reMu.Unlock()

	if re != nil {
		return re.MatchString(body)
	}
	return strings.Contains(strings.ToLower(body), strings.ToLower(pat))
}

// normalize lowercases and strips the trailing root dot (a resolver returns an FQDN
// like "x.io.").
func normalize(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
