// Package identity maps a recognized technology to a VERIFIED CPE identity so a
// fingerprint that names a tech but carries no CPE can still be bridged to CVE/NVD
// WITHOUT guessing. It is a NEW intel domain alongside cve and kev: the matcher
// records a CPE only when a source attests one (schema.Pattern.CPE, "never
// fabricated"), which leaves recognized-but-unmatchable tech (e.g. a chunk of the
// baseline carries no CPE) unable to be looked up for CVEs. This package resolves
// (techName / vendor / product) against the authoritative NVD CPE dictionary and
// returns a CPE ONLY when the dictionary itself confirms it.
//
// The one source is supplied by the operator as a URL (never hardcoded, off by
// default) and kept honest about its license (§4):
//
//	NVD CPE dictionary — NIST's official product dictionary (the "products" feed of
//	the NVD 2.0 API / official-cpe-dictionary). A U.S. Government work in the public
//	domain, so a small sample is embedded (go:embed) as an air-gap baseline and
//	recorded in NOTICE. The operator's SIGFORGE_SOURCE_CPE_DICT_URL upgrades it to
//	the full live dictionary. Empty env means the embedded sample only, not "no CPE".
//
// HONESTY (the whole point, §2). ResolveCPE returns StateVerified with a CPE and the
// matching dictionary title ONLY when exactly one distinct vendor:product base in the
// dictionary matches the query; a tech the dictionary does not know, and an AMBIGUOUS
// query that matches two different products, both return StateUnknown with an empty
// CPE. A CPE is NEVER synthesized from the caller's own strings — guessing a CPE
// would point CVE lookups at the wrong product. StateUnknown is "not confirmed", not
// "no CPE = safe". The returned CPE is deliberately version-wildcarded
// (cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*): the dictionary confirms the product
// identity, not the specific version the target runs, so it is a VERIFIED suggestion
// for a consumer/operator to adopt, never an automatic overwrite of the baseline.
//
// ParseDict and Match are PURE functions (no network) for deterministic tests; the
// network path (load) is FAIL-OPEN: a dead or off dictionary falls back to the
// embedded public-domain sample rather than erroring or blocking a scan.
package identity

import (
	"context"
	_ "embed"
	"encoding/json"
	"sort"
	"strings"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// EnvCPEDictURL is the environment variable the operator uses to supply the NVD CPE
// dictionary URL (the "products" feed of the NVD 2.0 API). It mirrors the other intel
// adapters' SIGFORGE_SOURCE_*_URL naming and is off by default, so nothing goes to the
// network when it is unset — the embedded public-domain sample is used instead.
const EnvCPEDictURL = "SIGFORGE_SOURCE_CPE_DICT_URL"

// CPEDictLicense records the source's provenance so a caller can tag it. The NVD CPE
// dictionary is a U.S. Government work in the public domain (embeddable); see NOTICE.
const CPEDictLicense = "public-domain (NVD / NIST / U.S. Government work)"

// State is the honest tri-state of a resolution. There is no "no CPE" state: a tech the
// dictionary cannot confirm is Unknown, never asserted clean.
type State int

const (
	// StateUnknown: the dictionary does not confirm a single CPE for the query (no
	// match, or an ambiguous one). NOT "safe" and NOT "has no CPE" — just unconfirmed.
	StateUnknown State = iota
	// StateVerified: exactly one distinct vendor:product base in the dictionary matched.
	StateVerified
)

func (s State) String() string {
	if s == StateVerified {
		return "Verified"
	}
	return "Unknown"
}

// Entry is one normalized, version-agnostic CPE identity from the dictionary: the
// vendor:product base (CPE), the parsed vendor and product tokens, and the human title
// that serves as the match evidence.
type Entry struct {
	CPE     string // version-wildcarded base, e.g. "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
	Vendor  string // the CPE vendor field, verbatim (e.g. "apache")
	Product string // the CPE product field, verbatim (e.g. "http_server")
	Title   string // the dictionary's human title (the evidence), e.g. "Apache HTTP Server"
}

//go:embed data/cpe-dict-snapshot.json
var cpeSnapshot []byte

// cpeDoc is the NVD 2.0 CPE API schema: products[] each wrapping a cpe object with its
// cpeName, a deprecated flag, and localized titles. Other fields are ignored.
type cpeDoc struct {
	Products []struct {
		CPE struct {
			CPEName    string `json:"cpeName"`
			Deprecated bool   `json:"deprecated"`
			Titles     []struct {
				Title string `json:"title"`
				Lang  string `json:"lang"`
			} `json:"titles"`
		} `json:"cpe"`
	} `json:"products"`
}

// Resolver resolves a tech to a verified CPE against the operator-supplied dictionary
// URL, falling back to the embedded public-domain sample. The zero value is not ready;
// use New.
type Resolver struct {
	dictURL string
	client  *fetch.Client
}

// New builds a resolver bound to the operator-supplied CPE dictionary URL and client.
// The URL may be empty (the embedded public-domain sample is then used).
func New(dictURL string, client *fetch.Client) *Resolver {
	return &Resolver{dictURL: strings.TrimSpace(dictURL), client: client}
}

// ResolveCPE resolves (name / vendor / product) to a VERIFIED CPE or Unknown. When
// vendor and product are both given they are the match key; otherwise name is matched
// against the dictionary's "vendor product" and "product" token forms. It returns a
// version-wildcarded CPE and the matching dictionary title ONLY when exactly one
// distinct vendor:product base matches — never a CPE built from the inputs. Fail-open:
// a dead/off dictionary uses the embedded sample, so a tech the sample does not know
// still returns Unknown rather than erroring.
func (r *Resolver) ResolveCPE(ctx context.Context, name, vendor, product string) (cpe string, evidence string, state State) {
	return Match(r.load(ctx), name, vendor, product)
}

// load returns the dictionary entries, preferring the operator's live feed but failing
// open to the embedded public-domain sample on an empty URL, a fetch error, or junk
// content (a proxy serving HTML). It never returns nil.
func (r *Resolver) load(ctx context.Context) []Entry {
	snap, _ := ParseDict(cpeSnapshot)
	if r.dictURL == "" {
		return snap
	}
	raw, err := r.client.Get(ctx, r.dictURL)
	if err != nil {
		return snap
	}
	live, err := ParseDict(raw)
	if err != nil || len(live) == 0 {
		return snap
	}
	return live
}

// ParseDict is the PURE decode of an NVD CPE dictionary feed into version-agnostic
// Entry bases keyed by vendor:product (no network). Deprecated entries and rows whose
// cpeName is not a well-formed CPE 2.3 string are skipped; multiple versioned CPEs for
// one product collapse to a single base, keeping the first English title as evidence.
// The result is sorted by CPE for deterministic tests and logs.
func ParseDict(b []byte) ([]Entry, error) {
	var doc cpeDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	byBase := make(map[string]Entry)
	for _, p := range doc.Products {
		if p.CPE.Deprecated {
			continue
		}
		base, vendor, product := baseCPE(p.CPE.CPEName)
		if base == "" {
			continue
		}
		if _, seen := byBase[base]; seen {
			continue // first title wins; a later versioned row adds nothing new
		}
		byBase[base] = Entry{CPE: base, Vendor: vendor, Product: product, Title: pickTitle(p.CPE.Titles)}
	}
	out := make([]Entry, 0, len(byBase))
	for _, e := range byBase {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CPE < out[j].CPE })
	return out, nil
}

// Match is the PURE resolution rule (no network, table-testable). It collects the
// dictionary entries matching the query, collapses them to distinct vendor:product
// bases, and returns Verified ONLY when exactly one base matches — 0 (unknown) or >1
// (ambiguous) both yield Unknown with an empty CPE. It NEVER constructs a CPE from the
// query. When vendor+product are both given they are the key; otherwise name is matched
// against each entry's "vendor product" and "product" token forms.
func Match(entries []Entry, name, vendor, product string) (cpe string, evidence string, state State) {
	v, p, n := normWords(vendor), normWords(product), normWords(name)
	if v == "" && p == "" && n == "" {
		return "", "", StateUnknown
	}
	hits := make(map[string]Entry)
	for _, e := range entries {
		ev, ep := normWords(e.Vendor), normWords(e.Product)
		full := strings.TrimSpace(ev + " " + ep)
		var matched bool
		switch {
		case v != "" && p != "":
			matched = ev == v && ep == p
		case p != "":
			matched = ep == p
		case v != "":
			matched = ev == v // vendor alone is usually ambiguous → caught as >1 below
		default: // name only
			matched = n == full || n == ep
		}
		if matched {
			hits[e.CPE] = e
		}
	}
	if len(hits) != 1 {
		return "", "", StateUnknown
	}
	for _, e := range hits {
		return e.CPE, "NVD CPE dictionary title: " + e.Title, StateVerified
	}
	return "", "", StateUnknown
}

// baseCPE parses a CPE 2.3 formatted string and returns its version-agnostic base
// (cpe:2.3:<part>:<vendor>:<product>:*:*:*:*:*:*:*:*) plus the raw vendor and product
// fields. It returns "" for anything that is not a well-formed 2.3 string with a
// non-empty vendor and product, so a malformed row is skipped rather than guessed.
func baseCPE(cpeName string) (base, vendor, product string) {
	f := splitCPE(strings.TrimSpace(cpeName))
	if len(f) != 13 || f[0] != "cpe" || f[1] != "2.3" {
		return "", "", ""
	}
	part := f[2]
	vendor, product = f[3], f[4]
	if part == "" || part == "*" || vendor == "" || vendor == "*" || product == "" || product == "*" {
		return "", "", ""
	}
	return "cpe:2.3:" + part + ":" + vendor + ":" + product + ":*:*:*:*:*:*:*:*", vendor, product
}

// splitCPE splits a CPE 2.3 string on ':' while honoring the backslash escape the spec
// uses for a literal special character, so a "\:" inside a field does not split it.
func splitCPE(s string) []string {
	var fields []string
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			cur.WriteRune(r)
			esc = true
		case r == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(fields, cur.String())
}

// pickTitle returns the English title, else the first non-empty one, else "".
func pickTitle(titles []struct {
	Title string `json:"title"`
	Lang  string `json:"lang"`
}) string {
	for _, t := range titles {
		if strings.EqualFold(t.Lang, "en") && strings.TrimSpace(t.Title) != "" {
			return strings.TrimSpace(t.Title)
		}
	}
	for _, t := range titles {
		if strings.TrimSpace(t.Title) != "" {
			return strings.TrimSpace(t.Title)
		}
	}
	return ""
}

// normWords lower-cases s and collapses every run of non-alphanumeric characters to a
// single space, so the CPE token "http_server" and the human name "HTTP Server" both
// normalize to "http server" and can be compared without fuzzy guessing.
func normWords(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			space = false
		} else if !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}
