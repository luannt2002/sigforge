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
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// EnvCPEDictURL is the environment variable the operator uses to supply the NVD CPE
// dictionary URL (the "products" feed of the NVD 2.0 API). It mirrors the other intel
// adapters' SIGFORGE_SOURCE_*_URL naming and is off by default, so nothing goes to the
// network when it is unset — the embedded public-domain sample is used instead. The URL
// must serve the whole dictionary as one document: one page of the paged API is partial,
// and a partial dictionary never verifies.
const EnvCPEDictURL = "SIGFORGE_SOURCE_CPE_DICT_URL"

// maxDictBytes caps the downloaded dictionary on disk, guarding it against a runaway
// endpoint. The file is reduced row by row, so this is a disk ceiling, not a memory one.
// A var so a test can lower it.
var maxDictBytes int64 = 2 << 30

// dictDownloadLimit bounds the dictionary download end to end: a streamed download is not
// covered by the client's own timeout, which is sized for small catalogs.
const dictDownloadLimit = 10 * time.Minute

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

// cpeProduct is one row of the NVD 2.0 CPE API schema's products[]: a cpe object with its
// cpeName, a deprecated flag, and localized titles. Other fields are ignored.
type cpeProduct struct {
	CPE struct {
		CPEName    string `json:"cpeName"`
		Deprecated bool   `json:"deprecated"`
		Titles     []struct {
			Title string `json:"title"`
			Lang  string `json:"lang"`
		} `json:"titles"`
	} `json:"cpe"`
}

// Resolver resolves a tech to a verified CPE against the operator-supplied dictionary
// URL, falling back to the embedded public-domain sample. The zero value is not ready;
// use New.
type Resolver struct {
	dictURL string
	client  *fetch.Client

	// shortcut: the dictionary loads once per Resolver and a failed live load stays on
	// the snapshot for the Resolver's lifetime (visible in Status); build a new Resolver
	// to retry.
	once    sync.Once
	entries []Entry
	status  DictStatus
}

// DictStatus says which dictionary ResolveCPE matches against, so a configured live
// dictionary that failed — or delivered only one page of a paged feed — is visible
// instead of silently degrading every resolution to the small embedded sample.
type DictStatus struct {
	Source   string // "live" or "snapshot"
	Entries  int    // distinct vendor:product bases available to Match
	Products int    // product rows the feed delivered (before collapsing versions)
	Total    int    // product rows the feed says exist (totalResults); 0 when it does not say
	Err      string // why the configured live dictionary could not be fetched now (Cached: a stale synced copy is in use); "" otherwise
	Cached   bool   // the operator's dictionary came from the local store (synced copy), not a fetch now
}

// Partial reports that the feed delivered fewer products than it says exist — one page
// of the paged NVD API, not the whole dictionary. ResolveCPE never verifies against it, and
// the resolver does not walk the pages: the whole dictionary is one document the operator
// mirrors, not a run's worth of requests to a rate-limited API.
func (s DictStatus) Partial() bool { return s.Total > s.Products }

// New builds a resolver bound to the operator-supplied CPE dictionary URL and client.
// The URL may be empty (the embedded public-domain sample is then used).
func New(dictURL string, client *fetch.Client) *Resolver {
	return &Resolver{dictURL: strings.TrimSpace(dictURL), client: client}
}

// Status loads the dictionary if it is not loaded yet and reports which one is in use.
func (r *Resolver) Status(ctx context.Context) DictStatus {
	r.once.Do(func() { r.load(ctx) })
	return r.status
}

// ResolveCPE resolves (name / vendor / product) to a VERIFIED CPE or Unknown. When
// vendor and product are both given they are the match key; otherwise name is matched
// against the dictionary's "vendor product" and "product" token forms. It returns a
// version-wildcarded CPE and the matching dictionary title ONLY when exactly one
// distinct vendor:product base matches — never a CPE built from the inputs. Fail-open:
// a dead/off dictionary uses the embedded sample, so a tech the sample does not know
// still returns Unknown rather than erroring.
func (r *Resolver) ResolveCPE(ctx context.Context, name, vendor, product string) (cpe string, evidence string, state State) {
	r.once.Do(func() { r.load(ctx) })
	cpe, evidence, state = Match(r.entries, name, vendor, product)
	if state == StateVerified && (r.status.Source != "live" || r.status.Partial()) {
		return "", "", StateUnknown // the embedded sample or one page is not the dictionary: a unique match there proves nothing
	}
	return cpe, evidence, state
}

// load fills entries and status, preferring the operator's live feed but failing open
// to the embedded public-domain sample on an empty URL, a fetch error, or junk content
// (a proxy serving HTML) — and recording why in status instead of hiding it.
func (r *Resolver) load(ctx context.Context) {
	snap, products, total, _ := parseDict(bytes.NewReader(cpeSnapshot))
	r.entries = snap
	r.status = DictStatus{Source: "snapshot", Entries: len(snap), Products: products, Total: total}
	if r.dictURL == "" {
		return
	}
	dctx, cancel := context.WithTimeout(ctx, dictDownloadLimit)
	defer cancel()
	var read *dictFile // what the store's check read, so a file it accepted is not decoded twice
	path, meta, release, err := r.client.DownloadChecked(dctx, r.dictURL, maxDictBytes, func(p string) error {
		d, err := readDictFile(p)
		read = &d
		return err
	})
	defer release()
	if err == nil && (read == nil || meta.Stale) { // a stored copy served without the check, or kept over a refused one
		d, derr := readDictFile(path)
		read, err = &d, derr
	}
	if err != nil {
		r.status.Err = err.Error()
		return
	}
	r.entries = read.entries
	r.status = DictStatus{Source: "live", Entries: len(read.entries), Products: read.products, Total: read.total, Cached: meta.Cached, Err: meta.Err}
}

// dictFile is a dictionary as the resolver reads it.
type dictFile struct {
	entries         []Entry
	products, total int
}

// readDictFile decodes the dictionary at path as it reads it; one the parser refuses, or that lists no usable
// CPE entry (the rule sync applies too), is an error.
func readDictFile(path string) (dictFile, error) {
	var d dictFile
	f, err := os.Open(path)
	if err != nil {
		return d, err
	}
	defer f.Close()
	d.entries, d.products, d.total, err = parseDict(f)
	if err != nil {
		return d, fmt.Errorf("live dictionary unparseable: %w", err)
	}
	if len(d.entries) == 0 {
		return d, errors.New("live dictionary had no usable CPE entries")
	}
	return d, nil
}

// ParseDict is the PURE decode of an NVD CPE dictionary feed into version-agnostic
// Entry bases keyed by vendor:product (no network). Deprecated entries and rows whose
// cpeName is not a well-formed CPE 2.3 string are skipped; multiple versioned CPEs for
// one product collapse to a single base, keeping the first English title as evidence.
// The result is sorted by CPE for deterministic tests and logs.
func ParseDict(b []byte) ([]Entry, error) {
	e, _, _, err := parseDict(bytes.NewReader(b))
	return e, err
}

// ReadDict is ParseDict over a reader, decoded as it is read — the way the resolver loads a
// dictionary too large for memory — so a caller can check one without holding it whole.
func ReadDict(r io.Reader) ([]Entry, error) {
	e, _, _, err := parseDict(r)
	return e, err
}

// parseDict is ParseDict over a reader, plus the feed's delivered and declared product
// counts, which Status needs to tell one page of a paged feed from the whole dictionary.
// It walks the document token by token so only one product row is in memory at a time.
func parseDict(rd io.Reader) (entries []Entry, products, total int, err error) {
	dec := json.NewDecoder(rd)
	byBase := make(map[string]Entry)
	if err := delim(dec, '{'); err != nil {
		return nil, 0, 0, err
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, 0, 0, err
		}
		switch key {
		case "totalResults": // products the feed says exist; more than it delivered on one page of a paged feed
			err = dec.Decode(&total)
		case "products":
			err = delim(dec, '[')
			for err == nil && dec.More() {
				var p cpeProduct
				if err = dec.Decode(&p); err == nil {
					products++
					addBase(byBase, p)
				}
			}
			if err == nil {
				err = delim(dec, ']')
			}
		default:
			var skip json.RawMessage
			err = dec.Decode(&skip)
		}
		if err != nil {
			return nil, 0, 0, err
		}
	}
	if err := delim(dec, '}'); err != nil {
		return nil, 0, 0, err // a body cut short is not a smaller dictionary
	}
	out := make([]Entry, 0, len(byBase))
	for _, e := range byBase {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CPE < out[j].CPE })
	return out, products, total, nil
}

// addBase records p's vendor:product base unless p is deprecated, malformed, or a later
// versioned row of a base already seen (the first title wins).
func addBase(byBase map[string]Entry, p cpeProduct) {
	if p.CPE.Deprecated {
		return
	}
	base, vendor, product := baseCPE(p.CPE.CPEName)
	if base == "" {
		return
	}
	if _, seen := byBase[base]; !seen {
		byBase[base] = Entry{CPE: base, Vendor: vendor, Product: product, Title: pickTitle(p.CPE.Titles)}
	}
}

// delim reads the next token and fails unless it is want.
func delim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != want {
		return fmt.Errorf("want %v, got %v", want, tok)
	}
	return nil
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
