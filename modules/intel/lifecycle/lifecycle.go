// Package lifecycle turns a detected technology + version into an end-of-life
// LEAD: is that version still maintained, or past its vendor EOL date? This is a
// NEW intel domain on top of detection — detection says "PHP 7.2 is here",
// lifecycle says "PHP 7.2 reached EOL on 2020-11-30".
//
// It is an endoflife.date-style adapter: the operator supplies the feed's base
// URL (env SIGFORGE_SOURCE_ENDOFLIFE_URL or a flag) and this fetches a product's
// cycles JSON — [{cycle, eol (date|bool), latest, ...}]. NO URL is hardcoded; the
// feed is OFF by default.
//
// HONESTY. The reported version is whatever a scanner detected, and a detected
// version is spoofable (a forged Server header), so an EOL verdict is a LEAD to
// corroborate, never proof. Classification is honest about absence: an unknown
// product, an unknown cycle, or a feed that is off all yield StateUnknown — never
// "supported". Only a cycle with a past eol date is StateEOL; eol:false or a
// future date is StateSupported.
//
// LICENSE. endoflife.date's data + code are MIT-licensed
// (github.com/endoflife-date/endoflife.date). Only the cycle/eol/latest fields
// are consumed here; product prose (Wikipedia-derived, CC BY-SA) is not. Fetched
// feed responses are operator-generated and never vendored into this repo.
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// EnvVar is the environment variable the operator uses to supply the feed's base
// URL (e.g. https://endoflife.date/api). It mirrors the source adapters' naming.
const EnvVar = "SIGFORGE_SOURCE_ENDOFLIFE_URL"

// License is the SPDX id of the endoflife.date data this adapter consumes.
const License = "MIT"

// ErrFeedOff is returned by EOLStatus when the feed is off (no base URL) for a
// known product. It is a sentinel so a consumer can tell "feed off / not checked"
// apart from a fetch/decode failure ("source unavailable") with errors.Is.
var ErrFeedOff = errors.New(EnvVar + " not set: endoflife feed is off (set it to the feed base URL; see .env.example)")

// State is the tri-state EOL verdict. The zero value is StateUnknown, so an
// unset verdict is honestly "unknown", never a false "supported".
type State int

const (
	StateUnknown   State = iota // product unknown, cycle unmatched, or feed off — we do NOT know
	StateSupported              // in a cycle whose eol is false or a future date
	StateEOL                    // in a cycle whose eol date is in the past
)

func (s State) String() string {
	switch s {
	case StateSupported:
		return "supported"
	case StateEOL:
		return "eol"
	default:
		return "unknown"
	}
}

// Status is one lifecycle lookup's result. Cycle and EOLDate are filled only when
// a cycle matched; EOLDate is the raw feed value ("2020-11-30", or "false").
type Status struct {
	Product   string    // endoflife.date product id the tech maps to, "" if unmapped
	Version   string    // the (spoofable) detected version that was looked up
	Cycle     string    // the matched release cycle, e.g. "7.2"; "" if none matched
	EOLDate   string    // the cycle's eol field as seen in the feed; "" if none matched
	IsEOL     State     // tri-state verdict (see State)
	FetchedAt time.Time // when the feed answered (UTC); zero when no fetch happened (unmapped / feed off)
	Cached    bool      // the answer came from the locally synced bundle (a snapshot as of FetchedAt), not a fetch now
	Stale     bool      // ...because the source failed: the last synced bundle, kept past its freshness
}

// Cycle is one release line from an endoflife.date product feed. EOL is a raw
// message because the feed uses either a date string ("2020-11-30") or a bool.
type Cycle struct {
	Cycle  string          `json:"cycle"`
	EOL    json.RawMessage `json:"eol"`
	Latest string          `json:"latest,omitempty"`
}

// EnvBundleURL is the environment variable for the operator's ONE-document bundle of
// every product's cycles (the endoflife API v1 products/full). When set it replaces the
// per-product URL: one fetch per Adapter instead of one per detected product.
const EnvBundleURL = "SIGFORGE_SOURCE_ENDOFLIFE_BUNDLE_URL"

// Adapter fetches product cycles from the operator-supplied feed base URL, or from a
// bundle of every product loaded once.
type Adapter struct {
	baseURL string
	client  *fetch.Client

	bundleURL string
	once      sync.Once
	bundle    map[string][]Cycle
	byCPE     map[string]string // cpe vendor:product → product; "" when two products share it
	bundleAt  time.Time
	bundleHit bool // the bundle came from the local store (a synced snapshot)
	bundleOld bool // ...because the source failed: a stale copy
	bundleErr error
}

// New builds an adapter bound to the operator-supplied feed base URL and client.
// An empty baseURL is allowed here (so a caller can report "off"); EOLStatus is
// what refuses to run without one.
func New(baseURL string, client *fetch.Client) *Adapter {
	return &Adapter{baseURL: strings.TrimSpace(baseURL), client: client}
}

// NewBundle builds an adapter that loads the operator-supplied bundle once and serves
// every product from it.
func NewBundle(bundleURL string, client *fetch.Client) *Adapter {
	return &Adapter{bundleURL: strings.TrimSpace(bundleURL), client: client}
}

// EOLStatus maps tech→product, fetches that product's cycles from the feed, and
// classifies version against them as of now.
//
// It returns StateUnknown (and a nil error) for an unmapped tech or an unmatched
// cycle — legitimate "we don't track this" answers. It returns an error (with
// StateUnknown) when the feed is off or the fetch/decode fails — operational
// problems the operator must see. It never reports StateSupported on absence.
func (a *Adapter) EOLStatus(ctx context.Context, tech, version string) (Status, error) {
	st := Status{Version: version, IsEOL: StateUnknown}
	product, ok := ProductFor(tech)
	if !ok {
		return st, nil // unknown product → unknown, honestly
	}
	st.Product = product
	if a.bundleURL != "" {
		return a.fromBundle(ctx, st, product, version)
	}
	if a.baseURL == "" {
		return st, ErrFeedOff
	}
	url := strings.TrimRight(a.baseURL, "/") + "/" + product + ".json"
	raw, err := a.client.Get(ctx, url)
	if err != nil {
		return st, fmt.Errorf("lifecycle: fetch %q: %w", product, err)
	}
	cycles, err := ParseCycles(raw)
	if err != nil {
		return st, fmt.Errorf("lifecycle: %q: %w", product, err)
	}
	now := time.Now()
	st.Cycle, st.EOLDate, st.IsEOL = Classify(cycles, version, now)
	st.FetchedAt = now.UTC()
	return st, nil
}

// ParseCycles decodes an endoflife.date product feed (a JSON array of cycles).
func ParseCycles(raw []byte) ([]Cycle, error) {
	var cycles []Cycle
	if err := json.Unmarshal(raw, &cycles); err != nil {
		return nil, fmt.Errorf("decode cycles: %w", err)
	}
	return cycles, nil
}

// EOLStatusByCPE resolves the product from a CPE instead of the tech name: with the bundle,
// every product whose identifiers list that CPE's vendor:product is covered — far beyond
// the hand-kept name map. A CPE two products share stays unknown (no guess), and the
// per-product feed has no identifiers, so it always answers unknown.
func (a *Adapter) EOLStatusByCPE(ctx context.Context, cpe, version string) (Status, error) {
	st := Status{Version: version, IsEOL: StateUnknown}
	if a.bundleURL == "" {
		return st, nil
	}
	a.once.Do(func() { a.loadBundle(ctx) })
	if a.bundleErr != nil {
		return st, a.bundleErr
	}
	product := a.byCPE[cpeVendorProduct(cpe)]
	if product == "" {
		return st, nil
	}
	return a.fromBundle(ctx, st, product, version)
}

// fromBundle classifies version against product's cycles in the bundle. A failed bundle is
// remembered for the Adapter's life: falling back to one request per product would turn
// one failure into N requests.
func (a *Adapter) fromBundle(ctx context.Context, st Status, product, version string) (Status, error) {
	a.once.Do(func() { a.loadBundle(ctx) })
	if a.bundleErr != nil {
		return st, a.bundleErr
	}
	cycles, ok := a.bundle[product]
	if !ok {
		st.Product = "" // the feed does not track it: unknown product, never "supported"
		return st, nil
	}
	st.Product = product
	st.Cycle, st.EOLDate, st.IsEOL = Classify(cycles, version, time.Now())
	st.FetchedAt, st.Cached, st.Stale = a.bundleAt, a.bundleHit, a.bundleOld
	return st, nil
}

func (a *Adapter) loadBundle(ctx context.Context) {
	raw, meta, err := a.client.GetMeta(ctx, a.bundleURL)
	if err != nil {
		a.bundleErr = fmt.Errorf("lifecycle: fetch bundle: %w", err)
		return
	}
	a.bundle, a.byCPE, err = parseBundle(raw)
	if err != nil {
		a.bundleErr = fmt.Errorf("lifecycle: bundle: %w", err)
		return
	}
	a.bundleAt, a.bundleHit, a.bundleOld = meta.FetchedAt, meta.Cached, meta.Stale
}

// cpeVendorProduct is the "vendor:product" of a CPE 2.3 string, "" if it is not one.
func cpeVendorProduct(cpe string) string {
	f := strings.Split(cpe, ":")
	if len(f) < 5 || f[0] != "cpe" || f[3] == "" || f[4] == "" {
		return ""
	}
	return strings.ToLower(f[3] + ":" + f[4])
}

// ParseBundle decodes the endoflife API v1 bundle (products/full) into the same
// per-product cycles ParseCycles yields, so Classify is unchanged: a release name is the
// cycle, eolFrom (a date) — or isEol when there is no date, or when the date would reopen a
// release isEol says has ended — is the eol value (neither stated: unknown), and
// latest.name is the latest version. Checked 06/11/2026 against the per-product API for
// nginx, php and wordpress: every release name and eol value matched.
func ParseBundle(raw []byte) (map[string][]Cycle, error) {
	cycles, _, err := parseBundle(raw)
	return cycles, err
}

// parseBundle is ParseBundle plus the CPE index: each product's cpe identifiers by
// vendor:product, with "" marking one that two products share.
func parseBundle(raw []byte) (map[string][]Cycle, map[string]string, error) {
	var doc struct {
		Result []struct {
			Name        string `json:"name"`
			Identifiers []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"identifiers"`
			Releases []struct {
				Name    string  `json:"name"`
				IsEol   *bool   `json:"isEol"`
				EolFrom *string `json:"eolFrom"`
				Latest  *struct {
					Name string `json:"name"`
				} `json:"latest"`
			} `json:"releases"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("decode endoflife bundle: %w", err)
	}
	if len(doc.Result) == 0 {
		return nil, nil, errors.New("endoflife bundle lists no products")
	}
	out := make(map[string][]Cycle, len(doc.Result))
	byCPE := map[string]string{}
	for _, p := range doc.Result {
		name := strings.ToLower(visible(p.Name)) // one product listed under names differing in case is one product
		cycles := make([]Cycle, 0, len(p.Releases))
		for _, r := range p.Releases {
			eol := json.RawMessage("null") // a release stating neither is unknown, never supported
			if r.IsEol != nil {
				eol, _ = json.Marshal(*r.IsEol)
			}
			if r.EolFrom != nil {
				date, _ := json.Marshal(*r.EolFrom)
				// the date decides, unless it would reopen a release the feed says has ended
				if r.IsEol == nil || !*r.IsEol || judgeEOL(date, time.Now()) == StateEOL {
					eol = date
				}
			}
			c := Cycle{Cycle: r.Name, EOL: eol}
			if r.Latest != nil {
				c.Latest = r.Latest.Name
			}
			cycles = append(cycles, c)
		}
		out[name] = append(out[name], cycles...) // a product listed twice: a release its lists disagree on is unknown
		for _, id := range p.Identifiers {
			vp := cpeVendorProduct(id.ID)
			if id.Type != "cpe" || vp == "" {
				continue
			}
			if prev, seen := byCPE[vp]; seen && prev != name {
				byCPE[vp] = "" // shared by two products: ambiguous, never guessed
			} else {
				byCPE[vp] = name
			}
		}
	}
	return out, byCPE, nil
}

// Classify is the PURE EOL decision (no network): it finds the cycle that version
// belongs to and judges its eol field as of now. A version belongs to a cycle
// when it equals the cycle or begins with "<cycle>." (endoflife cycles are version
// prefixes, e.g. "7.2" owns "7.2.34"); of the cycles it belongs to, the longest is its
// own — a feed lists a coarse line ("2") beside its sub-lines ("2.346"). StateUnknown
// when nothing matches, the eol value is uninterpretable, one cycle is listed twice
// with opposite verdicts, or a supported cycle does not vouch for its other versions
// (see vouches).
func Classify(cycles []Cycle, version string, now time.Time) (cycle, eolDate string, state State) {
	version = cycleName(version) // in the same form as the cycles it is compared with
	var own *Cycle
	ownName := ""
	for i := range cycles {
		c, name := &cycles[i], cycleName(cycles[i].Cycle)
		switch {
		case !versionInCycle(version, name):
		case own == nil || len(name) > len(ownName):
			own, ownName = c, name
		case name == ownName && judgeEOL(c.EOL, now) != judgeEOL(own.EOL, now):
			return "", "", StateUnknown
		}
	}
	if own == nil {
		return "", "", StateUnknown
	}
	state = judgeEOL(own.EOL, now)
	if state == StateSupported && !vouches(cycles, ownName) {
		state = StateUnknown
	}
	return ownName, string(trimQuotes(own.EOL)), state
}

// vouches reports whether a supported cycle's verdict covers its other versions: not when
// it has sub-lines of its own (a coarse line whose sub-lines end on their own), nor when a
// row of the list could not be read (a nameless row could be such a sub-line).
func vouches(cycles []Cycle, cycle string) bool {
	for _, c := range cycles {
		if name := cycleName(c.Cycle); name == "" || strings.HasPrefix(name, cycle+".") {
			return false
		}
	}
	return true
}

// cycleName is a cycle as a version prefix: visible, a decimal comma read as a dot, without a
// "v" or "V" before a digit.
func cycleName(cycle string) string {
	cycle = strings.ReplaceAll(visible(cycle), ",", ".")
	if len(cycle) > 1 && (cycle[0] == 'v' || cycle[0] == 'V') && cycle[1] >= '0' && cycle[1] <= '9' {
		return cycle[1:]
	}
	return cycle
}

// visible is s trimmed and without format characters (zero-width space, BOM) that hand-edited data carries unseen.
func visible(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s))
}

func versionInCycle(version, cycle string) bool {
	if version == "" || cycle == "" {
		return false
	}
	return version == cycle || strings.HasPrefix(version, cycle+".")
}

// judgeEOL interprets the eol field: bool false → supported, bool true → eol, a
// date past now → eol, a future/today date → supported, anything else → unknown.
func judgeEOL(raw json.RawMessage, now time.Time) State {
	s := strings.TrimSpace(string(raw))
	switch s {
	case "false":
		return StateSupported
	case "true":
		return StateEOL
	case "", "null":
		return StateUnknown
	}
	date := string(trimQuotes(raw))
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return StateUnknown
	}
	if t.Before(now.UTC().Truncate(24 * time.Hour)) {
		return StateEOL
	}
	return StateSupported
}

// trimQuotes strips surrounding JSON quotes from a raw scalar, so a date string
// is reported without its quotes and a bare bool is reported as-is.
func trimQuotes(raw json.RawMessage) []byte {
	s := string(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return []byte(s[1 : len(s)-1])
	}
	return raw
}
