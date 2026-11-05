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
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// EnvVar is the environment variable the operator uses to supply the feed's base
// URL (e.g. https://endoflife.date/api). It mirrors the source adapters' naming.
const EnvVar = "SIGFORGE_SOURCE_ENDOFLIFE_URL"

// License is the SPDX id of the endoflife.date data this adapter consumes.
const License = "MIT"

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
	Product string // endoflife.date product id the tech maps to, "" if unmapped
	Version string // the (spoofable) detected version that was looked up
	Cycle   string // the matched release cycle, e.g. "7.2"; "" if none matched
	EOLDate string // the cycle's eol field as seen in the feed; "" if none matched
	IsEOL   State  // tri-state verdict (see State)
}

// Cycle is one release line from an endoflife.date product feed. EOL is a raw
// message because the feed uses either a date string ("2020-11-30") or a bool.
type Cycle struct {
	Cycle  string          `json:"cycle"`
	EOL    json.RawMessage `json:"eol"`
	Latest string          `json:"latest,omitempty"`
}

// Adapter fetches product cycles from the operator-supplied feed base URL.
type Adapter struct {
	baseURL string
	client  *fetch.Client
}

// New builds an adapter bound to the operator-supplied feed base URL and client.
// An empty baseURL is allowed here (so a caller can report "off"); EOLStatus is
// what refuses to run without one.
func New(baseURL string, client *fetch.Client) *Adapter {
	return &Adapter{baseURL: strings.TrimSpace(baseURL), client: client}
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
	if a.baseURL == "" {
		return st, errors.New(EnvVar + " not set: endoflife feed is off (set it to the feed base URL, e.g. https://endoflife.date/api)")
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
	st.Cycle, st.EOLDate, st.IsEOL = Classify(cycles, version, time.Now())
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

// Classify is the PURE EOL decision (no network): it finds the cycle that version
// belongs to and judges its eol field as of now. A version belongs to a cycle
// when it equals the cycle or begins with "<cycle>." (endoflife cycles are version
// prefixes, e.g. "7.2" owns "7.2.34"). No match, or an uninterpretable eol value,
// yields StateUnknown.
func Classify(cycles []Cycle, version string, now time.Time) (cycle, eolDate string, state State) {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	for _, c := range cycles {
		if !versionInCycle(version, c.Cycle) {
			continue
		}
		return c.Cycle, string(trimQuotes(c.EOL)), judgeEOL(c.EOL, now)
	}
	return "", "", StateUnknown
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
