// Package cve bridges a detected technology — its CPE and a (spoofable) version —
// to the known CVEs an operator-supplied CVE feed attests for that exact CPE. It is
// a NEW intel domain on top of detection and lifecycle: detection says "nginx 1.18.0
// is here", lifecycle says "is that version maintained", and cve says "the feed lists
// CVE-2021-23017 (CVSS 7.7) against cpe f5:nginx at 1.18.0".
//
// It is an NVD-CVE-API-shaped adapter: the operator supplies the API base URL (env
// SIGFORGE_SOURCE_CVE_URL or a flag) and this queries it by the CPE
// (`<base>?virtualMatchString=<cpe-with-version>`), which matches the version against
// each CVE's configured version ranges. NO URL is hardcoded; the feed is OFF by
// default; no network happens when the env is unset.
//
// Why NVD-by-CPE and not OSV: OSV is keyed by package ecosystem + package name
// (npm, PyPI, Go modules), not by CPE, so it does not answer "what CVEs apply to
// this web-tech CPE". NVD's CPE applicability is the right source for the CPE ids
// sigforge's fingerprints carry.
//
// HONESTY (the controlled part). A detected version is spoofable (a forged Server
// banner) and a CPE only tracks the vendor:product the SOURCE attested (e.g.
// f5:nginx — the query uses the CPE exactly as stored, never a guessed
// vendor:product), so every returned CVE is a LEAD to corroborate, never proof of
// exploitability. Severity and CVSS are taken verbatim from the feed, never
// fabricated. Absence is never upgraded to "safe": the tri-state State is
// StateUnknown (feed off, or no CPE to query — we did NOT check) vs StateNoKnownCVE
// (the feed WAS queried and listed nothing for this CPE+version — still not a safety
// guarantee: CPE mapping, NVD coverage and the version itself are all fallible) vs
// StateHasCVE (the feed returned one or more CVE leads). A bare "0 CVEs" is never
// emitted as "safe".
//
// Feed responses are operator-generated and never vendored into this repo — same
// posture as the fetch sources and the lifecycle feed.
package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// EnvVar is the environment variable the operator uses to supply the CVE API base
// URL (e.g. https://services.nvd.nist.gov/rest/json/cves/2.0). It mirrors the source
// adapters' and lifecycle's naming.
const EnvVar = "SIGFORGE_SOURCE_CVE_URL"

// ErrFeedOff is returned by Lookup when the feed is off (no base URL). It is a
// sentinel so a consumer (e.g. the unified adapter) can tell "feed off / not
// checked" apart from a fetch/decode failure ("source unavailable") with
// errors.Is — the two are both StateUnknown but mean different things for honesty.
var ErrFeedOff = errors.New(EnvVar + " not set: CVE feed is off (set it to the CVE API base URL; see .env.example)")

// State is the tri-state CVE verdict. The zero value is StateUnknown, so an unset
// verdict is honestly "unknown / not-checked", never a false "no CVEs = safe".
type State int

const (
	StateUnknown    State = iota // feed off, or no CPE to query — we did NOT check
	StateNoKnownCVE              // feed queried, listed no CVE for this CPE+version (NOT a safety guarantee)
	StateHasCVE                  // feed returned one or more CVE LEADs
)

func (s State) String() string {
	switch s {
	case StateNoKnownCVE:
		return "no-known-cve"
	case StateHasCVE:
		return "has-cve"
	default:
		return "unknown"
	}
}

// CVE is one known-vulnerability lead as the feed reports it. CVSS and Severity are
// the feed's own values (the highest-precedence CVSS metric present); Source is the
// feed's attribution for that metric (e.g. "nvd@nist.gov").
type CVE struct {
	ID          string
	CVSS        float64
	Severity    string
	Source      string
	CWE         string // the weakness ids NVD lists for it, comma-separated (a string keeps CVE comparable)
	Published   string // NVD's publication timestamp, as given
	Description string // NVD's English description (descriptions[lang=en]); "" when the feed gives none — never fabricated
}

// Result is one lookup's outcome. CPE is the exact CPE queried (version filled in);
// State is the honest tri-state; CVEs is non-empty only for StateHasCVE.
type Result struct {
	CPE       string
	Version   string
	State     State
	CVEs      []CVE
	Total     int       // CVEs the feed says match (totalResults); more than len(CVEs) when it returned one page
	Partial   bool      // the feed counts more matches (Total) than this page returned — results are "N of M", NOT the full/clean list
	FetchedAt time.Time // when the feed answered (UTC); zero when no fetch happened (feed off / no CPE)
}

// Adapter queries the operator-supplied CVE API base URL for a CPE's known CVEs.
type Adapter struct {
	baseURL string
	client  *fetch.Client
}

// New builds an adapter bound to the operator-supplied CVE API base URL and client.
// An empty baseURL is allowed (so a caller can report "off"); Lookup is what refuses
// to run without one.
func New(baseURL string, client *fetch.Client) *Adapter {
	return &Adapter{baseURL: strings.TrimSpace(baseURL), client: client}
}

// Lookup returns the CVE leads the feed attests for cpe at version.
//
// An empty CPE yields StateUnknown with a nil error (there is nothing to bridge — a
// legitimate "we have no CPE for this detection", honestly not-checked). A feed that
// is off yields StateUnknown with an error the operator must see. A queried feed that
// lists nothing yields StateNoKnownCVE (never "safe"); one or more leads yield
// StateHasCVE. Fetch/decode failures return StateUnknown with an error.
func (a *Adapter) Lookup(ctx context.Context, cpe, version string) (Result, error) {
	cpe = strings.TrimSpace(cpe)
	version = strings.TrimSpace(version)
	res := Result{CPE: cpe, Version: version, State: StateUnknown}
	if cpe == "" {
		return res, nil // no CPE to query → unknown, honestly (not an operator error)
	}
	query := withVersion(cpe, version)
	res.CPE = query
	if a.baseURL == "" {
		return res, ErrFeedOff
	}
	return a.fetchInto(ctx, a.baseURL+"?virtualMatchString="+url.QueryEscape(query), query, res)
}

// LookupID returns the CVE lead the feed attests for a single CVE-ID (NVD's cveId
// query). Honesty mirrors Lookup: an empty id yields StateUnknown with a nil error
// (nothing to query); a feed that is off yields StateUnknown with ErrFeedOff; a queried
// feed that lists the CVE yields StateHasCVE, one that lists nothing StateNoKnownCVE
// (never "safe"); fetch/decode failures return StateUnknown with an error.
func (a *Adapter) LookupID(ctx context.Context, id string) (Result, error) {
	id = strings.TrimSpace(id)
	res := Result{State: StateUnknown}
	if id == "" {
		return res, nil // nothing to query → unknown, honestly (not an operator error)
	}
	if a.baseURL == "" {
		return res, ErrFeedOff
	}
	return a.fetchInto(ctx, a.baseURL+"?cveId="+url.QueryEscape(id), id, res)
}

// fetchInto queries queryURL, decodes an NVD answer into res, and sets the honest
// tri-state and Partial flag; label names the lookup in errors. A fetch failure — which
// the client reports for 429/5xx/timeout too — or a decode failure leaves res
// StateUnknown with an error, never downgraded to StateNoKnownCVE ("clean").
func (a *Adapter) fetchInto(ctx context.Context, queryURL, label string, res Result) (Result, error) {
	raw, err := a.client.Get(ctx, queryURL)
	if err != nil {
		return res, fmt.Errorf("cve: fetch %q: %w", label, err)
	}
	cves, total, err := parse(raw)
	if err != nil {
		return res, fmt.Errorf("cve: %q: %w", label, err)
	}
	res.CVEs, res.Total, res.Partial = cves, total, total > len(cves)
	res.FetchedAt = time.Now().UTC()
	if len(cves) == 0 {
		res.State = StateNoKnownCVE
	} else {
		res.State = StateHasCVE
	}
	return res, nil
}

// withVersion returns cpe with its version component (field 5 of a CPE 2.3 URI)
// replaced by version, so a stored CPE whose version is a wildcard is queried at the
// detected version. The vendor:product is left EXACTLY as stored — never guessed. A
// non-CPE-2.3 string or an empty version is returned unchanged.
func withVersion(cpe, version string) string {
	if version == "" || !strings.HasPrefix(cpe, "cpe:2.3:") {
		return cpe
	}
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 { // cpe, 2.3, part, vendor, product, version, ...
		return cpe
	}
	parts[5] = version
	return strings.Join(parts, ":")
}

// nvdResponse is the slice of the NVD CVE API 2.0 response this adapter reads: the CVE id,
// its CVSS metrics, and — read leniently, a malformed one costs only itself — its weaknesses
// and publication date. Every other field (descriptions, references, configurations) is ignored.
type nvdResponse struct {
	TotalResults    *int `json:"totalResults"` // the API pages results; more than len(Vulnerabilities) ⇒ one page came back; absent ⇒ not an NVD answer
	Vulnerabilities []struct {
		CVE struct {
			ID           string          `json:"id"`
			Published    json.RawMessage `json:"published"`
			Weaknesses   json.RawMessage `json:"weaknesses"`
			Descriptions json.RawMessage `json:"descriptions"`
			Metrics      struct {
				V40 []nvdMetric `json:"cvssMetricV40"`
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdWeaknesses is the CVE's weakness ids, comma-separated; "" when the field is malformed.
func nvdWeaknesses(raw json.RawMessage) string {
	var ws []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	}
	if json.Unmarshal(raw, &ws) != nil {
		return ""
	}
	var weak []string
	for _, w := range ws {
		for _, d := range w.Description {
			weak = append(weak, d.Value)
		}
	}
	return strings.Join(unified.CWEIDs(weak), ",")
}

// nvdDescription returns the English CVE description from NVD's descriptions array; ""
// when the field is malformed or carries no English entry (never fabricated).
func nvdDescription(raw json.RawMessage) string {
	var ds []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &ds) != nil {
		return ""
	}
	for _, d := range ds {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// nvdMetric is one CVSS metric. CVSS v3/v4 carry baseSeverity inside cvssData; CVSS
// v2 carries it at the metric level — pickSeverity reads whichever is set.
type nvdMetric struct {
	Source       string `json:"source"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// Parse is the PURE decode of an NVD CVE API 2.0 response into CVE leads (no
// network). Each CVE's CVSS/Severity come from its highest-precedence metric present
// (v4.0 → v3.1 → v3.0 → v2.0); a CVE with no CVSS metric is still reported, with a
// zero CVSS and empty Severity, rather than dropped.
func Parse(raw []byte) ([]CVE, error) {
	cves, _, err := parse(raw)
	return cves, err
}

// parse is Parse plus the feed's declared total (totalResults), which Lookup keeps so a
// truncated page is reported instead of read as the complete list.
func parse(raw []byte) ([]CVE, int, error) {
	var resp nvdResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, 0, fmt.Errorf("decode cve response: %w", err)
	}
	if resp.TotalResults == nil {
		return nil, 0, errors.New("decode cve response: not an NVD CVE API answer (no totalResults)")
	}
	out := make([]CVE, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		if strings.TrimSpace(v.CVE.ID) == "" {
			continue
		}
		c := CVE{ID: v.CVE.ID, CWE: nvdWeaknesses(v.CVE.Weaknesses), Description: nvdDescription(v.CVE.Descriptions)}
		_ = json.Unmarshal(v.CVE.Published, &c.Published)
		if m, ok := pickMetric(v.CVE.Metrics.V40, v.CVE.Metrics.V31, v.CVE.Metrics.V30, v.CVE.Metrics.V2); ok {
			c.CVSS = m.CVSSData.BaseScore
			c.Severity = pickSeverity(m)
			c.Source = m.Source
		}
		out = append(out, c)
	}
	return out, *resp.TotalResults, nil
}

// pickMetric returns the first metric from the highest-precedence non-empty group.
func pickMetric(groups ...[]nvdMetric) (nvdMetric, bool) {
	for _, g := range groups {
		if len(g) > 0 {
			return g[0], true
		}
	}
	return nvdMetric{}, false
}

// pickSeverity reads baseSeverity from cvssData (v3/v4) or the metric level (v2).
func pickSeverity(m nvdMetric) string {
	if m.CVSSData.BaseSeverity != "" {
		return m.CVSSData.BaseSeverity
	}
	return m.BaseSeverity
}
