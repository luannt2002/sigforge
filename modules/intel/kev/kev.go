// Package kev prioritizes a set of CVEs by evidence of REAL-WORLD exploitation
// rather than by a bare CVSS score. It is a NEW intel domain alongside cve and
// lifecycle: cve says "CVE-2021-44228 (CVSS 10.0) applies here", kev says "that
// CVE is being actively exploited in the wild (CISA KEV) and has a 0.94 EPSS
// probability of exploitation in the next 30 days" — so it is the one to patch
// FIRST, ahead of a dormant 9.8.
//
// Two sources, each supplied by the operator as a URL (never hardcoded, off by
// default), and each kept honest about its license (§4):
//
//	KEV  — CISA's catalog of CVEs confirmed under active exploitation, with a
//	       ransomware-use flag. A U.S. Government work in the public domain, so a
//	       small sample is embedded (go:embed) as an air-gap baseline and recorded
//	       in NOTICE. The operator's SIGFORGE_SOURCE_KEV_URL upgrades it to the
//	       full live catalog.
//	EPSS — FIRST.org's probability (0..1) + percentile that a CVE is exploited
//	       within 30 days. FIRST publishes no permissive license for the data
//	       ("All Rights Reserved"), so it is OPERATOR-FETCH-ONLY via
//	       SIGFORGE_SOURCE_EPSS_URL and is NEVER vendored or embedded. Empty env
//	       means no EPSS scores, not "safe".
//
// HONESTY (the controlled part). A KEV/EPSS signal only ever RAISES priority on
// evidence; its absence is never turned into "safe". PriorityFor returns "" for
// "no standout exploitation signal", which tells the caller to keep its existing
// ranking, not that the CVE is harmless. Everything touching the network is
// FAIL-OPEN: an error, no network, or a feed that is off yields an empty signal,
// never a panic and never a blocked scan. PriorityFor, ExtractCVEs, ParseKEV and
// ParseEPSS are PURE functions (no network) for deterministic tests.
package kev

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// EnvKEVURL / EnvEPSSURL are the environment variables the operator uses to supply
// each source's URL (e.g. the CISA KEV JSON feed and the FIRST.org EPSS API). They
// mirror the other intel adapters' SIGFORGE_SOURCE_*_URL naming; both are off by
// default, so nothing goes to the network when they are unset.
const (
	EnvKEVURL  = "SIGFORGE_SOURCE_KEV_URL"
	EnvEPSSURL = "SIGFORGE_SOURCE_EPSS_URL"
)

// KEVLicense / EPSSLicense record each source's provenance so a caller can tag it.
// KEV is embeddable; EPSS is operator-fetch-only (see the package doc and §4).
const (
	KEVLicense  = "public-domain (CISA / U.S. Government work)"
	EPSSLicense = "FIRST.org EPSS — no permissive license published; operator-fetch-only, never vendored"
)

// epssBatch caps the CVEs stuffed into one EPSS request: an over-long query string
// is easily 414'd or truncated at a proxy. A scan usually yields few CVEs (one batch).
const epssBatch = 100

// Signal is the aggregated "under exploitation" signal for one CVE: the KEV flags
// (actively exploited, ransomware) merged with the EPSS score and percentile.
type Signal struct {
	CVE        string  // the CVE id, UPPER-cased
	InKEV      bool    // present in CISA KEV → confirmed exploited in the wild
	Ransomware bool    // KEV flags it as used in a ransomware campaign
	EPSS       float64 // probability of exploitation in the next 30 days, 0..1
	EPSSPct    float64 // the EPSS percentile across all CVEs, 0..1
	HasEPSS    bool    // EPSS actually returned a score for this CVE — distinguishes a real 0.0 from "no score" (nil in unified)
}

// KEVEntry is one normalized KEV row. It keeps a few descriptive fields so a caller
// can explain WHY a CVE is urgent (name, vendor, the date it entered the catalog).
type KEVEntry struct {
	CVE           string // UPPER-cased, the lookup key
	VendorProject string
	Product       string
	Name          string // vulnerabilityName
	DateAdded     string // YYYY-MM-DD, per the upstream catalog
	Ransomware    bool   // knownRansomwareCampaignUse == "Known"
}

//go:embed data/kev-snapshot.json
var kevSnapshot []byte

// kevDoc is the upstream KEV feed schema: an outer object with a vulnerabilities[]
// array. Other top-level fields (title, catalogVersion, count) are ignored.
type kevDoc struct {
	Count           *int `json:"count"` // the catalog's own entry count: what proves it whole
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// epssDoc is the FIRST.org EPSS API schema: data[] with cve/epss/percentile, where
// epss and percentile are STRINGS ("0.944210000"), not numbers — parsing them as
// numbers would unmarshal-error and drop the whole batch.
type epssDoc struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// Adapter prioritizes CVEs from the operator-supplied KEV and EPSS URLs. Either URL
// may be empty: an empty KEV URL falls back to the embedded public-domain snapshot,
// an empty EPSS URL means no EPSS scores (operator-fetch-only). The zero value is
// not ready; use New.
type Adapter struct {
	kevURL  string
	epssURL string
	client  *fetch.Client

	// shortcut: the KEV catalog loads once per Adapter, so build one Adapter per scan
	// (as callers do); a long-lived Adapter keeps its first catalog — rebuild to refresh.
	once      sync.Once
	catalog   map[string]KEVEntry
	freshness unified.Freshness
	fetchedAt time.Time
	status    CatalogStatus
	complete  bool // the live/synced catalog has as many rows as its count, one CVE id each, none repeated
}

// CatalogStatus says which KEV catalog prioritizes the leads, so a configured live
// catalog that failed (a 403, a 500, a proxy page) is visible instead of silently
// replaced by the small embedded snapshot.
type CatalogStatus struct {
	Source  string // "live" or "snapshot"
	Entries int    // KEV entries available to prioritize against
	Err     string // why the configured live catalog could not be fetched now (Cached: a stale synced copy is in use); "" otherwise
	Cached  bool   // the operator's catalog came from the local store (synced copy), not a fetch now
}

// Status loads the catalog if needed (once per Adapter, shared with every lookup) and
// reports which one is in use.
func (a *Adapter) Status(ctx context.Context) CatalogStatus {
	a.loadKEV(ctx)
	return a.status
}

// New builds an adapter bound to the operator-supplied KEV and EPSS URLs and client.
// Both URLs may be empty (the KEV snapshot still works; EPSS is simply off).
func New(kevURL, epssURL string, client *fetch.Client) *Adapter {
	return &Adapter{kevURL: strings.TrimSpace(kevURL), epssURL: strings.TrimSpace(epssURL), client: client}
}

// Enrich returns a Signal for EVERY valid CVE in cves, merging KEV (exploited +
// ransomware) with EPSS (score + percentile). There is always an entry per CVE —
// even when both sources are silent (an empty Signal) — so the caller can always
// query PriorityFor. Fail-open throughout: a dead or off source contributes nothing
// rather than erroring. Invalid / non-CVE inputs are dropped; the result is keyed by
// the UPPER-cased CVE id.
func (a *Adapter) Enrich(ctx context.Context, cves []string) map[string]Signal {
	ids := normalizeCVEs(cves)
	out := make(map[string]Signal, len(ids))
	if len(ids) == 0 {
		return out
	}
	epss := a.queryEPSS(ctx, ids) // EPSS/EPSSPct set, may be empty (off/fail-open)
	kev, _, _ := a.loadKEV(ctx)   // live catalog, or the embedded snapshot, never nil
	for _, id := range ids {
		s := epss[id] // zero-value Signal if EPSS had nothing
		s.CVE = id
		if e, ok := kev[id]; ok {
			s.InKEV = true
			s.Ransomware = e.Ransomware
		}
		out[id] = s
	}
	return out
}

// loadKEV returns the KEV lookup map, keyed by UPPER-cased CVE. It prefers the live
// catalog from the operator's URL but fails open to the embedded public-domain
// snapshot on an empty URL, a fetch error, or junk content (a proxy serving HTML),
// so an air-gapped run still recognizes the most notorious CVEs instead of going
// fully blind. It never returns nil. The second return is the data's freshness:
// Live when the operator's live catalog was used, Snapshot when it fell back to
// the embedded point-in-time baseline (so a consumer never reads it as live).
// The third return is the live catalog's fetch time (UTC), set only on the Live
// path; the embedded snapshot has no fetch time, so it stays zero, never faked.
// The catalog is fetched once per Adapter: enrich prioritizes every detection's CVE
// leads, and re-downloading the whole catalog per detection would be pure waste.
func (a *Adapter) loadKEV(ctx context.Context) (map[string]KEVEntry, unified.Freshness, time.Time) {
	a.once.Do(func() { a.catalog, a.freshness, a.fetchedAt = a.fetchKEV(ctx) })
	return a.catalog, a.freshness, a.fetchedAt
}

func (a *Adapter) fetchKEV(ctx context.Context) (map[string]KEVEntry, unified.Freshness, time.Time) {
	snap, _ := ParseKEV(kevSnapshot)
	a.status = CatalogStatus{Source: "snapshot", Entries: len(snap)}
	if a.kevURL == "" {
		return snap, unified.FreshnessSnapshot, time.Time{}
	}
	raw, meta, err := a.client.GetMeta(ctx, a.kevURL)
	if err != nil {
		a.status.Err = err.Error()
		return snap, unified.FreshnessSnapshot, time.Time{}
	}
	m, complete, err := parseKEVCatalog(raw)
	if err != nil {
		a.status.Err = "live KEV catalog unparseable: " + err.Error()
		return snap, unified.FreshnessSnapshot, time.Time{}
	}
	if len(m) == 0 {
		a.status.Err = "live KEV catalog had no entries"
		return snap, unified.FreshnessSnapshot, time.Time{}
	}
	a.status = CatalogStatus{Source: "live", Entries: len(m), Cached: meta.Cached, Err: meta.Err}
	a.complete = complete
	switch {
	case meta.Stale:
		return m, unified.FreshnessStale, meta.FetchedAt // the source failed: the last synced copy
	case meta.Cached:
		return m, unified.FreshnessSnapshot, meta.FetchedAt // the locally synced copy, as of its sync
	}
	return m, unified.FreshnessLive, meta.FetchedAt
}

// queryEPSS asks the operator's EPSS URL for scores, coalescing the CVEs into the
// fewest requests (batched by epssBatch). Thoroughly fail-open: an off URL, a fetch
// error, or bad JSON yields no scores for that batch, never a panic. The EPSS score
// set is per-scan and dynamic, so it is fetched fresh each call (no cache), matching
// the cve/lifecycle adapters. A CVE with no score is simply absent from the result.
func (a *Adapter) queryEPSS(ctx context.Context, ids []string) map[string]Signal {
	out := map[string]Signal{}
	if a.epssURL == "" || len(ids) == 0 {
		return out
	}
	for start := 0; start < len(ids); start += epssBatch {
		end := start + epssBatch
		if end > len(ids) {
			end = len(ids)
		}
		a.fetchEPSSBatch(ctx, ids[start:end], out)
	}
	return out
}

// fetchEPSSBatch fetches scores for up to epssBatch CVEs in one request
// (?cve=A,B,C) and merges what it can into out. Every error is swallowed (fail-open).
func (a *Adapter) fetchEPSSBatch(ctx context.Context, ids []string, out map[string]Signal) {
	u, err := url.Parse(a.epssURL)
	if err != nil {
		return
	}
	q := u.Query()
	q.Set("cve", strings.Join(ids, ",")) // EPSS takes many comma-separated CVEs per request
	u.RawQuery = q.Encode()

	raw, err := a.client.Get(ctx, u.String())
	if err != nil {
		return
	}
	scores, err := ParseEPSS(raw)
	if err != nil {
		return
	}
	for id, s := range scores {
		out[id] = s
	}
}

// ParseKEV is the PURE decode of a KEV feed into a lookup map keyed by UPPER-cased
// CVE (no network). A row without a valid CVE id is skipped.
func ParseKEV(b []byte) (map[string]KEVEntry, error) {
	m, _, err := parseKEVCatalog(b)
	return m, err
}

// parseKEVCatalog is ParseKEV plus whether the catalog proves itself whole: it has as many
// rows as the count it states, each row exactly one CVE id, no id repeated (a null,
// id-less, multi-id or repeated row leaves it unproven).
func parseKEVCatalog(b []byte) (map[string]KEVEntry, bool, error) {
	var doc kevDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, false, err
	}
	out := make(map[string]KEVEntry, len(doc.Vulnerabilities))
	exact := 0
	for _, r := range doc.Vulnerabilities {
		id := normalizeCVE(r.CveID)
		if id == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(r.CveID), id) {
			exact++
		}
		out[id] = KEVEntry{
			CVE:           id,
			VendorProject: strings.TrimSpace(r.VendorProject),
			Product:       strings.TrimSpace(r.Product),
			Name:          strings.TrimSpace(r.VulnerabilityName),
			DateAdded:     strings.TrimSpace(r.DateAdded),
			// Only an explicit "Known" counts as ransomware; "Unknown"/empty stays
			// false — never recklessly guess true.
			Ransomware: strings.EqualFold(strings.TrimSpace(r.KnownRansomwareCampaignUse), "Known"),
		}
	}
	rows := len(doc.Vulnerabilities)
	return out, doc.Count != nil && *doc.Count == rows && exact == rows && len(out) == rows, nil
}

// ParseEPSS is the PURE decode of a FIRST.org EPSS response into Signals carrying
// EPSS + EPSSPct, keyed by UPPER-cased CVE (no network). epss/percentile are strings
// in the JSON; a per-field parse failure is treated as 0 rather than dropping the CVE.
func ParseEPSS(b []byte) (map[string]Signal, error) {
	var doc epssDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]Signal, len(doc.Data))
	for _, d := range doc.Data {
		id := normalizeCVE(d.CVE)
		if id == "" {
			continue
		}
		epss, epssErr := strconv.ParseFloat(strings.TrimSpace(d.EPSS), 64)
		pct, _ := strconv.ParseFloat(strings.TrimSpace(d.Percentile), 64)
		// HasEPSS marks a real returned score (even 0.0) — only an unparseable
		// epss field leaves it false, so "no score" never reads as 0.0 downstream.
		out[id] = Signal{CVE: id, EPSS: epss, EPSSPct: pct, HasEPSS: epssErr == nil}
	}
	return out, nil
}

// PriorityFor is a PURE, deterministic rule (no network, table-testable):
//
//	actively exploited (KEV, incl. ransomware)                      → "P0" (patch FIRST)
//	high exploitation probability (EPSS ≥ 0.5 or percentile ≥ .95)  → "P1"
//	otherwise                                                       → ""   (keep the caller's ranking)
//
// It only RAISES priority on evidence; "" means "no standout signal", never "safe".
func PriorityFor(s Signal) string {
	if s.InKEV || s.Ransomware {
		return "P0"
	}
	if s.EPSS >= 0.5 || s.EPSSPct >= 0.95 {
		return "P1"
	}
	return ""
}

// cveRe matches a CVE id (CVE-<4-digit year>-<sequence>), case-insensitive, and is
// deliberately unanchored so it extracts a CVE EMBEDDED in a finding id such as
// "SRV-CVE-CVE-2021-23017". A "CVE-" not followed by 4 digits simply does not match.
var cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)

// ExtractCVEs pulls EVERY CVE id out of the given strings (finding ids, details),
// UPPER-cased and deduped, in first-appearance order (deterministic, stable logs).
func ExtractCVEs(texts ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range texts {
		for _, m := range cveRe.FindAllString(t, -1) {
			id := strings.ToUpper(m)
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// normalizeCVE extracts the valid CVE part from s and UPPER-cases it (FindString, so
// "SRV-CVE-CVE-2021-23017" yields "CVE-2021-23017", not the whole string). "" if none.
func normalizeCVE(s string) string {
	m := cveRe.FindString(s)
	if m == "" {
		return ""
	}
	return strings.ToUpper(m)
}

// normalizeCVEs normalizes + dedupes a list into a stable sorted order, so EPSS
// batches are deterministic across identical runs.
func normalizeCVEs(cves []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range cves {
		id := normalizeCVE(c)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
