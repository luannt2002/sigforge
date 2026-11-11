package cve

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// ToUnified maps one Lookup outcome (its Result and error) into a unified.Result,
// keeping each cve verdict's exact meaning — absence is never upgraded to "clean":
//
//	feed off (ErrFeedOff)        → StateNotChecked        (we did NOT query)
//	fetch/decode error           → StateSourceUnavailable (queried, source broke)
//	StateUnknown (empty CPE)     → StateUnknownProduct    (no CPE to bridge)
//	StateNoKnownCVE              → StateNotChecked        (a paged per-query API: a miss is never a clearance)
//	StateHasCVE                  → StateAffectedByAdvisory + one Lead per CVE
//	StateHasCVE, no version      → StatePotentiallyAffected (advisories exist, none pinned)
//
// Freshness is Live for the two states that actually reached the feed; the rest
// never fetched, so it stays Unknown rather than claiming a fetch happened.
// FetchedAt carries the feed's answer time (RFC3339) only when a fetch happened;
// a zero res.FetchedAt (feed off / no CPE / error) leaves it empty, never faked.
func ToUnified(res Result, err error) unified.Result {
	u := unified.Result{Scope: "cpe", Identity: res.CPE, Version: res.Version, Source: "cve"}
	if !res.FetchedAt.IsZero() {
		u.FetchedAt = res.FetchedAt.UTC().Format(time.RFC3339)
	}
	switch {
	case errors.Is(err, ErrFeedOff):
		u.State = unified.StateNotChecked
	case err != nil:
		u.State = unified.StateSourceUnavailable
		u.Err = err.Error()
	case res.State == StateUnknown:
		u.State = unified.StateUnknownProduct
	case res.State == StateNoKnownCVE:
		// A per-query, paged API cannot prove its "no CVE" complete: never a clearance.
		u.State, _ = unified.Clean(unified.Evidence{FullData: false, Positioned: true})
		u.Err = "the CVE source listed no CVE for this CPE and version; that answer is not provably complete, so it is not a clearance"
		u.Freshness = unified.FreshnessLive
	case res.State == StateHasCVE:
		// A query with no version lists every advisory for the product.
		u.State = unified.AdvisoryState(res.Version != "")
		if res.Version == "" {
			u.Err = unified.NoteNoVersion
		}
		if res.Total > len(res.CVEs) {
			u.Err = joinNote(u.Err, fmt.Sprintf("partial: %d of %d CVEs returned (one page of a paged feed)", len(res.CVEs), res.Total))
		}
		u.Freshness = unified.FreshnessLive
		u.Leads = leadsFromCVEs(res.CVEs)
	}
	return u
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// LookupUnified is Lookup plus ToUnified — the one call a unified consumer makes.
func (a *Adapter) LookupUnified(ctx context.Context, cpe, version string) unified.Result {
	res, err := a.Lookup(ctx, cpe, version)
	return ToUnified(res, err)
}

// leadsFromCVEs passes CVSS/severity through verbatim. Score (the numeric CVSS) is
// a pointer: nil when the feed gave no metric, so "no score" never reads as a real
// 0.0. shortcut: a genuine CVSS 0.0 (severity NONE) is indistinguishable from a
// missing metric here (Parse zeroes both), so it reports no score; upgrade to a
// presence flag in cve.CVE if a NONE-severity CVE ever needs its 0.0 preserved.
func leadsFromCVEs(cves []CVE) []unified.Lead {
	out := make([]unified.Lead, 0, len(cves))
	for _, c := range cves {
		l := unified.Lead{ID: c.ID, Severity: c.Severity, CWE: unified.CWEIDs(strings.Split(c.CWE, ",")), Published: c.Published}
		if c.ID != "" {
			l.CVE = []string{c.ID}
		}
		if c.CVSS != 0 {
			l.CVSS = strconv.FormatFloat(c.CVSS, 'f', -1, 64)
			score := c.CVSS
			l.Score = &score
		}
		out = append(out, l)
	}
	return out
}
