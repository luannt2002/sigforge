// Package coverage measures what SigForge can actually answer, so a gap is counted
// instead of hidden: how much of a fingerprint DB can reach a CVE lookup or extract a
// version, and how much of one enrich run was answered versus left unanswered. Both
// are pure and offline — a gap nobody counts is a gap nobody sees.
package coverage

import (
	"sort"

	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// DBReport is the coverage of one fingerprint DB.
type DBReport struct {
	Fingerprints  int            `json:"fingerprints"`
	WithCPE       int            `json:"with_cpe"`           // attested CPE: can reach a CVE lookup
	CandidateOnly int            `json:"candidate_cpe_only"` // only a borrowed, unverified CPE: a lead, never looked up
	WithVersion   int            `json:"with_version"`       // can extract a version
	Blind         []string       `json:"no_cpe_no_version"`  // detection only: no attested CPE and no version (sorted)
	ByProvenance  map[string]int `json:"by_provenance"`
	ByLicense     map[string]int `json:"by_license"`
}

// DB measures a fingerprint DB; a nil DB reports zero coverage. An entry with no
// provenance or license is counted under "unknown" rather than dropped.
func DB(db *schema.DB) DBReport {
	r := DBReport{Blind: []string{}, ByProvenance: map[string]int{}, ByLicense: map[string]int{}}
	if db == nil {
		return r
	}
	for name, fp := range db.Fingerprints {
		r.Fingerprints++
		hasCPE := len(fp.CPE) > 0
		if hasCPE {
			r.WithCPE++
		} else if len(fp.CPECandidate) > 0 {
			r.CandidateOnly++
		}
		hasVersion := fp.CapturesVersion()
		if hasVersion {
			r.WithVersion++
		}
		if !hasCPE && !hasVersion {
			r.Blind = append(r.Blind, name)
		}
		r.ByProvenance[orUnknown(fp.Provenance)]++
		r.ByLicense[orUnknown(fp.License)]++
	}
	sort.Strings(r.Blind)
	return r
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// ResultsReport counts one enrich run by honest state. Unanswered is never clean: it
// is every result a source did not evaluate — off, failed, or an identity/version it
// could not resolve.
type ResultsReport struct {
	Total       int            `json:"total"`
	Answered    int            `json:"answered"`   // affected, potentially affected, or not affected by advisory
	Unanswered  int            `json:"unanswered"` // not_checked, source_unavailable, unknown_product, unknown_version
	ByState     map[string]int `json:"by_state"`   // every state, zeros included, so an absent state is visibly 0
	ByFreshness map[string]int `json:"by_freshness"`
}

var allStates = []unified.State{
	unified.StateNotChecked, unified.StateSourceUnavailable, unified.StateUnknownProduct,
	unified.StateUnknownVersion, unified.StatePotentiallyAffected, unified.StateAffectedByAdvisory,
	unified.StateNotAffectedByAdvisory,
}

// Results counts one enrich run.
func Results(rs []unified.Result) ResultsReport {
	r := ResultsReport{Total: len(rs), ByState: map[string]int{}, ByFreshness: map[string]int{}}
	for _, s := range allStates {
		r.ByState[s.String()] = 0
	}
	for _, res := range rs {
		r.ByState[res.State.String()]++
		r.ByFreshness[res.Freshness.String()]++
		if res.State.Answered() {
			r.Answered++
		} else {
			r.Unanswered++
		}
	}
	return r
}
