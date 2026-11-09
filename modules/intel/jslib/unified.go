package jslib

import "github.com/luannt2002/sigforge/modules/intel/unified"

// unifiedSource is this provider's source id in a unified.Result.
const unifiedSource = "jslib"

// ToUnified maps a Result into a unified.Result, keeping the honest tri-state distinct:
//
//	Resolved + leads   → affected_by_advisory     (installed version inside a published range)
//	                     potentially_affected     (no version: every advisory for the library)
//	Resolved + none    → not_checked              (the repository carries no count: a miss is never a clearance)
//	UnparsedVersion    → unknown_version          (a version was detected but is not comparable)
//	!KnownLib          → unknown_product          (the feed does not list this library — never "clean")
//
// Freshness is honest, carried by res.Live (threaded out of loadRepo): FreshnessLive when the
// repository was fetched from the operator's live URL, FreshnessSnapshot when the adapter fell open to
// the embedded Apache-2.0 snapshot (empty URL, fetch error, or junk feed). It never overstates live.
func ToUnified(res Result) unified.Result {
	freshness := unified.FreshnessSnapshot
	switch {
	case res.Stale:
		freshness = unified.FreshnessStale // the source failed: the last synced copy
	case res.Live:
		freshness = unified.FreshnessLive
	}
	u := unified.Result{
		Scope:     "jslib",
		Identity:  res.Library,
		Version:   res.Version,
		Source:    unifiedSource,
		Freshness: freshness,
	}
	switch {
	case res.Resolved && len(res.Vulns) > 0:
		// No version: resolve kept every vuln the library ever had, none pinned.
		u.State = unified.AdvisoryState(res.Version != "" && !res.Unpositioned)
		switch {
		case res.Version == "":
			u.Err = unified.NoteNoVersion
		case res.Unpositioned:
			u.Err = "a version or advisory bound is not one the npm order can compare: whether these advisories apply is unknown"
		}
		u.Leads = unifiedLeads(res.Vulns)
	case res.Resolved:
		// The repository carries no count to prove itself whole: "nothing matched" is never a clearance.
		u.State, _ = unified.Clean(unified.Evidence{FullData: false, Positioned: true})
		u.Err = "no Retire.js advisory matched; that data cannot prove itself complete, so it is not a clearance"
		if res.Sample {
			u.Err = "only the embedded Retire.js sample is in use: no advisory in it matched, which is not a clearance"
		}
	case res.UnparsedVersion:
		u.State = unified.StateUnknownVersion
	default: // !KnownLib (feed off/dead collapses here via the snapshot fallback)
		u.State = unified.StateUnknownProduct
	}
	return u
}

// unifiedLeads maps jslib leads to unified leads; Retire.js carries a qualitative severity only (no
// numeric score), so Lead.Score stays nil to keep "unscored" distinct from a real 0.0.
func unifiedLeads(leads []Lead) []unified.Lead {
	if len(leads) == 0 {
		return nil
	}
	out := make([]unified.Lead, 0, len(leads))
	for _, l := range leads {
		out = append(out, unified.Lead{
			ID:         l.ID,
			CVE:        l.CVE,
			Title:      l.Summary,
			Severity:   l.Severity,
			References: l.Info,
		})
	}
	return out
}
