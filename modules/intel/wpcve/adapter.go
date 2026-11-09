package wpcve

import "github.com/luannt2002/sigforge/modules/intel/unified"

// sourceID labels the unified result's origin so a consumer can group leads by
// provider. It is the module name, not a third-party vendor (the feed vendor stays
// in env, per §1).
const sourceID = "wpcve"

// ToUnified maps a PluginResult onto the one unified.Result contract so a consumer
// (ASIE, the enrich pipeline) handles every intel source the same way. The mapping
// is HONEST: each of wpcve's tri-state branches lands on its own unified.State and
// UNKNOWN is never promoted to "clean". Additive — the typed PluginResult API is
// unchanged.
//
//	Resolved + Vulns>0          → affected_by_advisory   (+ Leads; a range match, not proof)
//	  …and no version           → potentially_affected   (every advisory for the slug)
//	Resolved + Vulns empty      → not_checked (the feed carries no count: a miss is never a clearance)
//	UnparsedVersion             → unknown_version
//	feed not configured         → not_checked
//	feed errored / unreachable  → source_unavailable
//	feed lists no such slug     → unknown_product
//
// Freshness is live wherever the feed actually answered (wpcve is operator-fetch,
// never an embedded snapshot); it stays unknown when nothing was fetched.
func ToUnified(pr PluginResult) unified.Result {
	r := unified.Result{
		Scope:    scopeFor(pr.Kind),
		Identity: pr.Slug,
		Version:  pr.Version,
		Source:   sourceID,
	}
	switch {
	case pr.UnparsedVersion: // a version WAS detected but can't be compared — the feed was still reached
		r.State, r.Freshness = unified.StateUnknownVersion, unified.FreshnessLive
	case !pr.Resolved:
		switch pr.reason {
		case reasonSourceDown:
			r.State = unified.StateSourceUnavailable
		case reasonUnknownSlug:
			r.State, r.Freshness = unified.StateUnknownProduct, unified.FreshnessLive
		default: // reasonFeedOff and the no-identity early return: nothing was looked up
			r.State, r.Err = unified.StateNotChecked, "WordPress vulnerability feed off, or no slug to look up"
		}
	case len(pr.Vulns) > 0:
		// No version: lookup kept every vuln of the slug as a lead, none pinned.
		r.State, r.Freshness = unified.AdvisoryState(pr.Version != "" && !pr.Unpositioned), unified.FreshnessLive
		switch {
		case pr.Version == "":
			r.Err = unified.NoteNoVersion
		case pr.Unpositioned:
			r.Err = "an advisory bound is not a version PHP's version_compare can read: whether these advisories apply is unknown"
		}
		r.Leads = leadsFor(pr.Vulns)
	default:
		// The feed carries no count to prove its list whole: "nothing matched" is never a clearance.
		r.Freshness = unified.FreshnessLive
		r.State, _ = unified.Clean(unified.Evidence{FullData: false, Positioned: true})
		r.Err = "the WordPress vulnerability feed listed nothing for this version; it cannot prove that list complete, so it is not a clearance"
	}
	return r
}

func scopeFor(kind string) string {
	if kind == "theme" {
		return "wordpress:theme"
	}
	return "wordpress:plugin"
}

// leadsFor maps the version-range LEADs across. Severity/CVSS are passed through
// as the feed gave them; Score is a pointer that stays nil unless the feed carried
// a numeric CVSS (Severity != "" ⇔ a real score) — a missing score is never
// fabricated as 0.0 (§2).
func leadsFor(vs []Lead) []unified.Lead {
	out := make([]unified.Lead, 0, len(vs))
	for i := range vs {
		v := &vs[i]
		u := unified.Lead{
			ID:       v.ID,
			Title:    v.Title,
			Severity: v.Severity,
			CVSS:     v.CVSS,
		}
		if v.CVE != "" {
			u.CVE = []string{v.CVE}
		}
		if v.Severity != "" {
			s := v.Score
			u.Score = &s
		}
		out = append(out, u)
	}
	return out
}
