package kev

import (
	"context"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// SignalToLead turns one CVE's exploitation signal into a unified.Lead. KnownExpl
// is KEV membership; EPSS is the probability as a *float64 that is nil when EPSS
// returned no score — so a missing EPSS is never the real 0.0 that FIRST can
// legitimately return. It goes in Lead.EPSS, never Lead.Score (CVSS, another scale).
func SignalToLead(s Signal) unified.Lead {
	l := unified.Lead{ID: s.CVE, CVE: []string{s.CVE}, KnownExpl: s.InKEV, DueDate: s.DueDate, RequiredAction: s.RequiredAction, CWE: unified.CWEIDs(strings.Split(s.CWE, ","))}
	if s.Ransomware {
		l.Title = "used in a known ransomware campaign"
	}
	if s.HasEPSS {
		epss := s.EPSS
		l.EPSS = &epss
	}
	return l
}

// MapSignal maps one CVE's signal into a unified.Result at the given freshness
// (the KEV catalog's freshness from loadKEV). kev is CVE-centric, so Scope is
// "cve" and Identity is the CVE id. State reflects the exploitation evidence —
// absence is never "safe", only "no standout signal from THIS source":
//
//	InKEV                 → StateAffectedByAdvisory (CISA confirms real-world exploitation)
//	not InKEV, has EPSS   → StatePotentiallyAffected (an EPSS probability exists; KEV does not confirm)
//	not InKEV, no EPSS    → StateNotChecked + unified.NoteNoClearance (neither source flags it: no clearance)
//
// A Lead carries the signal whenever there is one (InKEV or an EPSS score).
// fullCatalog says the KEV data is the catalog (live or synced), not the embedded sample, so
// that absence from it is a whole-data miss (still no clearance) rather than a partial one.
func MapSignal(s Signal, fresh unified.Freshness, fullCatalog bool) unified.Result {
	u := unified.Result{Scope: "cve", Identity: s.CVE, Source: "kev", Freshness: fresh}
	switch {
	case s.InKEV:
		// CVE-centric: the identity IS the CVE, so there is no product version to pin and
		// unified.AdvisoryState does not apply.
		u.State = unified.StateAffectedByAdvisory
		u.Leads = []unified.Lead{SignalToLead(s)}
	case s.HasEPSS:
		u.State = unified.StatePotentiallyAffected
		u.Leads = []unified.Lead{SignalToLead(s)}
	default:
		u.State, u.Err = unified.Clean(unified.Evidence{FullData: fullCatalog, Positioned: true})
	}
	return u
}

// EnrichUnified is Enrich mapped into unified.Results, keyed by UPPER-cased CVE.
// It carries the KEV data's real freshness (Snapshot when the live catalog was
// unavailable and the embedded baseline was used) so a consumer never reads a
// fallback snapshot as live truth. FetchedAt is the live catalog's fetch time
// (RFC3339), set only on the Live path; a snapshot run leaves it empty.
func (a *Adapter) EnrichUnified(ctx context.Context, cves []string) map[string]unified.Result {
	ids := normalizeCVEs(cves)
	out := make(map[string]unified.Result, len(ids))
	if len(ids) == 0 {
		return out
	}
	epss := a.queryEPSS(ctx, ids)
	kev, fresh, fetchedAt := a.loadKEV(ctx)
	for _, id := range ids {
		s := epss[id] // zero-value Signal (HasEPSS false) if EPSS had nothing
		s.CVE = id
		if e, ok := kev[id]; ok {
			markKEV(&s, e)
		}
		u := MapSignal(s, fresh, a.status.Source == "live" && a.complete)
		if !fetchedAt.IsZero() {
			u.FetchedAt = fetchedAt.Format(time.RFC3339)
		}
		out[id] = u
	}
	return out
}
