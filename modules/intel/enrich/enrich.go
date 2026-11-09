// Package enrich composes the breadth layer (matcher detections) with the depth
// layers (cve + lifecycle lookups) into one EnrichedDetection per technology. It is
// PURE composition: the depth lookups are INJECTED as providers, so a caller wires
// the real operator-gated adapters and a test wires fakes — no network lives here.
//
// HONESTY carries through from the layers it composes. The depth providers are
// operator-gated and may be nil (feed off); when a provider is nil the matching
// field stays its zero/UNKNOWN value — never a fabricated "no CVE = safe" or
// "supported". A detected version is spoofable, so every CVE/EOL field is a LEAD to
// corroborate, not proof. Corroboration is surfaced directly: Provenance is the set
// of DISTINCT sources that attested the tech, so len(Provenance) >= 2 means more than
// one independent source agreed.
package enrich

import (
	"context"
	"strings"

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// EnrichedDetection is one technology with its breadth (tech/version/confidence/
// provenance/categories) and depth (cpe/cves/eol) intel joined. Provenance holds the
// distinct sources that attested the tech (its count is the corroboration). CVEs is
// nil when the CVE provider is off or attested nothing — nil is "no leads attached",
// NOT a safety claim. EOL carries its own tri-state (lifecycle.StateUnknown when the
// feed is off), so absence there is honest too.
type EnrichedDetection struct {
	Tech       string
	Version    string
	Confidence int
	Provenance []string
	Categories []int
	CPE        []string
	CVEs       []cve.CVE
	EOL        lifecycle.Status
}

// CVEProvider is the depth hook into the CVE domain; *cve.Adapter satisfies it.
type CVEProvider interface {
	Lookup(ctx context.Context, cpe, version string) (cve.Result, error)
}

// EOLProvider is the depth hook into the lifecycle domain; *lifecycle.Adapter
// satisfies it.
type EOLProvider interface {
	EOLStatus(ctx context.Context, tech, version string) (lifecycle.Status, error)
}

// KEVProvider is the prioritization hook: given CVE ids it returns an exploitation
// signal (CISA KEV membership, EPSS) per id, keyed by UPPER-cased CVE. *kev.Adapter
// satisfies it. nil means "no prioritization" — leads pass through unranked, never
// dropped.
type KEVProvider interface {
	EnrichUnified(ctx context.Context, cves []string) map[string]unified.Result
}

// IdentityResolver resolves a tech to a dictionary-VERIFIED CPE. *identity.Resolver's
// ResolveCPE method satisfies it directly. nil means identity resolution is off: the
// pipeline falls back to the source-attested CPE on the fingerprint.
type IdentityResolver func(ctx context.Context, name, vendor, product string) (cpe, evidence string, state identity.State)

// OSVLookup bridges an ecosystem package to its unified result. An operator wraps
// osv.LoadIndex + Index.Lookup + osv.ToUnified into this closure, so enrich stays pure
// (no network). nil = the OSV feed is off: a dispatched package yields StateNotChecked.
type OSVLookup func(ctx context.Context, ecosystem, name, version string) unified.Result

// WPLookup bridges a WordPress plugin/theme slug to its unified result (operator wraps
// the wpcve provider + wpcve.ToUnified). kind is "plugin" (default) or "theme". nil = off.
type WPLookup func(ctx context.Context, slug, version, kind string) unified.Result

// JSLookup bridges a JS library to its unified result (operator wraps the jslib adapter
// + jslib.ToUnified). nil = off.
type JSLookup func(ctx context.Context, name, version string) unified.Result

// Options carries the operator-gated depth providers. A nil provider means that
// depth layer is OFF: its field stays UNKNOWN rather than being fabricated. The
// IdentityResolver, KEV and the OSV/WP/JS dispatch hooks are additive — EnrichUnified /
// EnrichUnifiedExt use them; the older Enrich ignores them, so existing callers are
// unaffected.
type Options struct {
	CVE              CVEProvider
	EOL              EOLProvider
	IdentityResolver IdentityResolver
	KEV              KEVProvider
	OSV              OSVLookup
	WP               WPLookup
	JS               JSLookup
}

// PkgRef is one ecosystem package to dispatch to OSV (operator/ASIE supplied, not
// page-derived). WPRef / LibRef are the WordPress and JS equivalents.
type PkgRef struct {
	Ecosystem string
	Name      string
	Version   string
}

type WPRef struct {
	Slug    string
	Version string
	Kind    string // "plugin" (default) or "theme"
}

type LibRef struct {
	Name    string
	Version string
}

// EnrichInput carries the identities an operator/ASIE supplies out-of-band (not from the
// page): packages to look up in OSV, WordPress slugs in wpcve, JS libraries in jslib.
type EnrichInput struct {
	Packages []PkgRef
	WPSlugs  []WPRef
	JSLibs   []LibRef
}

type agg struct {
	conf    int
	version string
	cats    []int
	provs   []string
}

// Enrich joins detections with depth intel. Detections are grouped by tech (a tech
// attested by several sources collapses into one result whose Provenance records
// each), CPE/categories are taken from the DB entry, and — only when the matching
// provider is set — CVE and EOL leads are attached. Provider errors (feed off, fetch
// failure) leave the field UNKNOWN, honestly, rather than failing the whole run.
func Enrich(ctx context.Context, dets []matcher.Detection, db *schema.DB, opt Options) []EnrichedDetection {
	order := make([]string, 0, len(dets))
	groups := make(map[string]*agg, len(dets))
	for _, d := range dets {
		g := groups[d.Tech]
		if g == nil {
			g = &agg{cats: d.Categories}
			groups[d.Tech] = g
			order = append(order, d.Tech)
		}
		if d.Confidence > g.conf {
			g.conf = d.Confidence
			g.cats = d.Categories
		}
		if len(d.Version) > len(g.version) {
			g.version = d.Version
		}
		if d.Provenance != "" {
			g.provs = appendDistinct(g.provs, d.Provenance)
		}
	}

	out := make([]EnrichedDetection, 0, len(order))
	for _, tech := range order {
		g := groups[tech]
		ed := EnrichedDetection{
			Tech:       tech,
			Version:    g.version,
			Confidence: g.conf,
			Categories: g.cats,
			Provenance: g.provs,
		}
		if db != nil {
			if fp, ok := db.Fingerprints[tech]; ok {
				ed.CPE = fp.CPE
				if len(fp.Cats) > 0 {
					ed.Categories = fp.Cats
				}
				if fp.Provenance != "" {
					ed.Provenance = appendDistinct(ed.Provenance, fp.Provenance)
				}
			}
		}
		if opt.CVE != nil {
			for _, cpe := range ed.CPE {
				res, _ := opt.CVE.Lookup(ctx, cpe, ed.Version) // error → no leads, field stays UNKNOWN
				ed.CVEs = append(ed.CVEs, res.CVEs...)
			}
		}
		if opt.EOL != nil {
			ed.EOL, _ = opt.EOL.EOLStatus(ctx, tech, ed.Version) // error → Status stays StateUnknown
		}
		out = append(out, ed)
	}
	return out
}

// EnrichUnified runs the full depth pipeline per Detection and emits the unified
// result shape every consumer (ASIE, a report) reads: one "cpe"-scoped CVE result
// (per queried CPE) and one "eol"-scoped result per detection. It is PURE — every
// source is INJECTED through Options, so no network lives here; a provider that is
// off/absent yields StateNotChecked, never a fabricated "clean".
//
// Honesty carries through unchanged: a CVE/EOL advisory match is a LEAD on a
// spoofable version, never proof. When Detection.VersionConflict is set the version
// cannot be pinned: an advisory HIT is downgraded to potentially-affected and a clean
// answer — none in v0.4 — to unknown_version (only one claimed version was asked). The CPE
// fed to CVE lookup is a dictionary-VERIFIED identity when the IdentityResolver
// confirms one, else the source-ATTESTED fingerprint CPE; an unverified CPECandidate
// is NEVER used (identity contamination).
func EnrichUnified(ctx context.Context, dets []matcher.Detection, db *schema.DB, opt Options) []unified.Result {
	out := make([]unified.Result, 0, len(dets)*2)
	for _, d := range dets {
		from := len(out)
		cpes, cpeState, cpeEvidence := resolveCPEs(ctx, d, db, opt)
		out = append(out, cveResults(ctx, d, cpes, cpeState, cpeEvidence, opt)...)
		out = append(out, eolResult(ctx, d, cpes, opt))
		if opt.JS != nil && isJSLib(db, d.Tech) {
			out = append(out, applyVersionConflict(dispatchJS(ctx, LibRef{Name: d.Tech, Version: d.Version}, opt), d))
		}
		for i := from; i < len(out); i++ {
			out[i].Tech = d.Tech
		}
	}
	return prioritize(ctx, out, opt)
}

// jsCategories are the fingerprint categories (Wappalyzer numbering) of client-side
// JavaScript — frameworks (12), libraries (59), UI frameworks (66): the techs a JS
// advisory source tracks. Chosen by category, not by name, so every JS library a DB
// knows is looked up.
var jsCategories = map[int]bool{12: true, 59: true, 66: true}

func isJSLib(db *schema.DB, tech string) bool {
	if db == nil {
		return false
	}
	for _, c := range db.Fingerprints[tech].Cats {
		if jsCategories[c] {
			return true
		}
	}
	return false
}

// EnrichUnifiedExt is EnrichUnified plus the operator/ASIE-supplied identities that do
// NOT come from the page: each package/slug/lib is dispatched to its provider (OSV/WP/JS)
// and the unified results are appended. It is PURE — every provider is INJECTED through
// Options; a nil hook means that feed is OFF, so its dispatch yields StateNotChecked
// (unknown, never a fabricated "clean"). The detection half is unchanged, so callers that
// only pass detections get exactly EnrichUnified's output.
func EnrichUnifiedExt(ctx context.Context, dets []matcher.Detection, db *schema.DB, inp EnrichInput, opt Options) []unified.Result {
	out := EnrichUnified(ctx, dets, db, opt)
	seenJS := map[string]bool{} // a library the page already revealed is not looked up again
	for _, d := range dets {
		if opt.JS != nil && isJSLib(db, d.Tech) {
			seenJS[strings.ToLower(d.Tech)+"@"+d.Version] = true
		}
	}
	for _, p := range inp.Packages {
		out = append(out, dispatchOSV(ctx, p, opt))
	}
	for _, w := range inp.WPSlugs {
		out = append(out, dispatchWP(ctx, w, opt))
	}
	for _, l := range inp.JSLibs {
		if seenJS[strings.ToLower(l.Name)+"@"+l.Version] {
			continue
		}
		out = append(out, dispatchJS(ctx, l, opt))
	}
	return out
}

func dispatchOSV(ctx context.Context, p PkgRef, opt Options) unified.Result {
	if opt.OSV == nil {
		return offResult("ecosystem:"+p.Ecosystem, p.Name, p.Version, "osv", "osv feed off")
	}
	return opt.OSV(ctx, p.Ecosystem, p.Name, p.Version)
}

func dispatchWP(ctx context.Context, w WPRef, opt Options) unified.Result {
	scope := "wordpress:plugin"
	if w.Kind == "theme" {
		scope = "wordpress:theme"
	}
	if opt.WP == nil {
		return offResult(scope, w.Slug, w.Version, "wpcve", "wp feed off")
	}
	return opt.WP(ctx, w.Slug, w.Version, w.Kind)
}

func dispatchJS(ctx context.Context, l LibRef, opt Options) unified.Result {
	if opt.JS == nil {
		return offResult("jslib", l.Name, l.Version, "jslib", "js feed off")
	}
	return opt.JS(ctx, l.Name, l.Version)
}

// offResult is the honest "feed off" result for a dispatched identity: StateNotChecked,
// never clean.
func offResult(scope, id, version, source, note string) unified.Result {
	r := unified.Unknown(scope, id, unified.StateNotChecked, note)
	r.Source, r.Version = source, version
	return r
}

// resolveCPEs picks the CPE(s) to bridge to CVE: a dictionary-VERIFIED identity wins,
// else the tech's source-ATTESTED CPE (schema.Fingerprint.CPE). An unverified borrowed
// CPECandidate is NEVER returned — it must not reach a CVE lookup.
func resolveCPEs(ctx context.Context, d matcher.Detection, db *schema.DB, opt Options) (cpes []string, state, evidence string) {
	if opt.IdentityResolver != nil {
		if c, _, st := opt.IdentityResolver(ctx, d.Tech, "", ""); st == identity.StateVerified && c != "" {
			return []string{c}, "verified", "nvd-dict"
		}
	}
	if db != nil {
		if fp, ok := db.Fingerprints[d.Tech]; ok && len(fp.CPE) > 0 {
			return fp.CPE, "attested", "source"
		}
	}
	return nil, "none", ""
}

// cveResults queries the CVE provider for each resolved CPE and maps the outcome into
// unified results, upgrading each lead with KEV/EPSS prioritization and reflecting a
// version conflict. How the CPE was resolved rides on CPEState/CPEEvidence (not Err, so
// it is never mistaken for a lookup failure). Provider off → one StateNotChecked result;
// no CPE to query → one StateUnknownProduct result (honestly "no verified identity").
func cveResults(ctx context.Context, d matcher.Detection, cpes []string, cpeState, cpeEvidence string, opt Options) []unified.Result {
	withCPE := func(r unified.Result) unified.Result {
		r.CPEState, r.CPEEvidence = cpeState, cpeEvidence
		return r
	}
	if opt.CVE == nil {
		r := unified.Unknown("cpe", first(cpes), unified.StateNotChecked, "cve feed off")
		r.Source, r.Version = "cve", d.Version
		return []unified.Result{withCPE(applyVersionConflict(r, d))}
	}
	if len(cpes) == 0 {
		r := unified.Unknown("cpe", "", unified.StateUnknownProduct, "no verified/attested cpe to query")
		r.Source, r.Version = "cve", d.Version
		return []unified.Result{withCPE(applyVersionConflict(r, d))}
	}
	out := make([]unified.Result, 0, len(cpes))
	for _, cpe := range cpes {
		res, err := opt.CVE.Lookup(ctx, cpe, d.Version)
		out = append(out, withCPE(applyVersionConflict(cve.ToUnified(res, err), d)))
	}
	return out
}

// eolResult maps the EOL provider's status into a unified result; provider off → one
// StateNotChecked result. A version conflict downgrades an EOL hit the same way.
// EOLByCPE is an optional EOLProvider capability: resolve the product from a CPE when the
// tech name maps to none — so every product the EOL source lists by CPE is covered, not
// only a hand-kept name list. *lifecycle.Adapter has it in bundle mode.
type EOLByCPE interface {
	EOLStatusByCPE(ctx context.Context, cpe, version string) (lifecycle.Status, error)
}

func eolResult(ctx context.Context, d matcher.Detection, cpes []string, opt Options) unified.Result {
	if opt.EOL == nil {
		r := unified.Unknown("eol", d.Tech, unified.StateNotChecked, "eol feed off")
		r.Source, r.Version = "lifecycle", d.Version
		return applyVersionConflict(r, d)
	}
	st, err := opt.EOL.EOLStatus(ctx, d.Tech, d.Version)
	if byCPE, ok := opt.EOL.(EOLByCPE); ok && err == nil && st.Product == "" {
		for _, c := range cpes {
			if s, e := byCPE.EOLStatusByCPE(ctx, c, d.Version); e != nil || s.Product != "" {
				st, err = s, e
				break
			}
		}
	}
	return applyVersionConflict(lifecycle.ToUnified(st, err), d)
}

// prioritize upgrades every CVE lead of the run with the KEV/EPSS exploitation signal so
// a consumer can rank leads — in ONE ask for the whole run, because the EPSS API takes
// many CVEs per request and asking per detection turns N detections into N requests.
// KEV off or no CVE leads → results pass through unchanged (never dropped).
func prioritize(ctx context.Context, rs []unified.Result, opt Options) []unified.Result {
	if opt.KEV == nil {
		return rs
	}
	seen := map[string]bool{}
	var ids []string
	for _, r := range rs {
		if r.Source != "cve" {
			continue
		}
		for _, l := range r.Leads {
			if l.ID != "" && !seen[l.ID] {
				seen[l.ID] = true
				ids = append(ids, l.ID)
			}
		}
	}
	if len(ids) == 0 {
		return rs
	}
	sig := opt.KEV.EnrichUnified(ctx, ids)
	for ri := range rs {
		if rs[ri].Source != "cve" {
			continue
		}
		for i := range rs[ri].Leads {
			l := &rs[ri].Leads[i]
			k, ok := sig[strings.ToUpper(l.ID)]
			if !ok || len(k.Leads) == 0 {
				continue
			}
			kl := k.Leads[0]
			l.KnownExpl = kl.KnownExpl
			if kl.EPSS != nil {
				l.EPSS = kl.EPSS // added beside the CVSS Score, never over it
			}
			if l.Title == "" {
				l.Title = kl.Title
			}
		}
	}
	return rs
}

// applyVersionConflict honours Detection.VersionConflict: a conflicted version cannot
// be pinned, so an advisory-range HIT is only POTENTIALLY affected and a "not affected"
// answer — none in v0.4 — becomes unknown_version (the other claimed versions were never asked). Every
// other state is already unanswered and is left as-is; a note records the conflict.
func applyVersionConflict(u unified.Result, d matcher.Detection) unified.Result {
	if !d.VersionConflict {
		return u
	}
	switch u.State {
	case unified.StateAffectedByAdvisory:
		u.State = unified.StatePotentiallyAffected
	case unified.StateNotAffectedByAdvisory:
		u.State = unified.StateUnknownVersion // only one claimed version was asked; the others never were
	}
	u.Err = joinNote(u.Err, "version conflict: "+versionClaims(d))
	return u
}

func versionClaims(d matcher.Detection) string {
	vs := make([]string, 0, len(d.VersionClaims))
	for _, c := range d.VersionClaims {
		vs = append(vs, c.Version)
	}
	if len(vs) == 0 {
		return d.Version + " (uncertain)"
	}
	return strings.Join(vs, " vs ")
}

func first(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

func appendDistinct(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
