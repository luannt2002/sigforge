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

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
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

// Options carries the operator-gated depth providers. A nil provider means that
// depth layer is OFF: its field stays UNKNOWN rather than being fabricated.
type Options struct {
	CVE CVEProvider
	EOL EOLProvider
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

func appendDistinct(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
