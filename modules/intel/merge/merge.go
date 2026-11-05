// Package merge combines sigforge's curated baseline with normalized source sets
// into one fingerprint set. It is pure — no I/O, no network.
//
// Precedence: the baseline is always the source of truth; among sources a higher
// Trust wins, ties resolve to the order given. On a tech-id conflict the
// higher-precedence entry is kept whole, and the losing entry's version-capturing
// patterns are preserved as alternates in the winner's version_regex so no
// version signal is silently dropped. Likewise a CPE (the CVE bridge) is carried
// through: the winner keeps its own, but if it has none the losing source's CPE is
// kept as info so a CVE id is never silently dropped. Every entry carries the
// provenance and license of the source it came from, so the operator — who chose
// which sources to include — owns the license posture of the output.
package merge

import (
	"sort"
	"strings"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// Source is one normalized set to merge below the baseline, with a trust rank.
type Source struct {
	Name  string // provenance id stamped onto its entries, e.g. "nuclei"
	Trust int    // higher wins against other sources on a tech-id conflict
	Set   map[string]schema.Fingerprint
}

// Merge returns a new set; inputs are not mutated. Baseline entries are stamped
// provenance "baseline" when they carry none; source entries are stamped with the
// source name. Sources are applied in descending Trust so the strongest is tried
// first.
func Merge(baseline map[string]schema.Fingerprint, sources ...Source) map[string]schema.Fingerprint {
	out := make(map[string]schema.Fingerprint, len(baseline))
	for name, fp := range baseline {
		out[name] = stamp(fp, "baseline", fp.License)
	}

	ordered := append([]Source(nil), sources...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Trust > ordered[j].Trust })

	for _, src := range ordered {
		for name, fp := range src.Set {
			incoming := stamp(fp, src.Name, fp.License)
			if winner, ok := out[name]; ok {
				winner.VersionRegex, winner.VersionRegexProv = mergeAlternates(
					zipAlts(winner.VersionRegex, winner.VersionRegexProv, provOf(winner)),
					versionAlts(incoming),
				)
				if len(winner.CPE) == 0 && len(incoming.CPE) > 0 {
					winner.CPE = incoming.CPE // the winner lacked a CVE id; keep the losing source's as info
				}
				out[name] = winner
				continue
			}
			out[name] = incoming
		}
	}
	return out
}

// stamp sets provenance (and license, if given) on a copy of fp when it lacks one.
func stamp(fp schema.Fingerprint, provenance, license string) schema.Fingerprint {
	if fp.Provenance == "" {
		fp.Provenance = provenance
	}
	if fp.License == "" {
		fp.License = license
	}
	return fp
}

// versionAlt is one alternate version pattern paired with the provenance+license
// of the source it truly came from, so a GPL pattern pooled under an Apache winner
// keeps its own license.
type versionAlt struct {
	rx   string
	prov schema.PatternProv
}

// provOf is the entry's own provenance trio, used as the license of patterns that
// originated in this entry (its inline `\;version:` fields and any alternates it
// carried without a recorded provenance).
func provOf(fp schema.Fingerprint) schema.PatternProv {
	return schema.PatternProv{Provenance: fp.Provenance, ProvenanceVersion: fp.ProvenanceVersion, License: fp.License}
}

// versionAlts collects every version-capturing pattern in an entry tagged with its
// true provenance: the inline `\;version:` patterns belong to the entry's own
// source, while already-stashed alternates keep the provenance recorded for them.
func versionAlts(fp schema.Fingerprint) []versionAlt {
	own := provOf(fp)
	var out []versionAlt
	add := func(raw string) {
		if strings.Contains(raw, `\;version:`) {
			out = append(out, versionAlt{rx: raw, prov: own})
		}
	}
	for _, m := range []map[string]schema.StringList{fp.Headers, fp.Cookies, fp.Meta} {
		for _, raws := range m {
			for _, raw := range raws {
				add(raw)
			}
		}
	}
	for _, raw := range fp.HTML {
		add(raw)
	}
	for _, raw := range fp.ScriptSrc {
		add(raw)
	}
	return append(out, zipAlts(fp.VersionRegex, fp.VersionRegexProv, own)...)
}

// zipAlts pairs each VersionRegex pattern with its recorded provenance, padding any
// unrecorded tail with own (those patterns originated in this entry).
func zipAlts(rx []string, prov []schema.PatternProv, own schema.PatternProv) []versionAlt {
	out := make([]versionAlt, len(rx))
	for i, r := range rx {
		p := own
		if i < len(prov) {
			p = prov[i]
		}
		out[i] = versionAlt{rx: r, prov: p}
	}
	return out
}

// mergeAlternates unions existing and incoming alternates, de-duplicated by pattern
// (first provenance seen wins) and ordered so the result is stable, then splits the
// aligned pattern/provenance slices back out.
func mergeAlternates(existing, incoming []versionAlt) ([]string, []schema.PatternProv) {
	seen := make(map[string]bool, len(existing)+len(incoming))
	all := make([]versionAlt, 0, len(existing)+len(incoming))
	for _, a := range existing {
		if !seen[a.rx] {
			seen[a.rx] = true
			all = append(all, a)
		}
	}
	for _, a := range incoming {
		if !seen[a.rx] {
			seen[a.rx] = true
			all = append(all, a)
		}
	}
	if len(all) == 0 {
		return nil, nil
	}
	if len(all) > 1 {
		sort.Slice(all, func(i, j int) bool { return all[i].rx < all[j].rx })
	}
	rx := make([]string, len(all))
	prov := make([]schema.PatternProv, len(all))
	for i, a := range all {
		rx[i] = a.rx
		prov[i] = a.prov
	}
	return rx, prov
}
