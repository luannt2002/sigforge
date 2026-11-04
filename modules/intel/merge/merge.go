// Package merge combines sigforge's curated baseline with normalized source sets
// into one fingerprint set. It is pure — no I/O, no network.
//
// Precedence: the baseline is always the source of truth; among sources a higher
// Trust wins, ties resolve to the order given. On a tech-id conflict the
// higher-precedence entry is kept whole, and the losing entry's version-capturing
// patterns are preserved as alternates in the winner's version_regex so no
// version signal is silently dropped. Every entry carries the provenance and
// license of the source it came from, so the operator — who chose which sources to
// include — owns the license posture of the output.
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
				winner.VersionRegex = mergeVersionRegex(winner.VersionRegex, versionPatterns(incoming))
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

// versionPatterns collects every version-capturing pattern in an entry: the
// inline `\;version:` patterns across its fields plus any already-stashed
// alternates.
func versionPatterns(fp schema.Fingerprint) []string {
	var out []string
	add := func(raw string) {
		if strings.Contains(raw, `\;version:`) {
			out = append(out, raw)
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
	out = append(out, fp.VersionRegex...)
	return out
}

// mergeVersionRegex appends new alternates to existing ones, de-duplicated and
// ordered so the result is stable.
func mergeVersionRegex(existing, incoming []string) []string {
	seen := make(map[string]bool, len(existing)+len(incoming))
	var out []string
	for _, s := range existing {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range incoming {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) > 1 {
		sort.Strings(out)
	}
	return out
}
