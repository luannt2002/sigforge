package osv

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// unifiedSource is this provider's source id in a unified.Result.
const unifiedSource = "osv"

// ToUnified maps a Lookup result for name@version (looked up in ecosystem eco) into a unified.Result,
// keeping the honest sub-cases a bare Status folds distinct via res.PackageKnown / res.VersionPinned:
//
//	Vulnerable + version pinned   → affected_by_advisory     (concrete version inside an advisory range)
//	Vulnerable + not pinned       → potentially_affected     (advisories exist, version not pinnable)
//	Unknown    + package known    → potentially_affected     (advisories exist, version could not be positioned)
//	Unknown    + package unknown  → unknown_product          (package absent from the index — never "clean")
//	NoKnownVuln                   → not_checked + unified.NoteNoClearance (a whole dump, nothing matched: no clearance)
//
// fetchedAt is when the operator-fetched dump behind the index was built (Index.BuiltAt); OSV is
// operator-fetch-only, so a served lookup is always live.
func ToUnified(res Result, eco, name, version string, fetchedAt time.Time) unified.Result {
	u := unified.Result{
		Scope:     "ecosystem:" + trimEcosystem(eco),
		Identity:  name,
		Version:   version,
		Source:    unifiedSource,
		Freshness: unified.FreshnessLive,
	}
	if !fetchedAt.IsZero() {
		u.FetchedAt = fetchedAt.UTC().Format(time.RFC3339)
	}
	switch res.Status {
	case StatusVulnerable:
		u.State = unified.AdvisoryState(res.VersionPinned)
		u.Leads = unifiedLeads(res.Vulns)
		if !res.VersionPinned {
			u.Err = unified.NoteNoVersion
		}
	case StatusNoKnownVuln:
		u.State, u.Err = unified.Clean(unified.Evidence{FullData: !res.Partial, Positioned: res.VersionPinned})
	default: // StatusUnknown
		if res.PackageKnown {
			u.State = unified.StatePotentiallyAffected
			u.Err = "the version could not be placed against the package's advisories: whether they apply is unknown"
			u.Leads = unifiedLeads(res.Vulns)
		} else {
			u.State = unified.StateUnknownProduct
		}
	}
	return u
}

// noteOutsideListed is why a platform release's lead may not apply: the advisory reaches it only "from the
// start", yet lists the package's releases and none so old — the version may belong to another release line
// (Shopware 5 in a Shopware 6 package) or predate the package's publication (Liferay 6.2, artifact from 7.0).
const noteOutsideListed = "the version is older than every version this package's advisories name and reaches this advisory only through its from-the-start range: it may not be one of this package's releases — confirm before relying on it"

// Unavailable maps a LoadIndex failure to an honest unified.Result: a disabled source (errSourceOff)
// is not_checked, any other failure is source_unavailable — neither is ever read as "clean".
func Unavailable(eco, name, version string, err error) unified.Result {
	state := unified.StateSourceUnavailable
	if errors.Is(err, errSourceOff) {
		state = unified.StateNotChecked
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	u := unified.Unknown("ecosystem:"+trimEcosystem(eco), name, state, msg)
	u.Version = version
	u.Source = unifiedSource
	return u
}

// unifiedLeads maps OSV vulns to unified leads; Lead.Score is the base score of the record's CVSS v3
// vector, nil when it has none
// (an absent score is never fabricated as 0.0).
func unifiedLeads(vulns []Vuln) []unified.Lead {
	if len(vulns) == 0 {
		return nil
	}
	out := make([]unified.Lead, 0, len(vulns))
	for _, v := range vulns {
		l := unified.Lead{ID: v.ID, Title: v.Summary, Severity: v.Severity, CVSS: v.Vector, CWE: unified.CWEIDs(strings.Split(v.CWE, ",")), Published: v.Published}
		if v.OutsideListed {
			l.Note = noteOutsideListed
		}
		if v.Scored {
			score := v.Score
			l.Score = &score
		}
		if v.CVE != "" {
			l.CVE = []string{v.CVE}
		}
		if v.URL != "" {
			l.References = []string{v.URL}
		}
		out = append(out, l)
	}
	return out
}

// Lookuper returns the lookup for one run: each ecosystem's dump is loaded once — a dump
// is the whole ecosystem, so loading it per package would download it N times — and every
// package is answered from that index. What the source cannot answer stays unanswered: an
// off source or an unsupported ecosystem is not_checked, a failed load source_unavailable.
func (a *Adapter) Lookuper() func(ctx context.Context, eco, name, version string) unified.Result {
	pkg, _ := a.Lookupers()
	return pkg
}

// Lookupers returns one run's two lookups over the same loaded dumps: pkg for a package's own
// version (Lookuper), release for a detected platform's release looked up in its core packages — a
// version the package may not hold, so one older than every version the package's advisories name
// is not reached by the from-the-start ranges of those that list its releases.
func (a *Adapter) Lookupers() (pkg, release func(ctx context.Context, eco, name, version string) unified.Result) {
	type loaded struct {
		once sync.Once
		idx  *Index
		err  error
	}
	var mu sync.Mutex
	byEco := map[string]*loaded{}
	lookup := func(rel bool) func(ctx context.Context, eco, name, version string) unified.Result {
		return func(ctx context.Context, eco, name, version string) unified.Result {
			unanswered := func(state unified.State, why string) unified.Result {
				u := unified.Unknown("ecosystem:"+trimEcosystem(eco), name, state, why)
				u.Version, u.Source = version, unifiedSource
				return u
			}
			e, ok := Ecosystem(eco)
			if !ok {
				return unanswered(unified.StateNotChecked, "OSV ecosystem "+eco+" is not supported")
			}
			eco = e + strings.TrimPrefix(eco, trimEcosystem(eco)) // the canonical name, release kept
			if releaseScoped[e] && !strings.Contains(eco, ":") {
				return unanswered(unified.StateNotChecked, e+" advisories differ per release: give the package as a purl with its distro qualifier (…?distro=<release>)")
			}
			key := e
			if releaseScoped[e] && a.client != nil && a.client.CacheDir != "" {
				key = eco // with a store each release is its own index, read from the dump's index file
			}
			mu.Lock() // guards only the map: one ecosystem's long load never holds up another's
			l := byEco[key]
			if l == nil {
				l = &loaded{}
				byEco[key] = l
			}
			mu.Unlock()
			l.once.Do(func() { l.idx, l.err = a.LoadIndex(ctx, key) })
			switch {
			case errors.Is(l.err, errSourceOff):
				return unanswered(unified.StateNotChecked, "osv feed off")
			case l.err != nil:
				return unanswered(unified.StateSourceUnavailable, l.err.Error())
			}
			u := ToUnified(l.idx.lookup(eco, name, version, rel), e, name, version, l.idx.BuiltAt)
			switch {
			case l.idx.fetched.Stale:
				u.Freshness = unified.FreshnessStale
				note := "osv source failed: verdict from the last synced dump (stale): " + l.idx.fetched.Err
				if u.Err != "" {
					note = u.Err + "; " + note // keep why the verdict is what it is
				}
				u.Err = note
			case l.idx.fetched.Cached:
				u.Freshness = unified.FreshnessSnapshot
			}
			return u
		}
	}
	return lookup(false), lookup(true)
}
