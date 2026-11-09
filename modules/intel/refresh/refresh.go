// Package refresh is the regression gate between a live fingerprint DB and a freshly
// built candidate. A re-sync of third-party sources can quietly make the data WORSE —
// drop a fingerprint, lose a tech's verified CPE (its CVE bridge) or its version-
// capturing signal — and a plain overwrite would publish that downgrade silently.
// Gate measures the downgrade from the two DBs alone (no corpus, no network) and names
// exactly what would regress, so the operator never trades a good DB for a worse one by
// accident.
//
// It is PURE and in-domain: it imports only schema and diff, so it is fully testable
// with offline fixture DBs. The fetch/build/publish wiring lives in the command layer.
package refresh

import (
	"sort"

	"github.com/luannt2002/sigforge/modules/intel/diff"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// Reason classifies a regression the gate refuses to publish silently.
type Reason string

const (
	ReasonRemoved     Reason = "removed"            // a fingerprint present in current is gone from the candidate
	ReasonLostCPE     Reason = "lost-cpe"           // a tech kept in both lost its verified CPE (the CVE bridge)
	ReasonLostVersion Reason = "lost-version-regex" // a tech kept in both lost its version-capturing signal
)

// Finding is one regression, naming the tech and what it lost — the evidence the
// operator sees instead of a silent data downgrade.
type Finding struct {
	Tech   string
	Reason Reason
}

// Report is the gate's verdict: the diff counts plus every regression found. No
// findings → the candidate may publish; any finding → keep current.
type Report struct {
	Added    int
	Removed  int
	Changed  int
	Findings []Finding
}

// OK reports whether the candidate may be published (no regression found).
func (r Report) OK() bool { return len(r.Findings) == 0 }

// Gate compares the current DB against a candidate and reports regressions that must
// block a publish: fingerprints removed beyond allowRemoved, and — for a tech kept in
// both — a lost verified CPE or lost version-capturing signal. A nil current (first
// publish) has nothing to regress against, so the candidate always passes. allowRemoved
// is the operator's escape hatch for removals they intend; it never relaxes the lost-
// CPE / lost-version checks, which are always regressions for a tech that stays.
func Gate(current, candidate *schema.DB, allowRemoved int) Report {
	d := diff.Diff(current, candidate)
	r := Report{Added: len(d.Added), Removed: len(d.Removed), Changed: len(d.Changed)}

	// Removed fingerprints trip the gate only past the operator's threshold; under it
	// they are intended removals the operator vouched for with --allow-removed.
	if len(d.Removed) > allowRemoved {
		for _, tech := range d.Removed { // diff.Removed is already sorted
			r.Findings = append(r.Findings, Finding{Tech: tech, Reason: ReasonRemoved})
		}
	}

	// A tech kept across the refresh must not silently lose its CVE bridge (CPE) or its
	// version-capturing signal — honest-data downgrades even though the entry survives.
	cur := fingerprints(current)
	cand := fingerprints(candidate)
	for _, tech := range sortedKeys(cur) {
		c, ok := cand[tech]
		if !ok {
			continue // handled above as removed
		}
		o := cur[tech]
		if hasCPE(o) && !hasCPE(c) {
			r.Findings = append(r.Findings, Finding{Tech: tech, Reason: ReasonLostCPE})
		}
		if o.CapturesVersion() && !c.CapturesVersion() {
			r.Findings = append(r.Findings, Finding{Tech: tech, Reason: ReasonLostVersion})
		}
	}
	return r
}

func fingerprints(db *schema.DB) map[string]schema.Fingerprint {
	if db == nil {
		return nil
	}
	return db.Fingerprints
}

func sortedKeys(m map[string]schema.Fingerprint) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// hasCPE reports whether the entry attests a verified CPE. cpe_candidate is an
// unverified lead from another entry, not this entry's identity, so it does not count.
func hasCPE(fp schema.Fingerprint) bool { return len(fp.CPE) > 0 }
