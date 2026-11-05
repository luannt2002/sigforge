// Package diff compares two fingerprint DBs and reports which technologies a
// re-sync added, removed or changed. An operator who re-runs `merge --fetch`
// diffs the new DB against the previous one (or against what the SYNC-MANIFEST
// last produced) to see exactly what a third-party source update moved, instead
// of trusting that "nothing surprising happened".
//
// It is a PURE, in-domain comparison: no network, no third-party data, no state.
package diff

import (
	"reflect"
	"sort"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// Result is the set difference between an old and a new DB, keyed by technology
// name. Each list is stable-sorted so the same inputs always print the same way.
type Result struct {
	Added   []string // techs present in new but not old
	Removed []string // techs present in old but not new
	Changed []string // techs in both whose fingerprint differs (markers, provenance/version, license or confidence)
}

// Empty reports whether the two DBs are identical in their fingerprint sets.
func (r Result) Empty() bool {
	return len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Changed) == 0
}

// Diff computes Result = new relative to old. A nil DB is treated as an empty
// set, so diffing against a missing previous DB reports everything as added.
func Diff(old, new *schema.DB) Result {
	oldSet := fingerprints(old)
	newSet := fingerprints(new)

	var r Result
	for name, newFP := range newSet {
		oldFP, ok := oldSet[name]
		switch {
		case !ok:
			r.Added = append(r.Added, name)
		case !reflect.DeepEqual(oldFP, newFP):
			r.Changed = append(r.Changed, name)
		}
	}
	for name := range oldSet {
		if _, ok := newSet[name]; !ok {
			r.Removed = append(r.Removed, name)
		}
	}
	sort.Strings(r.Added)
	sort.Strings(r.Removed)
	sort.Strings(r.Changed)
	return r
}

func fingerprints(db *schema.DB) map[string]schema.Fingerprint {
	if db == nil {
		return nil
	}
	return db.Fingerprints
}
