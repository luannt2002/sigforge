package matcher

import (
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// largePage is a synthetic page on which thousands of techs resolve, the way a hostile page can
// make them: per group i a base B (every third in category 6), a gated G requiring B and implying
// I, which implies J, and every tenth group an excluder X labeling B plus a C gated on category 6 —
// so requires, requiresCategory, implies and excludes all feed the labels.
func largePage(n int) (*schema.DB, map[string]*hit) {
	fps := make(map[string]schema.Fingerprint, 5*n)
	hits := make(map[string]*hit, 3*n)
	own := func(name string, fp schema.Fingerprint) {
		fps[name] = fp
		hits[name] = &hit{conf: 100, fp: fp, evidence: []MatchEvidence{{Field: "html"}}}
	}
	for i := 0; i < n; i++ {
		k := strconv.Itoa(i)
		base := schema.Fingerprint{}
		if i%3 == 0 {
			base.Cats = []int{6}
		}
		own("B"+k, base)
		own("G"+k, schema.Fingerprint{Requires: schema.StringList{"B" + k}, Implies: schema.StringList{"I" + k}})
		fps["I"+k] = schema.Fingerprint{Implies: schema.StringList{"J" + k}}
		fps["J"+k] = schema.Fingerprint{}
		if i%10 == 0 {
			own("X"+k, schema.Fingerprint{Excludes: schema.StringList{"B" + k}})
			own("C"+k, schema.Fingerprint{RequiresCategory: []int{6}})
		}
	}
	return &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: fps}, hits
}

// BenchmarkConditionsLargePage times the part of Match a page's size drives once patterns have
// matched: admitting gated techs and labeling excludes over thousands of resolved techs.
func BenchmarkConditionsLargePage(b *testing.B) {
	db, hits := largePage(1000)
	for b.Loop() {
		excludedBy(resolveConditions(db, hits))
	}
}

// Labeling a page on which thousands of techs resolve must not compare every pair of them: that
// took seconds per page. The bound is far above a linear pass, so only a quadratic one fails it.
func TestConditionsLargePageStaysFast(t *testing.T) {
	db, hits := largePage(1000)
	start := time.Now()
	labels := excludedBy(resolveConditions(db, hits))
	if took := time.Since(start); took > time.Second {
		t.Errorf("resolveConditions + excludedBy took %v on %d own matches", took, len(hits))
	}
	// the labels still spread along requires and implies, so the fast path did the whole job
	for _, tech := range []string{"B0", "G0", "I0", "J0"} {
		if !slices.Equal(labels[tech], []string{"X0"}) {
			t.Errorf("%s labeled %v, want [X0]", tech, labels[tech])
		}
	}
	if labels["C0"] != nil || labels["G1"] != nil {
		t.Errorf("C0 labeled %v, G1 labeled %v, want neither: an unlabeled tech meets their gates", labels["C0"], labels["G1"])
	}
}
