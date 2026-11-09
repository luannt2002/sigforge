package refresh

import (
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// db builds a one-schema-version DB from the given fingerprints for a gate test.
func db(fps map[string]schema.Fingerprint) *schema.DB {
	return &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: fps}
}

// full is a tech that carries both the CVE bridge (CPE) and a version signal, so a
// candidate that strips either is a measurable downgrade.
func full() schema.Fingerprint {
	return schema.Fingerprint{
		CPE:          []string{"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
		VersionRegex: []string{`nginx/([\d.]+)\;version:\1`},
	}
}

// reasons extracts the (tech,reason) pairs as a lookup for assertions.
func reasons(r Report) map[string]Reason {
	m := make(map[string]Reason, len(r.Findings))
	for _, f := range r.Findings {
		m[f.Tech] = f.Reason
	}
	return m
}

func TestGate(t *testing.T) {
	current := db(map[string]schema.Fingerprint{
		"Nginx": full(),
		"PHP":   {CPE: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}},
	})

	t.Run("better candidate publishes", func(t *testing.T) {
		cand := db(map[string]schema.Fingerprint{
			"Nginx":   full(),
			"PHP":     {CPE: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}},
			"NewTech": {HTML: schema.StringList{"new-marker"}},
		})
		r := Gate(current, cand, 0)
		if !r.OK() {
			t.Fatalf("a strictly-additive candidate must pass, got findings %+v", r.Findings)
		}
		if r.Added != 1 || r.Removed != 0 {
			t.Fatalf("want +1/-0, got +%d/-%d", r.Added, r.Removed)
		}
	})

	t.Run("removed fingerprint aborts at threshold 0", func(t *testing.T) {
		cand := db(map[string]schema.Fingerprint{"Nginx": full()}) // PHP gone
		r := Gate(current, cand, 0)
		if r.OK() {
			t.Fatal("dropping a fingerprint must trip the gate")
		}
		if reasons(r)["PHP"] != ReasonRemoved {
			t.Fatalf("want PHP removed, got %+v", r.Findings)
		}
	})

	t.Run("allow-removed relaxes intended removal", func(t *testing.T) {
		cand := db(map[string]schema.Fingerprint{"Nginx": full()}) // PHP gone
		if r := Gate(current, cand, 1); !r.OK() {
			t.Fatalf("one removal under --allow-removed=1 must pass, got %+v", r.Findings)
		}
	})

	t.Run("lost CPE on a kept tech aborts even with allow-removed", func(t *testing.T) {
		cand := db(map[string]schema.Fingerprint{
			"Nginx": {VersionRegex: full().VersionRegex}, // CPE stripped, entry stays
			"PHP":   {CPE: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}},
		})
		r := Gate(current, cand, 99)
		if reasons(r)["Nginx"] != ReasonLostCPE {
			t.Fatalf("stripping a kept tech's CPE must abort regardless of --allow-removed, got %+v", r.Findings)
		}
	})

	t.Run("lost version signal on a kept tech aborts", func(t *testing.T) {
		cand := db(map[string]schema.Fingerprint{
			"Nginx": {CPE: full().CPE}, // version_regex stripped
			"PHP":   {CPE: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}},
		})
		r := Gate(current, cand, 0)
		if reasons(r)["Nginx"] != ReasonLostVersion {
			t.Fatalf("stripping a kept tech's version signal must abort, got %+v", r.Findings)
		}
	})

	t.Run("inline version suffix counts as version capture", func(t *testing.T) {
		cur := db(map[string]schema.Fingerprint{
			"App": {HTML: schema.StringList{`app ([\d.]+)\;version:\1`}},
		})
		cand := db(map[string]schema.Fingerprint{
			"App": {HTML: schema.StringList{"app"}}, // marker kept, version suffix gone
		})
		if r := Gate(cur, cand, 0); reasons(r)["App"] != ReasonLostVersion {
			t.Fatalf("losing an inline \\;version suffix must abort, got %+v", r.Findings)
		}
	})

	t.Run("nil current is the first publish", func(t *testing.T) {
		if r := Gate(nil, current, 0); !r.OK() {
			t.Fatalf("first publish (nil current) must pass, got %+v", r.Findings)
		}
	})
}
