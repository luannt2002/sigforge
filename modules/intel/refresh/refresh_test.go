package refresh

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/baseline"
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

// TestGateLostDetection: a kept tech whose candidate entry carries no detection channel
// stays listed but can never be matched again, so the gate must refuse it whichever
// channel it used to have — and must not block a tech that never had one (implied-only,
// like the baseline's Node.js/Ruby), one that only changed its patterns, or a removal.
func TestGateLostDetection(t *testing.T) {
	one := func(fp schema.Fingerprint) *schema.DB { return db(map[string]schema.Fingerprint{"Demo": fp}) }
	marker := schema.Fingerprint{HTML: schema.StringList{"demo-marker"}}
	lost := []Finding{{Tech: "Demo", Reason: ReasonLostDetection}}

	channels := []struct {
		name string
		fp   schema.Fingerprint
	}{
		{"header", schema.Fingerprint{Headers: map[string]schema.StringList{"Server": {"demo"}}}},
		{"cookie", schema.Fingerprint{Cookies: map[string]schema.StringList{"demo_sid": {""}}}},
		{"meta", schema.Fingerprint{Meta: map[string]schema.StringList{"generator": {"Demo"}}}},
		{"html", marker},
		{"scriptSrc", schema.Fingerprint{ScriptSrc: schema.StringList{`demo\.js`}}},
		{"dom", schema.Fingerprint{Dom: json.RawMessage(`{"#demo-app":{"exists":""}}`)}},
	}
	for _, ch := range channels {
		t.Run("lost "+ch.name+" aborts", func(t *testing.T) {
			r := Gate(one(ch.fp), one(schema.Fingerprint{}), 0)
			if r.OK() || !slices.Equal(r.Findings, lost) {
				t.Fatalf("a kept tech left with no detection channel must abort as lost-detection, got %+v", r.Findings)
			}
		})
	}

	t.Run("kept metadata, implies and version alternates do not detect", func(t *testing.T) {
		cand := schema.Fingerprint{
			Cats:         []int{1},
			Implies:      schema.StringList{"PHP"},
			VersionRegex: []string{`demo/([\d.]+)\;version:\1`},
			CPE:          []string{"cpe:2.3:a:demo:demo:*:*:*:*:*:*:*:*"},
		}
		if r := Gate(one(marker), one(cand), 0); !slices.Equal(r.Findings, lost) {
			t.Fatalf("an entry with only non-detecting fields is blind, want lost-detection, got %+v", r.Findings)
		}
	})

	t.Run("allow-removed does not relax lost detection", func(t *testing.T) {
		if r := Gate(one(marker), one(schema.Fingerprint{}), 99); r.OK() || !slices.Equal(r.Findings, lost) {
			t.Fatalf("lost detection on a kept tech must abort regardless of --allow-removed, got %+v", r.Findings)
		}
	})

	t.Run("losing everything keeps every reason", func(t *testing.T) {
		old := schema.Fingerprint{
			HTML: schema.StringList{`demo ([\d.]+)\;version:\1`},
			CPE:  []string{"cpe:2.3:a:demo:demo:*:*:*:*:*:*:*:*"},
		}
		r := Gate(one(old), one(schema.Fingerprint{}), 0)
		got := map[Reason]bool{}
		for _, f := range r.Findings {
			if f.Tech == "Demo" {
				got[f.Reason] = true
			}
		}
		if len(r.Findings) != 3 || !got[ReasonLostCPE] || !got[ReasonLostVersion] || !got[ReasonLostDetection] {
			t.Fatalf("want lost-cpe, lost-version-regex and lost-detection together, got %+v", r.Findings)
		}
	})

	t.Run("implied-only tech in both passes", func(t *testing.T) {
		nodeLike := schema.Fingerprint{Cats: []int{27}, CPE: []string{"cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"}}
		if r := Gate(one(nodeLike), one(nodeLike), 0); !r.OK() {
			t.Fatalf("a tech with no detection channel on either side has nothing to lose, got %+v", r.Findings)
		}
	})

	t.Run("implied-only tech gaining a channel passes", func(t *testing.T) {
		if r := Gate(one(schema.Fingerprint{Cats: []int{27}}), one(marker), 0); !r.OK() {
			t.Fatalf("gaining a detection channel is an improvement, not a loss, got %+v", r.Findings)
		}
	})

	t.Run("changed patterns that keep a channel pass", func(t *testing.T) {
		cases := []struct {
			name          string
			before, after schema.Fingerprint
		}{
			{"html to header", marker, schema.Fingerprint{Headers: map[string]schema.StringList{"Server": {"demo"}}}},
			{"html+cookie to dom", schema.Fingerprint{HTML: marker.HTML, Cookies: map[string]schema.StringList{"demo_sid": {""}}},
				schema.Fingerprint{Dom: json.RawMessage(`{"#demo-app":{"exists":""}}`)}},
			{"partial loss keeps header", schema.Fingerprint{HTML: marker.HTML, Headers: map[string]schema.StringList{"Server": {"demo"}}},
				schema.Fingerprint{Headers: map[string]schema.StringList{"Server": {"demo"}}}},
		}
		for _, c := range cases {
			if r := Gate(one(c.before), one(c.after), 0); !r.OK() {
				t.Errorf("%s: a tech that still has a detection channel must pass, got %+v", c.name, r.Findings)
			}
		}
	})

	t.Run("removed tech stays a removal", func(t *testing.T) {
		cur := db(map[string]schema.Fingerprint{"Demo": marker, "Keep": {HTML: schema.StringList{"keep-marker"}}})
		cand := db(map[string]schema.Fingerprint{"Keep": {HTML: schema.StringList{"keep-marker"}}})
		if r := Gate(cur, cand, 0); !slices.Equal(r.Findings, []Finding{{Tech: "Demo", Reason: ReasonRemoved}}) {
			t.Fatalf("a dropped tech is a removal only, got %+v", r.Findings)
		}
		if r := Gate(cur, cand, 1); !r.OK() {
			t.Fatalf("an intended removal under --allow-removed=1 must still pass, got %+v", r.Findings)
		}
	})
}

// TestGateBaselineNoFalseBlock runs the gate over the real embedded baseline against
// itself: data already shipped must not be blocked. The baseline holds implied-only
// techs with no channel of their own, so a rule judging the candidate alone trips here.
func TestGateBaselineNoFalseBlock(t *testing.T) {
	bl, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}
	var implied []string
	for name, fp := range bl.Fingerprints {
		if !fp.HasDetection() {
			implied = append(implied, name)
		}
	}
	slices.Sort(implied)
	if len(implied) == 0 {
		t.Fatal("baseline has no implied-only tech left, so this test no longer exercises the old-side condition — pick another fixture")
	}
	t.Logf("baseline: %d techs, implied-only %v", len(bl.Fingerprints), implied)
	if r := Gate(bl, bl, 0); !r.OK() {
		t.Fatalf("the shipped baseline must pass against itself, got %+v", r.Findings)
	}
}
