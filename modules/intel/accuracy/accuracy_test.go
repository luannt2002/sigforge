// The accuracy HARNESS: it MEASURES detection + enrichment correctness against
// recorded, offline fixtures. Everything here runs with no internet — the one
// network-shaped path (cve.Lookup) is driven over an httptest loopback serving a
// recorded fixture, exactly as the cve/lifecycle package tests do. See docs/accuracy.md
// for the measured numbers and the periodic LIVE-spot-check procedure.
package accuracy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/baseline"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/enrich"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// recallFloor is the documented minimum recall on the golden set (see
// docs/accuracy.md §3). Precision is held at the hard 1.0 — a false positive is a
// correctness bug, not a tuning knob.
const recallFloor = 0.90

func detectedNames(dets []matcher.Detection) []string {
	out := make([]string, len(dets))
	for i, d := range dets {
		out[i] = d.Tech
	}
	return out
}

// goldenCase is one recorded HTTP response with its KNOWN-true technologies.
type goldenCase struct {
	name  string
	page  matcher.Page
	truth []string // includes techs reached via `implies`
}

// goldenSet: recorded responses whose true technologies are known by construction.
func goldenSet() []goldenCase {
	return []goldenCase{
		{
			name: "nginx+wordpress+jquery",
			page: matcher.Page{
				Headers:    map[string][]string{"Server": {"nginx/1.18.0"}},
				HTML:       `<html><head><meta name="generator" content="WordPress 6.5.2"></head><body><link href="/wp-content/themes/x/style.css"></body></html>`,
				ScriptSrcs: []string{"/assets/jquery-3.6.0.min.js"},
			},
			truth: []string{"Nginx", "WordPress", "jQuery", "PHP"}, // PHP via WordPress implies
		},
		{
			name:  "clean-minimal-site",
			page:  matcher.Page{HTML: `<html><head><title>Hello</title></head><body><h1>Welcome</h1><p>Hello world</p></body></html>`},
			truth: nil, // nothing here — any detection would be a false positive
		},
		{
			name:  "apache-coyote-negative",
			page:  matcher.Page{Headers: map[string][]string{"Server": {"Apache-Coyote/1.1"}}},
			truth: []string{"Apache Tomcat", "Java"}, // Tomcat yes, Java implied — but NOT "Apache"
		},
		{
			name: "php-site",
			page: matcher.Page{
				Headers: map[string][]string{"X-Powered-By": {"PHP/8.2.1"}},
				Cookies: []string{"PHPSESSID=abc123; path=/; HttpOnly"},
			},
			truth: []string{"PHP"},
		},
	}
}

// TestGoldenSetPrecisionRecall runs the real baseline matcher over the golden set
// and asserts precision == 1.0 (no false positive) and recall >= the documented
// floor. It PRINTS the measured numbers.
func TestGoldenSetPrecisionRecall(t *testing.T) {
	db, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}
	var score Score
	for _, c := range goldenSet() {
		got := detectedNames(matcher.Match(db, c.page))
		score.Add(got, c.truth)
		t.Logf("%-24s detected=%v truth=%v", c.name, got, c.truth)
	}
	p, r := score.Precision(), score.Recall()
	t.Logf("GOLDEN SET: precision=%.3f recall=%.3f (TP=%d FP=%d FN=%d)",
		p, r, score.TruePositive, score.FalsePositive, score.FalseNegative)
	if p != 1.0 {
		t.Errorf("precision = %.3f, want 1.0 (a false positive is a correctness bug)", p)
	}
	if r < recallFloor {
		t.Errorf("recall = %.3f, below documented floor %.2f", r, recallFloor)
	}
}

// oracle fixtures — MINIMAL recorded excerpts of the real authoritative shapes, kept
// tiny per the repo's "no third-party data beyond a 1-2 CVE NVD sample + 1 product
// endoflife sample" posture. They lock the parsers to the shapes NVD / endoflife
// actually emit, so a drift breaks a test rather than silently mis-scoring.

// nvdOracle: recorded NVD CVE API 2.0 response for nginx 1.18.0 (one CVE).
const nvdOracle = `{
  "totalResults": 1,
  "vulnerabilities": [
    {"cve": {"id": "CVE-2021-23017",
      "metrics": {"cvssMetricV31": [
        {"source": "nvd@nist.gov", "cvssData": {"version": "3.1", "baseScore": 7.7, "baseSeverity": "HIGH"}}]}}}
  ]
}`

// endoflifeOracle: recorded endoflife.date php feed excerpt (one EOL cycle).
const endoflifeOracle = `[{"cycle":"7.2","eol":"2020-11-30","latest":"7.2.34"}]`

// TestOraclePairs locks cve.Lookup and lifecycle.Classify to the recorded authoritative
// values. cve.Lookup runs over an httptest loopback serving the recorded fixture (no
// internet); lifecycle.Classify is pure.
func TestOraclePairs(t *testing.T) {
	// CVE oracle: nginx 1.18.0 → CVE-2021-23017, CVSS 7.7 HIGH.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("virtualMatchString") == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*" {
			w.Write([]byte(nvdOracle))
			return
		}
		w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	res, err := cve.New(srv.URL, fetch.New()).Lookup(context.Background(), "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0")
	if err != nil {
		t.Fatalf("cve.Lookup: %v", err)
	}
	if res.State != cve.StateHasCVE || len(res.CVEs) != 1 {
		t.Fatalf("oracle CVE: %+v, want one CVE (StateHasCVE)", res)
	}
	if c := res.CVEs[0]; c.ID != "CVE-2021-23017" || c.CVSS != 7.7 || c.Severity != "HIGH" {
		t.Errorf("oracle CVE = %+v, want CVE-2021-23017 / 7.7 / HIGH", c)
	}

	// EOL oracle: php 7.2.34 → cycle 7.2, eol 2020-11-30, past a fixed reference date.
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cycles, err := lifecycle.ParseCycles([]byte(endoflifeOracle))
	if err != nil {
		t.Fatalf("ParseCycles: %v", err)
	}
	cycle, eolDate, state := lifecycle.Classify(cycles, "7.2.34", now)
	if cycle != "7.2" || eolDate != "2020-11-30" || state != lifecycle.StateEOL {
		t.Errorf("oracle EOL = (%q, %q, %v), want (7.2, 2020-11-30, eol)", cycle, eolDate, state)
	}
}

// TestAdversarialNegatives: three mimics that must NOT produce a false detection.
func TestAdversarialNegatives(t *testing.T) {
	db, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}
	has := func(dets []matcher.Detection, tech string) bool {
		for _, d := range dets {
			if d.Tech == tech {
				return true
			}
		}
		return false
	}
	cases := []struct {
		name   string
		page   matcher.Page
		absent string // this tech must NOT be detected
	}{
		{"apache-coyote-mimic", matcher.Page{Headers: map[string][]string{"Server": {"Apache-Coyote/1.1"}}}, "Apache"},
		{"version-in-body-not-attribute", matcher.Page{HTML: `<p>our ng-version is 15.1.2, we love it</p>`}, "Angular"},
		{"substring-mimic-script", matcher.Page{ScriptSrcs: []string{"/static/xjquery.js"}}, "jQuery"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if has(matcher.Match(db, c.page), c.absent) {
				t.Errorf("false positive: %q detected on adversarial input %q", c.absent, c.name)
			}
		})
	}
}

// TestCorroborationCountsSources: a tech attested by two source fixtures enriches to
// a provenance set of >= 2 (the corroboration signal).
func TestCorroborationCountsSources(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"Nginx": {Cats: []int{22}, Provenance: "baseline"},
	}}
	dets := []matcher.Detection{
		{Tech: "Nginx", Version: "1.18.0", Confidence: 100, Provenance: "baseline"},
		{Tech: "Nginx", Version: "1.18.0", Confidence: 80, Provenance: "webappanalyzer"},
	}
	got := enrich.Enrich(context.Background(), dets, db, enrich.Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 enriched tech, got %d", len(got))
	}
	if n := len(got[0].Provenance); n < 2 {
		t.Errorf("corroboration = %d (%v), want >= 2 distinct sources", n, got[0].Provenance)
	}
}
