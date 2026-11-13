// The accuracy HARNESS: it MEASURES detection + enrichment correctness against
// recorded, offline fixtures. Everything here runs with no internet — the one
// network-shaped path (cve.Lookup) is driven over an httptest loopback serving a
// recorded fixture, exactly as the cve/lifecycle package tests do. See docs/accuracy.md
// for the measured numbers and the periodic LIVE-spot-check procedure.
//
// It reports PER-TECHNOLOGY, not just an aggregate: a 1.0 micro-average over a handful
// of techs is not 1.0 over the whole baseline, so the harness prints each tech's score
// AND the coverage gap (baseline techs no fixture exercises). It never claims a
// population estimate from hand-built fixtures.
package accuracy

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// goldenSet: hand-built responses whose true technologies are known by construction —
// each is derived from a real baseline signature (a Server banner, a cookie name, a
// generator meta, a library script path) so the matcher is exercised on the canonical
// signal, not a toy. The truth list is what the signature legitimately supports,
// implied techs included. These are regression-and-correctness fixtures, NOT a sample
// of real web traffic; growth comes from producerFixtures (see below).
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
			name:  "apache-coyote",
			page:  matcher.Page{Headers: map[string][]string{"Server": {"Apache-Coyote/1.1"}}},
			truth: []string{"Apache Tomcat", "Java"}, // Tomcat yes, Java implied — but NOT "Apache" (a false-positive guard, see TestHardNegatives)
		},
		{
			name: "php-site",
			page: matcher.Page{
				Headers: map[string][]string{"X-Powered-By": {"PHP/8.2.1"}},
				Cookies: []string{"PHPSESSID=abc123; path=/; HttpOnly"},
			},
			truth: []string{"PHP"},
		},
		{
			name:  "apache-httpd",
			page:  matcher.Page{Headers: map[string][]string{"Server": {"Apache/2.4.52 (Ubuntu)"}}},
			truth: []string{"Apache"},
		},
		{
			name: "iis-aspnet",
			page: matcher.Page{
				Headers: map[string][]string{"Server": {"Microsoft-IIS/10.0"}, "X-Powered-By": {"ASP.NET"}, "X-AspNet-Version": {"4.0.30319"}},
				Cookies: []string{"ASP.NET_SessionId=xyz; path=/"},
			},
			truth: []string{"Microsoft IIS", "Microsoft ASP.NET"},
		},
		{
			name:  "aspnet-core-kestrel",
			page:  matcher.Page{Headers: map[string][]string{"Server": {"Kestrel"}}},
			truth: []string{"Microsoft ASP.NET Core"},
		},
		{
			name:  "python-werkzeug",
			page:  matcher.Page{Headers: map[string][]string{"Server": {"Werkzeug/2.0.3 Python/3.9.7"}}},
			truth: []string{"Python"},
		},
		{
			name:  "gunicorn",
			page:  matcher.Page{Headers: map[string][]string{"Server": {"gunicorn/20.1.0"}}},
			truth: []string{"Gunicorn", "Python"}, // Python implied
		},
		{
			name:  "express-node",
			page:  matcher.Page{Headers: map[string][]string{"X-Powered-By": {"Express"}}},
			truth: []string{"Express", "Node.js"}, // Node.js implied
		},
		{
			name: "django",
			page: matcher.Page{
				Cookies: []string{"csrftoken=abcd; path=/"},
				HTML:    `<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>`,
			},
			truth: []string{"Django", "Python"}, // Python implied
		},
		{
			name:  "laravel",
			page:  matcher.Page{Cookies: []string{"laravel_session=eyJ; path=/; HttpOnly"}},
			truth: []string{"Laravel", "PHP"}, // PHP implied
		},
		{
			name:  "drupal",
			page:  matcher.Page{Headers: map[string][]string{"X-Generator": {"Drupal 9 (https://www.drupal.org)"}}},
			truth: []string{"Drupal", "PHP"}, // PHP implied
		},
		{
			name:  "joomla",
			page:  matcher.Page{HTML: `<meta name="generator" content="Joomla! - Open Source Content Management">`},
			truth: []string{"Joomla", "PHP"}, // PHP implied
		},
		{
			name: "woocommerce",
			page: matcher.Page{HTML: `<meta name="generator" content="WooCommerce 8.2.1"><link href="/wp-content/plugins/woocommerce/assets/css/x.css">`},
			// WooCommerce ⇒ WordPress ⇒ PHP; the /wp-content/ path also fires WordPress directly.
			truth: []string{"WooCommerce", "WordPress", "PHP"},
		},
		{
			name: "magento",
			page: matcher.Page{
				Cookies: []string{"X-Magento-Vary=abc; path=/"},
				HTML:    `<script src="/static/version1700000000/frontend/base/theme.js"></script>`,
			},
			truth: []string{"Magento", "PHP"}, // PHP implied
		},
		{
			name:  "shopify",
			page:  matcher.Page{Headers: map[string][]string{"X-ShopId": {"12345678"}}},
			truth: []string{"Shopify"},
		},
		{
			name:  "ghost",
			page:  matcher.Page{HTML: `<meta name="generator" content="Ghost 5.75">`},
			truth: []string{"Ghost", "Node.js"}, // Node.js implied
		},
		{
			name: "nextjs",
			page: matcher.Page{
				HTML:       `<div id="__next"></div><script id="__NEXT_DATA__" type="application/json">{}</script><link href="/_next/static/css/x.css">`,
				ScriptSrcs: []string{"/_next/static/chunks/main-abc123.js"},
			},
			truth: []string{"Next.js", "React", "Node.js"}, // React + Node.js implied
		},
		{
			name:  "react-spa",
			page:  matcher.Page{ScriptSrcs: []string{"/static/js/react-dom.18.2.0.min.js"}},
			truth: []string{"React"},
		},
		{
			name:  "vue-cdn",
			page:  matcher.Page{ScriptSrcs: []string{"/js/vue.min.js"}},
			truth: []string{"Vue.js"},
		},
		{
			name:  "angular-dom",
			page:  matcher.Page{HTML: `<body><app-root ng-version="16.2.0"></app-root></body>`},
			truth: []string{"Angular"},
		},
		{
			name:  "bootstrap+jquery",
			page:  matcher.Page{ScriptSrcs: []string{"/js/jquery-3.6.0.min.js", "/js/bootstrap.min.js"}},
			truth: []string{"jQuery", "Bootstrap"},
		},
		{
			name:  "cloudflare-edge",
			page:  matcher.Page{Headers: map[string][]string{"CF-RAY": {"7d1a2b3c4d5e-SJC"}}},
			truth: []string{"Cloudflare"},
		},
		{
			name:  "google-analytics",
			page:  matcher.Page{ScriptSrcs: []string{"https://www.googletagmanager.com/gtag/js?id=G-ABC123"}},
			truth: []string{"Google Analytics"},
		},
	}
}

// negativeCase is a hard-negative: a page that must produce NO detection. Each carries
// the reason it is a trap, so a future failure reads as a story, not a bare diff. Folded
// into the per-tech Report with truth=nil, so ANY detection becomes a measured false
// positive and trips the precision gate — a stronger check than naming one forbidden tech.
type negativeCase struct {
	name   string
	reason string
	page   matcher.Page
}

// hardNegatives: the FP corpus. These are the mistakes substring/banner matchers are
// known to make (Apache-Coyote read as Apache httpd has a real repo precedent), plus
// SPA shells, marketing text and mis-placed generators.
func hardNegatives() []negativeCase {
	return []negativeCase{
		{
			name:   "clean-minimal-site",
			reason: "plain HTML with no technology marker — any detection is invented",
			page:   matcher.Page{HTML: `<html><head><title>Hello</title></head><body><h1>Welcome</h1><p>Hello world</p></body></html>`},
		},
		{
			name:   "spa-shell-hashed-bundle",
			reason: "framework-less SPA shell; a hashed bundle name must not be read as a named library",
			page:   matcher.Page{HTML: `<div id="root"></div>`, ScriptSrcs: []string{"/assets/index-4f3a2b1c.js"}},
		},
		{
			name:   "substring-mimic-script",
			reason: "/static/xjquery.js embeds 'jquery' mid-token; the token-boundary guard must reject it",
			page:   matcher.Page{ScriptSrcs: []string{"/static/xjquery.js"}},
		},
		{
			name:   "ng-version-in-body-text",
			reason: "'ng-version' sits in prose, not an attribute; the dom rule must not fire Angular",
			page:   matcher.Page{HTML: `<p>our ng-version is 15.1.2, we love it</p>`},
		},
		{
			name:   "server-name-in-body-text",
			reason: "a footer brag 'Powered by nginx' is not the Server header; Nginx must not fire from body text",
			page:   matcher.Page{HTML: `<footer>Powered by nginx and tomcat</footer>`},
		},
		{
			name:   "generator-in-html-comment",
			reason: "generator sits in an HTML comment, not a <meta> tag, and no /wp-content path is present",
			page:   matcher.Page{HTML: `<!-- generator: WordPress 6.5.2 --><html><body>hi</body></html>`},
		},
	}
}

// producerFixtureDir holds OPTIONAL producer-real captures the operator drops in: one
// JSON file per case, {"name":..,"page":{<matcher.Page>},"truth":[..]}. The harness
// folds any it finds into the golden corpus, so a real-traffic capture grows coverage
// with zero code change. Empty by default — committing third-party captures would carry
// their license (see the license policy in README.md), so the operator owns whatever lands here. This is the
// seam for loading from a real producer (e.g. replayed scans); it does NOT fabricate.
const producerFixtureDir = "testdata/golden"

func producerFixtures(t *testing.T) []goldenCase {
	t.Helper()
	entries, err := os.ReadDir(producerFixtureDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read producer fixtures: %v", err)
	}
	var out []goldenCase
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(producerFixtureDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var c struct {
			Name  string       `json:"name"`
			Page  matcher.Page `json:"page"`
			Truth []string     `json:"truth"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		if c.Name == "" {
			c.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		out = append(out, goldenCase{name: c.Name, page: c.Page, truth: c.Truth})
	}
	return out
}

func baselineUniverse(db *schema.DB) []string {
	names := make([]string, 0, len(db.Fingerprints))
	for n := range db.Fingerprints {
		names = append(names, n)
	}
	return names
}

// TestGoldenCorpus runs the real baseline matcher over the positive golden set (plus
// any producer-real captures) and the hard-negative corpus, tallies PER-TECHNOLOGY,
// prints the per-tech table + coverage gap, and gates on the aggregate: precision must
// be 1.0 (no false positive) and recall must clear the documented floor.
func TestGoldenCorpus(t *testing.T) {
	db, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}

	positives := append(goldenSet(), producerFixtures(t)...)
	negatives := hardNegatives()

	rep := accuracyReport(db, positives, negatives, t)

	t.Logf("fixtures: %d positive (%d built-in + %d producer-real), %d hard-negative",
		len(positives), len(goldenSet()), len(positives)-len(goldenSet()), len(negatives))
	t.Logf("\n%s", rep.Render(baselineUniverse(db)))

	tot := rep.Total()
	p, r := tot.Precision(), tot.Recall()
	t.Logf("TOTAL: precision=%.3f recall=%.3f (TP=%d FP=%d FN=%d)",
		p, r, tot.TruePositive, tot.FalsePositive, tot.FalseNegative)
	if p != 1.0 {
		t.Errorf("precision = %.3f, want 1.0 (a false positive is a correctness bug)", p)
	}
	if r < recallFloor {
		t.Errorf("recall = %.3f, below documented floor %.2f", r, recallFloor)
	}
}

// accuracyReport folds the positive and negative corpora into one per-tech Report.
func accuracyReport(db *schema.DB, positives []goldenCase, negatives []negativeCase, t *testing.T) *Report {
	rep := NewReport()
	for _, c := range positives {
		got := detectedNames(matcher.Match(db, c.page))
		rep.Add(got, c.truth)
		t.Logf("+ %-24s detected=%v truth=%v", c.name, got, c.truth)
	}
	for _, c := range negatives {
		got := detectedNames(matcher.Match(db, c.page))
		rep.Add(got, nil) // nothing is true here: any detection is a false positive
		t.Logf("- %-24s detected=%v (want none — %s)", c.name, got, c.reason)
	}
	return rep
}

// TestHardNegatives asserts each hard-negative fires NOTHING, with a named message, and
// that the Apache-Coyote banner (which legitimately fires Tomcat) never leaks "Apache"
// HTTP Server — the classic over-match this corpus exists to catch.
func TestHardNegatives(t *testing.T) {
	db, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range hardNegatives() {
		t.Run(c.name, func(t *testing.T) {
			if got := detectedNames(matcher.Match(db, c.page)); len(got) != 0 {
				t.Errorf("false positive %v on %q (%s)", got, c.name, c.reason)
			}
		})
	}
	t.Run("coyote-not-apache-httpd", func(t *testing.T) {
		got := detectedNames(matcher.Match(db, matcher.Page{Headers: map[string][]string{"Server": {"Apache-Coyote/1.1"}}}))
		for _, d := range got {
			if d == "Apache" {
				t.Errorf("Apache-Coyote leaked a false 'Apache' HTTP Server detection (got %v)", got)
			}
		}
	})
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
