package matcher

import (
	"encoding/json"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/baseline"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

func db(fps map[string]schema.Fingerprint) *schema.DB {
	return &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: fps}
}

func find(dets []Detection, tech string) (Detection, bool) {
	for _, d := range dets {
		if d.Tech == tech {
			return d, true
		}
	}
	return Detection{}, false
}

func TestMatchHeaderVersionAndProvenance(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"Nginx": {
			Cats:       []int{22},
			Headers:    map[string]schema.StringList{"Server": {`nginx(?:/([\d.]+))?\;version:\1`}},
			Provenance: "baseline",
			License:    "Apache-2.0",
		},
	})
	got := Match(d, Page{Headers: map[string][]string{"server": {"nginx/1.18.0"}}})
	n, ok := find(got, "Nginx")
	if !ok {
		t.Fatal("Nginx not detected")
	}
	if n.Version != "1.18.0" {
		t.Fatalf("version = %q", n.Version)
	}
	if n.Confidence != 100 {
		t.Fatalf("confidence = %d", n.Confidence)
	}
	if n.Provenance != "baseline" || n.License != "Apache-2.0" {
		t.Fatalf("provenance/license = %q/%q", n.Provenance, n.License)
	}
}

func TestMatchImplies(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"WordPress": {Meta: map[string]schema.StringList{"generator": {`WordPress ?([\d.]+)?\;version:\1`}}, Implies: schema.StringList{"PHP"}},
		"PHP":       {Cats: []int{27}},
	})
	got := Match(d, Page{HTML: `<meta name="generator" content="WordPress 6.5.2">`})
	if w, ok := find(got, "WordPress"); !ok || w.Version != "6.5.2" {
		t.Fatalf("WordPress = %+v ok=%v", w, ok)
	}
	if _, ok := find(got, "PHP"); !ok {
		t.Fatal("PHP should be implied")
	}
}

func TestScriptSrcBoundaryGuard(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"jQuery": {ScriptSrc: schema.StringList{`jquery(?:[.-]([\d.]+))?(?:\.min)?\.js\;version:\1`}},
	})
	// a real jquery file detects; a hashed bundle that merely contains the letters does not
	if got := Match(d, Page{ScriptSrcs: []string{"/assets/jquery-3.6.0.min.js"}}); func() bool { _, ok := find(got, "jQuery"); return !ok }() {
		t.Fatal("real jquery src should detect")
	}
	if got := Match(d, Page{ScriptSrcs: []string{"/static/xjquery.js"}}); func() bool { _, ok := find(got, "jQuery"); return ok }() {
		t.Fatal("glued substring must not detect")
	}
}

func TestCookiePresence(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"PHP": {Cookies: map[string]schema.StringList{"PHPSESSID": {""}}},
	})
	got := Match(d, Page{Cookies: []string{"PHPSESSID=abc123; path=/; HttpOnly"}})
	if _, ok := find(got, "PHP"); !ok {
		t.Fatal("PHP should detect from PHPSESSID cookie")
	}
}

func TestNoFalsePositiveOnBlankPage(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"Nginx":     {Headers: map[string]schema.StringList{"Server": {`nginx\;version:\1`}}},
		"WordPress": {HTML: schema.StringList{"/wp-content/"}},
	})
	if got := Match(d, Page{HTML: "<html><body>hello</body></html>"}); len(got) != 0 {
		t.Fatalf("expected no detections, got %+v", got)
	}
}

func TestVersionRegexRefinesLeadOnly(t *testing.T) {
	// detection comes from a presence signal (no version); an alternate version_regex fills it
	d := db(map[string]schema.Fingerprint{
		"PHP": {
			Cookies:      map[string]schema.StringList{"PHPSESSID": {""}},
			VersionRegex: []string{`PHP/([\d.]+)\;version:\1`},
		},
	})
	got := Match(d, Page{
		Cookies: []string{"PHPSESSID=x"},
		HTML:    "served by PHP/8.2.1 somewhere",
	})
	p, ok := find(got, "PHP")
	if !ok || p.Version != "8.2.1" {
		t.Fatalf("PHP = %+v ok=%v", p, ok)
	}
	// without any detection signal, version_regex alone must not create a detection
	d2 := db(map[string]schema.Fingerprint{"PHP": {VersionRegex: []string{`PHP/([\d.]+)\;version:\1`}}})
	if got := Match(d2, Page{HTML: "PHP/8.2.1"}); len(got) != 0 {
		t.Fatalf("version_regex alone must not detect, got %+v", got)
	}
}

func TestDomRules(t *testing.T) {
	ng := db(map[string]schema.Fingerprint{
		"Angular": {Dom: json.RawMessage(`{"[ng-version]":{"attributes":{"ng-version":"([\\d.]+)\\;version:\\1"}}}`)},
	})
	vite := db(map[string]schema.Fingerprint{
		"Vite": {Dom: json.RawMessage(`{"#vite-legacy-polyfill":{"exists":""}}`)},
	})
	cases := []struct {
		name    string
		db      *schema.DB
		html    string
		tech    string
		want    bool
		version string
	}{
		{"ng-version attribute → Angular+version", ng, `<app-root ng-version="15.1.2"></app-root>`, "Angular", true, "15.1.2"},
		{"ng-version in body text only → no detect", ng, `<p>talking about ng-version here</p>`, "Angular", false, ""},
		{"no ng-version at all → no detect", ng, `<html><body>hi</body></html>`, "Angular", false, ""},
		{"vite-legacy-polyfill id present → Vite", vite, `<script type="module" id="vite-legacy-polyfill"></script>`, "Vite", true, ""},
		{"no vite marker → no detect", vite, `<div>plain page</div>`, "Vite", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Match(c.db, Page{HTML: c.html})
			d, ok := find(got, c.tech)
			if ok != c.want {
				t.Fatalf("detected=%v want=%v (got %+v)", ok, c.want, got)
			}
			if ok && d.Version != c.version {
				t.Fatalf("version=%q want=%q", d.Version, c.version)
			}
		})
	}
}

// TestBaselineApacheNotCoyote guards the real baseline Apache marker: it must
// detect Apache HTTP Server but never fire on Tomcat's "Apache-Coyote" banner
// (which is a distinct tech), matching how the upstream webappanalyzer data anchors
// the pattern. Regression for the over-broad "(?:Apache)(?:/...)?" that matched the
// "Apache" inside "Apache-Coyote/1.1".
func TestBaselineApacheNotCoyote(t *testing.T) {
	b, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}
	got := Match(b, Page{Headers: map[string][]string{"Server": {"Apache/2.4.57 (Debian)"}}})
	if d, ok := find(got, "Apache"); !ok || d.Version != "2.4.57" {
		t.Fatalf("real Apache = %+v ok=%v", d, ok)
	}
	got = Match(b, Page{Headers: map[string][]string{"Server": {"Apache-Coyote/1.1"}}})
	if _, ok := find(got, "Apache"); ok {
		t.Fatal("Apache-Coyote (Tomcat) must not be detected as Apache HTTP Server")
	}
	if _, ok := find(got, "Apache Tomcat"); !ok {
		t.Fatal("Apache-Coyote should still detect Apache Tomcat")
	}
}

// TestRequiredLitAlternationSafe guards fix #1: the longest-run pre-filter must not
// reject a page that matches one branch of an alternation. `(wordpress|joomla)` used
// to require "wordpress", dropping a joomla-only page the regex matches.
func TestRequiredLitAlternationSafe(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"CMS": {HTML: schema.StringList{`(wordpress|joomla)`}},
	})
	// positive: a page with only the second branch must detect
	if got := Match(d, Page{HTML: `<meta content="Powered by joomla">`}); func() bool { _, ok := find(got, "CMS"); return !ok }() {
		t.Fatal("joomla-only page must detect CMS")
	}
	// positive: the first branch still detects
	if got := Match(d, Page{HTML: `<div>wordpress site</div>`}); func() bool { _, ok := find(got, "CMS"); return !ok }() {
		t.Fatal("wordpress page must detect CMS")
	}
	// negative: a page with neither branch must not detect
	if got := Match(d, Page{HTML: `<div>plain drupal page</div>`}); func() bool { _, ok := find(got, "CMS"); return ok }() {
		t.Fatal("page with neither branch must not detect CMS")
	}
}

// TestRequiredLitUnit pins the pre-filter directly: a mandatory top-level literal is
// kept (optimization), an alternation branch literal is not required, and a letter
// made optional by a trailing quantifier is trimmed.
func TestRequiredLitUnit(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{`/wp-content/`, "content"},    // plain literal: longest required run
		{`(wordpress|joomla)`, ""},     // alternation branch is not required
		{`wordpress|joomla`, ""},       // top-level alternation: nothing required
		{`word(?:press)?`, "word"},     // optional group content is not required
		{`caches?`, "cache"},           // trailing ? makes the last letter optional
		{`apple(x|y)banana`, "banana"}, // literals around a group stay required
		{`abc`, ""},                    // shorter than the 4-char floor
	}
	for _, c := range cases {
		if got := requiredLit(c.expr); got != c.want {
			t.Errorf("requiredLit(%q) = %q, want %q", c.expr, got, c.want)
		}
	}
}

// TestResolveVersionDeterministic pins the resolution: the more specific version
// (more numeric components) wins, and the result does not depend on the order claims
// were recorded in — the old keep-first rule made the winner depend on map order.
func TestResolveVersionDeterministic(t *testing.T) {
	// "1.18.0" (3 components) beats "1.18" (2); they are a refinement, not a conflict
	v, conflict := resolveVersion([]VersionClaim{{Version: "1.18"}, {Version: "1.18.0"}})
	if v != "1.18.0" || conflict {
		t.Fatalf("refine: version=%q conflict=%v, want 1.18.0/false", v, conflict)
	}
	// order of claims must not change the outcome
	v2, _ := resolveVersion([]VersionClaim{{Version: "1.18.0"}, {Version: "1.18"}})
	if v2 != v {
		t.Fatalf("order dependence: %q vs %q", v, v2)
	}
	// genuinely incompatible versions: pick is deterministic and conflict is flagged
	v, conflict = resolveVersion([]VersionClaim{{Version: "10"}, {Version: "9.5"}})
	if v != "9.5" || !conflict { // "9.5" has more numeric components than "10"
		t.Fatalf("conflict: version=%q conflict=%v, want 9.5/true", v, conflict)
	}
}

// TestVersionConflictDeterministic is the core regression: two headers of the same
// tech capture different, incompatible versions. Map iteration over the header
// patterns used to decide which version survived, so the output flapped between runs.
// Running Match 100 times must yield an identical Detection every time, and the
// conflict must be surfaced honestly.
func TestVersionConflictDeterministic(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"Acme": {Headers: map[string]schema.StringList{
			"X-Acme-A": {`v([\d.]+)\;version:\1`},
			"X-Acme-B": {`v([\d.]+)\;version:\1`},
		}},
	})
	page := Page{Headers: map[string][]string{
		"x-acme-a": {"v10"},
		"x-acme-b": {"v9.5"},
	}}

	first := Match(d, page)
	want, _ := json.Marshal(first)
	for i := 0; i < 100; i++ {
		got, _ := json.Marshal(Match(d, page))
		if string(got) != string(want) {
			t.Fatalf("run %d differs:\n first=%s\n got  =%s", i, want, got)
		}
	}
	a, ok := find(first, "Acme")
	if !ok {
		t.Fatal("Acme not detected")
	}
	if !a.VersionConflict {
		t.Fatalf("expected VersionConflict=true, got %+v", a)
	}
	if len(a.VersionClaims) != 2 {
		t.Fatalf("expected 2 distinct claims, got %+v", a.VersionClaims)
	}
}

// TestEvidenceTracesTheLead checks the explain flow: a header detection carries one
// MatchEvidence naming the field, the pattern that fired and the actual matched
// string; an implied technology carries none (it has no direct signal, so inventing
// evidence would be a lie).
func TestEvidenceTracesTheLead(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"WordPress": {Meta: map[string]schema.StringList{"generator": {`WordPress ?([\d.]+)?\;version:\1`}}, Implies: schema.StringList{"PHP"}},
		"PHP":       {Cats: []int{27}},
		"Nginx":     {Headers: map[string]schema.StringList{"Server": {`nginx(?:/([\d.]+))?\;version:\1`}}},
	})
	got := Match(d, Page{
		Headers: map[string][]string{"server": {"nginx/1.18.0"}},
		HTML:    `<meta name="generator" content="WordPress 6.5.2">`,
	})

	n, ok := find(got, "Nginx")
	if !ok || len(n.Evidence) != 1 {
		t.Fatalf("Nginx evidence = %+v ok=%v", n.Evidence, ok)
	}
	ev := n.Evidence[0]
	if ev.Field != "header" || ev.Pattern == "" || ev.Matched != "nginx/1.18.0" {
		t.Fatalf("evidence = %+v, want field=header, non-empty pattern, matched=nginx/1.18.0", ev)
	}

	// positive: the HTML/meta detection also records its field
	w, ok := find(got, "WordPress")
	if !ok || len(w.Evidence) == 0 || w.Evidence[0].Field != "meta" {
		t.Fatalf("WordPress evidence = %+v ok=%v", w.Evidence, ok)
	}

	// negative: an implied technology has no direct evidence — none must be fabricated
	p, ok := find(got, "PHP")
	if !ok {
		t.Fatal("PHP should be implied")
	}
	if len(p.Evidence) != 0 {
		t.Fatalf("implied PHP must carry no evidence, got %+v", p.Evidence)
	}
}

func TestConfidenceSuffixLowersAndSums(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"Weak": {HTML: schema.StringList{`data-weak-marker\;confidence:50`}},
	})
	got := Match(d, Page{HTML: `<div data-weak-marker="1">`})
	w, ok := find(got, "Weak")
	if !ok || w.Confidence != 50 {
		t.Fatalf("Weak = %+v ok=%v", w, ok)
	}
}
