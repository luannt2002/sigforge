package matcher

import (
	"encoding/json"
	"sort"
	"strings"
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

// "Apache-Coyote/1.1" names the HTTP/1.1 connector, not the Tomcat release: it detects Tomcat with
// no version. The default error page's "Apache Tomcat/9.0.71" is the release.
func TestBaselineTomcatVersionIsTheReleaseNotTheConnector(t *testing.T) {
	db, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}
	version := func(p Page) (string, bool) {
		for _, d := range Match(db, p) {
			if d.Tech == "Apache Tomcat" {
				return d.Version, true
			}
		}
		return "", false
	}
	if v, ok := version(Page{Headers: map[string][]string{"Server": {"Apache-Coyote/1.1"}}}); !ok || v != "" {
		t.Errorf("Coyote banner: detected=%v version=%q, want Tomcat with no version", ok, v)
	}
	if v, ok := version(Page{HTML: "<h3>Apache Tomcat/9.0.71</h3>"}); !ok || v != "9.0.71" {
		t.Errorf("error page: detected=%v version=%q, want 9.0.71", ok, v)
	}
}

// A version is taken whole and from the thing it names: Jetty's release keeps its build qualifier
// (9.4.51.v20230217, not "9.4.51."), a file merely containing "bootstrap" (angular-ui-bootstrap) is
// not Bootstrap, and Tomcat's version comes from its error page heading or title, not from any sentence.
func TestBaselineVersionsAreWholeAndOwned(t *testing.T) {
	db, err := baseline.DB()
	if err != nil {
		t.Fatal(err)
	}
	ver := func(p Page, tech string) (string, bool) {
		d, ok := find(Match(db, p), tech)
		return d.Version, ok
	}
	if v, _ := ver(Page{Headers: map[string][]string{"Server": {"Jetty(9.4.51.v20230217)"}}}, "Jetty"); v != "9.4.51.v20230217" {
		t.Errorf("Jetty version = %q, want 9.4.51.v20230217", v)
	}
	if v, ok := ver(Page{ScriptSrcs: []string{"https://cdn.example/js/angular-ui-bootstrap-2.5.0.min.js"}}, "Bootstrap"); ok {
		t.Errorf("angular-ui-bootstrap read as Bootstrap %q", v)
	}
	if v, _ := ver(Page{ScriptSrcs: []string{"https://cdn.example/js/bootstrap-4.6.2.min.js"}}, "Bootstrap"); v != "4.6.2" {
		t.Errorf("bootstrap-4.6.2.min.js = %q, want 4.6.2", v)
	}
	for _, html := range []string{"<p>We migrated from Apache Tomcat/10.1.0 last year.</p>", "<p>Apache Tomcat/10.1.0</p>"} {
		if v, ok := ver(Page{HTML: html}, "Apache Tomcat"); ok {
			t.Errorf("%q gave Tomcat version %q", html, v)
		}
	}
}

// parse builds a DB from Wappalyzer-shaped JSON, so a test goes through the on-disk field
// names (requires / requiresCategory / excludes) a source actually writes.
func parse(t *testing.T, fingerprints string) *schema.DB {
	t.Helper()
	d, err := schema.Parse([]byte(`{"schema_version":"1.0.0","fingerprints":` + fingerprints + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// detected lists the detected techs sorted by name; an implied one (no evidence) is marked "*"
// and a labeled one is followed by its JSON excludedBy, e.g. "B<A,C" — the key a consumer reads.
func detected(dets []Detection) string {
	out := make([]string, 0, len(dets))
	for _, d := range dets {
		n := d.Tech
		if len(d.Evidence) == 0 {
			n += "*"
		}
		b, _ := json.Marshal(d)
		var label struct {
			ExcludedBy []string `json:"excludedBy"`
		}
		_ = json.Unmarshal(b, &label)
		if len(label.ExcludedBy) > 0 {
			n += "<" + strings.Join(label.ExcludedBy, ",")
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// A tech with requires counts only once a tech it requires is resolved, detected or implied.
// Like Wappalyzer, any one of several required techs suffices, and chains settle.
func TestRequiresGatesDetection(t *testing.T) {
	d := parse(t, `{
		"WordPress": {"meta": {"generator": "^WordPress"}},
		"WP Plugin": {"html": "wp-plugin-marker", "implies": "WordPress"},
		"Joomla":    {"meta": {"generator": "^Joomla"}},
		"Dependent": {"html": "dependent-marker", "requires": ["WordPress"]},
		"Child":     {"html": "child-marker", "requires": "Dependent"},
		"Either":    {"html": "either-marker", "requires": ["Joomla", "WordPress"]}
	}`)
	wp := `<meta name="generator" content="WordPress 6.5">`
	cases := []struct{ name, html, want string }{
		{"required tech absent", `dependent-marker child-marker either-marker`, ""},
		{"required tech detected", wp + `dependent-marker`, "Dependent WordPress"},
		{"required tech implied", `wp-plugin-marker dependent-marker`, "Dependent WP Plugin WordPress*"},
		{"chain settles", wp + `dependent-marker child-marker`, "Child Dependent WordPress"},
		{"chain without its root", `dependent-marker child-marker`, ""},
		{"any one required tech suffices", wp + `either-marker`, "Either WordPress"},
	}
	for _, c := range cases {
		if got := detected(Match(d, Page{HTML: c.html})); got != c.want {
			t.Errorf("%s: detected %q, want %q", c.name, got, c.want)
		}
	}
}

// A resolved tech labels, never drops, each tech it excludes (house rule: no lead is dropped or
// hidden). The excluded tech stays with excludedBy whether present directly or implied, an
// implied excluder labels too, a tech present only through implies from labeled techs inherits
// their label, a labeled tech still meets a requires gate (an edition that requires and excludes
// its base stays unlabeled: a tech never labels itself), and without the excluder nothing is labeled.
func TestExcludesLabelsExcludedTech(t *testing.T) {
	d := parse(t, `{
		"A":       {"html": "a-marker", "excludes": ["B"]},
		"B":       {"html": "b-marker", "implies": "BLang"},
		"BLang":   {},
		"C":       {"html": "c-marker", "implies": "B"},
		"D":       {"html": "d-marker", "implies": "BLang"},
		"E":       {"html": "e-source", "implies": "A"},
		"Base":    {"html": "base-marker"},
		"Edition": {"html": "edition-marker", "requires": ["Base"], "excludes": ["Base"]}
	}`)
	cases := []struct{ name, html, want string }{
		{"excluder absent", `b-marker`, "B BLang*"},
		{"excluder detected", `a-marker b-marker`, "A B<A BLang*<A"},
		{"excluded tech present through implies", `a-marker c-marker`, "A B*<A BLang*<A C"},
		{"implied tech also supported by an unlabeled tech", `a-marker b-marker d-marker`, "A B<A BLang* D"},
		{"implied excluder", `e-source b-marker`, "A* B<A BLang*<A E"},
		{"edition labels the base it requires", `base-marker edition-marker`, "Base<Edition Edition"},
		{"edition without its base", `edition-marker`, ""},
	}
	for _, c := range cases {
		if got := detected(Match(d, Page{HTML: c.html})); got != c.want {
			t.Errorf("%s: detected %q, want %q", c.name, got, c.want)
		}
	}
}

// The label only adds excludedBy: the excluded tech keeps its confidence, version and evidence,
// and an unlabeled detection's JSON carries no excludedBy key.
func TestExcludedTechKeepsItsLead(t *testing.T) {
	d := parse(t, `{
		"A": {"html": "a-marker", "excludes": ["B"]},
		"B": {"html": "b-marker-([\\d.]+)\\;version:\\1\\;confidence:60"}
	}`)
	alone, _ := find(Match(d, Page{HTML: `b-marker-1.2`}), "B")
	excluded, ok := find(Match(d, Page{HTML: `a-marker b-marker-1.2`}), "B")
	if !ok {
		t.Fatal("an excluded tech must stay in the result")
	}
	plain, _ := json.Marshal(alone)
	if strings.Contains(string(plain), "excludedBy") {
		t.Fatalf("an unlabeled detection carries excludedBy: %s", plain)
	}
	b, _ := json.Marshal(excluded)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if got := string(fields["excludedBy"]); got != `["A"]` {
		t.Errorf(`excludedBy = %s, want ["A"]`, got)
	}
	delete(fields, "excludedBy")
	rest, _ := json.Marshal(fields)
	var want map[string]json.RawMessage
	_ = json.Unmarshal(plain, &want)
	if wantJSON, _ := json.Marshal(want); string(rest) != string(wantJSON) {
		t.Errorf("labeling changed the lead:\n got  %s\n want %s", rest, wantJSON)
	}
}

// Techs that exclude each other, all detected, are all kept and each labeled with the others
// (real data: Angular/AngularJS, Lodash/Underscore.js) — the same on every run, no order decides.
func TestMutualExcludesLabelBoth(t *testing.T) {
	d := parse(t, `{
		"Alpha": {"html": "alpha-marker", "excludes": ["Beta"]},
		"Beta":  {"html": "beta-marker", "excludes": ["Alpha", "Gamma"]},
		"Gamma": {"html": "gamma-marker", "excludes": ["Beta"]}
	}`)
	for i := 0; i < 50; i++ {
		if got := detected(Match(d, Page{HTML: `alpha-marker beta-marker gamma-marker`})); got != "Alpha<Beta Beta<Alpha,Gamma Gamma<Beta" {
			t.Fatalf("run %d: detected %q, want all three, each labeled", i, got)
		}
	}
}

// A tech never labels itself: not through its own excludes, and not by inheriting a label that
// names it (A implies B, B excludes A, B present only through A: A carries B, B carries nothing).
func TestTechNeverLabelsItself(t *testing.T) {
	d := parse(t, `{
		"A":    {"html": "a-marker", "implies": "B"},
		"B":    {"excludes": ["A"]},
		"Self": {"html": "self-marker", "excludes": ["Self"]}
	}`)
	cases := []struct{ name, html, want string }{
		{"inherited label names the tech itself", `a-marker`, "A<B B*"},
		{"tech excluding itself", `self-marker`, "Self"},
	}
	for _, c := range cases {
		if got := detected(Match(d, Page{HTML: c.html})); got != c.want {
			t.Errorf("%s: detected %q, want %q", c.name, got, c.want)
		}
	}
}

// requiresCategory is met by the cats of a resolved tech, an implied one included.
func TestRequiresCategoryGatesDetection(t *testing.T) {
	d := parse(t, `{
		"Shop":     {"cats": [6], "headers": {"X-Shop": ""}},
		"Theme":    {"cats": [80], "html": "shop-theme-marker", "implies": "Shop"},
		"Blog":     {"cats": [1], "headers": {"X-Blog": ""}},
		"Payments": {"cats": [41], "html": "pay-widget", "requiresCategory": [6]}
	}`)
	cases := []struct {
		name string
		page Page
		want string
	}{
		{"no tech in the category", Page{HTML: "pay-widget", Headers: map[string][]string{"X-Blog": {"1"}}}, "Blog"},
		{"tech in the category", Page{HTML: "pay-widget", Headers: map[string][]string{"X-Shop": {"1"}}}, "Payments Shop"},
		{"implied tech in the category", Page{HTML: "shop-theme-marker pay-widget"}, "Payments Shop* Theme"},
	}
	for _, c := range cases {
		if got := detected(Match(d, c.page)); got != c.want {
			t.Errorf("%s: detected %q, want %q", c.name, got, c.want)
		}
	}
}

// A gated tech's own match never resolves its own requirement: not when it implies the very
// tech it requires (real data: Quasar requires and implies Vue.js), nor when its own category is
// the required one; with the requirement on the page it counts. A gated tech another resolved
// tech implies is returned, as an implied detection, even when its requirement is not resolved.
func TestGatedTechDoesNotMeetItsOwnRequirement(t *testing.T) {
	d := parse(t, `{
		"Vue":    {"html": "vue-marker"},
		"Quasar": {"html": "quasar-marker", "requires": ["Vue"], "implies": "Vue"},
		"Plugin": {"html": "plugin-marker", "implies": "Quasar"},
		"Shop":   {"cats": [6], "html": "shopcat-marker", "requiresCategory": [6]},
		"Dep":    {"html": "dep-marker", "requires": ["Vue"]},
		"DepImplier": {"html": "depimplier-marker", "implies": "Dep"}
	}`)
	cases := []struct{ name, html, want string }{
		{"own match implies its requirement", `quasar-marker`, ""},
		{"own category is its required category", `shopcat-marker`, ""},
		{"requirement on the page", `quasar-marker vue-marker`, "Quasar Vue"},
		{"implied by another tech, which brings its implies along", `plugin-marker`, "Plugin Quasar* Vue*"},
		{"implied by another tech, requirement not resolved", `depimplier-marker`, "Dep* DepImplier"},
	}
	for _, c := range cases {
		if got := detected(Match(d, Page{HTML: c.html})); got != c.want {
			t.Errorf("%s: detected %q, want %q", c.name, got, c.want)
		}
	}
}

// An inherited label follows every implies step: A excludes L, and L implies U implies T, each
// present only through the one before, so L, U and T all carry A.
func TestExcludedByFollowsImpliesChain(t *testing.T) {
	d := parse(t, `{
		"A": {"html": "a-marker", "excludes": ["L"]},
		"L": {"html": "l-marker", "implies": "U"},
		"U": {"implies": "T"},
		"T": {}
	}`)
	if got := detected(Match(d, Page{HTML: `a-marker l-marker`})); got != "A L<A T*<A U*<A" {
		t.Errorf("detected %q, want %q", got, "A L<A T*<A U*<A")
	}
}

// A requires/excludes/implies reference may carry a `\;confidence:` or `\;version:` suffix (real
// data: 12 of 1409 implies do); it still names the tech before the suffix.
func TestReferencesIgnoreTheirSuffix(t *testing.T) {
	d := parse(t, `{
		"Base":  {"html": "base-marker"},
		"Dep":   {"html": "dep-marker", "requires": "Base\\;confidence:50"},
		"X":     {"html": "x-marker", "excludes": "Y\\;version:2"},
		"Y":     {"html": "y-marker", "implies": "YLang\\;confidence:50"},
		"YLang": {}
	}`)
	cases := []struct{ name, html, want string }{
		{"requires with a suffix", `base-marker dep-marker`, "Base Dep"},
		{"excludes and implies with a suffix", `x-marker y-marker`, "X Y<X YLang*<X"},
	}
	for _, c := range cases {
		if got := detected(Match(d, Page{HTML: c.html})); got != c.want {
			t.Errorf("%s: detected %q, want %q", c.name, got, c.want)
		}
	}
}
