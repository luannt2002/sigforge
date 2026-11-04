package matcher

import (
	"testing"

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
