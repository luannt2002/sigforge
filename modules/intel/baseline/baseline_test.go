package baseline

import (
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/matcher"
)

func TestBaselineLoadsAndIsStamped(t *testing.T) {
	db, err := DB()
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Fingerprints) == 0 {
		t.Fatal("empty baseline")
	}
	for _, want := range []string{"Nginx", "WordPress", "jQuery", "Cloudflare", "PHP"} {
		if _, ok := db.Fingerprints[want]; !ok {
			t.Errorf("baseline missing %q", want)
		}
	}
	for name, fp := range db.Fingerprints {
		if fp.Provenance == "" || fp.License == "" {
			t.Errorf("%q missing provenance/license", name)
		}
	}
}

func TestBaselineEndToEndDetect(t *testing.T) {
	db, err := DB()
	if err != nil {
		t.Fatal(err)
	}
	got := matcher.Match(db, matcher.Page{
		Headers:    map[string][]string{"Server": {"nginx/1.25.3"}, "X-Powered-By": {"PHP/8.2.0"}},
		HTML:       `<meta name="generator" content="WordPress 6.5">` + "\n/wp-content/themes/x/",
		ScriptSrcs: []string{"/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"},
	})
	for _, want := range []string{"Nginx", "PHP", "WordPress"} {
		if !has(got, want) {
			t.Errorf("expected %q detected, got %v", want, names(got))
		}
	}
}

func has(dets []matcher.Detection, tech string) bool {
	for _, d := range dets {
		if d.Tech == tech {
			return true
		}
	}
	return false
}

func names(dets []matcher.Detection) []string {
	out := make([]string, len(dets))
	for i, d := range dets {
		out[i] = d.Tech
	}
	return out
}
