package baseline

import (
	"strings"
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

// Major, versionable techs must carry a real CPE (the bridge to CVE/NVD), shaped
// as an application CPE 2.3 string. CDNs and bare JS libs with no NVD product are
// intentionally left without one, so this asserts only the techs that have a CPE.
func TestBaselineMajorTechsCarryApplicationCPE(t *testing.T) {
	db, err := DB()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Nginx", "Apache", "WordPress", "jQuery", "PHP", "Drupal", "Django", "Microsoft IIS"} {
		fp, ok := db.Fingerprints[want]
		if !ok {
			t.Errorf("baseline missing %q", want)
			continue
		}
		if len(fp.CPE) == 0 {
			t.Errorf("%q should carry a CPE", want)
			continue
		}
		for _, c := range fp.CPE {
			if !strings.HasPrefix(c, "cpe:2.3:a:") {
				t.Errorf("%q CPE %q is not an application cpe:2.3:a: string", want, c)
			}
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
