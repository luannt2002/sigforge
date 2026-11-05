package merge

import (
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

func TestBaselineWinsOnConflictAndKeepsAlternateVersion(t *testing.T) {
	base := map[string]schema.Fingerprint{
		"Nginx": {Headers: map[string]schema.StringList{"Server": {`nginx(?:/([\d.]+))?\;version:\1`}}},
	}
	src := Source{Name: "other", Trust: 10, Set: map[string]schema.Fingerprint{
		"Nginx": {Headers: map[string]schema.StringList{"Server": {`Nginx v([\d.]+)\;version:\1`}}},
	}}
	out := Merge(base, src)
	nginx := out["Nginx"]
	if nginx.Provenance != "baseline" {
		t.Fatalf("baseline must win, provenance = %q", nginx.Provenance)
	}
	// the baseline's own Server pattern must be untouched
	if nginx.Headers["Server"][0] != `nginx(?:/([\d.]+))?\;version:\1` {
		t.Fatalf("baseline header rewritten: %v", nginx.Headers["Server"])
	}
	// the losing source's version pattern is kept as an alternate
	found := false
	for _, vr := range nginx.VersionRegex {
		if vr == `Nginx v([\d.]+)\;version:\1` {
			found = true
		}
	}
	if !found {
		t.Fatalf("alternate version regex not kept: %v", nginx.VersionRegex)
	}
}

func TestConflictCarriesSourceCPEWhenBaselineHasNone(t *testing.T) {
	base := map[string]schema.Fingerprint{
		"Nginx":     {Headers: map[string]schema.StringList{"Server": {"nginx"}}}, // no CPE
		"WordPress": {CPE: []string{"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"}},
	}
	src := Source{Name: "webappanalyzer", Trust: 5, Set: map[string]schema.Fingerprint{
		"Nginx":     {CPE: []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}},
		"WordPress": {CPE: []string{"cpe:2.3:a:other:other:*:*:*:*:*:*:*:*"}}, // must NOT override baseline's
	}}
	out := Merge(base, src)
	if got := out["Nginx"].CPE; len(got) != 1 || got[0] != "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*" {
		t.Fatalf("baseline-without-CPE should adopt source CPE, got %v", got)
	}
	if got := out["WordPress"].CPE; len(got) != 1 || got[0] != "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*" {
		t.Fatalf("baseline CPE must win over source, got %v", got)
	}
}

func TestNewTechFromSourceIsStamped(t *testing.T) {
	base := map[string]schema.Fingerprint{"Nginx": {}}
	src := Source{Name: "nuclei", Trust: 1, Set: map[string]schema.Fingerprint{
		"Grafana": {Cats: []int{22}},
	}}
	out := Merge(base, src)
	g, ok := out["Grafana"]
	if !ok {
		t.Fatal("Grafana should be added")
	}
	if g.Provenance != "nuclei" {
		t.Fatalf("provenance = %q", g.Provenance)
	}
}

func TestSourcePrecedenceByTrust(t *testing.T) {
	base := map[string]schema.Fingerprint{"X": {}} // X exists so sources only add alternates
	hi := Source{Name: "hi", Trust: 10, Set: map[string]schema.Fingerprint{"Y": {Cats: []int{1}}}}
	lo := Source{Name: "lo", Trust: 1, Set: map[string]schema.Fingerprint{"Y": {Cats: []int{2}}}}
	out := Merge(base, lo, hi) // given low-first, but trust must order hi first
	if out["Y"].Cats[0] != 1 {
		t.Fatalf("higher trust should win for Y, got cats %v", out["Y"].Cats)
	}
}

func TestMergeDoesNotMutateInputs(t *testing.T) {
	base := map[string]schema.Fingerprint{"Nginx": {}}
	_ = Merge(base)
	if base["Nginx"].Provenance != "" {
		t.Fatal("Merge mutated the baseline input")
	}
}
