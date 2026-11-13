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

// TestConflictKeepsSourceCPEAsUnverifiedCandidate guards the CPE identity-contamination
// fix: when the winner lacks a CPE and a losing entry of the same tech name carries one
// (possibly a DIFFERENT edition/fork — f5:nginx vs the winner's unknown identity), the
// source CPE must NOT be promoted to the winner's verified CPE. It is kept as an
// unverified cpe_candidate, tagged with the source's own provenance+license, so a CVE
// lookup (which reads only CPE) never silently trusts an identity from another entry.
func TestConflictKeepsSourceCPEAsUnverifiedCandidate(t *testing.T) {
	base := map[string]schema.Fingerprint{
		"Nginx":     {Headers: map[string]schema.StringList{"Server": {"nginx"}}}, // no CPE
		"WordPress": {CPE: []string{"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"}},
	}
	src := Source{Name: "webappanalyzer", Trust: 5, Set: map[string]schema.Fingerprint{
		"Nginx":     {CPE: []string{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}, License: "GPL-3.0-only"}, // a DIFFERENT edition's CPE
		"WordPress": {CPE: []string{"cpe:2.3:a:other:other:*:*:*:*:*:*:*:*"}},                       // must NOT override baseline's
	}}
	out := Merge(base, src)

	// The borrowed CPE must NOT become the winner's verified CPE (identity contamination).
	if got := out["Nginx"].CPE; len(got) != 0 {
		t.Fatalf("source CPE must NOT be promoted to the winner's verified CPE, got %v", got)
	}
	// It is kept as an unverified candidate lead instead.
	cand := out["Nginx"].CPECandidate
	if len(cand) != 1 || cand[0] != "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*" {
		t.Fatalf("source CPE should be kept as an unverified candidate, got %v", cand)
	}
	// Tagged with the SOURCE's provenance+license, not the winner's.
	prov := out["Nginx"].CPECandidateProv
	if len(prov) != len(cand) {
		t.Fatalf("CPECandidateProv must align with CPECandidate: %d vs %d", len(prov), len(cand))
	}
	if prov[0].Provenance != "webappanalyzer" || prov[0].License != "GPL-3.0-only" {
		t.Fatalf("candidate CPE must carry the source's provenance+license, got %q/%q", prov[0].Provenance, prov[0].License)
	}

	// A baseline that HAS its own CPE keeps it and borrows no candidate.
	if got := out["WordPress"].CPE; len(got) != 1 || got[0] != "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*" {
		t.Fatalf("baseline CPE must win over source, got %v", got)
	}
	if got := out["WordPress"].CPECandidate; len(got) != 0 {
		t.Fatalf("a winner with its own CPE must borrow no candidate, got %v", got)
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

// TestAlternateKeepsSourceLicenseNotWinnerLicense guards the license tag of an alternate: when a GPL
// source's version pattern is pooled as an alternate under an Apache baseline
// winner, that alternate must carry its own GPL provenance — never be served under
// the winner's Apache license (a mislabel the license policy in README.md rules out).
func TestAlternateKeepsSourceLicenseNotWinnerLicense(t *testing.T) {
	base := map[string]schema.Fingerprint{
		"Nginx": {
			Headers: map[string]schema.StringList{"Server": {`nginx(?:/([\d.]+))?\;version:\1`}},
			License: "Apache-2.0",
		},
	}
	src := Source{Name: "thirdparty", Trust: 10, Set: map[string]schema.Fingerprint{
		"Nginx": {
			Headers: map[string]schema.StringList{"Server": {`Nginx v([\d.]+)\;version:\1`}},
			License: "GPL-3.0-only",
		},
	}}
	out := Merge(base, src)
	nginx := out["Nginx"]

	// Baseline wins the entry, so the entry-level license stays Apache.
	if nginx.Provenance != "baseline" || nginx.License != "Apache-2.0" {
		t.Fatalf("baseline should win entry: prov=%q license=%q", nginx.Provenance, nginx.License)
	}
	if len(nginx.VersionRegex) != len(nginx.VersionRegexProv) {
		t.Fatalf("VersionRegexProv must align with VersionRegex: %d vs %d", len(nginx.VersionRegex), len(nginx.VersionRegexProv))
	}
	// The pooled GPL pattern must carry GPL provenance, not the winner's Apache.
	want := `Nginx v([\d.]+)\;version:\1`
	var found bool
	for i, rx := range nginx.VersionRegex {
		if rx != want {
			continue
		}
		found = true
		p := nginx.VersionRegexProv[i]
		if p.License != "GPL-3.0-only" || p.Provenance != "thirdparty" {
			t.Fatalf("GPL alternate mislabeled as %q/%q (want thirdparty/GPL-3.0-only)", p.Provenance, p.License)
		}
	}
	if !found {
		t.Fatalf("GPL alternate not kept: %v", nginx.VersionRegex)
	}
}

func TestMergeDoesNotMutateInputs(t *testing.T) {
	base := map[string]schema.Fingerprint{"Nginx": {}}
	_ = Merge(base)
	if base["Nginx"].Provenance != "" {
		t.Fatal("Merge mutated the baseline input")
	}
}
