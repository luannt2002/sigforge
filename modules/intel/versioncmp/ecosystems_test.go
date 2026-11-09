package versioncmp

import "testing"

type cmpCase struct {
	eco, a, b string
	want      int
}

func checkCases(t *testing.T, cases []cmpCase) {
	t.Helper()
	for _, c := range cases {
		got, ok := Compare(c.eco, c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("Compare(%q,%q,%q) = %d ok=%v; want %d", c.eco, c.a, c.b, got, ok, c.want)
		}
	}
}

// Every OSV ecosystem name — with its release suffix, as advisory records carry it — orders by
// the algorithm OSV itself uses for that ecosystem, not by a semver guess.
func TestOSVEcosystemNamesPickTheirScheme(t *testing.T) {
	checkCases(t, []cmpCase{
		{"Debian:12", "1:1.0-1", "2.0-1", 1},
		{"Ubuntu:22.04:LTS", "1.0~rc1-1", "1.0-1", -1},
		{"Echo", "1:1.0", "2.0", 1},
		{"Rocky Linux:8", "1:0.1-1", "0.2-1", 1},
		{"AlmaLinux:9", "1.0-10.el9", "1.0-9.el9", 1},
		{"Red Hat:enterprise_linux:8::baseos", "1.0-10", "1.0-9", 1},
		{"SUSE:Linux Enterprise Server 15 SP5", "1.0-10", "1.0-9", 1},
		{"openSUSE:Leap 15.5", "1.0-10", "1.0-9", 1},
		{"Mageia:9", "1.0-10.mga9", "1.0-9.mga9", 1},
		{"openEuler:22.03-LTS", "1.0-10", "1.0-9", 1},
		{"Alpine:v3.16", "1.2.3-r10", "1.2.3-r9", 1},
		{"Wolfi", "1.2.3-r10", "1.2.3-r9", 1},
		{"Chainguard", "1.2.3_rc1-r0", "1.2.3-r0", -1},
		{"MinimOS", "1.2.3-r10", "1.2.3-r9", 1},
		{"Hex", "1.0.0-rc.10", "1.0.0-rc.9", 1},
		{"SwiftURL", "1.0.0", "1.0.1", -1},
		{"Bitnami", "1.0.0", "1.0.1", -1},
		{"ConanCenter", "1.0.0", "1.0.1", -1},
		{"Maven:https://repo.maven.apache.org/maven2", "1.0-alpha", "1.0", -1},
	})
}

// An ecosystem with no ordering here is never guessed: ok=false keeps the version unknown.
// The empty ecosystem keeps its documented semver default.
func TestUnsupportedEcosystemIsNotGuessed(t *testing.T) {
	for _, eco := range []string{"GitHub Actions", "Linux", "Android", "OSS-Fuzz", "Photon OS:3.0", "Julia-ish"} {
		if c, ok := Compare(eco, "1.0.0", "2.0.0"); ok {
			t.Errorf("Compare(%q) = %d ok=true; an ecosystem without an ordering must be ok=false", eco, c)
		}
	}
	if c, ok := Compare("", "1.0.0", "2.0.0"); !ok || c != -1 {
		t.Errorf(`Compare("") = %d ok=%v; want the semver default -1`, c, ok)
	}
}

// Alpine apk ordering (apk-tools; the same rules OSV applies to Alpine-family records).
func TestAlpine(t *testing.T) {
	checkCases(t, []cmpCase{
		{"Alpine", "1.2.3-r10", "1.2.3-r9", 1}, // build number is numeric
		{"Alpine", "1.2.3_rc1-r0", "1.2.3-r0", -1},
		{"Alpine", "1.2.3_p1-r0", "1.2.3-r0", 1},
		{"Alpine", "2.0_alpha", "2.0_beta", -1},
		{"Alpine", "2.0_beta", "2.0_pre", -1},
		{"Alpine", "2.0_pre", "2.0_rc", -1},
		{"Alpine", "2.0_rc", "2.0", -1},
		{"Alpine", "2.0", "2.0_svn", -1},
		{"Alpine", "2.0_git", "2.0_hg", -1},
		{"Alpine", "2.0_hg", "2.0_p1", -1},
		{"Alpine", "2.0_rc2", "2.0_rc10", -1},
		{"Alpine", "1.2.3a", "1.2.3", 1}, // a letter ranks above none
		{"Alpine", "1.2.3b", "1.2.3a", 1},
		{"Alpine", "1.10", "1.9", 1},
		{"Alpine", "1.01", "1.1", -1}, // a leading zero after the first component compares as text
		{"Alpine", "1.0", "1", 0},
		{"Alpine", "1.2.3-r0", "1.2.3", 0},
		{"Alpine", "1.2.3~a1b2c3-r1", "1.2.3-r1", 0}, // the commit hash never orders
		{"Alpine", "1.1.1t-r0", "1.1.1s-r0", 1},
		{"Alpine", "3.0.8-r0", "1.1.1t-r0", 1},
	})
	for _, bad := range []string{"", "abc", "1.2.3-x1", "1.2.3_zz1"} {
		if _, ok := Compare("Alpine", bad, "1.0"); ok {
			t.Errorf("Compare(Alpine,%q) ok=true; an invalid apk version must be ok=false", bad)
		}
	}
}

// NuGet: up to four numeric parts, pre-release labels compared case-insensitively.
func TestNuGet(t *testing.T) {
	checkCases(t, []cmpCase{
		{"NuGet", "1.0.0-Beta", "1.0.0-alpha", 1},
		{"NuGet", "1.0.0-BETA", "1.0.0-beta", 0},
		{"NuGet", "1.2.3.4", "1.2.3.10", -1},
		{"NuGet", "1.0", "1.0.0.0", 0},
		{"NuGet", "1.0.0-rc.1", "1.0.0", -1},
		{"NuGet", "1.0.0+meta", "1.0.0", 0},
	})
}

// Packagist: Composer / PHP version_compare ordering (dev < alpha < beta < RC < release < patch).
func TestPackagist(t *testing.T) {
	checkCases(t, []cmpCase{
		{"Packagist", "1.0.0-beta10", "1.0.0-beta9", 1},
		{"Packagist", "v2.4.1.3", "2.4.1.2", 1},
		{"Packagist", "1.0.0-p1", "1.0.0", 1},
		{"Packagist", "1.0.0-patch1", "1.0.0", 1},
		{"Packagist", "1.0.0-RC1", "1.0.0", -1},
		{"Packagist", "1.0.0-rc1", "1.0.0-RC1", 0},
		{"Packagist", "1.0.0-alpha", "1.0.0-beta", -1},
		{"Packagist", "1.0.0-alpha2", "1.0.0-a2", 0},
		{"Packagist", "1.0.0-dev", "1.0.0-alpha", -1},
		{"Packagist", "1.0.0", "v1.0.0", 0},
		{"Packagist", "5.4.10", "5.4.9", 1},
		{"Packagist", "1.0.0.1", "1.0.0", 1}, // the longer one continuing with a number ranks above
	})
	if _, ok := Compare("Packagist", "dev-master", "1.0.0"); ok {
		t.Error("a Composer branch name (dev-master) is not a version; want ok=false")
	}
}

// Pub: semver, but build metadata orders (1.0.0+1 > 1.0.0), compared like pre-release identifiers.
func TestPub(t *testing.T) {
	checkCases(t, []cmpCase{
		{"Pub", "1.0.0+1", "1.0.0", 1},
		{"Pub", "1.0.0+10", "1.0.0+9", 1},
		{"Pub", "1.0.0-dev", "1.0.0", -1},
		{"Pub", "1.0.0-dev+1", "1.0.0", -1},
		{"Pub", "2.0.0", "1.9.9+5", 1},
	})
}

// Hackage (PVP) and CRAN: numeric component lists, a longer list ranks above its own prefix.
func TestHackageAndCRAN(t *testing.T) {
	checkCases(t, []cmpCase{
		{"Hackage", "1.2.3.4", "1.2.3.10", -1},
		{"Hackage", "1.0", "1.0.0", -1},
		{"Hackage", "1.10", "1.9", 1},
		{"CRAN", "1.2-10", "1.2-9", 1},
		{"CRAN", "0.9-1", "0.9.1", 0},
		{"CRAN", "1.0", "1.0.0", -1},
		{"CRAN", "01.2", "1.2", 0},
	})
	for _, c := range [][2]string{{"Hackage", "1.0-tag"}, {"CRAN", "1.2a"}, {"CRAN", "1..2"}} {
		if _, ok := Compare(c[0], c[1], "1.0"); ok {
			t.Errorf("Compare(%s,%q) ok=true; want ok=false", c[0], c[1])
		}
	}
}

// RPM compares epoch, then version, then release — each on its own — the way rpm and OSV's
// Red Hat ordering do. Running rpmvercmp over the whole "epoch:version-release" string compares
// a missing epoch's version against the other's epoch, and one version's release against the
// other's version segment.
func TestRPMEpochVersionRelease(t *testing.T) {
	checkCases(t, []cmpCase{
		{"AlmaLinux:9", "8.2.2637-20.el9_1", "2:8.2.2637-21.el9", -1}, // a missing epoch is 0
		{"Rocky Linux:8", "1:0.1-1", "0.2-1", 1},
		{"rpm", "1.2-10", "1.2.1-1", -1}, // version 1.2 < 1.2.1 whatever the releases
		{"rpm", "1:1.0-1.el8", "1:1.0-2.el8", -1},
		{"rpm", "1.0-1.el8", "1.0-1.el8", 0},
		{"rpm", "2:1.0-1", "10:0.1-1", -1}, // epochs compare as numbers
	})
	if _, ok := Compare("rpm", "1.2", "1.2-5.el9"); ok {
		t.Error("the same version with a release on one side only cannot be ordered; want ok=false")
	}
}

// Gem::Version compares canonical segments: trailing zeros are dropped from the release part and
// the pre-release part separately, so 2.0.0.rc1 is 2.rc1 — below 2.0.rc2 (2.rc2).
func TestRubyGemsCanonicalSegments(t *testing.T) {
	checkCases(t, []cmpCase{
		{"RubyGems", "2.0.0.rc1", "2.0.rc2", -1},
		{"gem", "1.0.a", "1.a", 0},
		{"RubyGems", "1.0", "1", 0},
	})
}
