// Three accuracy dimensions BEYOND fingerprint detection, each measured against
// hand-LABELLED fixtures (not real web traffic — the fixtures are built from the
// labels, see each case's `why`). The matcher proves "we SAW the tech"; these prove
// the three judgments a consumer actually acts on are correct:
//
//	identity-accuracy      — a tech name resolves to the RIGHT CPE, or honestly to Unknown
//	                         (never a fabricated CPE that would point CVE lookups at the
//	                         wrong product). identity.Match / ResolveCPE are the oracle.
//	version-accuracy       — conflicting version claims resolve DETERMINISTICALLY and are
//	                         flagged, a dotted refinement is NOT a conflict, and
//	                         versioncmp orders each ecosystem by its own rules.
//	applicability-accuracy — every provider's typed result maps to the RIGHT unified.State,
//	                         and an UNKNOWN never becomes "clean".
//
// Everything is hermetic and pure (identity.Match, versioncmp.Compare, matcher.Match
// on a constructed DB, each adapter's ToUnified) — no network, so the numbers printed
// under `go test -v` come straight from the running oracle code, never hard-coded.
package accuracy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/versioncmp"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// ---------------------------------------------------------------------------
// DIMENSION 1 — identity-accuracy
// ---------------------------------------------------------------------------

// identityDictJSON is a tiny NVD-2.0-shaped CPE dictionary sample, parsed by the real
// identity.ParseDict so the test exercises parse+match together. It is built to carry
// a deliberate AMBIGUITY (product "server" under two different vendors) so the
// "ambiguous → Unknown, no fabricated CPE" rule is actually measured, which the
// embedded public-domain snapshot (unique products) cannot do.
const identityDictJSON = `{"products":[
  {"cpe":{"cpeName":"cpe:2.3:a:nginx:nginx:1.21.0:*:*:*:*:*:*:*","titles":[{"title":"nginx","lang":"en"}]}},
  {"cpe":{"cpeName":"cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*","titles":[{"title":"Apache HTTP Server","lang":"en"}]}},
  {"cpe":{"cpeName":"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*","titles":[{"title":"OpenSSL","lang":"en"}]}},
  {"cpe":{"cpeName":"cpe:2.3:a:acme:server:1.0:*:*:*:*:*:*:*","titles":[{"title":"Acme Server","lang":"en"}]}},
  {"cpe":{"cpeName":"cpe:2.3:a:globex:server:2.0:*:*:*:*:*:*:*","titles":[{"title":"Globex Server","lang":"en"}]}}
]}`

type identityCase struct {
	name, vendor, product string
	wantCPE               string // "" when the resolution must be Unknown
	wantState             identity.State
	why                   string
}

// identityCases: each is one labelled (name/vendor/product → expected CPE-state).
func identityCases() []identityCase {
	return []identityCase{
		{name: "nginx", wantCPE: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", wantState: identity.StateVerified,
			why: "name matches exactly one product token"},
		{name: "openssl", wantCPE: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", wantState: identity.StateVerified,
			why: "name matches one vendor:product base"},
		{vendor: "apache", product: "http server", wantCPE: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", wantState: identity.StateVerified,
			why: "vendor+product key; 'http server' normalises to the CPE token 'http_server'"},
		{vendor: "acme", product: "server", wantCPE: "cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*", wantState: identity.StateVerified,
			why: "vendor+product disambiguates the shared product name"},
		{name: "server", wantState: identity.StateUnknown,
			why: "AMBIGUOUS: product 'server' exists under acme AND globex → two bases → Unknown, no fabricated CPE"},
		{name: "totally unknown tech", wantState: identity.StateUnknown,
			why: "the dictionary does not know it → Unknown, not an invented CPE"},
	}
}

// TestIdentityAccuracy measures identity resolution precision: of every case the oracle
// calls Verified, how many carry the CORRECT CPE; and separately that every case meant
// to be Unknown resolves to Unknown with an EMPTY CPE (the "never fabricate" guard).
func TestIdentityAccuracy(t *testing.T) {
	dict, err := identity.ParseDict([]byte(identityDictJSON))
	if err != nil {
		t.Fatalf("ParseDict: %v", err)
	}

	var verifiedPredicted, verifiedCorrect, unknownExpected, unknownCorrect int
	for _, c := range identityCases() {
		gotCPE, _, gotState := identity.Match(dict, c.name, c.vendor, c.product)
		t.Logf("  id  %-22q vendor=%-7q product=%-12q → %-8s cpe=%q (%s)",
			c.name, c.vendor, c.product, gotState, gotCPE, c.why)

		switch c.wantState {
		case identity.StateVerified:
			verifiedPredicted++
			if gotState == identity.StateVerified && gotCPE == c.wantCPE {
				verifiedCorrect++
			} else {
				t.Errorf("%q/%q/%q = (%s, %q), want (Verified, %q)", c.name, c.vendor, c.product, gotState, gotCPE, c.wantCPE)
			}
		case identity.StateUnknown:
			unknownExpected++
			if gotState == identity.StateUnknown && gotCPE == "" {
				unknownCorrect++
			} else {
				t.Errorf("%q/%q/%q = (%s, %q), want (Unknown, empty CPE) — a fabricated CPE is a correctness bug", c.name, c.vendor, c.product, gotState, gotCPE)
			}
		}
	}

	// The public ResolveCPE path over the embedded sample (empty URL ⇒ no network) never
	// verifies: the sample is a handful of bases, not the dictionary (it must not displace a
	// curated CPE).
	res := identity.New("", fetch.New())
	if cpe, _, st := res.ResolveCPE(context.Background(), "nginx", "", ""); st == identity.StateVerified {
		t.Errorf("ResolveCPE(nginx) over the embedded sample verified %q", cpe)
	}

	prec := 1.0
	if verifiedPredicted > 0 {
		prec = float64(verifiedCorrect) / float64(verifiedPredicted)
	}
	t.Logf("=== identity-accuracy === verified precision=%.3f (%d/%d correct CPE) · unknown-correct=%d/%d · COVERAGE-GAP: resolution only (not CPE-version or multilingual-title selection)",
		prec, verifiedCorrect, verifiedPredicted, unknownCorrect, unknownExpected)
	if prec != 1.0 {
		t.Errorf("identity verified precision = %.3f, want 1.0", prec)
	}
	if unknownCorrect != unknownExpected {
		t.Errorf("unknown-correct = %d, want %d (an unknown identity must resolve to Unknown)", unknownCorrect, unknownExpected)
	}
}

// ---------------------------------------------------------------------------
// DIMENSION 2 — version-accuracy
// ---------------------------------------------------------------------------

func findDet(dets []matcher.Detection, tech string) (matcher.Detection, bool) {
	for _, d := range dets {
		if d.Tech == tech {
			return d, true
		}
	}
	return matcher.Detection{}, false
}

// twoClaimDB builds a one-tech DB whose two headers each capture a version, so the
// matcher's version reconciliation (resolveVersion) is exercised end-to-end through
// the exported Match — the unexported resolver cannot be called from this package.
func twoClaimDB() *schema.DB {
	return &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"Acme": {Headers: map[string]schema.StringList{
			"X-Acme-A": {`v([\d.]+)\;version:\1`},
			"X-Acme-B": {`v([\d.]+)\;version:\1`},
		}},
	}}
}

// TestVersionAccuracy covers the two version judgments a consumer trusts: (1) two
// conflicting claims resolve to a DETERMINISTIC pick flagged VersionConflict=true,
// while a dotted refinement (1.18 vs 1.18.0) is reconciled WITHOUT a conflict; and
// (2) versioncmp orders each ecosystem by its own rules, returning ok=false (never a
// guessed verdict) where it cannot parse both operands.
func TestVersionAccuracy(t *testing.T) {
	db := twoClaimDB()

	type verCase struct {
		name         string
		page         matcher.Page
		wantVersion  string
		wantConflict bool
		why          string
	}
	cases := []verCase{
		{name: "conflict", page: matcher.Page{Headers: map[string][]string{"x-acme-a": {"v10"}, "x-acme-b": {"v9.5"}}},
			wantVersion: "9.5", wantConflict: true,
			why: "10 vs 9.5 are incompatible; more-components precedence picks 9.5 deterministically, conflict flagged"},
		{name: "refinement", page: matcher.Page{Headers: map[string][]string{"x-acme-a": {"v1.18"}, "x-acme-b": {"v1.18.0"}}},
			wantVersion: "1.18.0", wantConflict: false,
			why: "1.18.0 is a dotted refinement of 1.18 → not a conflict; the more specific wins"},
		{name: "agree", page: matcher.Page{Headers: map[string][]string{"x-acme-a": {"v2.4.1"}, "x-acme-b": {"v2.4.1"}}},
			wantVersion: "2.4.1", wantConflict: false, why: "identical claims → no conflict"},
	}

	var verTotal, verOK int
	for _, c := range cases {
		verTotal++
		// Determinism: 50 runs must produce a byte-identical Detection (map-iteration
		// order over the two header patterns must not change the resolved version).
		first := matcher.Match(db, c.page)
		want, _ := json.Marshal(first)
		stable := true
		for i := 0; i < 50; i++ {
			got, _ := json.Marshal(matcher.Match(db, c.page))
			if string(got) != string(want) {
				stable = false
				break
			}
		}
		d, ok := findDet(first, "Acme")
		t.Logf("  ver %-11s version=%-7q conflict=%-5v stable=%v (%s)", c.name, d.Version, d.VersionConflict, stable, c.why)
		if !ok {
			t.Errorf("%s: Acme not detected", c.name)
			continue
		}
		if !stable {
			t.Errorf("%s: version resolution is NON-deterministic across 50 runs", c.name)
			continue
		}
		if d.Version != c.wantVersion || d.VersionConflict != c.wantConflict {
			t.Errorf("%s: (version=%q conflict=%v), want (%q %v)", c.name, d.Version, d.VersionConflict, c.wantVersion, c.wantConflict)
			continue
		}
		verOK++
	}

	type cmpCase struct {
		eco, a, b string
		wantCmp   int
		wantOK    bool
		why       string
	}
	cmps := []cmpCase{
		{"pypi", "1.0a1", "1.0", -1, true, "PEP440: a pre-release sorts BELOW the final release (the semver-ish trap)"},
		{"pypi", "1.0", "1.0a1", 1, true, "PEP440: final release above its own pre-release"},
		{"pypi", "1.0.post1", "1.0", 1, true, "PEP440: a .post release sorts above the release"},
		{"npm", "1.2.0", "1.10.0", -1, true, "SemVer numeric-aware: 2 < 10, not lexical"},
		{"npm", "1.0.0-rc.1", "1.0.0", -1, true, "SemVer: a pre-release is below the release"},
		{"Go", "v1.2.3", "1.2.3", 0, true, "SemVer: a v prefix is stripped, equal"},
		{"", "1.2", "1.2.0", 0, true, "default SemVer: a trailing-zero segment is equal"},
		{"maven", "1.0.RELEASE", "1.0", 0, true, "Maven: the RELEASE qualifier equals the final release → equal"},
		{"debian", "1:2", "1", 1, true, "Debian: a higher epoch dominates the upstream version"},
		{"rpm", "1.0", "1.0~rc1", 1, true, "RPM: a ~ (tilde) pre-release sorts below its release"},
		{"rubygems", "1.0.0.pre", "1.0.0", -1, true, "RubyGems: a letter segment is a pre-release, below its release"},
	}
	var cmpTotal, cmpOK int
	for _, c := range cmps {
		cmpTotal++
		gotCmp, gotOK := versioncmp.Compare(c.eco, c.a, c.b)
		pass := gotOK == c.wantOK && (!c.wantOK || gotCmp == c.wantCmp)
		t.Logf("  cmp %-7s %-12q %-9q → cmp=%d ok=%v (%s)", c.eco, c.a, c.b, gotCmp, gotOK, c.why)
		if pass {
			cmpOK++
		} else {
			t.Errorf("Compare(%q,%q,%q) = (%d,%v), want (%d,%v)", c.eco, c.a, c.b, gotCmp, gotOK, c.wantCmp, c.wantOK)
		}
	}

	t.Logf("=== version-accuracy === reconciliation=%d/%d (deterministic+flagged) · versioncmp=%d/%d · PEP440/SemVer/Debian/RPM/Maven/RubyGems/Go compared natively; Packagist falls back to SemVer; unparseable operands (bare hash, GIT) stay ok=false → UNKNOWN by design",
		verOK, verTotal, cmpOK, cmpTotal)
}

// ---------------------------------------------------------------------------
// DIMENSION 3 — applicability-accuracy
// ---------------------------------------------------------------------------

type applCase struct {
	name         string
	got          unified.Result
	want         unified.State
	mustNotClean bool // an UNKNOWN/not-checked state must never read as not_affected (clean)
	why          string
}

// applCases: one labelled (provider typed-result → expected unified.State) per honest
// branch of each adapter, driven through the real ToUnified mappers. The cases flagged
// mustNotClean are the honesty core: an unknown product/version or an off source must
// NOT collapse to not_affected_by_advisory.
func applCases() []applCase {
	affectLead := []osv.Vuln{{ID: "GHSA-x", CVE: "CVE-2024-0001", Severity: "high"}}
	return []applCase{
		// osv
		{"osv/affected-pinned", osv.ToUnified(osv.Result{Status: osv.StatusVulnerable, VersionPinned: true, PackageKnown: true, Vulns: affectLead}, "npm", "lib", "1.0.0", timeZero()),
			unified.StateAffectedByAdvisory, false, "pinned version inside an advisory range"},
		{"osv/potentially-unpinned", osv.ToUnified(osv.Result{Status: osv.StatusVulnerable, VersionPinned: false, PackageKnown: true, Vulns: affectLead}, "npm", "lib", "", timeZero()),
			unified.StatePotentiallyAffected, true, "advisory exists but version not pinnable"},
		{"osv/unknown-version", osv.ToUnified(osv.Result{Status: osv.StatusUnknown, PackageKnown: true}, "npm", "lib", "weird", timeZero()),
			unified.StatePotentiallyAffected, true, "osv-unknown-version: package known, version could not be positioned → a LEAD, not clean"},
		{"osv/unknown-product", osv.ToUnified(osv.Result{Status: osv.StatusUnknown, PackageKnown: false}, "npm", "ghost", "1.0.0", timeZero()),
			unified.StateUnknownProduct, true, "package absent from the index → UNKNOWN, never clean"},
		{"osv/not-affected", osv.ToUnified(osv.Result{Status: osv.StatusNoKnownVuln, PackageKnown: true, VersionPinned: true}, "npm", "lib", "9.9.9", timeZero()),
			unified.StateNotChecked, false, "index consulted, nothing matched → no clearance (NoteNoClearance)"},

		// jslib
		{"jslib/affected", jslib.ToUnified(jslib.Result{Library: "jquery", Version: "1.6.0", KnownLib: true, Resolved: true, Vulns: []jslib.Lead{{ID: "x"}}}),
			unified.StateAffectedByAdvisory, false, "installed version inside a published range"},
		{"jslib/not-affected", jslib.ToUnified(jslib.Result{Library: "jquery", Version: "3.7.1", KnownLib: true, Resolved: true}),
			unified.StateNotChecked, true, "nothing matched, but the Retire.js data cannot prove itself complete → no clearance"},
		{"jslib/unknown-version", jslib.ToUnified(jslib.Result{Library: "jquery", Version: "latest", KnownLib: true, UnparsedVersion: true}),
			unified.StateUnknownVersion, true, "a version was detected but is not comparable → UNKNOWN"},
		{"jslib/unknown-product", jslib.ToUnified(jslib.Result{Library: "madeup", Version: "1.0.0"}),
			unified.StateUnknownProduct, true, "feed does not list the library → UNKNOWN, never clean"},

		// cve
		{"cve/affected", cve.ToUnified(cve.Result{CPE: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", Version: "1.18.0", State: cve.StateHasCVE, CVEs: []cve.CVE{{ID: "CVE-2021-23017", CVSS: 7.7, Severity: "HIGH"}}}, nil),
			unified.StateAffectedByAdvisory, false, "feed returned a CVE lead"},
		{"cve/not-affected", cve.ToUnified(cve.Result{CPE: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", Version: "9.9.9", State: cve.StateNoKnownCVE}, nil),
			unified.StateNotChecked, true, "no CVE listed, but a paged per-query API cannot prove that complete → no clearance"},
		{"cve/unknown-product", cve.ToUnified(cve.Result{State: cve.StateUnknown}, nil),
			unified.StateUnknownProduct, true, "empty CPE, nothing to bridge → UNKNOWN, never clean"},
		{"cve/not-checked", cve.ToUnified(cve.Result{}, cve.ErrFeedOff),
			unified.StateNotChecked, true, "feed off → we did NOT query, never clean"},
		{"cve/source-unavailable", cve.ToUnified(cve.Result{}, errors.New("dial tcp: timeout")),
			unified.StateSourceUnavailable, true, "feed errored → UNKNOWN, never clean"},

		// wpcve — only states constructable from EXPORTED fields; the reason-driven
		// unknown_product/source_unavailable states need the unexported `reason` and are
		// measured by wpcve's own in-package adapter_test (TestToUnifiedStates).
		{"wpcve/affected", wpcve.ToUnified(wpcve.PluginResult{Slug: "akismet", Version: "4.0", Kind: "plugin", Resolved: true, Vulns: []wpcve.Lead{{ID: "WPVDB-1"}}}),
			unified.StateAffectedByAdvisory, false, "feed lists a vuln touching this version"},
		{"wpcve/not-affected", wpcve.ToUnified(wpcve.PluginResult{Slug: "akismet", Version: "5.3", Kind: "plugin", Resolved: true}),
			unified.StateNotChecked, true, "nothing listed, but the feed cannot prove its list complete → no clearance"},
		{"wpcve/unknown-version", wpcve.ToUnified(wpcve.PluginResult{Slug: "akismet", Version: "latest", Kind: "plugin", UnparsedVersion: true}),
			unified.StateUnknownVersion, true, "version detected but not comparable → UNKNOWN"},
		{"wpcve/not-checked", wpcve.ToUnified(wpcve.PluginResult{Slug: "akismet", Kind: "plugin"}),
			unified.StateNotChecked, true, "nothing looked up → never clean"},
	}
}

func timeZero() time.Time { return time.Time{} }

// TestApplicabilityAccuracy asserts every adapter maps its typed result to the right
// unified.State, and — the honesty gate — that no UNKNOWN/off state ever lands on
// not_affected_by_advisory (clean).
func TestApplicabilityAccuracy(t *testing.T) {
	var total, correct, unknownGuarded int
	for _, c := range applCases() {
		total++
		ok := c.got.State == c.want
		if ok {
			correct++
		} else {
			t.Errorf("%s: state = %s, want %s", c.name, c.got.State, c.want)
		}
		if c.mustNotClean {
			if c.got.State == unified.StateNotAffectedByAdvisory {
				t.Errorf("%s: UNKNOWN mapped to not_affected (clean) — honesty violation", c.name)
			} else {
				unknownGuarded++
			}
		}
		t.Logf("  app %-24s → %-24s (%s)", c.name, c.got.State, c.why)
	}
	t.Logf("=== applicability-accuracy === mapping=%d/%d correct · unknown-not-clean guard=%d cases held · COVERAGE-GAP: wpcve reason-states (unknown_product, source_unavailable) need the unexported reason — covered by wpcve's in-package adapter_test",
		correct, total, unknownGuarded)
}

// ---------------------------------------------------------------------------
// ADVERSARIAL CORPUS — the cases a lazy pipeline gets wrong
// ---------------------------------------------------------------------------

// TestAdversarialCorpus collects the known traps across the three dimensions. Each
// sub-test is one labelled adversarial input with the reason it is a trap; together
// they are the regression wall for the mistakes honesty is meant to prevent.
func TestAdversarialCorpus(t *testing.T) {
	dict, err := identity.ParseDict([]byte(identityDictJSON))
	if err != nil {
		t.Fatalf("ParseDict: %v", err)
	}

	t.Run("same-name-different-vendor", func(t *testing.T) {
		// product "server" is sold by acme AND globex: resolving it must NOT pick one
		// and fabricate its CPE — it must stay Unknown.
		cpe, _, st := identity.Match(dict, "server", "", "")
		if st != identity.StateUnknown || cpe != "" {
			t.Errorf("ambiguous 'server' = (%s, %q), want Unknown + empty CPE", st, cpe)
		}
		t.Logf("same product under two vendors → Unknown (no fabricated CPE)")
	})

	t.Run("version-conflict", func(t *testing.T) {
		d := matcher.Match(twoClaimDB(), matcher.Page{Headers: map[string][]string{"x-acme-a": {"v10"}, "x-acme-b": {"v9.5"}}})
		got, ok := findDet(d, "Acme")
		if !ok || !got.VersionConflict || len(got.VersionClaims) != 2 {
			t.Errorf("two incompatible claims = %+v, want VersionConflict with 2 distinct claims", got)
		}
		t.Logf("incompatible banners 10 vs 9.5 → deterministic pick %q, conflict flagged", got.Version)
	})

	t.Run("osv-unknown-version-not-clean", func(t *testing.T) {
		// A known package whose version cannot be positioned is potentially_affected,
		// NOT not_affected — the classic "no exact match ⇒ safe" mistake.
		u := osv.ToUnified(osv.Result{Status: osv.StatusUnknown, PackageKnown: true}, "npm", "lib", "weird", time.Time{})
		if u.State != unified.StatePotentiallyAffected {
			t.Errorf("osv unknown-version = %s, want potentially_affected (never clean)", u.State)
		}
		t.Logf("package known + version unresolvable → %s (not clean)", u.State)
	})

	t.Run("pep440-prerelease", func(t *testing.T) {
		// The single most common versioning bug: "1.0a1" read as ABOVE "1.0" by a
		// naive comparator. Under PEP 440 a pre-release is below the final release.
		if c, ok := versioncmp.Compare("pypi", "1.0a1", "1.0"); !ok || c != -1 {
			t.Errorf("Compare(pypi,1.0a1,1.0) = (%d,%v), want (-1,true)", c, ok)
		}
		t.Logf("PEP440 1.0a1 < 1.0 (pre-release below release)")
	})

	t.Run("kev-stale-still-flagged-stale", func(t *testing.T) {
		// A stale KEV catalog still confirms exploitation, but the result MUST carry
		// Freshness=stale so a consumer never reads the fallback snapshot as live truth.
		u := kev.MapSignal(kev.Signal{CVE: "CVE-2021-44228", InKEV: true}, unified.FreshnessStale, true)
		if u.State != unified.StateAffectedByAdvisory || u.Freshness != unified.FreshnessStale {
			t.Errorf("stale KEV = (state %s, freshness %s), want (affected_by_advisory, stale)", u.State, u.Freshness)
		}
		t.Logf("stale KEV hit → %s but freshness=%s (never read as live)", u.State, u.Freshness)
	})
}
