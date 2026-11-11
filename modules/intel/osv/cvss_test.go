package osv

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Known CVSS v3.x base scores (the specification's own formula; each value is the score the
// vector is published with).
func TestCVSS3BaseScore(t *testing.T) {
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":          9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H":          10.0, // Log4Shell
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N":          7.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H":          8.8,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H":          7.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N":          6.1, // reflected XSS
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N":          5.9,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H":          9.9, // PR weighs more when the scope changes
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H":          9.1,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":          9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N":          0.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O": 9.8, // temporal metrics do not change the base score
	} {
		got, ok := cvss3BaseScore(vec)
		if !ok || got != want {
			t.Errorf("%s = %v ok=%v, want %v", vec, got, ok, want)
		}
	}
	for _, bad := range []string{
		"", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",          // a base metric missing
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      // a value the specification does not define
		"CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // a metric given twice
	} {
		if got, ok := cvss3BaseScore(bad); ok {
			t.Errorf("%q scored %v, want not scorable", bad, got)
		}
	}
}

// An OSV record's CVSS v3 vector becomes the lead's score, and its qualitative band the
// severity when the record carries no label of its own.
func TestOSVLeadCarriesTheVectorScore(t *testing.T) {
	idx := buildIdx(t, "npm", map[string]string{"npm/X-1.json": `{"id":"X-1","aliases":["CVE-2099-1"],` +
		`"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],` +
		`"affected":[{"package":{"name":"p","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`,
		"npm/X-2.json": `{"id":"X-2","affected":[{"package":{"name":"q","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`})
	u := ToUnified(idx.Lookup("p", "1.0.0"), "npm", "p", "1.0.0", time.Time{})
	if len(u.Leads) != 1 || u.Leads[0].Score == nil || *u.Leads[0].Score != 10.0 || u.Leads[0].Severity != "critical" {
		t.Fatalf("lead = %+v, want score 10 and severity critical from the vector", u.Leads)
	}
	if q := ToUnified(idx.Lookup("q", "1.0.0"), "npm", "q", "1.0.0", time.Time{}); len(q.Leads) != 1 || q.Leads[0].Score != nil {
		t.Fatalf("a record with no vector must carry no score, got %+v", q.Leads)
	}
}

// The score travels in the index file, so a later run reading it still has it.
func TestIndexFileKeepsTheScore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.idx.gz")
	s := 9.8
	w := newIndexWriter(path, "stamp")
	w.put(&record{pkg: "p", ecosystem: "npm", id: "X-1", severity: "critical", score: &s, vulnKeys: []string{"X-1"},
		ranges: []affectedRange{{typ: rangeSemver, introduced: "0", fixed: "2.0.0"}}})
	w.putSkipped(0)
	w.finish(true)
	idx, err := readIndexFile(path, "stamp", "npm", releaseRows("npm"))
	if err != nil {
		t.Fatal(err)
	}
	if res := idx.Lookup("p", "1.0.0"); len(res.Vulns) != 1 || !res.Vulns[0].Scored || res.Vulns[0].Score != s {
		t.Fatalf("score lost in the index file: %+v", res.Vulns)
	}
}

// The record's weakness ids, publication date and raw vector reach the lead, through the index
// file as well.
func TestOSVLeadCarriesWeaknessDateAndVector(t *testing.T) {
	const vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
	entry := `{"id":"X-1","published":"2021-12-10T00:40:56Z","database_specific":{"cwe_ids":["CWE-502","CWE-400"],"severity":"CRITICAL"},` +
		`"severity":[{"type":"CVSS_V3","score":"` + vec + `"}],` +
		`"affected":[{"package":{"name":"p","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`
	idx := buildIdx(t, "npm", map[string]string{"npm/X-1.json": entry})
	check := func(where string, res Result) {
		u := ToUnified(res, "npm", "p", "1.0.0", time.Time{})
		if len(u.Leads) != 1 {
			t.Fatalf("%s: leads = %+v", where, u.Leads)
		}
		l := u.Leads[0]
		if !reflect.DeepEqual(l.CWE, []string{"CWE-502", "CWE-400"}) || l.Published != "2021-12-10T00:40:56Z" || l.CVSS != vec {
			t.Errorf("%s: lead = %+v, want the CWEs, the published date and the vector", where, l)
		}
	}
	check("in memory", idx.Lookup("p", "1.0.0"))
	path := filepath.Join(t.TempDir(), "dump.idx.gz")
	w := newIndexWriter(path, "stamp")
	r, _ := makeZip(t, map[string]string{"npm/X-1.json": entry})
	if _, err := reduceZip(context.Background(), r, int64(r.Len()), "npm", func(rec *record) error { w.put(rec); return nil }); err != nil {
		t.Fatal(err)
	}
	w.putSkipped(0)
	w.finish(true)
	fromFile, err := readIndexFile(path, "stamp", "npm", releaseRows("npm"))
	if err != nil {
		t.Fatal(err)
	}
	check("index file", fromFile.Lookup("p", "1.0.0"))
}

// Roundup works on integers: a float a hair above a tenth (1.1*3 = 3.3000000000000003) is that tenth,
// while anything above it at the fifth decimal goes up (the specification rounds there first).
func TestRoundUp1IgnoresFloatError(t *testing.T) {
	x := 1.1
	x *= 3
	for in, want := range map[float64]float64{x: 3.3, 4.0: 4.0, 4.02: 4.1, 4.00001: 4.1, 4.000001: 4.0} {
		if got := roundUp1(in); got != want {
			t.Errorf("roundUp1(%v) = %v, want %v", in, got, want)
		}
	}
}
