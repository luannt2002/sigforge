package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/enrich"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/merge"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// TestMergeChecksumVerifyRoundTrip proves the supply-chain integrity path end to end:
// merge writes a DB plus its .sha256 sidecar, verify re-reads both and passes; then one
// flipped byte in the DB makes verify fail (drift detected), and a removed sidecar makes
// verify refuse rather than silently report OK.
func TestMergeChecksumVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(db + ".sha256"); err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}

	out := captureStdout(t, func() {
		if err := cmdVerify([]string{db}); err != nil {
			t.Fatalf("verify of a fresh merge failed: %v", err)
		}
	})
	for _, want := range []string{"sha256 matches sidecar", "NOT authenticity"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q:\n%s", want, out)
		}
	}

	data, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0x20 // flip one byte in the middle of the DB
	if err := os.WriteFile(db, data, 0o644); err != nil {
		t.Fatal(err)
	}
	err = cmdVerify([]string{db})
	if err == nil || !strings.Contains(err.Error(), "MISMATCH") {
		t.Fatalf("tampered DB must fail verify with a mismatch, got: %v", err)
	}

	if err := os.Remove(db + ".sha256"); err != nil {
		t.Fatal(err)
	}
	err = cmdVerify([]string{db})
	if err == nil || !strings.Contains(err.Error(), "no checksum") {
		t.Fatalf("missing sidecar must refuse, got: %v", err)
	}
}

// TestVerifyRejectsBrokenRegexWithValidChecksum proves verify is not fooled by a DB
// whose checksum is honest but whose content is not: an unbalanced-paren regex passes
// the SHA-256 gate (the sidecar is recomputed to match) yet must still fail verify,
// because schema.Parse re-runs schema.Validate and refuses a regex that cannot compile.
// Guards the audit N2 concern that verify would report such a DB as OK.
func TestVerifyRejectsBrokenRegexWithValidChecksum(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	content := []byte(`{"schema_version":"1.0.0","fingerprints":{"Broken":{"html":"foo(bar"}}}`)
	if err := os.WriteFile(db, content, 0o644); err != nil {
		t.Fatal(err)
	}
	// Recompute the sidecar so the checksum gate passes — the failure must come from
	// schema validation, not from a stale hash.
	if err := os.WriteFile(merge.SidecarPath(db), []byte(merge.Checksum(content)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := cmdVerify([]string{db})
	if err == nil {
		t.Fatal("verify reported OK for a checksum-valid DB with a broken regex")
	}
	for _, want := range []string{"schema is invalid", "regex"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("verify error missing %q: %v", want, err)
		}
	}
}

// TestMergeManifestVerifyCompat proves merge writes a governance manifest, verify accepts
// a compatible one (and says so), and a manifest whose engine MAJOR differs is refused as
// INCOMPATIBLE even though its content hash is honest — the compat gate, not the hash, is
// what rejects it. A missing manifest is a warning, not a clean OK.
func TestMergeManifestVerifyCompat(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json")}); err != nil {
		t.Fatal(err)
	}
	manPath := merge.ManifestPath(db)
	manBytes, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	man, err := merge.ParseManifest(manBytes)
	if err != nil {
		t.Fatal(err)
	}
	dbBytes, _ := os.ReadFile(db)
	if man.ContentSHA256 != merge.Checksum(dbBytes) || man.EngineVersion != merge.EngineVersion {
		t.Fatalf("manifest does not describe the DB: %+v", man)
	}

	out := captureStdout(t, func() {
		if err := cmdVerify([]string{db}); err != nil {
			t.Fatalf("verify of a compatible snapshot failed: %v", err)
		}
	})
	if !strings.Contains(out, "manifest compatible") {
		t.Errorf("verify output missing compat line:\n%s", out)
	}

	// Fake an incompatible engine major, keeping the honest content hash, so only the
	// compat gate can reject it.
	man.EngineVersion = "99.0.0"
	bad, _ := man.JSON()
	if err := os.WriteFile(manPath, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	err = cmdVerify([]string{db})
	if err == nil || !strings.Contains(err.Error(), "INCOMPATIBLE") {
		t.Fatalf("incompatible manifest must fail verify with INCOMPATIBLE, got: %v", err)
	}

	// No manifest → warning, still checks integrity, never a clean OK.
	if err := os.Remove(manPath); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		if err := cmdVerify([]string{db}); err != nil {
			t.Fatalf("verify without manifest should warn, not fail: %v", err)
		}
	})
	if !strings.Contains(out, "no manifest") {
		t.Errorf("verify without manifest missing warning:\n%s", out)
	}
}

// TestMergeArchivesPrevAndRollback proves an overwriting merge archives the prior snapshot
// to <out>.prev*, that rollback restores exactly that snapshot (checksum + schema verified,
// the newer entry gone), and that rollback refuses when there is no .prev and when the
// .prev checksum does not match (no blind rollback).
func TestMergeArchivesPrevAndRollback(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")

	// v1: baseline only.
	if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json")}); err != nil {
		t.Fatal(err)
	}
	v1Bytes, _ := os.ReadFile(db)
	v1, _ := schema.LoadFile(db)
	const extraTech = "RollbackProbeTech"
	if _, present := v1.Fingerprints[extraTech]; present {
		t.Fatalf("baseline unexpectedly contains %q", extraTech)
	}

	// Rollback with no .prev must refuse.
	if err := cmdRollback([]string{db}); err == nil || !strings.Contains(err.Error(), "nothing to roll back") {
		t.Fatalf("rollback without .prev must refuse, got: %v", err)
	}

	// v2: add a source so the new snapshot differs from v1, triggering the .prev archive.
	srcPath := filepath.Join(dir, "src.json")
	src := `{"schema_version":"1.0.0","fingerprints":{"` + extraTech + `":{"html":["probe-marker"]}}}`
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdMerge([]string{"--out", db, "--source", "probe=" + srcPath, "--manifest", filepath.Join(dir, "m.json")}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{db + ".prev", db + ".prev.sha256", db + ".prev.manifest.json"} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("archive %q missing after overwriting merge: %v", f, err)
		}
	}
	v2, _ := schema.LoadFile(db)
	if _, present := v2.Fingerprints[extraTech]; !present {
		t.Fatalf("v2 should contain %q from the source", extraTech)
	}

	// Rollback restores v1 exactly.
	out := captureStdout(t, func() {
		if err := cmdRollback([]string{db}); err != nil {
			t.Fatalf("rollback of a valid .prev failed: %v", err)
		}
	})
	if !strings.Contains(out, "rolled back") {
		t.Errorf("rollback output missing confirmation:\n%s", out)
	}
	gotBytes, _ := os.ReadFile(db)
	if merge.Checksum(gotBytes) != merge.Checksum(v1Bytes) {
		t.Fatal("rollback did not restore the v1 bytes")
	}
	restored, _ := schema.LoadFile(db)
	if _, present := restored.Fingerprints[extraTech]; present {
		t.Fatalf("rollback left the v2 entry %q in place", extraTech)
	}

	// Corrupt the .prev DB (its archived sidecar still records the true hash) → refuse.
	if err := cmdMerge([]string{"--out", db, "--source", "probe=" + srcPath, "--manifest", filepath.Join(dir, "m.json")}); err != nil {
		t.Fatal(err)
	}
	prevBytes, _ := os.ReadFile(db + ".prev")
	prevBytes[len(prevBytes)/2] ^= 0x20
	if err := os.WriteFile(db+".prev", prevBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdRollback([]string{db}); err == nil || !strings.Contains(err.Error(), "CORRUPT") {
		t.Fatalf("corrupt .prev must refuse rollback, got: %v", err)
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	out, _ := io.ReadAll(r)
	return string(out)
}

// TestCmdCVEExplainEndToEnd drives the full cve --explain path against an in-process
// NVD-shaped feed (the established httptest pattern), proving the real StateHasCVE
// branch prints the leads followed by the WHY trace.
func TestCmdCVEExplainEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-23017","metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","cvssData":{"baseScore":7.7,"baseSeverity":"HIGH"}}]}}}]}`)
	}))
	defer srv.Close()
	t.Setenv(cve.EnvVar, srv.URL)
	out := captureStdout(t, func() {
		if err := cmdCVE([]string{"--explain", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0"}); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{"CVE-2021-23017", "CVSS 7.7", "virtualMatchString=cpe:2.3:a:f5:nginx:1.18.0", "never proof of exploitability"} {
		if !strings.Contains(out, want) {
			t.Errorf("cve --explain output missing %q:\n%s", want, out)
		}
	}
}

// TestCmdEOLExplainEndToEnd drives the full eol --explain path against an in-process
// endoflife-shaped feed, proving the real StateEOL branch prints the status followed
// by the version→cycle→eol trace.
func TestCmdEOLExplainEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"cycle":"7.2","eol":"2020-11-30","latest":"7.2.34"}]`)
	}))
	defer srv.Close()
	t.Setenv(lifecycle.EnvVar, srv.URL)
	out := captureStdout(t, func() {
		if err := cmdEOL([]string{"--explain", "PHP", "7.2.34"}); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{"status=eol", `cycle "7.2" owns it`, "eol field = 2020-11-30", "endoflife.date (license MIT)"} {
		if !strings.Contains(out, want) {
			t.Errorf("eol --explain output missing %q:\n%s", want, out)
		}
	}
}

func TestExplainCVE(t *testing.T) {
	// Unknown (no CPE queried) must never read as "no CVEs = safe".
	got := explainCVE(cve.Result{State: cve.StateUnknown})
	if !strings.Contains(got, "NOT checked") || strings.Contains(got, "safe'\n  query") {
		t.Fatalf("unknown explain lost its honesty: %q", got)
	}
	// A queried result shows the exact CPE and the LEAD caveat, and credits NVD
	// for the range match (sigforge does not re-derive min/max).
	got = explainCVE(cve.Result{CPE: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", State: cve.StateHasCVE})
	for _, want := range []string{"virtualMatchString=cpe:2.3:a:f5:nginx:1.18.0", "NVD applied", "LEAD"} {
		if !strings.Contains(got, want) {
			t.Fatalf("has-cve explain missing %q in %q", want, got)
		}
	}
}

func TestExplainEOL(t *testing.T) {
	cases := map[string]struct {
		st       lifecycle.Status
		tech     string
		contains string
	}{
		"unmapped": {lifecycle.Status{}, "FooTech", `no endoflife.date product is mapped for "FooTech"`},
		"no-cycle": {lifecycle.Status{Product: "php", Version: "99.9"}, "PHP", "matched no release cycle"},
		"matched":  {lifecycle.Status{Product: "php", Version: "7.2.34", Cycle: "7.2", EOLDate: "2020-11-30", IsEOL: lifecycle.StateEOL}, "PHP", `cycle "7.2" owns it`},
	}
	for name, c := range cases {
		if got := explainEOL(c.st, c.tech); !strings.Contains(got, c.contains) {
			t.Errorf("%s: explainEOL missing %q in %q", name, c.contains, got)
		}
	}
	// Every mapped-and-matched explain must keep "never 'supported'" honesty absent
	// only when a real status is known, and always credit the feed.
	if got := explainEOL(lifecycle.Status{Product: "php", Version: "7.2.34", Cycle: "7.2", EOLDate: "2020-11-30", IsEOL: lifecycle.StateEOL}, "PHP"); !strings.Contains(got, "endoflife.date (license MIT)") {
		t.Errorf("matched explain missing feed attribution: %q", got)
	}
}

func TestRequestsNote(t *testing.T) {
	if got := requestsNote(nil); got != "" {
		t.Errorf("no requests must print nothing, got %q", got)
	}
	got := requestsNote(map[string]fetch.HostStats{"b.example": {Sent: 1, HeldOff: 3}, "a.example": {Sent: 4}})
	want := "requests: a.example=4 sent, b.example=1 sent (3 held off after a 429)"
	if got := requestsNote(map[string]fetch.HostStats{"c.example": {Cached: 2}}); got != "requests: c.example=0 sent (2 served from the local store)" {
		t.Errorf("store hits must be shown, got %q", got)
	}
	if got != want {
		t.Errorf("requestsNote = %q, want %q", got, want)
	}
}

// sync refuses without a store, refuses with nothing configured, and reports a failed
// source (non-zero) while still storing the sources that worked.
func TestSync(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	t.Setenv(EnvCacheDir, "")
	if err := cmdSync(nil); err == nil || !strings.Contains(err.Error(), EnvCacheDir) {
		t.Fatalf("sync without a store must say which variable to set, got %v", err)
	}
	store := t.TempDir()
	t.Setenv(EnvCacheDir, store)
	if err := cmdSync(nil); err == nil || !strings.Contains(err.Error(), "no catalog source") {
		t.Fatalf("sync with nothing configured must say so, got %v", err)
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`))
	}))
	defer ok.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusInternalServerError) }))
	defer down.Close()
	t.Setenv(kev.EnvKEVURL, ok.URL)
	t.Setenv(lifecycle.EnvBundleURL, down.URL)
	var err error
	captureStdout(t, func() { err = cmdSync(nil) })
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("one failed source of two must fail the sync and say so, got %v", err)
	}
	if entries, _ := os.ReadDir(store); len(entries) == 0 {
		t.Fatal("the source that worked must still be in the store")
	}
}

// Every identity the flags name — packages of any ecosystem, an SBOM's components, WP
// plugins/themes, JS libraries — reaches the input once; a bad package is refused.
func TestBuildEnrichInput(t *testing.T) {
	sbom := filepath.Join(t.TempDir(), "bom.json")
	writeFile(t, sbom, `{"bomFormat":"CycloneDX","components":[{"purl":"pkg:pypi/django@3.2.0"},{"purl":"pkg:npm/lodash@4.17.20"},{"name":"no-purl"}]}`)
	inp, skipped, err := buildEnrichInput(
		[]string{"pkg:npm/lodash@4.17.20", "maven:org.apache.logging.log4j:log4j-core@2.14.1"}, sbom,
		[]string{"contact-form-7@5.0"}, []string{"astra@3.0"}, []string{"jquery@3.4.0"})
	if err != nil {
		t.Fatal(err)
	}
	wantPkgs := []enrich.PkgRef{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
		{Ecosystem: "pypi", Name: "django", Version: "3.2.0"},
	}
	if !reflect.DeepEqual(inp.Packages, wantPkgs) || skipped != 1 {
		t.Fatalf("packages = %+v (skipped %d), want %+v (skipped 1)", inp.Packages, skipped, wantPkgs)
	}
	wantWP := []enrich.WPRef{{Slug: "contact-form-7", Version: "5.0", Kind: "plugin"}, {Slug: "astra", Version: "3.0", Kind: "theme"}}
	if !reflect.DeepEqual(inp.WPSlugs, wantWP) || !reflect.DeepEqual(inp.JSLibs, []enrich.LibRef{{Name: "jquery", Version: "3.4.0"}}) {
		t.Fatalf("wp = %+v, js = %+v", inp.WPSlugs, inp.JSLibs)
	}
	if _, _, err := buildEnrichInput([]string{"lodash@1.0"}, "", nil, nil, nil); err == nil {
		t.Fatal("a package without an ecosystem must be refused")
	}
}

// offline turns off every source the environment configures, so a test reaches only the server it sets.
func offline(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "SIGFORGE_") {
			t.Setenv(k, "")
		}
	}
}

// An inventory flag that names nothing — empty, blank, or a version with no name, as an unset variable
// leaves "$NAME@$VER" — is refused naming the flag, before enrich reads a page or prints a result; a
// version left empty keeps its meaning: the slug is looked up with no version.
func TestEnrichRefusesAnEmptyInventoryValue(t *testing.T) {
	offline(t)
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	stdin := os.Stdin
	os.Stdin = null // no page
	defer func() { os.Stdin = stdin }()
	for _, flag := range []string{"package", "wp-plugin", "wp-theme", "jslib"} {
		for _, v := range []string{"", " \t", "@", "@3.1.0"} {
			for _, mode := range [][]string{nil, {"--json"}} {
				out := captureStdout(t, func() { err = cmdEnrich(append(mode, "--"+flag, v)) })
				if err == nil || !strings.Contains(err.Error(), "flag -"+flag) || out != "" {
					t.Errorf("enrich %q --%s %q must fail naming the flag and print nothing: err=%v\n%s", mode, flag, v, err, out)
				}
			}
		}
	}
	for _, v := range []string{"npm:@1.0", "npm:@"} { // "npm:$NAME@$VER" with the name unset
		for _, mode := range [][]string{nil, {"--json"}} {
			out := captureStdout(t, func() { err = cmdEnrich(append(mode, "--package", v)) })
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("package %q", v)) || out != "" {
				t.Errorf("enrich %q --package %q must fail naming it and print nothing: err=%v\n%s", mode, v, err, out)
			}
		}
	}
	out := captureStdout(t, func() { err = cmdEnrich([]string{"--json", "--wp-plugin", "akismet@"}) })
	if err != nil || !strings.Contains(out, `"identity": "akismet"`) {
		t.Fatalf("a slug whose version is left empty is still looked up: err=%v\n%s", err, out)
	}
}

// Every command's repeatable flag keeps each value it took — a package, slug or library with or without
// a version (an npm scope's leading "@" included), an OSV ecosystem — trimmed, in order.
func TestListFlagKeepsEveryValueThatNamesSomething(t *testing.T) {
	valid := []string{
		"pkg:npm/lodash@4.17.20", "pkg:npm/%40angular/core@12.0.0", "npm:@angular/core@12.0.0", "maven:org.apache.logging.log4j:log4j-core@2.14.1", // --package
		"contact-form-7@5.0", "akismet@", "astra", // --wp-plugin, --wp-theme
		"jquery@3.4.0", "jquery", "@angular/core", "@angular/core@12.0.0", // --jslib
		"npm", "PyPI", "Debian:12", "crates.io", ".net", "Rocky Linux", // sync --osv
	}
	var l listFlag
	for _, v := range valid {
		if err := l.Set(" " + v + "\t"); err != nil {
			t.Errorf("Set(%q) = %v, want it kept", v, err)
		}
	}
	if !reflect.DeepEqual([]string(l), valid) {
		t.Errorf("kept %q, want %q", []string(l), valid)
	}
}

// sync --osv keeps an ecosystem's dump in the store and always asks the source — even with a
// MaxAge set — so an unchanged dump costs one 304, never a second download.
func TestSyncOSVDump(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	t.Setenv(EnvCacheDir, t.TempDir())
	t.Setenv(EnvCacheMaxAge, "24h")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, _ := zw.Create("npm/GHSA-1.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-1","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	_ = zw.Close()
	dump := zbuf.Bytes()
	var hits, lists, bodies atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/modified_id.csv" {
			lists.Add(1) // this mirror holds dumps only: the changed-records list is not there
		}
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"d1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		bodies.Add(1)
		w.Header().Set("ETag", `"d1"`)
		_, _ = w.Write(dump)
	}))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	for i := 0; i < 2; i++ {
		var err error
		out := captureStdout(t, func() { err = cmdSync([]string{"--osv", "npm"}) })
		if err != nil || !strings.Contains(out, "OSV npm") || !strings.Contains(out, fmt.Sprintf("%d bytes", len(dump))) {
			t.Fatalf("run %d: err=%v out=%q", i, err, out)
		}
	}
	// the second sync asks for the changed-records list once, finds none, and revalidates the dump (304)
	if hits.Load() != 2 || bodies.Load() != 1 || lists.Load() > 1 {
		t.Fatalf("want 2 dump requests, 1 download and at most 1 ask for the changed-records list, got %d, %d and %d", hits.Load(), bodies.Load(), lists.Load())
	}
	if idx, _ := filepath.Glob(filepath.Join(os.Getenv(EnvCacheDir), "*.idx.gz")); len(idx) != 1 {
		t.Fatalf("sync must leave the dump's index file for scans to read, found %v", idx)
	}
}
