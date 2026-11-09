package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/merge"
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
