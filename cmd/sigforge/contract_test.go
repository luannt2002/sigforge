package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/feedset"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

var updateContract = flag.Bool("update-contract", false, "rewrite testdata/contract from the current output")

// contractCase is one consumer fixture: the command, its exit, and what it printed as JSON.
type contractCase struct {
	Case    string           `json:"case"`
	Args    []string         `json:"args"`
	Env     []string         `json:"env,omitempty"`
	Exit    int              `json:"exit"`
	Error   string           `json:"error,omitempty"`
	Results []unified.Result `json:"results,omitempty"`
}

// TestContractFixtures runs enrich --json on the cases a consumer must tell apart — nothing to look up, a source
// off, a source failing, an identity the source does not list, a version it cannot read, a match, a whole-data
// miss, a stale stored copy, KEV read from the embedded sample — and holds the output to the fixtures in
// testdata/contract, which consumers mirror. The six looked-up-or-not cases each carry their own (state, reason):
// none is told apart only by the error text.
func TestContractFixtures(t *testing.T) {
	offline(t)
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, _ := zw.Create("npm/GHSA-test-0001.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-test-0001","aliases":["CVE-2099-1111"],"database_specific":{"severity":"HIGH"},` +
		`"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	_ = zw.Close()
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() || strings.HasPrefix(r.URL.Path, "/bad/") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/cve" { // one CVE for whatever is asked: enough to show what a version conflict does to a hit
			_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-2222"}}]}`))
			return
		}
		if r.URL.Path != "/ok/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", "Mon, 09 Nov 2026 02:00:00 GMT")
		_, _ = w.Write(zbuf.Bytes())
	}))
	defer srv.Close()
	store := t.TempDir()
	osvOK, osvBad := osv.EnvOSVURL+"="+srv.URL+"/ok", osv.EnvOSVURL+"="+srv.URL+"/bad"
	var page string // the page on stdin; most cases give none
	pkg := func(v string) []string { return []string{"--json", "--package", "npm:lodash@" + v} }
	cases := []struct {
		name string
		args []string
		env  []string
		pre  func()
	}{
		{"1-nothing-to-look-up", []string{"--json"}, nil, nil},
		{"2-source-off", pkg("4.17.20"), nil, nil},
		{"3-source-error", pkg("4.17.20"), []string{osvBad}, nil},
		{"4-not-in-source", []string{"--json", "--package", "npm:left-pad@1.0.0"}, []string{osvOK}, nil},
		{"5-version-unreadable", pkg("not.a.version"), []string{osvOK}, nil},
		{"6-advisory-match", pkg("4.17.20"), []string{osvOK}, nil},
		{"7-no-clearance", pkg("4.17.21"), []string{osvOK}, nil},
		{"8-stale-stored-copy", pkg("4.17.20"), []string{osvOK, feedset.EnvCacheDir + "=" + store}, func() {
			t.Setenv(osv.EnvOSVURL, srv.URL+"/ok")
			t.Setenv(feedset.EnvCacheDir, store)
			stdinOf(t, "")
			captureStdout(t, func() { _ = cmdEnrich(pkg("4.17.20")) }) // a good copy enters the store
			failing.Store(true)
		}},
		{"9-kev-from-sample", []string{"--json", "--jslib", "jquery@1.8.0"}, nil, nil},
		{"10-version-conflict", []string{"--json", "--db", "testdata/contract/conflict-db.json"}, []string{cve.EnvVar + "=" + srv.URL + "/cve"}, func() {
			page = `{"headers":{"X-Acme":["acme/9.5"]},"html":"acme-v10.0"}` // two version claims that disagree
		}},
		{"11-distro-build", []string{"--json"}, []string{cve.EnvVar + "=" + srv.URL + "/cve"}, func() {
			page = `{"headers":{"Server":["Apache/2.4.6 (CentOS)"]}}` // the upstream number of a distro's package build
		}},
	}
	normalize := regexp.MustCompile(`"fetched_at": "[^"]*"`)
	seen := map[[2]string]string{}
	for _, c := range cases {
		offline(t)
		page = ""
		failing.Store(false)
		if c.pre != nil {
			c.pre()
		}
		for _, kv := range c.env {
			k, v, _ := strings.Cut(kv, "=")
			t.Setenv(k, v)
		}
		stdinOf(t, page)
		var err error
		out := captureStdout(t, func() { err = cmdEnrich(c.args) })
		got := contractCase{Case: c.name, Args: c.args, Env: envNames(c.env)}
		if err != nil {
			got.Exit, got.Error = 1, err.Error()
		}
		if out != "" {
			if jerr := json.Unmarshal([]byte(out), &got.Results); jerr != nil {
				t.Fatalf("%s: stdout is not JSON: %v\n%s", c.name, jerr, out)
			}
		}
		b, _ := json.MarshalIndent(got, "", "  ")
		b = normalize.ReplaceAll(bytes.ReplaceAll(b, []byte(srv.URL), []byte("http://source.test")), []byte(`"fetched_at": "2000-01-01T00:00:00Z"`))
		path := filepath.Join("testdata", "contract", c.name+".json")
		if *updateContract {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, rerr := os.ReadFile(path)
		if rerr != nil || string(want) != string(b)+"\n" {
			t.Errorf("%s: output differs from %s (rerun with -update-contract after review):\n%s", c.name, path, b)
		}
		if len(got.Results) == 1 && c.name != "8-stale-stored-copy" && c.name != "9-kev-from-sample" && c.name != "10-version-conflict" && c.name != "11-distro-build" {
			key := [2]string{got.Results[0].State.String(), got.Results[0].Reason}
			if prev, dup := seen[key]; dup {
				t.Errorf("%s and %s share state/reason %v: a consumer could not tell them apart", prev, c.name, key)
			}
			seen[key] = c.name
		}
	}
	if len(seen) != 6 {
		t.Errorf("want 6 distinct state/reason pairs among the looked-up-or-not cases, got %d: %v", len(seen), seen)
	}
}

// envNames is the variables a case set, by name only: a fixture never carries a URL a consumer would mistake for a source.
func envNames(env []string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		out = append(out, k)
	}
	return out
}

// enrich --sbom with no page and no component carrying a usable purl looks nothing up: it fails as watch does,
// rather than print "no detections" that a timer reads as quiet.
func TestEnrichSBOMWithNothingUsableFails(t *testing.T) {
	offline(t)
	sbom := filepath.Join(t.TempDir(), "bom.json")
	writeFile(t, sbom, `{"bomFormat":"CycloneDX","components":[{"name":"no-purl"},{"purl":"not a purl"}]}`)
	for _, args := range [][]string{{"--sbom", sbom}, {"--json", "--sbom", sbom}} {
		stdinOf(t, "")
		var err error
		out := captureStdout(t, func() { err = cmdEnrich(args) })
		if err == nil || !strings.Contains(err.Error(), "nothing to look up") || !strings.Contains(err.Error(), "SBOM") || out != "" {
			t.Errorf("enrich %q: err=%v out=%q, want a failure naming nothing to look up in the SBOM and no output", args, err, out)
		}
	}
}

// The text kev column says false only when the CISA KEV catalog was checked: absent from the embedded sample,
// or with KEV not consulted, a lead is "-" (not known); a lead KEV lists is true either way.
func TestEnrichTextKEV(t *testing.T) {
	offline(t)
	stdinOf(t, "")
	out := captureStdout(t, func() { _ = cmdEnrich([]string{"--jslib", "jquery@1.8.0"}) })
	if strings.Contains(out, "kev=false") || !strings.Contains(out, "kev=-") {
		t.Errorf("KEV from the embedded sample only must print kev=- for a lead it does not list:\n%s", out)
	}
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"count":1,"vulnerabilities":[{"cveID":"CVE-2020-11022"}]}`))
	}))
	defer catalog.Close()
	t.Setenv(kev.EnvKEVURL, catalog.URL)
	stdinOf(t, "")
	out = captureStdout(t, func() { _ = cmdEnrich([]string{"--jslib", "jquery@1.8.0"}) })
	if !strings.Contains(out, "kev=false") || !strings.Contains(out, "kev=true") || strings.Contains(out, "kev=-") {
		t.Errorf("with the catalog checked a lead is true or false, never -:\n%s", out)
	}
}

// A result with no identity (no CPE for a detection) names its tech in the enrich table instead of "-", so a reader
// can tell which detection was not looked up.
func TestEnrichTextNamesTheTechOfAResultWithNoIdentity(t *testing.T) {
	offline(t)
	db := filepath.Join(t.TempDir(), "db.json")
	writeFile(t, db, `{"schema_version":"1.0.0","fingerprints":{"Acme":{"headers":{"X-Acme":[""]}}}}`)
	stdinOf(t, `{"headers":{"X-Acme":["1"]}}`)
	out := captureStdout(t, func() { _ = cmdEnrich([]string{"--db", db}) })
	if !strings.Contains(out, "[cpe] Acme - → not_checked") {
		t.Errorf("a cpe result with no identity must name its tech:\n%s", out)
	}
}

// Every fixture survives a round trip — JSON → unified.Result → JSON, byte for byte: no state, reason, freshness, null
// score or note is lost or invented on the way through the contract's own types. Over the whole fixture suite it also
// counts what must stay zero: a result read as clean (not_affected_by_advisory — sigforge issues none) and a result not
// concluded that gives no reason.
func TestContractFixturesRoundTrip(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "contract", "[0-9]*.json"))
	if err != nil || len(files) < 11 {
		t.Fatalf("want the 11 contract fixtures, got %d (%v)", len(files), err)
	}
	results, clean, noReason := 0, 0, 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c contractCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		again, _ := json.MarshalIndent(c, "", "  ")
		if string(again)+"\n" != string(raw) {
			t.Errorf("%s does not survive a round trip:\n%s", f, again)
		}
		for _, r := range c.Results {
			results++
			if r.State == unified.StateNotAffectedByAdvisory {
				clean++
			}
			if (!r.State.Concluded() || r.State == unified.StatePotentiallyAffected) && r.Reason == "" {
				noReason++
			}
		}
	}
	if clean != 0 || noReason != 0 {
		t.Errorf("over %d results: %d read as clean, %d not concluded without a reason — want 0 and 0", results, clean, noReason)
	}
	t.Logf("%d fixtures, %d results: round trip lossless; clean 0; unconcluded without reason 0", len(files), results)
}
