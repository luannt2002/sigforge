package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/feedset"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/osv"
)

// sigforge eol says what the end-of-life source did, read from the one place that decides it (the result's reason):
// "not looked up" only when nothing could be asked, "does not list it" when the source was asked and answered so —
// with the request count to match — and --explain says the same; an off or failing source is an error.
func TestCmdEOLSaysWhatTheSourceDid(t *testing.T) {
	var asked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		switch {
		case r.URL.Path == "/bad":
			w.WriteHeader(http.StatusInternalServerError)
		case r.URL.Path == "/bundle":
			_, _ = w.Write([]byte(`{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true}]}]}`))
		case r.URL.Path == "/feed/nginx.json":
			_, _ = w.Write([]byte(`[{"cycle":"1.18","eol":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	const notAsked, notListed = "unknown (no end-of-life product is known for this name: not looked up)", "unknown (the end-of-life source does not list it)"
	for _, tc := range []struct {
		mode, env, url, tech string
		explain              bool
		want, wantErr        string
		requests             int32
	}{
		{"off", "", "", "Nginx", false, "", "feed is off", 0},
		{"off", "", "", "AcmeNoName", false, "", "feed is off", 0},
		{"per product", lifecycle.EnvVar, "/feed", "Nginx", false, "product=nginx", "", 1},
		{"per product", lifecycle.EnvVar, "/feed", "AcmeNoName", false, notAsked, "", 0},
		{"bundle", lifecycle.EnvBundleURL, "/bundle", "Nginx", false, "product=nginx", "", 1},
		{"bundle", lifecycle.EnvBundleURL, "/bundle", "Drupal", false, notListed, "", 1},
		{"bundle", lifecycle.EnvBundleURL, "/bundle", "Drupal", true, "was asked for \"Drupal\" and does not list it", "", 1},
		{"bundle", lifecycle.EnvBundleURL, "/bundle", "AcmeNoName", false, notAsked, "", 0},
		{"bundle", lifecycle.EnvBundleURL, "/bundle", "AcmeNoName", true, "it was not asked", "", 0},
		{"bundle failing", lifecycle.EnvBundleURL, "/bad", "Nginx", false, "", "fetch bundle", 1},
	} {
		offline(t)
		if tc.env != "" {
			t.Setenv(tc.env, srv.URL+tc.url)
		}
		args := []string{tc.tech, "1.18.0"}
		if tc.explain {
			args = append([]string{"--explain"}, args...)
		}
		asked.Store(0)
		var err error
		out := captureStdout(t, func() { err = cmdEOL(args) })
		name := tc.mode + " " + strings.Join(args, " ")
		switch {
		case tc.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err = %v, want one naming %q", name, err, tc.wantErr)
			}
		case err != nil || !strings.Contains(out, tc.want):
			t.Errorf("%s: err %v, output %q — want %q", name, err, out, tc.want)
		}
		if tc.requests != asked.Load() {
			t.Errorf("%s: %d request(s), want %d", name, asked.Load(), tc.requests)
		}
		if tc.want == notListed && strings.Contains(out, "not looked up") {
			t.Errorf("%s: the source was asked, yet the output says not looked up: %q", name, out)
		}
	}
}

// The enrich table names the reason of every result that has one, beside its state, so a reader sees "not
// configured", "not listed", "the source failed" or "no version" without reading the JSON.
func TestEnrichTextNamesTheReason(t *testing.T) {
	offline(t)
	stdinOf(t, "")
	out := captureStdout(t, func() { _ = cmdEnrich([]string{"--package", "npm:lodash@4.17.20"}) })
	if !strings.Contains(out, "[ecosystem:npm] lodash 4.17.20 → not_checked (source_off)  source=osv") {
		t.Errorf("an unconcluded result must name its reason:\n%s", out)
	}

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, _ := zw.Create("npm/GHSA-test-0001.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-test-0001","affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	_ = zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok/npm/all.zip" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(zbuf.Bytes())
	}))
	defer srv.Close()
	for url, want := range map[string][]string{
		srv.URL + "/ok":  {"left-pad 1.0.0 → unknown_product (not_in_source)", "lodash - → potentially_affected (no_version)"},
		srv.URL + "/bad": {"left-pad 1.0.0 → source_unavailable (source_error)"},
	} {
		offline(t)
		t.Setenv(osv.EnvOSVURL, url)
		stdinOf(t, "")
		out := captureStdout(t, func() { _ = cmdEnrich([]string{"--package", "npm:left-pad@1.0.0", "--package", "npm:lodash"}) })
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("OSV at %s: want a line with %q:\n%s", url, w, out)
			}
		}
	}
}

// sigforge eol says where its answer came from when it is not the source's answer now: the stored copy and its time
// (within SIGFORGE_CACHE_MAX_AGE), or the stored copy kept because the source failed, with why — a stored entry
// without a time is "an unknown time", never "not looked up". An answer fetched now prints as before.
func TestCmdEOLSaysHowFreshTheAnswerIs(t *testing.T) {
	var failing atomic.Bool
	var asked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true}]}]}`))
	}))
	defer srv.Close()
	store := t.TempDir()
	run := func(maxAge string, args ...string) string {
		t.Helper()
		offline(t)
		t.Setenv(lifecycle.EnvBundleURL, srv.URL+"/bundle")
		t.Setenv(feedset.EnvCacheDir, store)
		t.Setenv(feedset.EnvCacheMaxAge, maxAge)
		asked.Store(0)
		var err error
		out := captureStdout(t, func() { err = cmdEOL(args) })
		if err != nil {
			t.Fatalf("eol %v: %v", args, err)
		}
		return out
	}
	if out := run("", "Drupal", "9.5.0"); strings.Contains(out, "from:") || asked.Load() != 1 {
		t.Errorf("fetched now: %q after %d request(s) — want the answer alone, 1 request", out, asked.Load())
	}
	if out := run("1h", "--explain", "Drupal", "9.5.0"); !strings.Contains(out, "from:   the stored copy of 20") ||
		!strings.Contains(out, "the stored copy of the end-of-life source does not list \"Drupal\"") || asked.Load() != 0 {
		t.Errorf("within max age: %q after %d request(s) — want the stored copy and its time named, 0 requests", out, asked.Load())
	}
	failing.Store(true)
	if out := run("", "Nginx", "1.18.0"); !strings.Contains(out, "status=eol") || !strings.Contains(out, "kept because the source failed: ") || !strings.Contains(out, "status 500") {
		t.Errorf("source failing, stored copy: %q — want the verdict and the stored copy kept because the source failed", out)
	}
	metas, _ := filepath.Glob(filepath.Join(store, "*.meta"))
	for _, m := range metas { // a stored entry written without a fetch time
		var meta map[string]any
		b, _ := os.ReadFile(m)
		_ = json.Unmarshal(b, &meta)
		delete(meta, "fetched_at")
		b, _ = json.Marshal(meta)
		_ = os.WriteFile(m, b, 0o644)
	}
	out := run("", "Drupal", "9.5.0")
	if !strings.Contains(out, "unknown (the end-of-life source does not list it)") || strings.Contains(out, "not looked up") ||
		!strings.Contains(out, "the stored copy of an unknown time, kept because the source failed") || !strings.Contains(out, "status 500") {
		t.Errorf("source failing, stored copy without a time: %q — want does not list it, from the stored copy of an unknown time", out)
	}
}
