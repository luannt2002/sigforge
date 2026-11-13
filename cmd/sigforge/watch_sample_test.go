package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/osv"
)

const sampleNote = "only the embedded Retire.js sample answered: it ships in the binary and is not a source"

func uncheckedLines(keys ...string) string {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString("UNCHECKED  " + k + "  (the source did not answer: its leads are kept as they were)\n")
	}
	return b.String()
}

// A run only the embedded Retire.js sample answered for — the URL unset, as on a timer that lost its environment,
// or the repository down with nothing in the store — is a run no source answered for: it fails naming the sample,
// prints only what it could not check and leaves the state as it was, byte for byte. A library the sample lists at
// a version it matches nothing for was not answered at all: the run fails as one no source answered, sample unnamed.
func TestWatchFailsWhenOnlyTheEmbeddedSampleAnswers(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer down.Close()
	for _, c := range []struct {
		name, retireURL string
		inventory       []string
		leads           map[string][]string
		sample          bool
	}{
		{name: "the Retire.js URL unset, a library the sample lists", inventory: []string{"--jslib", "jquery@1.12.4"},
			leads: map[string][]string{"jslib jquery@1.12.4": {"CVE-2019-11358", "CVE-2099-0002"}}, sample: true},
		{name: "the Retire.js URL down, a library the sample does not list", retireURL: down.URL, inventory: []string{"--jslib", "fakelib@1.0.0"},
			leads: map[string][]string{"jslib fakelib@1.0.0": {"CVE-2099-0001"}}, sample: true},
		{name: "beside a package no source answered for", inventory: []string{"--jslib", "jquery@1.12.4", "--package", "pkg:npm/lodash@4.17.15"},
			leads: map[string][]string{"jslib jquery@1.12.4": {"CVE-2099-0002"}, "ecosystem:npm lodash@4.17.15": {"GHSA-1"}}, sample: true},
		{name: "a version the sample lists no advisory for", inventory: []string{"--jslib", "jquery@3.6.0"},
			leads: map[string][]string{"jslib jquery@3.6.0": {"CVE-2099-0003"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			offline(t)
			t.Setenv(jslib.EnvRetireJSURL, c.retireURL)
			state := filepath.Join(t.TempDir(), "watch.json")
			before, _ := json.Marshal(watchState{Updated: "2026-11-01T00:00:00Z", Leads: c.leads, Seen: sortedKeys(c.leads)})
			writeFile(t, state, string(before))
			out, err := watchOut(t, append([]string{"--state", state, "--fail-on-new"}, c.inventory...)...)
			if err == nil || !strings.Contains(err.Error(), "no source answered for any of the "+strconv.Itoa(len(c.leads))+" identit(ies) looked up") ||
				strings.Contains(err.Error(), sampleNote) != c.sample {
				t.Errorf("must fail as a run no source answered for, naming the sample only when it answered (%v): err=%v", c.sample, err)
			}
			if want := uncheckedLines(sortedKeys(c.leads)...); out != want {
				t.Errorf("must print only what it could not check:\n%s\nwant:\n%s", out, want)
			}
			if after := readState(t, state); after != string(before) {
				t.Errorf("the state must be left as it was, byte for byte:\n%s", after)
			}
		})
	}
}

// A first run only the embedded sample answered for follows the first-run rule of a run no source answered for: it
// fails and records nothing the sample said, so the library's first answer from the configured repository is FIRST,
// not NEW.
func TestWatchFirstRunOnlyTheEmbeddedSampleAnswersRecordsNothing(t *testing.T) {
	offline(t)
	state := filepath.Join(t.TempDir(), "watch.json")
	out, err := watchOut(t, "--state", state, "--fail-on-new", "--jslib", "jquery@1.12.4")
	want := "first run: 0 lead(s) on 0 identit(ies) recorded; later runs name what changes\n" + uncheckedLines("jslib jquery@1.12.4")
	if err == nil || !strings.Contains(err.Error(), sampleNote) || out != want {
		t.Fatalf("a first run only the sample answered must fail naming it: err=%v\n%s\nwant:\n%s", err, out, want)
	}
	var s watchState
	if err := json.Unmarshal([]byte(readState(t, state)), &s); err != nil || len(s.Leads) != 0 || len(s.Seen) != 0 {
		t.Fatalf("nothing the sample said may be recorded: err=%v\n%s", err, readState(t, state))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jquery":{"vulnerabilities":[{"below":"3.4.0","severity":"medium","identifiers":{"CVE":["CVE-2019-11358"]}}]}}`))
	}))
	defer srv.Close()
	t.Setenv(jslib.EnvRetireJSURL, srv.URL)
	if out, err := watchOut(t, "--state", state, "--fail-on-new", "--jslib", "jquery@1.12.4"); err != nil || out != "FIRST  jslib jquery@1.12.4  1 lead(s) recorded (its first answer)\n" {
		t.Fatalf("the repository's first answer is FIRST, not NEW: err=%v\n%s", err, out)
	}
}

// Beside an identity a configured source answered for, a library only the sample answered for is reckoned as it
// always was: these runs print, fail on and record exactly what they did before the sample rule.
func TestWatchCountsTheEmbeddedSampleBesideAConfiguredAnswer(t *testing.T) {
	offline(t)
	var dump atomic.Value
	dump.Store(osvDump(map[string]string{"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21")}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump.Load().([]byte)) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	inventory := []string{"--state", state, "--fail-on-new", "--jslib", "jquery@1.12.4", "--package", "pkg:npm/lodash@4.17.15"}
	if out, err := watchOut(t, inventory...); err != nil || out != "first run: 3 lead(s) on 2 identit(ies) recorded; later runs name what changes\n" {
		t.Fatalf("first run: err=%v\n%s", err, out)
	}
	dump.Store(osvDump(map[string]string{"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21"), "npm/GHSA-2.json": npmAdvisory("GHSA-2", "lodash", "4.17.21")}))
	out, err := watchOut(t, inventory...)
	if err == nil || err.Error() != "watch: 1 new lead(s)" || out != "NEW   ecosystem:npm lodash@4.17.15  GHSA-2\n" {
		t.Fatalf("second run: err=%v\n%s", err, out)
	}
	var s watchState
	if err := json.Unmarshal([]byte(readState(t, state)), &s); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Leads, map[string][]string{"ecosystem:npm lodash@4.17.15": {"GHSA-1", "GHSA-2"}, "jslib jquery@1.12.4": {"CVE-2019-11358", "CVE-2020-11022"}}; !reflect.DeepEqual(got, want) ||
		strings.Join(s.Seen, ",") != "ecosystem:npm lodash@4.17.15,jslib jquery@1.12.4" {
		t.Fatalf("the state must hold what it always did: %v %v", got, s.Seen)
	}
}

// The repository fails while another source still answers: the run goes on, and the sample it falls back to cannot
// rule out a lead the repository recorded — JavaScript data is never whole, so the lead is kept as UNCHECKED, never GONE.
func TestWatchKeepsAJSLeadTheSampleCannotRuleOutBesideASource(t *testing.T) {
	offline(t)
	var down atomic.Bool
	retire := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"fakelib":{"vulnerabilities":[{"below":"2.0.0","severity":"high","identifiers":{"CVE":["CVE-2099-0001"]}}]}}`))
	}))
	defer retire.Close()
	dump := osvDump(map[string]string{"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21")})
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump) }))
	defer osvSrv.Close()
	t.Setenv(jslib.EnvRetireJSURL, retire.URL)
	t.Setenv(osv.EnvOSVURL, osvSrv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	inventory := []string{"--state", state, "--fail-on-new", "--jslib", "fakelib@1.0.0", "--package", "pkg:npm/lodash@4.17.15"}
	if _, err := watchOut(t, inventory...); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	out, err := watchOut(t, inventory...)
	if want := "UNCHECKED  jslib fakelib@1.0.0  (the source cannot prove its data whole: 1 lead(s) absent from its answer are kept)\n"; err != nil || out != want {
		t.Fatalf("the lead must be kept as UNCHECKED, never GONE: err=%v\n%s\nwant:\n%s", err, out, want)
	}
	if got, want := stateLeads(t, state), map[string][]string{"ecosystem:npm lodash@4.17.15": {"GHSA-1"}, "jslib fakelib@1.0.0": {"CVE-2099-0001"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the state must keep the lead: %v", got)
	}
}

// The configured Retire.js repository served from the store — a synced copy within its age, or the last copy kept
// when the source fails — is the source answering, not the sample: the run goes on as any answered run.
func TestWatchCountsTheJSSourceFromItsStore(t *testing.T) {
	for name, maxAge := range map[string]string{"a synced copy": "", "a stale copy": "0s"} {
		t.Run(name, func(t *testing.T) {
			offline(t)
			t.Setenv(EnvCacheDir, t.TempDir())
			t.Setenv(EnvCacheMaxAge, maxAge)
			var down atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if down.Load() {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				_, _ = w.Write([]byte(`{"fakelib":{"vulnerabilities":[{"below":"2.0.0","severity":"high","identifiers":{"CVE":["CVE-2099-0001"]}}]}}`))
			}))
			defer srv.Close()
			t.Setenv(jslib.EnvRetireJSURL, srv.URL)
			state := filepath.Join(t.TempDir(), "watch.json")
			if _, err := watchOut(t, "--state", state, "--jslib", "fakelib@1.0.0"); err != nil {
				t.Fatal(err)
			}
			down.Store(true)
			out, err := watchOut(t, "--state", state, "--fail-on-new", "--jslib", "fakelib@1.0.0")
			if err != nil || out != "" || !strings.Contains(readState(t, state), "CVE-2099-0001") {
				t.Fatalf("the stored repository answers: the run passes and is recorded: err=%v\n%s\n%s", err, out, readState(t, state))
			}
		})
	}
}
