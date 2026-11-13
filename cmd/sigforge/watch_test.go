package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// watch re-checks an inventory against the sources as they are now and names what changed since its
// last run: a new advisory for a package in use is NEW (and, with --fail-on-new, fails the command so a
// timer can alarm), one no longer listed is GONE. The first run only records where things stand.
func TestWatchNamesNewAndGoneLeads(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	t.Setenv(EnvCacheDir, "")
	zipOf := func(entries map[string]string) []byte {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		for n, body := range entries {
			w, _ := zw.Create(n)
			_, _ = w.Write([]byte(body))
		}
		_ = zw.Close()
		return b.Bytes()
	}
	adv := func(id, fixed string) string {
		return `{"id":"` + id + `","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]}]}`
	}
	var dump atomic.Value
	dump.Store(zipOf(map[string]string{"npm/GHSA-old.json": adv("GHSA-old", "4.17.21")}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump.Load().([]byte)) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	run := func(extra ...string) (string, error) {
		var err error
		out := captureStdout(t, func() {
			err = cmdWatch(append([]string{"--state", state, "--package", "pkg:npm/lodash@4.17.20"}, extra...))
		})
		return out, err
	}

	if out, err := run(); err != nil || !strings.Contains(out, "first run") || strings.Contains(out, "NEW") {
		t.Fatalf("first run must only record: err=%v\n%s", err, out)
	}
	if out, err := run("--fail-on-new"); err != nil || strings.Contains(out, "NEW") || strings.Contains(out, "GONE") {
		t.Fatalf("nothing changed: err=%v\n%s", err, out)
	}
	dump.Store(zipOf(map[string]string{"npm/GHSA-new.json": adv("GHSA-new", "4.17.22")}))
	out, err := run("--fail-on-new")
	if err == nil || !strings.Contains(out, "NEW") || !strings.Contains(out, "GHSA-new") || !strings.Contains(out, "lodash") ||
		!strings.Contains(out, "GONE") || !strings.Contains(out, "GHSA-old") {
		t.Fatalf("a new advisory must be NEW and fail the run, the dropped one GONE: err=%v\n%s", err, out)
	}
	if out, err := run("--fail-on-new"); err != nil || strings.Contains(out, "NEW") {
		t.Fatalf("a lead already reported is not new again: err=%v\n%s", err, out)
	}
}

// watch runs right after sync (the documented timer): it reads the store sync keeps, so an unchanged
// inventory costs no request — even with SIGFORGE_CACHE_MAX_AGE unset — instead of a whole dump per run.
func TestWatchReadsTheSyncedStore(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	t.Setenv(EnvCacheDir, t.TempDir())
	t.Setenv(EnvCacheMaxAge, "")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, _ := zw.Create("npm/GHSA-1.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-1","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	_ = zw.Close()
	var dumps atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		dumps.Add(1)
		_, _ = w.Write(zbuf.Bytes())
	}))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	captureStdout(t, func() {
		if err := cmdSync([]string{"--osv", "npm"}); err != nil {
			t.Fatal(err)
		}
	})
	state := filepath.Join(t.TempDir(), "watch.json")
	for i := 0; i < 2; i++ {
		var err error
		out := captureStdout(t, func() { err = cmdWatch([]string{"--state", state, "--package", "pkg:npm/lodash@4.17.20"}) })
		if err != nil || (i == 1 && strings.Contains(out, "GHSA-1")) {
			t.Fatalf("run %d: err=%v\n%s", i, err, out)
		}
	}
	if dumps.Load() != 1 {
		t.Fatalf("sync downloads the dump once; watch must read it from the store, got %d dump requests", dumps.Load())
	}
}

// A run the source did not answer knows nothing about the inventory's leads: they are UNCHECKED, not
// GONE, and the next answered run does not report them NEW again.
func TestWatchKeepsLeadsTheSourceDidNotAnswerFor(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	t.Setenv(EnvCacheDir, "")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, _ := zw.Create("npm/GHSA-1.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-1","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	_ = zw.Close()
	var down atomic.Bool
	var dump atomic.Value
	dump.Store(zbuf.Bytes())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write(dump.Load().([]byte))
	}))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	run := func() (string, error) {
		var err error
		out := captureStdout(t, func() {
			err = cmdWatch([]string{"--state", state, "--fail-on-new", "--package", "pkg:npm/lodash@4.17.20"})
		})
		return out, err
	}
	if _, err := run(); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	// nothing in the inventory could be checked: the run fails, so a timer does not read it as quiet
	if out, err := run(); err == nil || strings.Contains(out, "GONE") || !strings.Contains(out, "UNCHECKED") || !strings.Contains(out, "lodash") {
		t.Fatalf("an unanswered run must say UNCHECKED, never GONE, and fail: err=%v\n%s", err, out)
	}
	down.Store(false)
	if out, err := run(); err != nil || strings.Contains(out, "NEW") {
		t.Fatalf("a lead known before the outage is not new after it: err=%v\n%s", err, out)
	}
	var fixed bytes.Buffer
	zw = zip.NewWriter(&fixed)
	f, _ = zw.Create("npm/GHSA-1.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-1","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.19"}]}]}]}`))
	_ = zw.Close()
	dump.Store(fixed.Bytes())
	if out, err := run(); err != nil || !strings.Contains(out, "GONE") || strings.Contains(out, "UNCHECKED") {
		t.Fatalf("an answered run that no longer lists the lead says GONE: err=%v\n%s", err, out)
	}
}

// An identity's first answer is where it stands, not news: a first run the source did not answer,
// or a package added to the inventory later, records its leads; only a lead appearing after that
// is NEW.
func TestWatchFirstAnswerIsRecordedNotNew(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	t.Setenv(EnvCacheDir, "")
	zipOf := func(ids ...string) []byte {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		for _, id := range ids {
			w, _ := zw.Create("npm/" + id + ".json")
			lodashFixed := "4.17.21"
			if id == "GHSA-2" {
				lodashFixed = "4.17.30"
			}
			_, _ = w.Write([]byte(`{"id":"` + id + `","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"` + lodashFixed + `"}]}]},` +
				`{"package":{"name":"minimist","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.6"}]}]}]}`))
		}
		_ = zw.Close()
		return b.Bytes()
	}
	var down atomic.Bool
	var dump atomic.Value
	dump.Store(zipOf("GHSA-1"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write(dump.Load().([]byte))
	}))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	run := func(pkgs ...string) (string, error) {
		var err error
		args := []string{"--state", state, "--fail-on-new"}
		for _, p := range pkgs {
			args = append(args, "--package", p)
		}
		out := captureStdout(t, func() { err = cmdWatch(args) })
		return out, err
	}
	down.Store(true)
	if _, err := run("pkg:npm/lodash@4.17.20"); err == nil {
		t.Fatal("a first run nothing answered must fail")
	}
	down.Store(false)
	if out, err := run("pkg:npm/lodash@4.17.20"); err != nil || strings.Contains(out, "NEW") || !strings.Contains(out, "FIRST") {
		t.Fatalf("the first answer after an unanswered first run is recorded, not new: err=%v\n%s", err, out)
	}
	inventory := []string{"pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.5", "pkg:npm/lodash@4.17.25"}
	if out, err := run(inventory...); err != nil || strings.Contains(out, "NEW") || !strings.Contains(out, "minimist") {
		t.Fatalf("a package added to the inventory is recorded, not new: err=%v\n%s", err, out)
	}
	// lodash@4.17.25 was answered with no lead: its first lead is news like any other
	dump.Store(zipOf("GHSA-1", "GHSA-2"))
	if out, err := run(inventory...); err == nil || strings.Count(out, "NEW") != 3 || !strings.Contains(out, "lodash@4.17.25  GHSA-2") {
		t.Fatalf("a lead appearing after the first answer is NEW for each identity: err=%v\n%s", err, out)
	}
}

// A run that looked nothing up — no inventory flag, --sbom from an unset variable, an SBOM without
// components — knows nothing about the inventory: it fails, reports nothing and leaves the state as it
// was, so a timer never reads it as quiet and the kept leads are neither reported GONE nor erased.
func TestWatchFailsWhenNothingIsLookedUp(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	t.Setenv(EnvCacheDir, "")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for _, id := range []string{"GHSA-1", "GHSA-2"} {
		f, _ := zw.Create("npm/" + id + ".json")
		_, _ = f.Write([]byte(`{"id":"` + id + `","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	}
	_ = zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(zbuf.Bytes()) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	primed := filepath.Join(t.TempDir(), "watch.json")
	var err error
	captureStdout(t, func() { err = cmdWatch([]string{"--state", primed, "--package", "pkg:npm/lodash@4.17.15"}) })
	before, rerr := os.ReadFile(primed)
	if err != nil || rerr != nil || !strings.Contains(string(before), "GHSA-1") || !strings.Contains(string(before), "GHSA-2") {
		t.Fatalf("the first run must record lodash's two leads: err=%v read=%v\n%s", err, rerr, before)
	}
	emptySBOM := filepath.Join(t.TempDir(), "inventory.cdx.json")
	writeFile(t, emptySBOM, `{"bomFormat":"CycloneDX","components":[]}`)
	for name, inventory := range map[string][]string{
		"no inventory flag":       nil,
		"empty --sbom":            {"--sbom", ""},
		"SBOM without components": {"--sbom", emptySBOM},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			state, absent := filepath.Join(dir, "watch.json"), filepath.Join(dir, "absent.json")
			writeFile(t, state, string(before))
			for _, path := range []string{state, absent} {
				var err error
				out := captureStdout(t, func() { err = cmdWatch(append([]string{"--state", path, "--fail-on-new"}, inventory...)) })
				if err == nil || !strings.Contains(err.Error(), "nothing to look up") || out != "" {
					t.Errorf("%s: a run with nothing to look up must fail and print nothing: err=%v\n%s", filepath.Base(path), err, out)
				}
			}
			if after, err := os.ReadFile(state); err != nil || !bytes.Equal(after, before) {
				t.Errorf("the state must be left as it was, byte for byte (read err=%v):\n%s", err, after)
			}
			if _, err := os.Stat(absent); !os.IsNotExist(err) {
				t.Errorf("a run with nothing to look up must not create a state file (stat err=%v)", err)
			}
		})
	}
}

// An inventory flag left empty — "$SLUG", or "$SLUG@$VER" with the slug unset — is refused naming the
// flag, alone or beside a valid identity; an SBOM whose components all lack a usable purl has nothing
// to look up and says so. Either way the run reports nothing and leaves the state as it was, so a
// broken unit neither erases the kept leads nor reads as quiet.
func TestWatchRefusesAnEmptyInventoryValue(t *testing.T) {
	offline(t)
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for _, id := range []string{"GHSA-1", "GHSA-2"} {
		f, _ := zw.Create("npm/" + id + ".json")
		_, _ = f.Write([]byte(`{"id":"` + id + `","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	}
	_ = zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(zbuf.Bytes()) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	const lodash = "pkg:npm/lodash@4.17.15"
	primed := filepath.Join(t.TempDir(), "watch.json")
	var err error
	captureStdout(t, func() { err = cmdWatch([]string{"--state", primed, "--package", lodash}) })
	before, rerr := os.ReadFile(primed)
	if err != nil || rerr != nil || !strings.Contains(string(before), "GHSA-1") || !strings.Contains(string(before), "GHSA-2") {
		t.Fatalf("the first run must record lodash's two leads: err=%v read=%v\n%s", err, rerr, before)
	}
	noPurl := filepath.Join(t.TempDir(), "inventory.cdx.json")
	writeFile(t, noPurl, `{"bomFormat":"CycloneDX","components":[{"name":"lodash","version":"4.17.15"},{"name":"left-pad","purl":"left-pad@1.3.0"}]}`)
	type refused struct {
		args []string
		want string // in the error
	}
	cases := map[string]refused{"SBOM without a usable purl": {[]string{"--sbom", noPurl}, "usable purl"}}
	for _, flag := range []string{"package", "wp-plugin", "wp-theme", "jslib"} {
		for _, v := range []string{"", " \t", "@", "@1.0"} {
			cases[fmt.Sprintf("--%s %q", flag, v)] = refused{[]string{"--" + flag, v}, "flag -" + flag}
			cases[fmt.Sprintf("--%s %q beside a valid package", flag, v)] = refused{[]string{"--package", lodash, "--" + flag, v}, "flag -" + flag}
		}
	}
	for _, v := range []string{"npm:@1.0", "npm:@"} { // "npm:$NAME@$VER" with the name unset
		cases["--package "+v] = refused{[]string{"--package", v}, fmt.Sprintf("package %q", v)}
		cases["--package "+v+" beside a valid package"] = refused{[]string{"--package", lodash, "--package", v}, fmt.Sprintf("package %q", v)}
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "watch.json")
			writeFile(t, state, string(before))
			var err error
			out := captureStdout(t, func() { err = cmdWatch(append([]string{"--state", state, "--fail-on-new"}, c.args...)) })
			if err == nil || !strings.Contains(err.Error(), c.want) || out != "" {
				t.Errorf("must fail with %q and print nothing: err=%v\n%s", c.want, err, out)
			}
			if after, err := os.ReadFile(state); err != nil || !bytes.Equal(after, before) {
				t.Errorf("the state must be left as it was, byte for byte (read err=%v):\n%s", err, after)
			}
		})
	}
}

func osvDump(entries map[string]string) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range entries {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	return b.Bytes()
}

func npmAdvisory(id, pkg, fixed string) string {
	return `{"id":"` + id + `","affected":[{"package":{"name":"` + pkg + `","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]}]}`
}

func watchOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = cmdWatch(args) })
	return out, err
}

func readState(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func stateLeads(t *testing.T, path string) map[string][]string {
	t.Helper()
	var s watchState
	if err := json.Unmarshal([]byte(readState(t, path)), &s); err != nil {
		t.Fatal(err)
	}
	return s.Leads
}

// A WordPress feed that answers but lists nothing for the plugin (null, {}, {"data":null}) cannot prove its
// list whole: the leads recorded before are kept and named UNCHECKED, never GONE. While it still lists
// every recorded lead, nothing is named.
func TestWatchKeepsLeadsTheWordPressFeedNoLongerLists(t *testing.T) {
	offline(t)
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body.Load().(string))) }))
	defer srv.Close()
	t.Setenv(wpcve.EnvWPVulnURL, srv.URL+"/{kind}/{slug}")
	const listed = `{"akismet":{"vulnerabilities":[{"id":"WPV-1","title":"XSS","min_version":"1.0","max_version":"5.0"},{"id":"WPV-2","title":"CSRF","max_version":"5.0"}]}}`
	for _, empty := range []string{"null", "{}", `{"data":null}`} {
		t.Run(empty, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "watch.json")
			body.Store(listed)
			if _, err := watchOut(t, "--state", state, "--wp-plugin", "akismet@4.0"); err != nil || !strings.Contains(readState(t, state), "WPV-2") {
				t.Fatalf("the first run must record the plugin's leads: err=%v\n%s", err, readState(t, state))
			}
			if out, err := watchOut(t, "--state", state, "--fail-on-new", "--wp-plugin", "akismet@4.0"); err != nil || out != "" {
				t.Fatalf("an answer that still lists every recorded lead names nothing: err=%v\n%s", err, out)
			}
			body.Store(empty)
			out, err := watchOut(t, "--state", state, "--fail-on-new", "--wp-plugin", "akismet@4.0")
			if err != nil || strings.Contains(out, "GONE") || !strings.Contains(out, "UNCHECKED  wordpress:plugin akismet@4.0") {
				t.Fatalf("a feed that lists nothing must keep the leads as UNCHECKED, never GONE: err=%v\n%s", err, out)
			}
			if s := readState(t, state); !strings.Contains(s, "WPV-1") || !strings.Contains(s, "WPV-2") {
				t.Fatalf("the kept leads must stay in the state:\n%s", s)
			}
		})
	}
}

// A dump with an entry it could not read is not the source's whole data: a lead absent from it may sit in
// that entry, so it is kept and named UNCHECKED, never GONE — whether the package lost one advisory or every
// one — while an advisory the dump does list is still NEW; once the dump reads whole again, nothing kept is new.
func TestWatchKeepsLeadsAPartialDumpCannotRuleOut(t *testing.T) {
	offline(t)
	var dump atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump.Load().([]byte)) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	run := func() (string, error) {
		return watchOut(t, "--state", state, "--fail-on-new", "--package", "pkg:npm/lodash@4.17.20", "--package", "pkg:npm/minimist@1.2.5")
	}
	whole := map[string]string{
		"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21"),
		"npm/GHSA-2.json": npmAdvisory("GHSA-2", "lodash", "4.17.21"),
		"npm/GHSA-M.json": npmAdvisory("GHSA-M", "minimist", "1.2.6"),
	}
	dump.Store(osvDump(whole))
	if _, err := run(); err != nil {
		t.Fatal(err)
	}
	dump.Store(osvDump(map[string]string{
		"npm/GHSA-1.json": whole["npm/GHSA-1.json"],
		"npm/GHSA-2.json": `{"id":"GHSA-2",`, // lodash keeps GHSA-1: the unreadable entry holds a kept lead
		"npm/GHSA-3.json": npmAdvisory("GHSA-3", "lodash", "4.17.21"),
		"npm/GHSA-M.json": `{"id":"GHSA-M",`, // minimist's only entry: the package is absent from the dump
	}))
	out, err := run()
	if err == nil || strings.Contains(out, "GONE") || !strings.Contains(out, "NEW   ecosystem:npm lodash@4.17.20  GHSA-3") ||
		!strings.Contains(out, "UNCHECKED  ecosystem:npm lodash@4.17.20") || !strings.Contains(out, "UNCHECKED  ecosystem:npm minimist@1.2.5") {
		t.Fatalf("a partial dump must keep what it no longer lists as UNCHECKED, never GONE, and still name a new advisory NEW: err=%v\n%s", err, out)
	}
	if s := readState(t, state); !strings.Contains(s, "GHSA-2") || !strings.Contains(s, "GHSA-3") || !strings.Contains(s, "GHSA-M") {
		t.Fatalf("the state must keep the leads the dump could not rule out and record the new one:\n%s", s)
	}
	if got, want := stateLeads(t, state), map[string][]string{"ecosystem:npm lodash@4.17.20": {"GHSA-1", "GHSA-2", "GHSA-3"}, "ecosystem:npm minimist@1.2.5": {"GHSA-M"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("a kept lead joins the answered ones in sorted order: got %v, want %v", got, want)
	}
	whole["npm/GHSA-3.json"] = npmAdvisory("GHSA-3", "lodash", "4.17.21")
	dump.Store(osvDump(whole))
	if out, err := run(); err != nil || out != "" {
		t.Fatalf("a dump read whole again changes nothing that was kept: err=%v\n%s", err, out)
	}
}

// A dump read whole that no longer lists the package at all (its advisories withdrawn) rules its leads out: GONE.
func TestWatchNamesGoneWhenAWholeDumpNoLongerListsThePackage(t *testing.T) {
	offline(t)
	var dump atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump.Load().([]byte)) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	minimist := npmAdvisory("GHSA-M", "minimist", "1.2.6")
	dump.Store(osvDump(map[string]string{"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21"), "npm/GHSA-M.json": minimist}))
	if _, err := watchOut(t, "--state", state, "--package", "pkg:npm/lodash@4.17.20"); err != nil {
		t.Fatal(err)
	}
	dump.Store(osvDump(map[string]string{"npm/GHSA-M.json": minimist}))
	out, err := watchOut(t, "--state", state, "--fail-on-new", "--package", "pkg:npm/lodash@4.17.20")
	if err != nil || !strings.Contains(out, "GONE  ecosystem:npm lodash@4.17.20  GHSA-1") || strings.Contains(out, "UNCHECKED") {
		t.Fatalf("a whole dump without the package must say GONE: err=%v\n%s", err, out)
	}
}

// The JavaScript source falls back to its embedded sample when the repository fails: a library the sample
// does not list is unknown to it, not rid of its advisories — the leads are kept, never GONE. The sample is not a
// source, so a run only it answered for fails naming it.
func TestWatchKeepsLeadsTheEmbeddedSampleCannotRuleOut(t *testing.T) {
	offline(t)
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
	if _, err := watchOut(t, "--state", state, "--jslib", "fakelib@1.0.0"); err != nil || !strings.Contains(readState(t, state), "CVE-2099-0001") {
		t.Fatalf("the first run must record the library's lead: err=%v\n%s", err, readState(t, state))
	}
	down.Store(true)
	out, err := watchOut(t, "--state", state, "--fail-on-new", "--jslib", "fakelib@1.0.0")
	if err == nil || !strings.Contains(err.Error(), "only the embedded Retire.js sample answered") || strings.Contains(out, "GONE") || !strings.Contains(out, "UNCHECKED  jslib fakelib@1.0.0") || !strings.Contains(readState(t, state), "CVE-2099-0001") {
		t.Fatalf("the embedded sample must keep the lead as UNCHECKED, never GONE: err=%v\n%s\n%s", err, out, readState(t, state))
	}
}

// A version the source can no longer compare (a parser that changed between releases) says nothing about
// the leads an earlier run recorded for it: they are kept and named UNCHECKED, never GONE.
func TestWatchKeepsLeadsOfAVersionTheSourceCannotCompare(t *testing.T) {
	offline(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"acme":{"vulnerabilities":[{"id":"V1","title":"XSS","min_version":"1.0","max_version":"5.0"}]}}`))
	}))
	defer srv.Close()
	t.Setenv(wpcve.EnvWPVulnURL, srv.URL+"/{kind}/{slug}")
	state := filepath.Join(t.TempDir(), "watch.json")
	const key = "wordpress:plugin acme@trunk"
	writeFile(t, state, `{"updated":"2026-11-01T00:00:00Z","leads":{"`+key+`":["V1"]},"seen":["`+key+`"]}`)
	out, err := watchOut(t, "--state", state, "--fail-on-new", "--wp-plugin", "acme@trunk")
	if err != nil || strings.Contains(out, "GONE") || !strings.Contains(out, "UNCHECKED  "+key) || !strings.Contains(readState(t, state), `"V1"`) {
		t.Fatalf("a version the source cannot compare must keep its leads as UNCHECKED, never GONE: err=%v\n%s\n%s", err, out, readState(t, state))
	}
}

// An identity that leaves the inventory (a version bump, a regenerated SBOM) was not looked up, so its
// advisories are not gone: one with leads is named REMOVED once, its leads leave the state and the run does
// not fail; listed again later, each of its leads is NEW. One without leads leaves unnamed.
func TestWatchNamesAnIdentityThatLeftTheInventoryRemoved(t *testing.T) {
	offline(t)
	dump := osvDump(map[string]string{"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21"), "npm/GHSA-2.json": npmAdvisory("GHSA-2", "lodash", "4.17.21")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	const old, bumped = "pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"
	if _, err := watchOut(t, "--state", state, "--package", old); err != nil {
		t.Fatal(err)
	}
	out, err := watchOut(t, "--state", state, "--fail-on-new", "--package", bumped)
	if err != nil || strings.Contains(out, "GONE") || !strings.Contains(out, "REMOVED  ecosystem:npm lodash@4.17.20") {
		t.Fatalf("an identity no longer in the inventory is REMOVED, not GONE, and does not fail the run: err=%v\n%s", err, out)
	}
	if s := readState(t, state); strings.Contains(s, "GHSA-1") || !strings.Contains(s, `"ecosystem:npm lodash@4.17.20"`) {
		t.Fatalf("its leads must leave the state while it stays seen:\n%s", s)
	}
	if out, err := watchOut(t, "--state", state, "--fail-on-new", "--package", bumped); err != nil || out != "" {
		t.Fatalf("REMOVED is named once: err=%v\n%s", err, out)
	}
	out, err = watchOut(t, "--state", state, "--fail-on-new", "--package", old) // lodash@4.17.21, with no lead, leaves
	if err == nil || !strings.Contains(out, "NEW   ecosystem:npm lodash@4.17.20  GHSA-1") || !strings.Contains(out, "NEW   ecosystem:npm lodash@4.17.20  GHSA-2") ||
		strings.Contains(out, "REMOVED") {
		t.Fatalf("an identity listed again names each of its leads NEW, and one without leads leaves unnamed: err=%v\n%s", err, out)
	}
}

// A run no source answered for knows nothing: it fails and leaves the state as it was, byte for byte —
// the leads of an identity it did not list are neither GONE nor REMOVED, and nothing is rewritten.
func TestWatchLeavesTheStateAsItWasWhenNoSourceAnswers(t *testing.T) {
	offline(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	const before = `{"updated":"2026-11-01T00:00:00Z","leads":{"ecosystem:npm lodash@4.17.15":["GHSA-1","GHSA-2"]},"seen":["ecosystem:npm lodash@4.17.15"]}`
	for name, inventory := range map[string][]string{
		"the WordPress feed off, another identity": {"--wp-plugin", "akismet@4.0"},
		"the OSV source down, the same identity":   {"--package", "pkg:npm/lodash@4.17.15"},
	} {
		t.Run(name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "watch.json")
			writeFile(t, state, before)
			out, err := watchOut(t, append([]string{"--state", state, "--fail-on-new"}, inventory...)...)
			if err == nil || !strings.Contains(out, "UNCHECKED") || strings.Contains(out, "GONE") || strings.Contains(out, "REMOVED") {
				t.Errorf("a run no source answered must fail naming only what it could not check: err=%v\n%s", err, out)
			}
			if after := readState(t, state); after != before {
				t.Errorf("the state must be left as it was, byte for byte:\n%s", after)
			}
		})
	}
}

// leadsByIdentity sorts each identity by what its answer can say: a source that did not look it up leaves it
// unchecked; one that did, from data it cannot prove whole or for a version it could not compare, leaves it
// answered but unable to rule a lead out (with why); only the rest can make a lead GONE.
func TestLeadsByIdentitySplitsWhatAnAnswerCanRuleOut(t *testing.T) {
	const key = "ecosystem:npm x@1"
	type split struct{ answered, unchecked, notWhole bool }
	for _, tc := range []struct {
		state       unified.State
		err         string
		part, whole split // FullData false, true
	}{
		{unified.StateNotChecked, "", split{false, true, false}, split{false, true, false}},
		{unified.StateNotChecked, unified.NoteNoClearance, split{true, false, true}, split{true, false, false}},
		{unified.StateSourceUnavailable, "", split{false, true, false}, split{false, true, false}},
		{unified.StateUnknownProduct, "", split{true, false, true}, split{true, false, false}},
		{unified.StateUnknownVersion, "", split{true, false, true}, split{true, false, true}},
		{unified.StatePotentiallyAffected, "", split{true, false, true}, split{true, false, false}},
		{unified.StateAffectedByAdvisory, "", split{true, false, true}, split{true, false, false}},
		{unified.StateNotAffectedByAdvisory, "", split{true, false, true}, split{true, false, false}},
	} {
		for _, full := range []bool{false, true} {
			want := tc.part
			if full {
				want = tc.whole
			}
			r := unified.Result{State: tc.state, Err: tc.err, FullData: full, Scope: "ecosystem:npm", Identity: "x", Version: "1", Leads: []unified.Lead{{ID: "B"}, {ID: "A"}}}
			leads, answered, unchecked, notWhole := leadsByIdentity([]unified.Result{r})
			got := split{answered[key], unchecked[key], notWhole[key] != ""}
			if got != want {
				t.Errorf("%v %q full=%v: answered/unchecked/not whole = %+v, want %+v", tc.state, tc.err, full, got, want)
			}
			if wantLeads := map[bool]string{true: "[A B]", false: "[]"}[tc.state.Applicable()]; fmt.Sprint(leads[key]) != wantLeads {
				t.Errorf("%v full=%v: leads = %v, want %s", tc.state, full, leads[key], wantLeads)
			}
		}
	}
}

// One package at one version looked up in two releases and once with no release is three keys, and only part of
// them is answered: the lookup with no release never is, and a dump with an entry it cannot read cannot rule out
// what it leaves out. Release 12's new advisory is still NEW though release 11 listed it before and is UNCHECKED
// beside it, and release 11's lead is kept, not GONE: one key for both releases hid that NEW.
func TestWatchNamesNewWhenOnlyPartOfAKeyIsAnswered(t *testing.T) {
	offline(t)
	var dump atomic.Value
	dump.Store(osvDump(map[string]string{"Debian/DSA-1.json": opensslAdvisory("DSA-1", "11")}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump.Load().([]byte)) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	run := func() (string, error) {
		return watchOut(t, "--state", state, "--fail-on-new", "--package", "pkg:deb/debian/openssl@3.0.11-1?distro=debian-11",
			"--package", "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", "--package", "pkg:deb/debian/openssl@3.0.11-1")
	}
	const k, k11, k12 = "ecosystem:Debian openssl@3.0.11-1", "ecosystem:Debian:11 openssl@3.0.11-1", "ecosystem:Debian:12 openssl@3.0.11-1"
	if out, err := run(); err != nil {
		t.Fatalf("the first run records where things stand: err=%v\n%s", err, out)
	}
	dump.Store(osvDump(map[string]string{"Debian/DSA-1.json": opensslAdvisory("DSA-1", "12"), "Debian/X.json": `{"id":"X",`}))
	out, err := run()
	want := "NEW   " + k12 + "  DSA-1\n" +
		"UNCHECKED  " + k + "  (the source did not answer: its leads are kept as they were)\n" +
		"UNCHECKED  " + k11 + "  (the source cannot prove its data whole: 1 lead(s) absent from its answer are kept)\n"
	if err == nil || !strings.Contains(err.Error(), "1 new lead(s)") || out != want {
		t.Fatalf("release 12's new advisory must be NEW beside release 11 UNCHECKED: err=%v\n%s\nwant\n%s", err, out, want)
	}
	if got, want := stateLeads(t, state), map[string][]string{k11: {"DSA-1"}, k12: {"DSA-1"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("each release keeps its own leads: got %v, want %v", got, want)
	}
	if out, err := run(); err != nil || strings.Contains(out, "NEW") {
		t.Fatalf("a recorded lead is not NEW again: err=%v\n%s", err, out)
	}
}

// A source down while another answers: the leads of the identity it did not answer for are kept, named
// UNCHECKED and never GONE, and not NEW once it answers again; an identity no source answers for and
// that has no lead adds no lead to the state.
func TestWatchKeepsLeadsOfAnUnansweredIdentityWhileAnotherIsAnswered(t *testing.T) {
	offline(t)
	dump := osvDump(map[string]string{"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21")})
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump) }))
	defer osvSrv.Close()
	t.Setenv(osv.EnvOSVURL, osvSrv.URL)
	var down atomic.Bool
	wpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"akismet":{"vulnerabilities":[{"id":"WPV-1","title":"XSS","min_version":"1.0","max_version":"5.0"}]}}`))
	}))
	defer wpSrv.Close()
	t.Setenv(wpcve.EnvWPVulnURL, wpSrv.URL+"/{kind}/{slug}")
	state := filepath.Join(t.TempDir(), "watch.json")
	run := func() (string, error) {
		return watchOut(t, "--state", state, "--fail-on-new", "--package", "pkg:npm/lodash@4.17.20", "--wp-plugin", "akismet@4.0",
			"--package", "pkg:deb/debian/openssl@3.0.11-1") // no release: OSV never answers for it
	}
	want := map[string][]string{"ecosystem:npm lodash@4.17.20": {"GHSA-1"}, "wordpress:plugin akismet@4.0": {"WPV-1"}}
	if out, err := run(); err != nil || !reflect.DeepEqual(stateLeads(t, state), want) {
		t.Fatalf("the first run records the answered leads only: err=%v\n%s\nstate %v", err, out, stateLeads(t, state))
	}
	down.Store(true)
	out, err := run()
	if err != nil || strings.Contains(out, "GONE") || strings.Contains(out, "REMOVED") || strings.Contains(out, "FIRST") || !strings.Contains(out, "UNCHECKED  wordpress:plugin akismet@4.0") ||
		!reflect.DeepEqual(stateLeads(t, state), want) {
		t.Fatalf("a source that did not answer keeps its leads while another answers, never GONE or REMOVED: err=%v\n%s\nstate %v", err, out, stateLeads(t, state))
	}
	down.Store(false)
	if out, err := run(); err != nil || strings.Contains(out, "NEW") || !reflect.DeepEqual(stateLeads(t, state), want) {
		t.Fatalf("a kept lead is not NEW when its source answers again: err=%v\n%s\nstate %v", err, out, stateLeads(t, state))
	}
}

// What a run names, records and fails on for one identity does not depend on the identity beside it: for every
// pair of the kinds below, in both orders of their keys — but a WordPress-only kind beside a Debian-only one only
// with the Debian key first, as a Debian key always sorts first — the run prints the lines of both, fails with
// --fail-on-new only on a NEW lead, and records the leads and Seen of both, no key null. Two rules hold for the
// whole run: one no source answered prints only what it could not check (never REMOVED), fails and leaves the
// state as it was; one with nothing to look up fails and prints nothing.
func TestWatchNamesEachIdentityOfARunOnItsOwn(t *testing.T) {
	offline(t)
	type kind struct {
		name             string
		scopes           string // D: a Debian package, its OSV dump whole; W: a WordPress plugin, the feed never whole
		before, after    []int  // its leads in the state before and after the run
		seenBefore, seen bool   // in Seen before and after the run
		listed, answered bool   // in the inventory; its source answers for it
		feed             []int  // the advisories its source lists for its version
		lines            []string
	}
	const down = "UNCHECKED  {key}  (the source did not answer: its leads are kept as they were)"
	kinds := []kind{
		{name: "NEW", scopes: "D", before: []int{1}, seenBefore: true, listed: true, answered: true, feed: []int{1, 2},
			lines: []string{"NEW   {key}  {id}2"}, after: []int{1, 2}, seen: true},
		{name: "GONE", scopes: "D", before: []int{1, 2}, seenBefore: true, listed: true, answered: true, feed: []int{1},
			lines: []string{"GONE  {key}  {id}2"}, after: []int{1}, seen: true},
		{name: "unchanged", scopes: "DW", before: []int{1}, seenBefore: true, listed: true, answered: true, feed: []int{1},
			after: []int{1}, seen: true},
		{name: "UNCHECKED, its source down", scopes: "DW", before: []int{1}, seenBefore: true, listed: true,
			lines: []string{down}, after: []int{1}, seen: true},
		{name: "UNCHECKED, its data not whole", scopes: "W", before: []int{1, 2}, seenBefore: true, listed: true, answered: true, feed: []int{2},
			lines: []string{"UNCHECKED  {key}  (the source cannot prove its data whole: 1 lead(s) absent from its answer are kept)"}, after: []int{1, 2}, seen: true},
		{name: "REMOVED", scopes: "DW", before: []int{1, 2}, seenBefore: true,
			lines: []string{"REMOVED  {key}  2 lead(s) dropped: it is no longer in the inventory"}, seen: true},
		{name: "FIRST", scopes: "DW", listed: true, answered: true, feed: []int{1, 2},
			lines: []string{"FIRST  {key}  2 lead(s) recorded (its first answer)"}, after: []int{1, 2}, seen: true},
		{name: "no lead, answered whole", scopes: "D", listed: true, answered: true, seen: true},
		{name: "no lead, its data not whole", scopes: "W", listed: true, answered: true, seen: true},
		{name: "no lead, its source down", scopes: "DW", listed: true, lines: []string{down}},
	}
	var dump, feed atomic.Value // the run's Debian dump; the WordPress feed's answers by slug, 502 for any other
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/Debian/all.zip" {
			_, _ = w.Write(dump.Load().([]byte))
			return
		}
		body, ok := feed.Load().(map[string]string)[strings.TrimPrefix(r.URL.Path, "/plugin/")]
		if !ok {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	t.Setenv(wpcve.EnvWPVulnURL, srv.URL+"/{kind}/{slug}")
	debian := func(id, pkg, fixed string) string {
		return `{"id":"` + id + `","affected":[{"package":{"name":"` + pkg + `","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]}]}`
	}
	for _, a := range kinds {
		for _, b := range kinds {
			scopes := [2]string{"D", "W"} // a Debian key sorts before a WordPress one
			for _, s := range []string{"D", "W"} {
				if strings.Contains(a.scopes, s) && strings.Contains(b.scopes, s) {
					scopes = [2]string{s, s} // the names order the keys
					break
				}
			}
			if !strings.Contains(a.scopes, scopes[0]) || !strings.Contains(b.scopes, scopes[1]) {
				continue // only WordPress holds a and only the Debian dump b: b's key always sorts first
			}
			t.Run(a.name+" then "+b.name, func(t *testing.T) {
				state := filepath.Join(t.TempDir(), "watch.json")
				prev := watchState{Updated: "2026-11-01T00:00:00Z", Leads: map[string][]string{}}
				args := []string{"--state", state, "--fail-on-new"}
				entries, answers, leads := map[string]string{}, map[string]string{}, map[string][]string{}
				var lines, seen []string
				looked, answered, news := 0, 0, 0
				for i, k := range []kind{a, b} {
					name := []string{"aaa", "bbb"}[i]
					ids := func(ns []int) []string {
						var out []string
						for _, n := range ns {
							out = append(out, fmt.Sprintf("%s-%d", name, n))
						}
						return out
					}
					key := "wordpress:plugin " + name + "@4.0"
					if scopes[i] == "D" && k.answered {
						key = "ecosystem:Debian:12 " + name + "@1.0-1" // looked up with its release
					} else if scopes[i] == "D" {
						key = "ecosystem:Debian " + name + "@1.0-1"
					}
					switch {
					case !k.listed:
					case scopes[i] == "W":
						args = append(args, "--wp-plugin", name+"@4.0")
						var vulns []string
						for _, id := range ids(k.feed) {
							vulns = append(vulns, `{"id":"`+id+`","title":"XSS","min_version":"1.0","max_version":"5.0"}`)
						}
						body := "{}" // the feed does not list the slug: answered, unknown to it
						if vulns != nil {
							body = `{"` + name + `":{"vulnerabilities":[` + strings.Join(vulns, ",") + `]}}`
						}
						if k.answered {
							answers[name] = body
						}
					case k.answered:
						args = append(args, "--package", "pkg:deb/debian/"+name+"@1.0-1?distro=debian-12")
						for _, id := range ids(k.feed) {
							entries["Debian/"+id+".json"] = debian(id, name, "2.0-1")
						}
						if k.feed == nil {
							entries["Debian/"+name+"-0.json"] = debian(name+"-0", name, "0.5-1") // fixed before its version: nothing matches
						}
					default:
						args = append(args, "--package", "pkg:deb/debian/"+name+"@1.0-1") // no release: OSV does not answer for it
					}
					placeholders := strings.NewReplacer("{key}", key, "{id}", name+"-")
					for _, l := range k.lines {
						lines = append(lines, placeholders.Replace(l))
						if strings.HasPrefix(l, "NEW ") {
							news++
						}
					}
					if k.before != nil {
						prev.Leads[key] = ids(k.before)
					}
					if k.after != nil {
						leads[key] = ids(k.after)
					}
					if k.seenBefore {
						prev.Seen = append(prev.Seen, key)
					}
					if k.seen {
						seen = append(seen, key)
					}
					if k.listed {
						looked++
					}
					if k.answered {
						answered++
					}
				}
				before, err := json.Marshal(prev)
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, state, string(before))
				dump.Store(osvDump(entries))
				feed.Store(answers)
				wantErr := ""
				switch {
				case looked == 0:
					wantErr, lines = "nothing to look up", nil
				case answered == 0: // knows of no change: names only what it could not check
					wantErr = fmt.Sprintf("no source answered for any of the %d identit(ies)", looked)
					lines = slices.DeleteFunc(lines, func(l string) bool { return strings.HasPrefix(l, "REMOVED") })
				case news > 0:
					wantErr = fmt.Sprintf("watch: %d new lead(s)", news)
				}
				out, err := watchOut(t, args...)
				got := strings.FieldsFunc(out, func(r rune) bool { return r == '\n' })
				slices.Sort(got)
				slices.Sort(lines)
				slices.Sort(seen) // the state lists Seen sorted: "ecosystem:Debian bbb" sorts before "ecosystem:Debian:12 aaa"
				if !slices.Equal(got, lines) {
					t.Errorf("the run must print the lines of both identities, each whole:\n got %q\nwant %q", got, lines)
				}
				if (err == nil) != (wantErr == "") || err != nil && !strings.Contains(err.Error(), wantErr) {
					t.Errorf("err = %v, want one naming %q (no error if empty)", err, wantErr)
				}
				raw := readState(t, state)
				if strings.Contains(raw, "null") {
					t.Errorf("no key may be null in the state:\n%s", raw)
				}
				if answered == 0 {
					if raw != string(before) {
						t.Errorf("the state must be left as it was, byte for byte:\n%s", raw)
					}
					return
				}
				var after watchState
				if err := json.Unmarshal([]byte(raw), &after); err != nil || !reflect.DeepEqual(after.Leads, leads) || !slices.Equal(after.Seen, seen) {
					t.Errorf("the state must hold the leads and Seen of both identities (err=%v):\n%s\nwant leads %v, seen %v", err, raw, leads, seen)
				}
			})
		}
	}
}

// Two identities that left the inventory and two no source answered for, beside one answered: each is named and
// kept on its own — REMOVED with its own count, UNCHECKED with its own leads — none GONE, none NEW.
func TestWatchLeftAndUnansweredBesideAnAnsweredOne(t *testing.T) {
	offline(t)
	dump := osvDump(map[string]string{"Debian/E-1.json": `{"id":"E-1","affected":[{"package":{"name":"eee","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]}]}]}`})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	k := func(n string) string { return "ecosystem:Debian " + n + "@1.0-1" }
	const e12 = "ecosystem:Debian:12 eee@1.0-1" // looked up with its release
	writeFile(t, state, `{"updated":"2026-11-01T00:00:00Z","leads":{"`+k("aaa")+`":["A-1","A-2"],"`+k("bbb")+`":["B-1","B-2"],"`+k("ccc")+`":["C-1"],"`+k("ddd")+`":["D-1"],"`+e12+`":["E-1"]},"seen":["`+k("aaa")+`","`+k("bbb")+`","`+k("ccc")+`","`+k("ddd")+`","`+e12+`"]}`)
	out, err := watchOut(t, "--state", state, "--fail-on-new", "--package", "pkg:deb/debian/ccc@1.0-1", "--package", "pkg:deb/debian/ddd@1.0-1", "--package", "pkg:deb/debian/eee@1.0-1?distro=debian-12")
	const left, down = "  2 lead(s) dropped: it is no longer in the inventory\n", "  (the source did not answer: its leads are kept as they were)\n"
	want := "REMOVED  " + k("aaa") + left + "REMOVED  " + k("bbb") + left + "UNCHECKED  " + k("ccc") + down + "UNCHECKED  " + k("ddd") + down
	if err != nil || out != want || !reflect.DeepEqual(stateLeads(t, state), map[string][]string{k("ccc"): {"C-1"}, k("ddd"): {"D-1"}, e12: {"E-1"}}) {
		t.Fatalf("each identity beside an answered one is named and kept on its own: err=%v\n%s\nstate %v", err, out, stateLeads(t, state))
	}
}

// One advisory listed for two identities is NEW and GONE for each on its own: a lead another identity had before is
// still NEW, and one another identity still has is still GONE.
func TestWatchSharedAdvisoryIsNamedPerIdentity(t *testing.T) {
	offline(t)
	adv := func(id string, pkgs ...string) string {
		var aff []string
		for _, p := range pkgs {
			aff = append(aff, `{"package":{"name":"`+p+`","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]}]}`)
		}
		return `{"id":"` + id + `","affected":[` + strings.Join(aff, ",") + `]}`
	}
	dump := osvDump(map[string]string{"Debian/S-1.json": adv("S-1", "aaa", "bbb"), "Debian/S-2.json": adv("S-2", "aaa")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	const a, b = "ecosystem:Debian:12 aaa@1.0-1", "ecosystem:Debian:12 bbb@1.0-1"
	writeFile(t, state, `{"updated":"2026-11-01T00:00:00Z","leads":{"`+a+`":["S-1"],"`+b+`":["S-1","S-2"]},"seen":["`+a+`","`+b+`"]}`)
	out, err := watchOut(t, "--state", state, "--fail-on-new", "--package", "pkg:deb/debian/aaa@1.0-1?distro=debian-12", "--package", "pkg:deb/debian/bbb@1.0-1?distro=debian-12")
	if err == nil || out != "NEW   "+a+"  S-2\nGONE  "+b+"  S-2\n" {
		t.Fatalf("a shared advisory is NEW and GONE per identity: err=%v\n%s", err, out)
	}
}

// The first run names no identity: one line counts the leads it recorded and the identities holding them — an
// identity answered with no lead holds none.
func TestWatchFirstRunCountsWhatItRecords(t *testing.T) {
	offline(t)
	dump := osvDump(map[string]string{
		"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21"),
		"npm/GHSA-2.json": npmAdvisory("GHSA-2", "lodash", "4.17.21"),
		"npm/GHSA-M.json": npmAdvisory("GHSA-M", "minimist", "1.2.6"),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	out, err := watchOut(t, "--state", state, "--fail-on-new", "--package", "pkg:npm/lodash@4.17.20", "--package", "pkg:npm/minimist@1.2.5", "--package", "pkg:npm/lodash@4.17.21")
	if err != nil || out != "first run: 3 lead(s) on 2 identit(ies) recorded; later runs name what changes\n" {
		t.Fatalf("the first run must count the leads it records and the identities holding them: err=%v\n%s", err, out)
	}
	if got, want := stateLeads(t, state), map[string][]string{"ecosystem:npm lodash@4.17.20": {"GHSA-1", "GHSA-2"}, "ecosystem:npm minimist@1.2.5": {"GHSA-M"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the first run records what it counts: got %v, want %v", got, want)
	}
}

// A run without the OSV URL (its variable not loaded) keeps each package under the key OSV gives it: the
// PyPI, Debian and Maven leads recorded with OSV on are kept and named UNCHECKED, never REMOVED, and the
// run with OSV back names no NEW lead, so --fail-on-new passes.
func TestWatchKeepsOSVLeadsThroughARunWithOSVOff(t *testing.T) {
	offline(t)
	adv := func(eco, pkg, fixed string) string {
		return `{"id":"` + eco + `-1","affected":[{"package":{"name":"` + pkg + `","ecosystem":"` + eco + `"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]}]}`
	}
	dumps := map[string][]byte{
		"/PyPI/all.zip":   osvDump(map[string]string{"PyPI/a.json": adv("PyPI", "requests", "2.31.0")}),
		"/Debian/all.zip": osvDump(map[string]string{"Debian/a.json": adv("Debian:12", "openssl", "3.0.13-1~deb12u1")}),
		"/Maven/all.zip":  osvDump(map[string]string{"Maven/a.json": adv("Maven", "org.apache:commons", "2.0")}),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := dumps[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		_, _ = w.Write([]byte(`{"akismet":{"vulnerabilities":[{"id":"WPV-1","title":"XSS","min_version":"1.0","max_version":"5.0"}]}}`))
	}))
	defer srv.Close()
	t.Setenv(wpcve.EnvWPVulnURL, srv.URL+"/{kind}/{slug}") // answers in every run, so the OSV-off run is not one nothing answered
	state := filepath.Join(t.TempDir(), "watch.json")
	run := func(osvURL string) (string, error) {
		t.Setenv(osv.EnvOSVURL, osvURL)
		return watchOut(t, "--state", state, "--fail-on-new", "--wp-plugin", "akismet@4.0", "--package", "pkg:pypi/requests@2.0.0",
			"--package", "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", "--package", "pkg:maven/org.apache/commons@1.0")
	}
	want := map[string][]string{
		"ecosystem:PyPI requests@2.0.0":          {"PyPI-1"},
		"ecosystem:Debian:12 openssl@3.0.11-1":   {"Debian:12-1"},
		"ecosystem:Maven org.apache:commons@1.0": {"Maven-1"},
		"wordpress:plugin akismet@4.0":           {"WPV-1"},
	}
	if out, err := run(srv.URL); err != nil || !reflect.DeepEqual(stateLeads(t, state), want) {
		t.Fatalf("the first run records every lead: err=%v\n%s\nstate %v", err, out, stateLeads(t, state))
	}
	out, err := run("")
	if err != nil || strings.Contains(out, "REMOVED") || strings.Contains(out, "GONE") || strings.Contains(out, "NEW") ||
		strings.Count(out, "UNCHECKED  ecosystem:") != 3 || !reflect.DeepEqual(stateLeads(t, state), want) {
		t.Fatalf("a run with OSV off keeps the OSV leads under their keys as UNCHECKED, never REMOVED: err=%v\n%s\nstate %v", err, out, stateLeads(t, state))
	}
	for _, key := range []string{"ecosystem:PyPI requests@2.0.0", "ecosystem:Debian:12 openssl@3.0.11-1", "ecosystem:Maven org.apache:commons@1.0"} {
		if !strings.Contains(out, "UNCHECKED  "+key+"  ") {
			t.Errorf("the OSV-off run must name %s UNCHECKED:\n%s", key, out)
		}
	}
	if out, err := run(srv.URL); err != nil || strings.Contains(out, "NEW") || !reflect.DeepEqual(stateLeads(t, state), want) {
		t.Fatalf("with OSV back no kept lead is NEW and --fail-on-new passes: err=%v\n%s\nstate %v", err, out, stateLeads(t, state))
	}
}

// opensslAdvisory is a Debian advisory for openssl in the given releases, fixed after the 3.0.11-1 the tests look up.
func opensslAdvisory(id string, releases ...string) string {
	var aff []string
	for _, rel := range releases {
		aff = append(aff, `{"package":{"name":"openssl","ecosystem":"Debian:`+rel+`"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.0-1"}]}]}`)
	}
	return `{"id":"` + id + `","affected":[` + strings.Join(aff, ",") + `]}`
}

// One package at one version in two releases of a distro is two keys, each holding its own release's leads.
func TestWatchKeysEachReleaseOnItsOwn(t *testing.T) {
	offline(t)
	dump := osvDump(map[string]string{"Debian/DSA-11.json": opensslAdvisory("DSA-11", "11"), "Debian/DSA-12.json": opensslAdvisory("DSA-12", "12")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dump) }))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	state := filepath.Join(t.TempDir(), "watch.json")
	out, err := watchOut(t, "--state", state, "--package", "pkg:deb/debian/openssl@3.0.11-1?distro=debian-11", "--package", "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12")
	want := map[string][]string{"ecosystem:Debian:11 openssl@3.0.11-1": {"DSA-11"}, "ecosystem:Debian:12 openssl@3.0.11-1": {"DSA-12"}}
	if err != nil || out != "first run: 2 lead(s) on 2 identit(ies) recorded; later runs name what changes\n" || !reflect.DeepEqual(stateLeads(t, state), want) {
		t.Fatalf("two releases must be two keys, two sets of leads: err=%v\n%s\nstate %v, want %v", err, out, stateLeads(t, state), want)
	}
}

// A state written before a distro key kept its release holds one key "ecosystem:Debian n@v" for every release. Any
// run while that key is in the state, the first after the upgrade or a later one, gives each release key of the run
// the state does not hold yet all of that key's leads and its Seen, and the old key leaves the state: no lead is lost
// and none is NEW for nothing — a lead the release does not list is GONE once, from a whole answer only. With no such
// release key the old key goes on as before: REMOVED when not looked up, UNCHECKED when looked up with no release.
// A run no source answers writes nothing. A second run of the same inventory names nothing new. Each case is
// numbered by its situation: 1 no old key, 2–3 an old key and no release key, 4–5 one release key, 6 two, 7 a release
// key the state already holds.
func TestWatchCarriesAnOldDistroKeyToItsReleaseKeys(t *testing.T) {
	offline(t)
	const (
		k, k11, k12 = "ecosystem:Debian openssl@3.0.11-1", "ecosystem:Debian:11 openssl@3.0.11-1", "ecosystem:Debian:12 openssl@3.0.11-1"
		npm         = "ecosystem:npm lodash@4.17.20" // answered, unchanged: the run is not one no source answers
		lodash      = "pkg:npm/lodash@4.17.20"
		r11, r12    = "pkg:deb/debian/openssl@3.0.11-1?distro=debian-11", "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12"
		bare        = "pkg:deb/debian/openssl@3.0.11-1" // no release: OSV does not answer for it
		down        = "  (the source did not answer: its leads are kept as they were)\n"
		removed     = "  1 lead(s) dropped: it is no longer in the inventory\n"
	)
	whole12 := map[string]string{"Debian/DSA-1.json": opensslAdvisory("DSA-1", "12")}
	// Ubuntu's release holds a ":" ("22.04:LTS"): the release-less key is cut at the first one
	const (
		u, u20, u22 = "ecosystem:Ubuntu curl@7.0-1", "ecosystem:Ubuntu:20.04:LTS curl@7.0-1", "ecosystem:Ubuntu:22.04:LTS curl@7.0-1"
		ru20, ru22  = "pkg:deb/ubuntu/curl@7.0-1?distro=ubuntu-20.04", "pkg:deb/ubuntu/curl@7.0-1?distro=ubuntu-22.04"
	)
	curl := func(id, release string) string {
		return `{"id":"` + id + `","affected":[{"package":{"name":"curl","ecosystem":"Ubuntu:` + release + `"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.0-1"}]}]}]}`
	}
	for _, tc := range []struct {
		row       string
		leads     map[string][]string // the state before
		seen      []string
		refs, wp  []string          // --package, --wp-plugin (the WordPress feed never answers)
		debian    map[string]string // the Debian dump, served as Ubuntu's too; nil: its source fails
		out, err  string
		after     map[string][]string // the state after; nil: left as it was
		seenAfter []string
	}{
		{row: "1 no old key: the release key is FIRST", leads: map[string][]string{npm: {"GHSA-1"}}, seen: []string{npm},
			refs: []string{lodash, r12}, debian: whole12,
			out:   "FIRST  " + k12 + "  1 lead(s) recorded (its first answer)\n",
			after: map[string][]string{npm: {"GHSA-1"}, k12: {"DSA-1"}}, seenAfter: []string{npm, k12}},
		{row: "1 a WordPress key is no distro key: it takes nothing", leads: map[string][]string{npm: {"GHSA-1"}, "ecosystem:wordpress akismet@4.0": {"X-1"}}, seen: []string{npm, "ecosystem:wordpress akismet@4.0"},
			refs: []string{lodash}, wp: []string{"akismet@4.0"},
			out:   "REMOVED  ecosystem:wordpress akismet@4.0" + removed + "UNCHECKED  wordpress:plugin akismet@4.0" + down,
			after: map[string][]string{npm: {"GHSA-1"}}, seenAfter: []string{npm, "ecosystem:wordpress akismet@4.0"}},
		{row: "2 old key, no release key, not looked up: REMOVED", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}}, seen: []string{npm, k},
			refs: []string{lodash}, debian: whole12,
			out:   "REMOVED  " + k + removed,
			after: map[string][]string{npm: {"GHSA-1"}}, seenAfter: []string{npm, k}},
		{row: "3 old key, no release key, looked up with no release: UNCHECKED, its leads kept", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}}, seen: []string{npm, k},
			refs: []string{lodash, bare}, debian: whole12,
			out:   "UNCHECKED  " + k + down,
			after: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}}, seenAfter: []string{npm, k}},
		{row: "4 one release key, a whole answer: what it no longer lists is GONE", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1", "DSA-2"}}, seen: []string{npm, k},
			refs: []string{lodash, r12}, debian: whole12,
			out:   "GONE  " + k12 + "  DSA-2\n",
			after: map[string][]string{npm: {"GHSA-1"}, k12: {"DSA-1"}}, seenAfter: []string{npm, k12}},
		{row: "4 one release key, an answer not whole: its leads kept", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1", "DSA-2"}}, seen: []string{npm, k},
			refs: []string{lodash, r12}, debian: map[string]string{"Debian/DSA-1.json": opensslAdvisory("DSA-1", "12"), "Debian/X.json": `{"id":"X",`},
			out:   "UNCHECKED  " + k12 + "  (the source cannot prove its data whole: 1 lead(s) absent from its answer are kept)\n",
			after: map[string][]string{npm: {"GHSA-1"}, k12: {"DSA-1", "DSA-2"}}, seenAfter: []string{npm, k12}},
		{row: "4 one release key its source did not answer: its lead kept", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}}, seen: []string{npm, k},
			refs:  []string{lodash, r12},
			out:   "UNCHECKED  " + k12 + down,
			after: map[string][]string{npm: {"GHSA-1"}, k12: {"DSA-1"}}, seenAfter: []string{npm, k12}},
		{row: "4 an old key seen with no lead, in a state with no leads: the release key is seen, a lead it has is NEW", seen: []string{npm, k},
			refs: []string{r12}, debian: whole12,
			out: "NEW   " + k12 + "  DSA-1\n", err: "1 new lead(s)",
			after: map[string][]string{k12: {"DSA-1"}}, seenAfter: []string{npm, k12}},
		{row: "4 no source answers: the state is left as it was", leads: map[string][]string{k: {"DSA-1"}}, seen: []string{k},
			refs: []string{r12},
			out:  "UNCHECKED  " + k12 + down, err: "no source answered"},
		{row: "4 Ubuntu, one release key holding a colon: it takes the leads and Seen; a lead it no longer lists is GONE, a new one NEW", leads: map[string][]string{npm: {"GHSA-1"}, u: {"USN-1", "USN-2"}}, seen: []string{npm, u},
			refs: []string{lodash, ru22}, debian: map[string]string{"Ubuntu/USN-1.json": curl("USN-1", "22.04:LTS"), "Ubuntu/USN-3.json": curl("USN-3", "22.04:LTS")},
			out: "NEW   " + u22 + "  USN-3\nGONE  " + u22 + "  USN-2\n", err: "1 new lead(s)",
			after: map[string][]string{npm: {"GHSA-1"}, u22: {"USN-1", "USN-3"}}, seenAfter: []string{npm, u22}},
		{row: "5 one release key, the old key looked up with no release: its own key, no lead", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1", "DSA-2"}}, seen: []string{npm, k},
			refs: []string{lodash, r12, bare}, debian: whole12,
			out:   "GONE  " + k12 + "  DSA-2\nUNCHECKED  " + k + down,
			after: map[string][]string{npm: {"GHSA-1"}, k12: {"DSA-1"}}, seenAfter: []string{npm, k12}},
		{row: "6 two release keys: each takes every lead, GONE once what its release does not list", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1", "DSA-2"}}, seen: []string{npm, k},
			refs: []string{lodash, r11, r12}, debian: map[string]string{"Debian/DSA-1.json": opensslAdvisory("DSA-1", "11"), "Debian/DSA-2.json": opensslAdvisory("DSA-2", "12")},
			out:   "GONE  " + k11 + "  DSA-2\nGONE  " + k12 + "  DSA-1\n",
			after: map[string][]string{npm: {"GHSA-1"}, k11: {"DSA-1"}, k12: {"DSA-2"}}, seenAfter: []string{npm, k11, k12}},
		{row: "6 Ubuntu, two release keys holding a colon: each takes every lead, GONE once what its release does not list", leads: map[string][]string{npm: {"GHSA-1"}, u: {"USN-1", "USN-2"}}, seen: []string{npm, u},
			refs: []string{lodash, ru20, ru22}, debian: map[string]string{"Ubuntu/USN-1.json": curl("USN-1", "22.04:LTS"), "Ubuntu/USN-2.json": curl("USN-2", "20.04:LTS"), "Ubuntu/USN-3.json": curl("USN-3", "20.04:LTS")},
			out: "NEW   " + u20 + "  USN-3\nGONE  " + u20 + "  USN-1\nGONE  " + u22 + "  USN-2\n", err: "1 new lead(s)",
			after: map[string][]string{npm: {"GHSA-1"}, u20: {"USN-2", "USN-3"}, u22: {"USN-1"}}, seenAfter: []string{npm, u20, u22}},
		{row: "6/7 one release key in the state, one not: only the new one takes the old key's leads", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1", "DSA-2"}, k11: {"DSA-1"}}, seen: []string{npm, k, k11},
			refs: []string{lodash, r11, r12}, debian: map[string]string{"Debian/DSA-1.json": opensslAdvisory("DSA-1", "11"), "Debian/DSA-2.json": opensslAdvisory("DSA-2", "12")},
			out:   "GONE  " + k12 + "  DSA-1\n",
			after: map[string][]string{npm: {"GHSA-1"}, k11: {"DSA-1"}, k12: {"DSA-2"}}, seenAfter: []string{npm, k11, k12}},
		{row: "7 the release key in the state: it takes nothing, the old key not looked up is REMOVED", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}, k12: {"DSA-2"}}, seen: []string{npm, k, k12},
			refs: []string{lodash, r12}, debian: map[string]string{"Debian/DSA-2.json": opensslAdvisory("DSA-2", "12")},
			out:   "REMOVED  " + k + removed,
			after: map[string][]string{npm: {"GHSA-1"}, k12: {"DSA-2"}}, seenAfter: []string{npm, k, k12}},
		{row: "7 the release key in the state: the old key looked up with no release is UNCHECKED", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}, k12: {"DSA-2"}}, seen: []string{npm, k, k12},
			refs: []string{lodash, r12, bare}, debian: map[string]string{"Debian/DSA-2.json": opensslAdvisory("DSA-2", "12")},
			out:   "UNCHECKED  " + k + down,
			after: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}, k12: {"DSA-2"}}, seenAfter: []string{npm, k, k12}},
		{row: "7 the release key in the state with leads, not seen: it takes nothing", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}, k12: {"DSA-2"}}, seen: []string{npm, k},
			refs: []string{lodash, r12}, debian: map[string]string{"Debian/DSA-2.json": opensslAdvisory("DSA-2", "12")},
			out:   "REMOVED  " + k + removed + "FIRST  " + k12 + "  1 lead(s) recorded (its first answer)\n",
			after: map[string][]string{npm: {"GHSA-1"}, k12: {"DSA-2"}}, seenAfter: []string{npm, k, k12}},
		{row: "7 the release key in the state only as seen: it takes nothing", leads: map[string][]string{npm: {"GHSA-1"}, k: {"DSA-1"}}, seen: []string{npm, k, k12},
			refs: []string{lodash, r12}, debian: map[string]string{"Debian/DSA-1.json": opensslAdvisory("DSA-1", "11")},
			out:   "REMOVED  " + k + removed,
			after: map[string][]string{npm: {"GHSA-1"}}, seenAfter: []string{npm, k, k12}},
	} {
		t.Run(tc.row, func(t *testing.T) {
			offline(t)
			npmDump, debDump := osvDump(map[string]string{"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21")}), osvDump(tc.debian)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/npm/all.zip":
					_, _ = w.Write(npmDump)
				case (r.URL.Path == "/Debian/all.zip" || r.URL.Path == "/Ubuntu/all.zip") && tc.debian != nil:
					_, _ = w.Write(debDump)
				default:
					w.WriteHeader(http.StatusBadGateway)
				}
			}))
			defer srv.Close()
			t.Setenv(osv.EnvOSVURL, srv.URL)
			t.Setenv(wpcve.EnvWPVulnURL, srv.URL+"/{kind}/{slug}")
			state := filepath.Join(t.TempDir(), "watch.json")
			before, err := json.Marshal(watchState{Updated: "2026-11-01T00:00:00Z", Leads: tc.leads, Seen: tc.seen})
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, state, string(before))
			args := []string{"--state", state, "--fail-on-new"}
			for _, ref := range tc.refs {
				args = append(args, "--package", ref)
			}
			for _, ref := range tc.wp {
				args = append(args, "--wp-plugin", ref)
			}
			out, err := watchOut(t, args...)
			if out != tc.out || (err == nil) != (tc.err == "") || err != nil && !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err = %v, want one naming %q (none if empty)\n got:\n%s\nwant:\n%s", err, tc.err, out, tc.out)
			}
			raw := readState(t, state)
			if tc.after == nil {
				if raw != string(before) {
					t.Fatalf("the state must be left as it was, byte for byte:\n%s", raw)
				}
			} else {
				var got watchState
				slices.Sort(tc.seenAfter)
				if err := json.Unmarshal([]byte(raw), &got); err != nil || !reflect.DeepEqual(got.Leads, tc.after) || !slices.Equal(got.Seen, tc.seenAfter) {
					t.Fatalf("state (err=%v):\n%s\nwant leads %v, seen %v", err, raw, tc.after, tc.seenAfter)
				}
			}
			out, err = watchOut(t, args...)
			if strings.Contains(out, "NEW") || strings.Contains(out, "GONE") || strings.Contains(out, "FIRST") || strings.Contains(out, "REMOVED") || (err == nil) != (tc.after != nil) {
				t.Fatalf("a second run names nothing new: err=%v\n%s", err, out)
			}
		})
	}
}
