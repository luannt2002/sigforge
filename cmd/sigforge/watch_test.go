package main

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/osv"
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
