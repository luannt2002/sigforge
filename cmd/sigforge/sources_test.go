package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/osv"
)

// sources reports what the last sync left: each configured source ok, failed (with why) or never
// synced, and an off one as off — and fails when one in use is failing or older than --max-age,
// so a monitor can alarm on it instead of a scan silently using old or sample data.
func TestSourcesReportsEachSourceAndFailsOnABadOne(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	store := t.TempDir()
	t.Setenv(EnvCacheDir, store)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`))
	}))
	defer ok.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusForbidden) }))
	defer down.Close()
	t.Setenv(kev.EnvKEVURL, ok.URL)
	t.Setenv(lifecycle.EnvBundleURL, down.URL)

	var err error
	out := captureStdout(t, func() { err = cmdSources(nil) })
	if err == nil || !strings.Contains(out, "never synced") {
		t.Fatalf("before any sync a configured source is never synced and fails the check: err=%v\n%s", err, out)
	}
	captureStdout(t, func() { _ = cmdSync(nil) })
	out = captureStdout(t, func() { err = cmdSources(nil) })
	if err == nil {
		t.Fatalf("a failing source must fail the check:\n%s", out)
	}
	for _, want := range []string{"KEV catalog", "ok", "endoflife bundle", "FAILED", "403", "Retire.js repository", "off"} {
		if !strings.Contains(out, want) {
			t.Errorf("report misses %q:\n%s", want, out)
		}
	}
	t.Setenv(lifecycle.EnvBundleURL, "")
	if out = captureStdout(t, func() { err = cmdSources(nil) }); err != nil {
		t.Fatalf("every source in use synced fine, want success: %v\n%s", err, out)
	}
	tick := now
	now = func() time.Time { return tick().Add(3 * time.Hour) }
	defer func() { now = tick }()
	if out = captureStdout(t, func() { err = cmdSources([]string{"--max-age", "2h"}) }); err == nil || !strings.Contains(out, "older than") {
		t.Fatalf("a source synced more than --max-age ago must fail the check: %v\n%s", err, out)
	}
}

// sources with no source in use checks nothing, so it fails naming each variable not set rather than
// reading as quiet — as when a timer runs it without the source variables; an OSV dump in the store is
// in use only with its variable set, and one source in use keeps the old outcome.
func TestSourcesFailsWhenNoSourceIsInUse(t *testing.T) {
	offline(t)
	store := t.TempDir()
	t.Setenv(EnvCacheDir, filepath.Join(store, "none")) // no store yet: nothing was ever synced
	var err error
	out := captureStdout(t, func() { err = cmdSources([]string{"--max-age", "26h"}) })
	if err == nil || !strings.Contains(err.Error(), "no source in use") || strings.Count(out, " off (") != len(syncSources) {
		t.Fatalf("every source off must fail the check after listing each: err=%v\n%s", err, out)
	}
	for _, s := range syncSources {
		if !strings.Contains(err.Error(), s.env) {
			t.Errorf("the error must name %s: %v", s.env, err)
		}
	}
	t.Setenv(osv.EnvOSVURL, "http://127.0.0.1:1")
	if out = captureStdout(t, func() { err = cmdSources(nil) }); err == nil || !strings.Contains(err.Error(), "no source in use") {
		t.Fatalf("an OSV URL with no dump in the store gives sources nothing to check, want a failure: err=%v\n%s", err, out)
	}
	t.Setenv(EnvCacheDir, store)
	recordSyncStatus(store, map[string]error{"OSV npm": nil, "OSV PyPI": nil})
	t.Setenv(osv.EnvOSVURL, "")
	if out = captureStdout(t, func() { err = cmdSources(nil) }); err == nil || strings.Count(err.Error(), osv.EnvOSVURL) != 1 {
		t.Fatalf("dumps in the store with %s unset are off, and the error names it once: err=%v\n%s", osv.EnvOSVURL, err, out)
	}
	t.Setenv(osv.EnvOSVURL, "http://127.0.0.1:1")
	if out = captureStdout(t, func() { err = cmdSources([]string{"--max-age", "26h"}) }); err != nil || strings.Count(out, "ok — synced") != 2 {
		t.Fatalf("two OSV dumps in use and fresh, want success: err=%v\n%s", err, out)
	}
}
