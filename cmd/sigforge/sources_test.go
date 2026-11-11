package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
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
