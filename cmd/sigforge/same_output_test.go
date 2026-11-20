package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The same input gives the same bytes on every run, from every command whose output a monitor or a diff reads: map
// iteration order must never reach an output. The fixtures put several keys in every map a command walks — headers,
// cookies, meta, implies, excludes, merge sources, versions in conflict — so a run order that leaks shows as a
// difference between two of the 20 runs. (Which claim a Detection keeps per version reaches no command's output; the
// matcher's own test holds it.)
func TestOutputsAreTheSameEveryRun(t *testing.T) {
	offline(t)
	defer func(orig func() time.Time) { now = orig }(now)
	at := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	now = func() time.Time { return at } // the DB says when it was generated: one clock for every run
	dir := t.TempDir()
	srcA, srcB, srcC := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "c.json")
	writeFile(t, srcA, `{"schema_version":"1.0.0","fingerprints":{
	  "Alpha":{"cats":[22],"headers":{"Server":"alpha/([\\d.]+)\\;version:\\1","X-Alpha":"xa/([\\d.]+)\\;version:\\1","X-Alpha-B":"xb/([\\d.]+)\\;version:\\1"},"implies":["Base","Lang"],"cpe":["cpe:2.3:a:alpha:alpha:*:*:*:*:*:*:*:*"]},
	  "Beta":{"cats":[1],"cookies":{"beta_sess":"","beta_v":"([\\d.]+)\\;version:\\1"},"meta":{"generator":"Beta ([\\d.]+)\\;version:\\1","beta-build":"b([\\d.]+)\\;version:\\1"},"excludes":["Gamma","Delta"]},
	  "Gamma":{"cats":[1],"html":["gamma-marker","gamma-([\\d.]+)\\;version:\\1"]},
	  "Delta":{"cats":[59],"scriptSrc":["delta-([\\d.]+)\\.js\\;version:\\1"],"headers":{"X-Delta":""}},
	  "Base":{"cats":[27]},"Lang":{"cats":[27]}}}`)
	writeFile(t, srcB, `{"schema_version":"1.0.0","fingerprints":{
	  "Alpha":{"cats":[22],"headers":{"Server":"alpha-([\\d.]+)\\;version:\\1"}},
	  "Epsilon":{"cats":[31],"headers":{"Via":"eps\\;confidence:50","X-Eps":"([\\d.]+)\\;version:\\1"}},
	  "Zeta":{"cats":[12],"meta":{"zeta":""},"cookies":{"zeta_id":""}}}}`)
	writeFile(t, srcC, `{"schema_version":"1.0.0","fingerprints":{
	  "Beta":{"cats":[1],"meta":{"generator":"BetaCMS ([\\d.]+)\\;version:\\1"}},
	  "Eta":{"cats":[18],"html":["eta-marker"],"implies":["Lang"]}}}`)
	page := filepath.Join(dir, "page.json")
	writeFile(t, page, `{"headers":{"server":["alpha/2.4.1"],"x-alpha":["xa/2.4.1"],"x-alpha-b":["xb/3.0"],"via":["1.1 eps"],"x-eps":["7.0"],"x-delta":["1"]},
	  "cookies":["beta_sess=1","beta_v=5.1","zeta_id=9"],
	  "html":"<meta name=\"generator\" content=\"Beta 5.2\"><meta name=\"beta-build\" content=\"b5.1\"><meta name=\"zeta\" content=\"1\"> gamma-marker gamma-3.0 eta-marker",
	  "scriptSrcs":["/js/delta-1.9.js","/js/delta-1.10.js"]}`)
	stdin := func(fn func()) func() {
		return func() {
			in, err := os.Open(page)
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			orig := os.Stdin
			os.Stdin = in
			defer func() { os.Stdin = orig }()
			fn()
		}
	}
	// merge writes into a directory of its own each run, so no run archives another's output; the outputs read are the
	// DB and its sidecar, and what merge prints with the directory written as <dir>.
	merged := func(i int) string {
		d := filepath.Join(dir, "m", strings.Repeat("x", i%2+1)+string(rune('a'+i)))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(d, "db.json")
		var err error
		printed := captureStdout(t, func() {
			err = cmdMerge([]string{"--out", out, "--manifest", filepath.Join(d, "m.json"), "--source", "a=" + srcA, "--source", "b=" + srcB, "--source", "c=" + srcC})
		})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		db, _ := os.ReadFile(out)
		sum, _ := os.ReadFile(out + ".sha256")
		return strings.ReplaceAll(printed, d, "<dir>") + "\n--db--\n" + string(db) + "\n--sum--\n" + strings.ReplaceAll(string(sum), d, "<dir>")
	}
	ref := filepath.Join(dir, "ref.json")
	var err error
	captureStdout(t, func() {
		err = cmdMerge([]string{"--out", ref, "--manifest", filepath.Join(dir, "ref-m.json"), "--source", "a=" + srcA, "--source", "b=" + srcB, "--source", "c=" + srcC})
	})
	if err != nil {
		t.Fatal(err)
	}
	run := map[string]func(i int) string{
		"match --explain": func(int) string {
			var out string
			stdin(func() { out = captureStdout(t, func() { _ = cmdMatch([]string{"--db", ref, "--explain"}) }) })()
			return out
		},
		"enrich --json": func(int) string {
			var out string
			stdin(func() {
				out = captureStdout(t, func() {
					_ = cmdEnrich([]string{"--db", ref, "--json", "--jslib", "jquery@1.8.0", "--package", "npm:lodash@4.17.20", "--wp-plugin", "akismet@5.0"})
				})
			})()
			return out
		},
		"merge":           merged,
		"diff":            func(int) string { return captureStdout(t, func() { _ = cmdDiff([]string{srcA, ref}) }) },
		"coverage --json": func(int) string { return captureStdout(t, func() { _ = cmdCoverage([]string{"--db", ref, "--json"}) }) },
		"inspect":         func(int) string { return captureStdout(t, func() { _ = cmdInspect([]string{"--db", ref, "Alpha"}) }) },
	}
	for name, fn := range run {
		first := fn(0)
		if strings.TrimSpace(first) == "" {
			t.Errorf("%s printed nothing: nothing to compare", name)
			continue
		}
		for i := 1; i < 20; i++ {
			if got := fn(i); got != first {
				t.Errorf("%s: run %d differs from run 0:\n--- run 0\n%s\n--- run %d\n%s", name, i, first, i, got)
				break
			}
		}
	}
}
