package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/source"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasTech(t *testing.T, dbPath, tech string) bool {
	t.Helper()
	db, err := schema.LoadFile(dbPath)
	if err != nil {
		t.Fatalf("load %q: %v", dbPath, err)
	}
	_, ok := db.Fingerprints[tech]
	return ok
}

// TestRefreshPublishesThenGatesRegression drives refresh end to end over local sources:
// first publish (no current), an additive re-sync that publishes and archives .prev, a
// re-sync that drops techs and is REFUSED (live DB left byte-identical), the same drop
// allowed through with --allow-removed, and rollback restoring the pre-drop snapshot.
func TestRefreshPublishesThenGatesRegression(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	man := filepath.Join(dir, "m.json")

	// Probe techs with html markers only (no CPE/version), so a removal is the sole
	// regression signal — isolates the removed-fingerprint gate from the CPE/version ones.
	srcAB := filepath.Join(dir, "ab.json")
	writeFile(t, srcAB, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]},"ProbeB":{"html":["marker-b"]}}}`)

	out := captureStdout(t, func() {
		if err := cmdRefresh([]string{"--out", db, "--source", "ab=" + srcAB, "--manifest", man}); err != nil {
			t.Fatalf("first refresh (no current) must publish: %v", err)
		}
	})
	if !strings.Contains(out, "published") {
		t.Errorf("first refresh missing publish line:\n%s", out)
	}
	if strings.Contains(out, ".prev") {
		t.Errorf("first publish archived nothing, so it must not claim a .prev:\n%s", out)
	}
	if !hasTech(t, db, "ProbeA") || !hasTech(t, db, "ProbeB") {
		t.Fatal("first publish missing the source techs")
	}
	if _, err := os.Stat(db + ".prev"); err == nil {
		t.Error("first publish must not archive a .prev (nothing to archive)")
	}

	// (a) additive candidate (adds ProbeC, keeps A+B) → publish, prior snapshot archived.
	srcABC := filepath.Join(dir, "abc.json")
	writeFile(t, srcABC, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]},"ProbeB":{"html":["marker-b"]},"ProbeC":{"html":["marker-c"]}}}`)
	if err := cmdRefresh([]string{"--out", db, "--source", "abc=" + srcABC, "--manifest", man}); err != nil {
		t.Fatalf("additive candidate must publish: %v", err)
	}
	if !hasTech(t, db, "ProbeC") {
		t.Fatal("additive publish missing ProbeC")
	}
	for _, f := range []string{db + ".prev", db + ".prev.sha256", db + ".prev.manifest.json"} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("publish must archive %q: %v", f, err)
		}
	}

	// (b) candidate drops ProbeB and ProbeC → REGRESSION: keep current, rc≠0, DB unchanged.
	before, _ := os.ReadFile(db)
	srcA := filepath.Join(dir, "a.json")
	writeFile(t, srcA, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	err := cmdRefresh([]string{"--out", db, "--source", "a=" + srcA, "--manifest", man})
	if err == nil || !strings.Contains(err.Error(), "REGRESSION") {
		t.Fatalf("dropping techs must abort with REGRESSION, got: %v", err)
	}
	if after, _ := os.ReadFile(db); !bytes.Equal(before, after) {
		t.Fatal("aborted refresh must leave the live DB byte-identical")
	}

	// (d) same drop under --allow-removed=2 (ProbeB + ProbeC are intended) → publishes.
	if err := cmdRefresh([]string{"--out", db, "--source", "a=" + srcA, "--allow-removed", "2", "--manifest", man}); err != nil {
		t.Fatalf("--allow-removed=2 must let the intended removals publish: %v", err)
	}
	if hasTech(t, db, "ProbeB") {
		t.Fatal("allowed removal should have dropped ProbeB")
	}

	// (e) rollback restores the pre-removal snapshot archived by (d) → ProbeB is back.
	if err := cmdRollback([]string{db}); err != nil {
		t.Fatalf("rollback after publish must restore the prior snapshot: %v", err)
	}
	if !hasTech(t, db, "ProbeB") {
		t.Fatal("rollback did not restore ProbeB")
	}
}

// TestRefreshAbortsOnInvalidCandidate proves refresh's candidate-validate step rejects a
// schema-invalid candidate and never touches the live DB. It fetches a webappanalyzer-
// shaped entry whose html pattern is an uncompilable regex; Normalize does NOT schema-
// validate, so refresh's own schema.Validate is the only gate that catches it (mutant:
// drop that validate and this test must fail).
func TestRefreshAbortsOnInvalidCandidate(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	man := filepath.Join(dir, "m.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"BadRegexTech":{"cats":[1],"html":"foo(bar"}}`)
	}))
	defer srv.Close()

	err := cmdRefresh([]string{"--out", db, "--fetch", "webappanalyzer=" + srv.URL, "--manifest", man})
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("a schema-invalid candidate must abort refresh, got: %v", err)
	}
	if _, statErr := os.Stat(db); statErr == nil {
		t.Fatal("aborted refresh must not create the live DB")
	}
	if _, statErr := os.Stat(man); statErr == nil {
		t.Fatal("aborted refresh must not record a sync in the manifest — nothing was published")
	}
}

// TestMergeRecordsSyncOnlyAfterPublish: the sync manifest says what was pulled into the
// DB, so a merge whose publish fails (here: --out in a missing directory) must not record
// a sync that never landed.
func TestMergeRecordsSyncOnlyAfterPublish(t *testing.T) {
	dir := t.TempDir()
	man := filepath.Join(dir, "m.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"GoodTech":{"cats":[1],"html":"good-marker"}}`)
	}))
	defer srv.Close()

	out := filepath.Join(dir, "missing-dir", "db.json")
	if err := cmdMerge([]string{"--out", out, "--fetch", "webappanalyzer=" + srv.URL, "--manifest", man}); err == nil {
		t.Fatal("publishing into a missing directory must fail")
	}
	if _, statErr := os.Stat(man); statErr == nil {
		t.Fatal("a failed publish must not record a sync in the manifest")
	}

	// The same fetch published successfully must record exactly that sync.
	if err := cmdMerge([]string{"--out", filepath.Join(dir, "db.json"), "--fetch", "webappanalyzer=" + srv.URL, "--manifest", man}); err != nil {
		t.Fatalf("merge into an existing directory must publish: %v", err)
	}
	m, err := source.LoadManifest(man)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Sources) != 1 || m.Sources[0].Source != "webappanalyzer" || m.Sources[0].EntryCount != 1 {
		t.Fatalf("a published fetch must be recorded once with its entry count, got %+v", m.Sources)
	}
}
