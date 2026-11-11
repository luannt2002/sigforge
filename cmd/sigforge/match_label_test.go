package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/enrich"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// The excludes label reaches the operator: match names the techs that exclude a kept lead,
// and an unlabeled detection prints exactly as before.
func TestMatchPrintsExcludedBy(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	page := filepath.Join(dir, "page.json")
	if err := os.WriteFile(db, []byte(`{"schema_version":"1.0.0","fingerprints":{
		"A": {"html": "a-marker", "excludes": ["B"]},
		"B": {"html": "b-marker"},
		"C": {"html": "c-marker"}
	}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(page, []byte(`{"html": "a-marker b-marker c-marker"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(page)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	orig := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = orig }()

	var runErr error
	out := captureStdout(t, func() { runErr = cmdMatch([]string{"--db", db}) })
	if runErr != nil {
		t.Fatal(runErr)
	}
	if want := "A  (confidence 100)\nB  (confidence 100, excluded by A)\nC  (confidence 100)\n"; out != want {
		t.Errorf("match output:\n%s\nwant:\n%s", out, want)
	}
}

// enrich prints the label as a note on each result of the labeled detection, and on no other.
func TestEnrichPrintsExcludedBy(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"A": {HTML: schema.StringList{"a-marker"}, Excludes: schema.StringList{"B"}},
		"B": {HTML: schema.StringList{"b-marker"}},
	}}
	results := enrich.EnrichUnified(context.Background(), matcher.Match(db, matcher.Page{HTML: "a-marker b-marker"}), db, enrich.Options{})
	labeled := 0
	for _, r := range results {
		if r.Tech == "B" {
			labeled++
		}
	}
	out := captureStdout(t, func() { printEnrich(results) })
	if got := strings.Count(out, "excluded by: A"); labeled == 0 || got != labeled {
		t.Errorf("%d excluded-by notes printed for %d results of B:\n%s", got, labeled, out)
	}
}
