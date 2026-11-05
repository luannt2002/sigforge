package source

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

func TestVersionPinnedAndUnversioned(t *testing.T) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		url  string
		want string
	}{
		{"https://raw.githubusercontent.com/enthec/webappanalyzer/abc1234def/src/technologies/a.json", "abc1234def"},
		{"https://example.test/repo/refs/tags/v1.2.3/data.json", "v1.2.3"},
		{"https://example.test/repo/main/data.json", "unversioned@2026-11-04T12:00:00Z"},
	}
	for _, c := range cases {
		if got := Version(c.url, at); got != c.want {
			t.Errorf("Version(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestSourceOffByDefault(t *testing.T) {
	for _, id := range []string{"webappanalyzer", "nuclei", "whatweb"} {
		src, ok := New(id, "", nil) // no URL, nil client
		if !ok {
			t.Fatalf("New(%q) not registered", id)
		}
		if _, err := src.Fetch(context.Background()); err == nil {
			t.Fatalf("%s with no URL must refuse to fetch", id)
		}
	}
	if _, ok := New("unknown", "http://x", nil); ok {
		t.Fatal("unknown source must not resolve")
	}
}

func TestEnvVar(t *testing.T) {
	if got := EnvVar("webappanalyzer"); got != "SIGFORGE_SOURCE_WEBAPPANALYZER_URL" {
		t.Fatalf("EnvVar = %q", got)
	}
}

func TestManifestUpsertRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SYNC-MANIFEST.json")
	m, err := LoadManifest(path) // missing → empty
	if err != nil || len(m.Sources) != 0 {
		t.Fatalf("empty load: %v, %+v", err, m)
	}
	m.Upsert(ManifestRow{Source: "nuclei", URL: "u1", Version: "v1", EntryCount: 3})
	m.Upsert(ManifestRow{Source: "webappanalyzer", URL: "u2", Version: "v2", EntryCount: 9})
	m.Upsert(ManifestRow{Source: "nuclei", URL: "u1b", Version: "v1b", EntryCount: 4}) // replaces
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	got, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("want 2 rows (upsert replaces), got %d", len(got.Sources))
	}
	if got.Sources[0].Source != "nuclei" { // sorted by id
		t.Fatalf("not sorted: %+v", got.Sources)
	}
	if got.Sources[0].Version != "v1b" || got.Sources[0].EntryCount != 4 {
		t.Fatalf("nuclei row not replaced: %+v", got.Sources[0])
	}
	if !strings.Contains(got.GeneratedAt, "T") {
		t.Fatalf("generated_at not set: %q", got.GeneratedAt)
	}
}

func TestStamp(t *testing.T) {
	set := map[string]schema.Fingerprint{
		"A": {},                                // no tags → all filled
		"B": {Provenance: "keep", License: ""}, // existing provenance kept, license filled
	}
	Stamp(set, "nuclei", "MIT", "abc123")
	if a := set["A"]; a.Provenance != "nuclei" || a.License != "MIT" || a.ProvenanceVersion != "abc123" {
		t.Fatalf("A = %+v", a)
	}
	if b := set["B"]; b.Provenance != "keep" || b.License != "MIT" || b.ProvenanceVersion != "abc123" {
		t.Fatalf("B = %+v", b)
	}
}
