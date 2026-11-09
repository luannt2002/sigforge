package merge

import (
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// TestBuildManifestCollectsSourcesAndPosture proves the manifest records the running
// engine/schema, the content hash and count the caller passed, and every distinct
// provenance+license posture present in the DB — including a lower-precedence pattern's
// own (e.g. GPL) license kept under an Apache winner, which must not be under-stated.
func TestBuildManifestCollectsSourcesAndPosture(t *testing.T) {
	db := &schema.DB{
		SchemaVersion: schema.SchemaVersion,
		Fingerprints: map[string]schema.Fingerprint{
			"Nginx": {
				Provenance: "baseline", License: "Apache-2.0",
				VersionRegexProv: []schema.PatternProv{{Provenance: "nuclei", ProvenanceVersion: "v3.1", License: "MIT"}},
				CPECandidateProv: []schema.PatternProv{{Provenance: "whatweb", License: "GPL-2.0-or-later"}},
			},
			"Apache": {Provenance: "baseline", License: "Apache-2.0"},
		},
	}
	m := BuildManifest(db, "deadbeef", "2026-11-05T00:00:00Z")

	if m.EngineVersion != EngineVersion || m.SchemaVersion != schema.SchemaVersion {
		t.Fatalf("engine/schema = %q/%q", m.EngineVersion, m.SchemaVersion)
	}
	if m.ContentSHA256 != "deadbeef" || m.FingerprintCount != 2 || m.Freshness != FreshnessSnapshot {
		t.Fatalf("manifest header wrong: %+v", m)
	}
	// baseline/Apache-2.0, nuclei/MIT, whatweb/GPL — each posture present exactly once.
	want := map[string]string{"baseline": "Apache-2.0", "nuclei": "MIT", "whatweb": "GPL-2.0-or-later"}
	if len(m.Sources) != len(want) {
		t.Fatalf("sources = %+v, want %d entries", m.Sources, len(want))
	}
	for _, s := range m.Sources {
		if want[s.ID] != s.License {
			t.Errorf("source %q license = %q, want %q", s.ID, s.License, want[s.ID])
		}
	}
	// Sorted by id for a reproducible manifest.
	for i := 1; i < len(m.Sources); i++ {
		if m.Sources[i-1].ID > m.Sources[i].ID {
			t.Errorf("sources not sorted: %+v", m.Sources)
		}
	}
}

// TestManifestCompatible proves the compat gate: the manifest this build writes is
// compatible, a differing MAJOR schema or engine version is INCOMPATIBLE, and the JSON
// round-trips. The INCOMPATIBLE path is what verify relies on to refuse a foreign snapshot.
func TestManifestCompatible(t *testing.T) {
	ok := Manifest{SchemaVersion: schema.SchemaVersion, EngineVersion: EngineVersion}
	if err := ok.Compatible(); err != nil {
		t.Fatalf("self-built manifest must be compatible: %v", err)
	}

	b, err := ok.JSON()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := ParseManifest(b)
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if rt.SchemaVersion != ok.SchemaVersion || rt.EngineVersion != ok.EngineVersion {
		t.Fatalf("round-trip lost version: %+v", rt)
	}

	for name, m := range map[string]Manifest{
		"schema-major": {SchemaVersion: "99.0.0", EngineVersion: EngineVersion},
		"engine-major": {SchemaVersion: schema.SchemaVersion, EngineVersion: "99.0.0"},
	} {
		err := m.Compatible()
		if err == nil || !strings.Contains(err.Error(), "INCOMPATIBLE") {
			t.Errorf("%s: want INCOMPATIBLE, got %v", name, err)
		}
	}
}
