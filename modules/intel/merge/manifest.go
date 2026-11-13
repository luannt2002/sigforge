package merge

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// EngineVersion is the sigforge build that produced (and can read) a manifest. verify
// refuses a snapshot whose manifest records a different MAJOR engine version, because a
// major bump may change merge semantics the running build would misread. It is the
// governance counterpart to schema.SchemaVersion, which versions the on-disk shape.
const EngineVersion = "0.5.0"

// FreshnessSnapshot marks a manifest's data as a point-in-time merged snapshot — its age
// is generated_at, never a live feed. A merged DB is a snapshot by construction, so this
// is the honest classification (mirrors the "snapshot" vocabulary consumers already use).
const FreshnessSnapshot = "snapshot"

// Manifest is the governance record written beside a merged DB: what build produced the
// snapshot, over which sources (with their license posture), when, and the content hash
// it must still match. verify reads it to refuse an incompatible or mis-described DB
// instead of silently trusting bytes.
type Manifest struct {
	SchemaVersion    string           `json:"schema_version"`
	EngineVersion    string           `json:"engine_version"`
	GeneratedAt      string           `json:"generated_at"`
	ContentSHA256    string           `json:"content_sha256"`
	FingerprintCount int              `json:"fingerprint_count"`
	Sources          []ManifestSource `json:"sources"`
	Freshness        string           `json:"freshness"`
}

// ManifestSource is one provenance present in the merged DB, with the synced version and
// license it carries. A single source can appear more than once when entries (or merged-in
// patterns) from it were synced at different versions/licenses — each distinct posture is
// listed, so the operator who owns the output's license posture sees every one.
type ManifestSource struct {
	ID                string `json:"id"`
	ProvenanceVersion string `json:"provenance_version,omitempty"`
	License           string `json:"license,omitempty"`
}

// ManifestPath is the manifest file beside a merged DB (db.json → db.json.manifest.json).
func ManifestPath(dbPath string) string { return dbPath + ".manifest.json" }

// BuildManifest derives the manifest from the merged DB plus the content hash and
// timestamp the caller wrote, so the manifest describes exactly the bytes on disk.
func BuildManifest(db *schema.DB, contentSHA, generatedAt string) Manifest {
	return Manifest{
		SchemaVersion:    db.SchemaVersion,
		EngineVersion:    EngineVersion,
		GeneratedAt:      generatedAt,
		ContentSHA256:    contentSHA,
		FingerprintCount: len(db.Fingerprints),
		Sources:          collectSources(db),
		Freshness:        FreshnessSnapshot,
	}
}

// collectSources walks every entry's provenance AND the per-pattern provenances kept
// during merge (VersionRegexProv / CPECandidateProv), so a GPL pattern pooled under an
// Apache winner is reported under its own license — the manifest must not under-state the
// license posture the merge took care to preserve. Deduplicated by (id, version, license)
// and sorted for a stable, reproducible manifest.
func collectSources(db *schema.DB) []ManifestSource {
	seen := make(map[string]ManifestSource)
	add := func(id, ver, lic string) {
		if id == "" {
			return
		}
		key := id + "\x00" + ver + "\x00" + lic
		if _, ok := seen[key]; !ok {
			seen[key] = ManifestSource{ID: id, ProvenanceVersion: ver, License: lic}
		}
	}
	for _, fp := range db.Fingerprints {
		add(fp.Provenance, fp.ProvenanceVersion, fp.License)
		for _, p := range fp.VersionRegexProv {
			add(p.Provenance, p.ProvenanceVersion, p.License)
		}
		for _, p := range fp.CPECandidateProv {
			add(p.Provenance, p.ProvenanceVersion, p.License)
		}
	}
	out := make([]ManifestSource, 0, len(seen))
	for _, s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].ProvenanceVersion != out[j].ProvenanceVersion {
			return out[i].ProvenanceVersion < out[j].ProvenanceVersion
		}
		return out[i].License < out[j].License
	})
	return out
}

// JSON renders the manifest as indented JSON with a trailing newline, for an on-disk file.
func (m Manifest) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseManifest decodes a manifest from its JSON bytes.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: decode: %w", err)
	}
	return m, nil
}

// Compatible reports whether this manifest's snapshot was produced by a build the running
// one can read: the same MAJOR schema version and the same MAJOR engine version. A
// differing major returns an INCOMPATIBLE error so verify refuses rather than trusting a
// snapshot whose shape or merge semantics it may misread. (Major-match mirrors the rule
// schema.Validate already applies to schema_version.)
func (m Manifest) Compatible() error {
	if err := sameMajor("schema_version", m.SchemaVersion, schema.SchemaVersion); err != nil {
		return err
	}
	return sameMajor("engine_version", m.EngineVersion, EngineVersion)
}

func sameMajor(field, got, want string) error {
	g, err := majorOf(got)
	if err != nil {
		return fmt.Errorf("manifest %s %q: %w", field, got, err)
	}
	w, _ := majorOf(want)
	if g != w {
		return fmt.Errorf("INCOMPATIBLE %s %q — this build is %q", field, got, want)
	}
	return nil
}

func majorOf(v string) (int, error) {
	head, _, _ := strings.Cut(strings.TrimSpace(v), ".")
	if head == "" {
		return 0, fmt.Errorf("missing major version")
	}
	return strconv.Atoi(head)
}
