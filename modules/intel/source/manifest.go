package source

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/luannt2002/sigforge/framework/fsio"
)

// ManifestRow is one source's sync marker: enough to diff a future re-sync against
// (which version was pulled, from where, when, and how many entries resulted).
type ManifestRow struct {
	Source     string `json:"source"`
	URL        string `json:"url"`
	Version    string `json:"version"` // git SHA / tag if the URL pinned one, else "unversioned@<ts>"
	FetchedAt  string `json:"fetched_at"`
	EntryCount int    `json:"entry_count"`
	License    string `json:"license"`
}

// Manifest is the per-source sync marker file (SYNC-MANIFEST.json). It is
// operator-generated metadata about third-party fetches — not third-party data
// itself — and like the merged DB it is gitignored, never committed.
type Manifest struct {
	GeneratedAt string        `json:"generated_at"`
	Sources     []ManifestRow `json:"sources"`
}

// LoadManifest reads an existing manifest; a missing file yields an empty one so a
// first fetch starts cleanly.
func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Manifest{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("source: read manifest %q: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("source: decode manifest %q: %w", path, err)
	}
	return &m, nil
}

// Upsert replaces the row for row.Source (one row per source id) or appends it.
func (m *Manifest) Upsert(row ManifestRow) {
	for i, r := range m.Sources {
		if r.Source == row.Source {
			m.Sources[i] = row
			return
		}
	}
	m.Sources = append(m.Sources, row)
}

// Save writes the manifest atomically, rows ordered by source id for a stable diff.
func (m *Manifest) Save(path string) error {
	m.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	sort.Slice(m.Sources, func(i, j int) bool { return m.Sources[i].Source < m.Sources[j].Source })
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsio.WriteAtomic(path, append(b, '\n'), 0o644)
}
