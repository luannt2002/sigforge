package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// The overlay an incremental sync writes the changed records into stays inside the store: a link put in its place —
// here at the very moment the changed-records list is asked for, between the old overlay's removal and the new one's
// creation — is never followed out, and nothing is written where it points.
func TestOverlayDirIsNeverALink(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	m := &osvMirror{dump: mustBytes(r)}
	store, elsewhere := t.TempDir(), t.TempDir()
	var plant atomic.Bool
	var planted atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if plant.Load() && req.URL.Path == "/npm/modified_id.csv" {
			bodies, _ := filepath.Glob(filepath.Join(store, "*.body"))
			for _, b := range bodies {
				if os.Symlink(elsewhere, b+".overlay") == nil {
					planted.Add(1)
				}
			}
		}
		m.ServeHTTP(w, req)
	}))
	defer srv.Close()
	ctx := context.Background()
	c := fetch.New()
	c.CacheDir = store
	if _, err := New(srv.URL, c).Sync(ctx, "npm"); err != nil {
		t.Fatal(err)
	}
	metas, _ := filepath.Glob(filepath.Join(store, "*.meta")) // age the stored dump: the next sync is incremental
	for _, mp := range metas {
		var meta map[string]any
		b, _ := os.ReadFile(mp)
		if json.Unmarshal(b, &meta) == nil && strings.HasSuffix(fmt.Sprint(meta["url"]), "/npm/all.zip") {
			meta["fetched_at"] = time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
			b, _ = json.Marshal(meta)
			_ = os.WriteFile(mp, b, 0o644)
		}
	}
	bodies, _ := filepath.Glob(filepath.Join(store, "*.body"))
	for _, p := range bodies {
		_ = os.Chtimes(p, time.Now().Add(-3*time.Hour), time.Now().Add(-3*time.Hour))
	}
	m.set(func() {
		m.csv = "2026-11-09T04:00:00Z,GHSA-new\n"
		m.records = map[string]string{"GHSA-new": lodashAdv("GHSA-new", "4.17.30", "")}
	})
	plant.Store(true)
	_, err := New(srv.URL, c).Sync(ctx, "npm") // refused, or the dump taken whole: either keeps the store's writes inside it
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the sync wrote %v where the planted link points", names)
	}
	if planted.Load() == 0 {
		t.Fatalf("no link was planted: the second sync never asked for the changed-records list")
	}
	if (err == nil || !strings.Contains(err.Error(), "overlay")) && m.zips.Load() < 2 {
		t.Errorf("sync with a planted overlay link = %v after %d dump download(s): want it refused naming the overlay, or the dump taken whole", err, m.zips.Load())
	}
}
