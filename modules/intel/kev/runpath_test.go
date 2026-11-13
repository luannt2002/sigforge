package kev

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// storeFiles is every file in the store with its bytes.
func storeFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// catalogServer serves whatever body holds and counts the requests.
func catalogServer(t *testing.T, body *atomic.Value) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

// A run that asks the source itself (no max age) puts a new catalog in the store only once the parser accepts it and
// finds an entry. A refused answer leaves every byte of the store; the run prioritizes against the stored copy,
// labelled stale, and says why — with no more requests than before: one per run.
func TestRunKeepsTheStoredCatalogOverJunk(t *testing.T) {
	for _, junk := range []struct{ name, body, why string }{
		{"html page", "<html>proxy login required</html>", "unparseable"},
		{"json of another shape", `{"unexpected": true, "items": [1, 2, 3]}`, "no entries"},
		{"empty body", "", "unparseable"},
		{"no entry", `{"vulnerabilities": []}`, "no entries"},
		{"rows without a CVE id", `{"vulnerabilities": [{"cveID": "not-a-cve"}]}`, "no entries"},
	} {
		t.Run(junk.name, func(t *testing.T) {
			var body atomic.Value
			body.Store(kevTestJSON)
			url, hits := catalogServer(t, &body)
			c := fetch.New()
			c.CacheDir = t.TempDir()
			ctx := context.Background()
			if s := New(url, "", c).Status(ctx); s.Source != "live" || s.Err != "" {
				t.Fatalf("the first run must take the good catalog: %+v", s)
			}
			before := storeFiles(t, c.CacheDir)
			body.Store(junk.body)
			a := New(url, "", c)
			got := a.EnrichUnified(ctx, []string{"CVE-2021-44228"})["CVE-2021-44228"]
			st := a.Status(ctx)
			if after := storeFiles(t, c.CacheDir); !maps.Equal(before, after) {
				t.Fatalf("the store must keep every byte it held: %d files before, now %v", len(before), after)
			}
			if got.Freshness != unified.FreshnessStale || got.State != unified.StateAffectedByAdvisory || st.Source != "live" || st.Entries != 3 ||
				!strings.Contains(st.Err, "unusable body") || !strings.Contains(st.Err, junk.why) {
				t.Fatalf("want the stored catalog, stale, with why: %+v / %+v", got, st)
			}
			if hits.Load() != 2 {
				t.Fatalf("want one request per run, sent %d over two runs", hits.Load())
			}
		})
	}
}

// With nothing stored, a refused answer stores nothing: leads are prioritized against the embedded snapshot and the
// status says why — never a live catalog.
func TestRunStoresNoRefusedCatalog(t *testing.T) {
	var body atomic.Value
	body.Store(`{"vulnerabilities": []}`)
	url, hits := catalogServer(t, &body)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	a := New(url, "", c)
	got := a.EnrichUnified(context.Background(), []string{"CVE-2021-44228"})["CVE-2021-44228"]
	st := a.Status(context.Background())
	if files := storeFiles(t, c.CacheDir); len(files) != 0 {
		t.Fatalf("a refused catalog must not enter the store, found %v", files)
	}
	if st.Source != "snapshot" || !strings.Contains(st.Err, "no entries") || got.Freshness == unified.FreshnessLive || hits.Load() != 1 {
		t.Fatalf("want the embedded snapshot with why, after one request: %+v / %+v / %d", got, st, hits.Load())
	}
}

// A stored copy no check passed — an older binary stored it, or sync just refused it on a 304 — reaches the loader
// unchecked: within max age with no request, or as the stale copy when the source fails. The loader reads it again with
// the same parser and emptiness rule, so it is never the catalog in use: leads are prioritized against the embedded
// snapshot and the status says why.
func TestRunRechecksAStoredCatalogServedUnchecked(t *testing.T) {
	html := "<html>proxy login required</html>"
	_, perr := ParseKEV([]byte(html))
	for _, junk := range []struct{ name, body, why string }{
		{"html page", html, "live KEV catalog unparseable: " + perr.Error()},
		{"no entry", `{"vulnerabilities": []}`, "live KEV catalog had no entries"},
	} {
		for _, run := range []struct {
			name   string
			maxAge time.Duration
			down   bool  // the source answers 500
			asks   int32 // requests the run sends
		}{
			{"within max age", time.Hour, false, 0},
			{"source down", 0, true, 1},
		} {
			t.Run(junk.name+"/"+run.name, func(t *testing.T) {
				var hits atomic.Int32
				var down atomic.Bool
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					if down.Load() {
						http.Error(w, "down", http.StatusInternalServerError)
						return
					}
					_, _ = w.Write([]byte(junk.body))
				}))
				defer srv.Close()
				c := fetch.New()
				c.CacheDir = t.TempDir()
				ctx := context.Background()
				if _, err := c.Get(ctx, srv.URL); err != nil { // stored unchecked, as an older binary did
					t.Fatal(err)
				}
				c.MaxAge = run.maxAge
				down.Store(run.down)
				a := New(srv.URL, "", c)
				got := a.EnrichUnified(ctx, []string{"CVE-2021-44228"})["CVE-2021-44228"]
				st := a.Status(ctx)
				if st.Source != "snapshot" || st.Entries == 0 || st.Err != junk.why || got.Freshness != unified.FreshnessSnapshot || got.State != unified.StateAffectedByAdvisory {
					t.Fatalf("want the embedded snapshot, with why the stored copy is not in use: %+v / %+v", got, st)
				}
				if n := hits.Load() - 1; n != run.asks {
					t.Fatalf("want %d requests from the run, sent %d", run.asks, n)
				}
			})
		}
	}
}

// A catalog the parser accepts still replaces the stored one, with one request per run.
func TestRunReplacesTheStoredCatalogWithAGoodOne(t *testing.T) {
	var body atomic.Value
	body.Store(kevTestJSON)
	url, hits := catalogServer(t, &body)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	New(url, "", c).Status(context.Background())
	next := `{"count": 1, "vulnerabilities": [{"cveID": "CVE-2099-0001", "knownRansomwareCampaignUse": "Unknown"}]}`
	body.Store(next)
	a := New(url, "", c)
	got := a.EnrichUnified(context.Background(), []string{"CVE-2099-0001"})["CVE-2099-0001"]
	st := a.Status(context.Background())
	stored := false
	for _, b := range storeFiles(t, c.CacheDir) {
		stored = stored || b == next
	}
	if !stored || st.Source != "live" || st.Entries != 1 || st.Err != "" || got.Freshness != unified.FreshnessLive || got.State != unified.StateAffectedByAdvisory || hits.Load() != 2 {
		t.Fatalf("want the new catalog live and in the store after one request per run: stored=%v %+v / %+v / %d", stored, got, st, hits.Load())
	}
}
