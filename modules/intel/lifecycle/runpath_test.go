package lifecycle

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

// bundleServer serves whatever body holds and counts the requests.
func bundleServer(t *testing.T, body *atomic.Value) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

// A run that asks the source itself (no max age) puts a new bundle in the store only once the parser accepts it and
// finds a product. A refused answer leaves every byte of the store; the run answers from the stored bundle, labelled
// stale, with a note saying why — one request per run, as before.
func TestRunKeepsTheStoredBundleOverJunk(t *testing.T) {
	for _, junk := range []struct{ name, body, why string }{
		{"html page", "<html>proxy login required</html>", "decode endoflife bundle"},
		{"json of another shape", `{"unexpected": true, "items": [1, 2, 3]}`, "lists no products"},
		{"empty body", "", "decode endoflife bundle"},
		{"no product", `{"result": []}`, "lists no products"},
	} {
		t.Run(junk.name, func(t *testing.T) {
			var body atomic.Value
			body.Store(bundleJSON)
			url, hits := bundleServer(t, &body)
			c := fetch.New()
			c.CacheDir = t.TempDir()
			ctx := context.Background()
			if st, err := NewBundle(url, c).EOLStatus(ctx, "PHP", "7.4.3"); err != nil || st.IsEOL != StateEOL {
				t.Fatalf("the first run must take the good bundle: %+v %v", st, err)
			}
			before := storeFiles(t, c.CacheDir)
			body.Store(junk.body)
			st, err := NewBundle(url, c).EOLStatus(ctx, "PHP", "7.4.3")
			u := ToUnified(st, err)
			if after := storeFiles(t, c.CacheDir); !maps.Equal(before, after) {
				t.Fatalf("the store must keep every byte it held: %d files before, now %v", len(before), after)
			}
			if err != nil || !st.Stale || u.State != unified.StateAffectedByAdvisory || u.Freshness != unified.FreshnessStale ||
				!strings.Contains(u.Err, "stale") || !strings.Contains(u.Err, "unusable body") || !strings.Contains(u.Err, junk.why) {
				t.Fatalf("want the stored bundle's verdict, stale, with a note saying why: %+v / %+v / %v", st, u, err)
			}
			if hits.Load() != 2 {
				t.Fatalf("want one request per run, sent %d over two runs", hits.Load())
			}
		})
	}
}

// With nothing stored, a refused answer stores nothing and the lookup is source_unavailable with why — never a verdict.
func TestRunStoresNoRefusedBundle(t *testing.T) {
	var body atomic.Value
	body.Store(`{"result": []}`)
	url, hits := bundleServer(t, &body)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	st, err := NewBundle(url, c).EOLStatus(context.Background(), "PHP", "7.4.3")
	u := ToUnified(st, err)
	if files := storeFiles(t, c.CacheDir); len(files) != 0 {
		t.Fatalf("a refused bundle must not enter the store, found %v", files)
	}
	if u.State != unified.StateSourceUnavailable || !strings.Contains(u.Err, "lists no products") || hits.Load() != 1 {
		t.Fatalf("want source_unavailable with why, after one request: %+v / %d", u, hits.Load())
	}
}

// A stored copy no check passed — an older binary stored it, or sync just refused it on a 304 — reaches the loader
// unchecked: within max age with no request, or as the stale copy when the source fails. The loader reads it again with
// the same parser, so it is never the bundle in use: the lookup is source_unavailable with why — never a verdict.
func TestRunRechecksAStoredBundleServedUnchecked(t *testing.T) {
	html := "<html>proxy login required</html>"
	_, perr := ParseBundle([]byte(html))
	for _, junk := range []struct{ name, body, why string }{
		{"html page", html, "lifecycle: bundle: " + perr.Error()},
		{"no product", `{"result": []}`, "lifecycle: bundle: endoflife bundle lists no products"},
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
				st, err := NewBundle(srv.URL, c).EOLStatus(ctx, "PHP", "7.4.3")
				u := ToUnified(st, err)
				if err == nil || err.Error() != junk.why || u.State != unified.StateSourceUnavailable || u.Err != junk.why {
					t.Fatalf("want source_unavailable with why the stored copy is not in use: %+v / %+v / %v", st, u, err)
				}
				if n := hits.Load() - 1; n != run.asks {
					t.Fatalf("want %d requests from the run, sent %d", run.asks, n)
				}
			})
		}
	}
}

// A bundle the parser accepts still replaces the stored one, with one request per run.
func TestRunReplacesTheStoredBundleWithAGoodOne(t *testing.T) {
	var body atomic.Value
	body.Store(bundleJSON)
	url, hits := bundleServer(t, &body)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	if _, err := NewBundle(url, c).EOLStatus(context.Background(), "PHP", "7.4.3"); err != nil {
		t.Fatal(err)
	}
	next := `{"result": [{"name": "php", "releases": [{"name": "7.4", "isEol": false, "eolFrom": "2099-12-31"}]}]}`
	body.Store(next)
	st, err := NewBundle(url, c).EOLStatus(context.Background(), "PHP", "7.4.3")
	stored := false
	for _, b := range storeFiles(t, c.CacheDir) {
		stored = stored || b == next
	}
	if u := ToUnified(st, err); !stored || err != nil || st.Stale || st.Cached || st.IsEOL != StateSupported || u.Freshness != unified.FreshnessLive || hits.Load() != 2 {
		t.Fatalf("want the new bundle's verdict, live and in the store, after one request per run: stored=%v %+v / %+v / %v / %d", stored, st, u, err, hits.Load())
	}
}
