package identity

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

// dictServer serves whatever body holds and counts the requests.
func dictServer(t *testing.T, body *atomic.Value) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

// A run that asks the source itself (no max age) puts a new dictionary in the store only once the parser accepts it
// and finds a usable CPE entry. A refused answer leaves every byte of the store; identity matches against the stored
// copy and the status says why — one request per run, as before.
func TestRunKeepsTheStoredDictionaryOverJunk(t *testing.T) {
	for _, junk := range []struct{ name, body, why string }{
		{"html page", "<html>proxy login required</html>", "unparseable"},
		{"json of another shape", `{"unexpected": true, "items": [1, 2, 3]}`, "no usable CPE entries"},
		{"empty body", "", "unparseable"},
		{"no entry", `{"products": []}`, "no usable CPE entries"},
	} {
		t.Run(junk.name, func(t *testing.T) {
			var body atomic.Value
			body.Store(dictTestJSON)
			url, hits := dictServer(t, &body)
			c := fetch.New()
			c.CacheDir = t.TempDir()
			ctx := context.Background()
			if s := New(url, c).Status(ctx); s.Source != "live" || s.Err != "" {
				t.Fatalf("the first run must take the good dictionary: %+v", s)
			}
			before := storeFiles(t, c.CacheDir)
			body.Store(junk.body)
			s := New(url, c).Status(ctx)
			if after := storeFiles(t, c.CacheDir); !maps.Equal(before, after) {
				t.Fatalf("the store must keep every byte it held: %d files before, now %v", len(before), after)
			}
			if s.Source != "live" || !s.Cached || s.Entries != 2 || !strings.Contains(s.Err, "unusable body") || !strings.Contains(s.Err, junk.why) {
				t.Fatalf("want the stored dictionary with why: %+v", s)
			}
			if hits.Load() != 2 {
				t.Fatalf("want one request per run, sent %d over two runs", hits.Load())
			}
		})
	}
}

// With nothing stored, a refused answer stores nothing: identity matches against the embedded sample — which never
// verifies — and the status says why.
func TestRunStoresNoRefusedDictionary(t *testing.T) {
	var body atomic.Value
	body.Store(`{"products": []}`)
	url, hits := dictServer(t, &body)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	s := New(url, c).Status(context.Background())
	if files := storeFiles(t, c.CacheDir); len(files) != 0 {
		t.Fatalf("a refused dictionary must not enter the store, found %v", files)
	}
	if s.Source != "snapshot" || !strings.Contains(s.Err, "no usable CPE entries") || hits.Load() != 1 {
		t.Fatalf("want the embedded sample with why, after one request: %+v / %d", s, hits.Load())
	}
}

// A stored copy no check passed — an older binary stored it, or sync just refused it on a 304 — reaches the loader
// unchecked: within max age with no request, or as the stale copy when the source fails. The loader reads it again with
// the same parser and emptiness rule, so it is never the dictionary in use: identity matches against the embedded
// sample and the status says why.
func TestRunRechecksAStoredDictionaryServedUnchecked(t *testing.T) {
	html := "<html>proxy login required</html>"
	_, _, _, perr := parseDict(strings.NewReader(html))
	for _, junk := range []struct{ name, body, why string }{
		{"html page", html, "live dictionary unparseable: " + perr.Error()},
		{"no entry", `{"products": []}`, "live dictionary had no usable CPE entries"},
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
				if s := New(srv.URL, c).Status(ctx); s.Source != "snapshot" || s.Cached || s.Err != junk.why {
					t.Fatalf("want the embedded sample, with why the stored copy is not in use: %+v", s)
				}
				if n := hits.Load() - 1; n != run.asks {
					t.Fatalf("want %d requests from the run, sent %d", run.asks, n)
				}
			})
		}
	}
}

// A dictionary the parser accepts still replaces the stored one, with one request per run.
func TestRunReplacesTheStoredDictionaryWithAGoodOne(t *testing.T) {
	var body atomic.Value
	body.Store(dictTestJSON)
	url, hits := dictServer(t, &body)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	New(url, c).Status(context.Background())
	next := `{"totalResults": 1, "products": [{"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "titles": [{"title": "Widget", "lang": "en"}]}}]}`
	body.Store(next)
	r := New(url, c)
	cpe, _, st := r.ResolveCPE(context.Background(), "", "acme", "widget")
	s := r.Status(context.Background())
	stored := false
	for _, b := range storeFiles(t, c.CacheDir) {
		stored = stored || b == next
	}
	if !stored || s.Source != "live" || s.Cached || s.Err != "" || s.Entries != 1 || st != StateVerified || cpe == "" || hits.Load() != 2 {
		t.Fatalf("want the new dictionary live and in the store after one request per run: stored=%v %+v / %q %v / %d", stored, s, cpe, st, hits.Load())
	}
}
