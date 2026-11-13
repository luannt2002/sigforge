package jslib

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

// repoServer serves whatever body holds and counts the requests.
func repoServer(t *testing.T, body *atomic.Value) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

// A run that asks the source itself (no max age) puts a new repository in the store only once the parser accepts it
// and finds a library. A refused answer leaves every byte of the store; the run answers from the stored copy, labelled
// stale, with a note saying why — one request per run, as before.
func TestRunKeepsTheStoredRepositoryOverJunk(t *testing.T) {
	for _, junk := range []struct{ name, body, why string }{
		{"html page", "<html>proxy login required</html>", "unparseable"},
		{"json of another shape", `{"unexpected": true, "items": [1, 2, 3]}`, "unparseable"},
		{"empty body", "", "unparseable"},
		{"no library", `{}`, "lists no libraries"},
	} {
		t.Run(junk.name, func(t *testing.T) {
			var body atomic.Value
			body.Store(nestedRepoJSON)
			url, hits := repoServer(t, &body)
			c := fetch.New()
			c.CacheDir = t.TempDir()
			ctx := context.Background()
			if r := New(url, c).LookupOne(ctx, "AngularJS", "1.6.0"); !r.Live || len(r.Vulns) != 1 {
				t.Fatalf("the first run must take the good repository: %+v", r)
			}
			before := storeFiles(t, c.CacheDir)
			body.Store(junk.body)
			r := New(url, c).LookupOne(ctx, "AngularJS", "1.6.0")
			u := ToUnified(r)
			if after := storeFiles(t, c.CacheDir); !maps.Equal(before, after) {
				t.Fatalf("the store must keep every byte it held: %d files before, now %v", len(before), after)
			}
			if r.Sample || !r.Stale || u.State != unified.StateAffectedByAdvisory || u.Freshness != unified.FreshnessStale ||
				!strings.Contains(u.Err, "unusable body") || !strings.Contains(u.Err, junk.why) {
				t.Fatalf("want the stored repository's answer, stale, with a note saying why: %+v / %+v", r, u)
			}
			if hits.Load() != 2 {
				t.Fatalf("want one request per run, sent %d over two runs", hits.Load())
			}
		})
	}
}

// With nothing stored, a refused answer stores nothing: the run falls back to the embedded sample, never clean, with
// a note saying why the configured repository is not in use.
func TestRunStoresNoRefusedRepository(t *testing.T) {
	var body atomic.Value
	body.Store(`{}`)
	url, hits := repoServer(t, &body)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	r := New(url, c).LookupOne(context.Background(), "lodash", "4.17.21")
	u := ToUnified(r)
	if files := storeFiles(t, c.CacheDir); len(files) != 0 {
		t.Fatalf("a refused repository must not enter the store, found %v", files)
	}
	if !r.Sample || u.State == unified.StateNotAffectedByAdvisory || u.Freshness != unified.FreshnessSnapshot || !strings.Contains(u.Err, "lists no libraries") ||
		!strings.Contains(u.Err, "only the embedded Retire.js sample") || hits.Load() != 1 {
		t.Fatalf("want the embedded sample's answer, not clean, with why, after one request: %+v / %+v / %d", r, u, hits.Load())
	}
}

// A stored copy no check passed — an older binary stored it, or sync just refused it on a 304 — reaches the loader
// unchecked: within max age with no request, or as the stale copy when the source fails. The loader reads it again with
// the same parser and emptiness rule, so it is never the repository in use: the run answers from the embedded sample,
// never clean, with a note saying why.
func TestRunRechecksAStoredRepositoryServedUnchecked(t *testing.T) {
	html := "<html>proxy login required</html>"
	_, perr := ParseRepo([]byte(html))
	for _, junk := range []struct{ name, body, why string }{
		{"html page", html, "Retire.js repository unparseable: " + perr.Error()},
		{"no library", `{}`, "Retire.js repository lists no libraries"},
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
				r := New(srv.URL, c).LookupOne(ctx, "lodash", "4.17.21")
				u := ToUnified(r)
				if !r.Sample || r.Live || r.Stale || r.Err != junk.why || u.Freshness != unified.FreshnessSnapshot || u.State == unified.StateNotAffectedByAdvisory ||
					!strings.Contains(u.Err, junk.why) || !strings.Contains(u.Err, "only the embedded Retire.js sample") {
					t.Fatalf("want the embedded sample's answer, not clean, with why the stored copy is not in use: %+v / %+v", r, u)
				}
				if n := hits.Load() - 1; n != run.asks {
					t.Fatalf("want %d requests from the run, sent %d", run.asks, n)
				}
			})
		}
	}
}

// A repository the parser accepts still replaces the stored one, with one request per run.
func TestRunReplacesTheStoredRepositoryWithAGoodOne(t *testing.T) {
	var body atomic.Value
	body.Store(nestedRepoJSON)
	url, hits := repoServer(t, &body)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	New(url, c).LookupOne(context.Background(), "AngularJS", "1.6.0")
	next := `{"widget": {"vulnerabilities": [{"below": "2.0.0", "severity": "low", "identifiers": {"CVE": ["CVE-2099-0002"]}}]}}`
	body.Store(next)
	r := New(url, c).LookupOne(context.Background(), "widget", "1.0.0")
	stored := false
	for _, b := range storeFiles(t, c.CacheDir) {
		stored = stored || b == next
	}
	if u := ToUnified(r); !stored || !r.Live || r.Stale || u.State != unified.StateAffectedByAdvisory || u.Err != "" || hits.Load() != 2 {
		t.Fatalf("want the new repository live and in the store after one request per run: stored=%v %+v / %+v / %d", stored, r, u, hits.Load())
	}
}
