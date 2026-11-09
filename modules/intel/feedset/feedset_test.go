package feedset

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/kev"
)

// Notes asks only the sources this run used: a configured KEV catalog the run never consulted is
// not fetched just to print a note — and once used, a failing one is named.
func TestNotesAskOnlyUsedSources(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	t.Setenv(kev.EnvKEVURL, srv.URL)
	t.Setenv(identity.EnvCPEDictURL, "")
	c, _ := Client()
	s := New(c)
	if notes := s.Notes(context.Background()); len(notes) != 0 || hits.Load() != 0 {
		t.Fatalf("an unused KEV source must cost nothing: notes=%v requests=%d", notes, hits.Load())
	}
	s.Options.KEV.EnrichUnified(context.Background(), []string{"CVE-2021-44228"})
	notes := s.Notes(context.Background())
	if len(notes) != 1 || !strings.Contains(notes[0], "status 403") {
		t.Fatalf("a used, failing KEV source must be named, got %v", notes)
	}
}

func TestClientReadsStoreAndMaxAge(t *testing.T) {
	t.Setenv(EnvCacheDir, "/tmp/store")
	t.Setenv(EnvCacheMaxAge, "24h")
	if c, note := Client(); c.CacheDir != "/tmp/store" || c.MaxAge.Hours() != 24 || note != "" {
		t.Fatalf("got dir=%q maxAge=%v note=%q", c.CacheDir, c.MaxAge, note)
	}
	t.Setenv(EnvCacheMaxAge, "tomorrow")
	if c, note := Client(); c.MaxAge != 0 || !strings.Contains(note, "tomorrow") {
		t.Fatalf("an unreadable max age must be ignored and named, got %v %q", c.MaxAge, note)
	}
}

// TestDictNote: enrich must say when the configured CPE dictionary is not what identity
// matched against — a failed live dictionary, or one page of a paged feed — and stay
// quiet when the live dictionary is fully in use.
func TestDictNote(t *testing.T) {
	cases := []struct {
		name string
		s    identity.DictStatus
		want string // substring; "" means no note
	}{
		{"live and complete", identity.DictStatus{Source: "live", Entries: 2, Products: 5, Total: 5}, ""},
		{"live failed", identity.DictStatus{Source: "snapshot", Entries: 3, Err: "status 500"}, "not in use (status 500)"},
		{"one page", identity.DictStatus{Source: "live", Entries: 2, Products: 2, Total: 1000}, "2 of 1000 products"},
	}
	for _, c := range cases {
		got := dictNote(c.s)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: dictNote = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestKEVNote(t *testing.T) {
	if got := kevNote(kev.CatalogStatus{Source: "live", Entries: 1400}); got != "" {
		t.Errorf("a live catalog must print no note, got %q", got)
	}
	got := kevNote(kev.CatalogStatus{Source: "snapshot", Entries: 3, Err: "status 403"})
	if !strings.Contains(got, "not in use (status 403)") || !strings.Contains(got, "3 entries") {
		t.Errorf("a failed live catalog must say why and what was used instead, got %q", got)
	}
}

// A stale synced copy in use still gets a note naming the failure.
func TestNotesOnStaleCopy(t *testing.T) {
	if got := kevNote(kev.CatalogStatus{Source: "live", Entries: 3, Cached: true, Err: "status 503"}); !strings.Contains(got, "last synced copy") || !strings.Contains(got, "status 503") {
		t.Errorf("kevNote on a stale copy = %q", got)
	}
	if got := dictNote(identity.DictStatus{Source: "live", Entries: 2, Cached: true, Err: "status 503"}); !strings.Contains(got, "last synced copy") || !strings.Contains(got, "status 503") {
		t.Errorf("dictNote on a stale copy = %q", got)
	}
}
