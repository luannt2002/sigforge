package feedset

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
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
		{"one page verifies nothing", identity.DictStatus{Source: "live", Entries: 2, Products: 2, Total: 1000}, "no identity is verified"},
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
	// in use, but with something to look at (its release date, skipped rows): named, not silent
	if got := kevNote(kev.CatalogStatus{Source: "live", Entries: 1400, Warn: "catalog released 2026-08-01T00:00:00Z, 100 days ago"}); !strings.Contains(got, "100 days ago") {
		t.Errorf("a live catalog's warning must be printed, got %q", got)
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

// OSV is wired only when its source is configured: unset, enrich names the gap for a package it is
// asked about, and a detected platform is not looked up at all — no extra "feed off" result for it.
func TestOSVWiredOnlyWhenConfigured(t *testing.T) {
	t.Setenv(osv.EnvOSVURL, "")
	if o := New(fetch.New()).Options; o.OSV != nil || o.OSVRelease != nil {
		t.Fatal("OSV must stay nil when its source is unset")
	}
	t.Setenv(osv.EnvOSVURL, "http://127.0.0.1:1")
	if o := New(fetch.New()).Options; o.OSV == nil || o.OSVRelease == nil {
		t.Fatal("both OSV lookups must be wired when its source is set")
	}
}

// wpFeed serves body with status as the WordPress vulnerability feed, behind the {kind}/{slug}
// template an operator would set, and returns the paths it was asked.
func wpFeed(t *testing.T, status int, body string) func() []string {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(wpcve.EnvWPVulnURL, srv.URL+"/{kind}/{slug}")
	t.Setenv(wpcve.EnvWPOrgURL, "")
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(paths)
	}
}

// WordPress core is looked up as core — one request for the core product, scope wordpress:core —
// never as a plugin named "wordpress".
func TestWPCoreGoesToCoreLookup(t *testing.T) {
	asked := wpFeed(t, http.StatusOK, `{"wordpress":{"vulnerabilities":[{"id":"C1","min_version":"5.0","max_version":"6.1"}]}}`)
	r := New(fetch.New()).Options.WP(context.Background(), "wordpress", "6.0", "core")
	if got := asked(); len(got) != 1 || got[0] != "/core/wordpress" {
		t.Fatalf("core must ask the feed once, for the core product; asked %v", got)
	}
	if r.Scope != "wordpress:core" || r.Identity != "wordpress" || r.State != unified.StateAffectedByAdvisory || len(r.Leads) != 1 {
		t.Fatalf("core 6.0 inside 5.0–6.1 ⇒ one wordpress:core lead, got scope=%q id=%q state=%s leads=%d", r.Scope, r.Identity, r.State, len(r.Leads))
	}
}

// Plugins and themes keep their route; an unset kind stays a plugin, the default enrich.WPLookup documents.
func TestWPPluginAndThemeKeepTheirRoute(t *testing.T) {
	for _, c := range []struct{ kind, slug, path, scope string }{
		{"plugin", "akismet", "/plugin/akismet", "wordpress:plugin"},
		{"", "akismet", "/plugin/akismet", "wordpress:plugin"},
		{"theme", "astra", "/theme/astra", "wordpress:theme"},
	} {
		asked := wpFeed(t, http.StatusOK, `{}`)
		r := New(fetch.New()).Options.WP(context.Background(), c.slug, "1.0", c.kind)
		if got := asked(); len(got) != 1 || got[0] != c.path || r.Scope != c.scope || r.Identity != c.slug {
			t.Errorf("kind %q: asked %v, scope %q, id %q; want %s on %s", c.kind, got, r.Scope, r.Identity, c.path, c.scope)
		}
	}
}

// A kind that is not plugin, theme or core is not guessed as a plugin: nothing is asked, and the
// result is not_checked with a reason naming the kind.
func TestWPUnknownKindIsNotAPlugin(t *testing.T) {
	asked := wpFeed(t, http.StatusOK, `{"akismet":{"vulnerabilities":[{"id":"V1"}]}}`)
	r := New(fetch.New()).Options.WP(context.Background(), "akismet", "1.0", "widget")
	if got := asked(); len(got) != 0 {
		t.Fatalf("an unknown kind must ask nothing, asked %v", got)
	}
	if r.State != unified.StateNotChecked || !strings.Contains(r.Err, `"widget"`) || r.Scope == "wordpress:plugin" || r.Freshness != unified.FreshnessUnknown {
		t.Fatalf("an unknown kind ⇒ not_checked naming it, never a plugin answer; got state=%s scope=%q fresh=%s err=%q", r.State, r.Scope, r.Freshness, r.Err)
	}
}

// Core with no data stays a gap and says which one: feed off, feed down and a feed that does not
// list core are three different answers, none of them clean.
func TestWPCoreGapsStayApart(t *testing.T) {
	ctx := context.Background()
	t.Setenv(wpcve.EnvWPVulnURL, "")
	off := New(fetch.New()).Options.WP(ctx, "wordpress", "6.0", "core")
	wpFeed(t, http.StatusInternalServerError, "down")
	down := New(fetch.New()).Options.WP(ctx, "wordpress", "6.0", "core")
	wpFeed(t, http.StatusOK, `{"error":0,"data":null}`)
	unlisted := New(fetch.New()).Options.WP(ctx, "wordpress", "6.0", "core")
	for _, c := range []struct {
		name string
		r    unified.Result
		want unified.State
	}{
		{"feed off", off, unified.StateNotChecked},
		{"feed down", down, unified.StateSourceUnavailable},
		{"core not listed", unlisted, unified.StateUnknownProduct},
	} {
		if c.r.State != c.want || c.r.Scope != "wordpress:core" {
			t.Errorf("%s: state=%s scope=%q, want %s on wordpress:core", c.name, c.r.State, c.r.Scope, c.want)
		}
	}
}
