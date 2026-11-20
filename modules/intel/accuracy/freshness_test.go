package accuracy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// The per-query feeds (CVE, WordPress) are asked on every lookup even with a store and a max age: their answer is
// live because it came from the source this run. When the source then fails the lookup is source_unavailable —
// never the stored answer passed off as live, nor a stale one. (Catalog and dump sources do use the store; their
// snapshot and stale labels are held in their own packages.)
func TestQueryFeedsAreNeverServedFromTheStore(t *testing.T) {
	ctx := context.Background()
	var asked atomic.Int32
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Query().Has("cpeName") || r.URL.Query().Has("virtualMatchString") {
			_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-0001"}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"acme":{"vulnerabilities":[{"id":"WPV-1","fixed_in":"2.0"}]}}`))
	}))
	defer srv.Close()
	client := func() *fetch.Client {
		c := fetch.New()
		c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
		return c
	}
	for name, look := range map[string]func(*fetch.Client) unified.Result{
		"cve": func(c *fetch.Client) unified.Result {
			return cve.ToUnified(cve.New(srv.URL, c).Lookup(ctx, "cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*", "1.0"))
		},
		"wpcve": func(c *fetch.Client) unified.Result {
			return wpcve.ToUnified(wpcve.New(srv.URL+"/{slug}", "", c).LookupPlugin(ctx, "acme", "1.0"))
		},
	} {
		failing.Store(false)
		c := client()
		before := asked.Load()
		first, second := look(c), look(c)
		if n := asked.Load() - before; n < 2 || first.Freshness != unified.FreshnessLive || second.Freshness != unified.FreshnessLive {
			t.Errorf("%s: %d request(s) for two lookups, freshness %s / %s — want the source asked each time, both live", name, n, first.Freshness, second.Freshness)
		}
		failing.Store(true)
		if r := look(c); r.State != unified.StateSourceUnavailable || r.Freshness == unified.FreshnessStale || r.Freshness == unified.FreshnessLive || r.Reason != unified.ReasonSourceError {
			t.Errorf("%s: source failing = %s / %s / %q, want source_unavailable, not stale or live, source_error", name, r.State, r.Freshness, r.Reason)
		}
	}
}

// A source that is off or failed fetched nothing, so its result claims no freshness — on the paths a run really
// takes (OSV through its Lookuper, the others through their adapters), not only through helpers.
func TestUnansweredResultsClaimNoFreshness(t *testing.T) {
	ctx := context.Background()
	down := serveBody(t, http.StatusInternalServerError, "")
	cases := map[string]unified.Result{
		"osv off":          osv.New("", fetch.New()).Lookuper()(ctx, "npm", "lodash", "4.17.20"),
		"osv failed":       osv.New(down, fetch.New()).Lookuper()(ctx, "npm", "lodash", "4.17.20"),
		"cve off":          cve.ToUnified(cve.New("", fetch.New()).Lookup(ctx, "cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*", "1.0")),
		"cve failed":       cve.ToUnified(cve.New(down, fetch.New()).Lookup(ctx, "cpe:2.3:a:acme:acme:*:*:*:*:*:*:*:*", "1.0")),
		"lifecycle off":    lifecycle.ToUnified(lifecycle.New("", fetch.New()).EOLStatus(ctx, "PHP", "7.4.3")),
		"lifecycle failed": lifecycle.ToUnified(lifecycle.NewBundle(down, fetch.New()).EOLStatus(ctx, "PHP", "7.4.3")),
		"wpcve off":        wpcve.ToUnified(wpcve.New("", "", fetch.New()).LookupPlugin(ctx, "acme", "1.0")),
		"wpcve failed":     wpcve.ToUnified(wpcve.New(down+"/{slug}", "", fetch.New()).LookupPlugin(ctx, "acme", "1.0")),
	}
	for name, u := range cases {
		if u.State.Concluded() || u.Freshness != unified.FreshnessUnknown || u.FetchedAt != "" {
			t.Errorf("%s: %s freshness %s fetched_at %q — want unanswered, no freshness, no fetch time", name, u.State, u.Freshness, u.FetchedAt)
		}
	}
}
