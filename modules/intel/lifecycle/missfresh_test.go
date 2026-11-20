package lifecycle

import (
	"context"
	"encoding/json"
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

// "The bundle does not list it" is an answer from the bundle, so it carries the bundle's freshness like any verdict:
// live when fetched now, snapshot when read from the store within its max age, stale — with why — when the source
// failed and the stored copy answered. By name and by CPE alike.
func TestBundleMissCarriesItsFreshness(t *testing.T) {
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true}]}]}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	store := t.TempDir()
	client := func(maxAge time.Duration) *fetch.Client {
		c := fetch.New()
		c.CacheDir, c.MaxAge = store, maxAge
		return c
	}
	misses := func(a *Adapter) map[string]unified.Result {
		byName, err := a.EOLStatus(ctx, "Drupal", "9.5.0")
		byCPE, err2 := a.EOLStatusByCPE(ctx, "cpe:2.3:a:other:other:*:*:*:*:*:*:*:*", "1.0")
		return map[string]unified.Result{"by name": ToUnified(byName, err), "by CPE": ToUnified(byCPE, err2)}
	}
	for _, tc := range []struct {
		name   string
		run    func() map[string]unified.Result
		fresh  unified.Freshness
		inNote string
	}{
		{"fetched now", func() map[string]unified.Result { return misses(NewBundle(srv.URL, client(0))) }, unified.FreshnessLive, ""},
		{"stored copy within max age", func() map[string]unified.Result { return misses(NewBundle(srv.URL, client(time.Hour))) }, unified.FreshnessSnapshot, ""},
		{"source failed, stored copy answers", func() map[string]unified.Result {
			failing.Store(true)
			return misses(NewBundle(srv.URL, client(0)))
		}, unified.FreshnessStale, "endoflife source failed"},
	} {
		for how, u := range tc.run() {
			if u.State != unified.StateUnknownProduct || u.Reason != unified.ReasonNotInSource || u.Freshness != tc.fresh || u.FetchedAt == "" ||
				!strings.Contains(u.Err, tc.inNote) {
				t.Errorf("%s, %s: %s / %q / %s / fetched_at %q / error %q — want not_in_source, %s, a fetch time, %q in error",
					tc.name, how, u.State, u.Reason, u.Freshness, u.FetchedAt, u.Err, tc.fresh, tc.inNote)
			}
		}
	}
}

// A stored bundle whose store entry carries no fetch time is still the bundle that answered: when the source fails,
// its "not listed" is stale, with why — the freshness comes from what was read, never inferred from the time, and
// the missing time is left out, never made up.
func TestBundleMissWithoutAStoredTime(t *testing.T) {
	var failing atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true}]}]}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	store := t.TempDir()
	client := func() *fetch.Client {
		c := fetch.New()
		c.CacheDir = store
		return c
	}
	if _, err := NewBundle(srv.URL, client()).EOLStatus(ctx, "Drupal", "9.5.0"); err != nil { // a good copy enters the store
		t.Fatal(err)
	}
	metas, _ := filepath.Glob(filepath.Join(store, "*.meta"))
	if len(metas) == 0 {
		t.Fatal("no store entry written")
	}
	for _, m := range metas { // an entry written without a fetch time
		var meta map[string]any
		b, _ := os.ReadFile(m)
		if err := json.Unmarshal(b, &meta); err != nil || meta["fetched_at"] == nil {
			t.Fatalf("store meta %s = %s, %v: want one carrying fetched_at", m, b, err)
		}
		delete(meta, "fetched_at")
		b, _ = json.Marshal(meta)
		if err := os.WriteFile(m, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	failing.Store(true)
	a := NewBundle(srv.URL, client())
	byName, err := a.EOLStatus(ctx, "Drupal", "9.5.0")
	byCPE, err2 := a.EOLStatusByCPE(ctx, "cpe:2.3:a:other:other:*:*:*:*:*:*:*:*", "1.0")
	for how, u := range map[string]unified.Result{"by name": ToUnified(byName, err), "by CPE": ToUnified(byCPE, err2)} {
		if u.State != unified.StateUnknownProduct || u.Reason != unified.ReasonNotInSource || u.Freshness != unified.FreshnessStale ||
			u.FetchedAt != "" || !strings.Contains(u.Err, "endoflife source failed") {
			t.Errorf("%s: %s / %q / %s / fetched_at %q / error %q — want not_in_source, stale, no time, why in error",
				how, u.State, u.Reason, u.Freshness, u.FetchedAt, u.Err)
		}
	}
}

// A CPE the bundle lists under two products names no one product: sigforge does not guess, and says so — never "the
// source does not list it", for it does. A string naming no vendor and product is a key the bundle does not list.
func TestEOLByCPEThatNamesNoOneProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":[
		  {"name":"twin-a","identifiers":[{"type":"cpe","id":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}],"releases":[{"name":"1","isEol":true}]},
		  {"name":"twin-b","identifiers":[{"type":"cpe","id":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}],"releases":[{"name":"1","isEol":true}]}]}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	u := ToUnified(NewBundle(srv.URL, fetch.New()).EOLStatusByCPE(ctx, "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "1.0"))
	if u.State != unified.StateNotChecked || u.Reason != unified.ReasonNoIdentity || u.Freshness != unified.FreshnessLive ||
		!strings.Contains(u.Err, "more than one product") {
		t.Errorf("CPE two products share = %s / %q / %s, error %q — want not_checked / no_identity, live (the bundle was read), the sharing named",
			u.State, u.Reason, u.Freshness, u.Err)
	}
	u = ToUnified(NewBundle(srv.URL, fetch.New()).EOLStatusByCPE(ctx, "not-a-cpe", "1.0"))
	if u.State != unified.StateUnknownProduct || u.Reason != unified.ReasonNotInSource || strings.Contains(u.Err, "more than one product") {
		t.Errorf("malformed CPE = %s / %q, error %q — want not_in_source", u.State, u.Reason, u.Err)
	}
}
