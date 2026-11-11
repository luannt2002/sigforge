package lifecycle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// now is a fixed clock so "past" and "future" eol dates are deterministic.
var now = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

// phpFeed is a trimmed real-shape endoflife.date php feed: eol as date strings.
const phpFeed = `[
  {"cycle":"8.3","eol":"2027-12-31","latest":"8.3.0"},
  {"cycle":"8.0","eol":"2023-11-26","latest":"8.0.30"},
  {"cycle":"7.2","eol":"2020-11-30","latest":"7.2.34"}
]`

// nginxFeed uses the bool form of eol (current cycles never expire in the feed).
const nginxFeed = `[
  {"cycle":"1.31","eol":false,"latest":"1.31.8"},
  {"cycle":"1.29","eol":"2026-05-13","latest":"1.29.8"}
]`

func TestClassify(t *testing.T) {
	php, _ := ParseCycles([]byte(phpFeed))
	nginx, _ := ParseCycles([]byte(nginxFeed))

	tests := []struct {
		name      string
		cycles    []Cycle
		version   string
		wantCycle string
		wantEOL   string
		wantState State
	}{
		{"php-7.2-patch-is-eol", php, "7.2.34", "7.2", "2020-11-30", StateEOL},
		{"php-8.3-is-supported", php, "8.3.1", "8.3", "2027-12-31", StateSupported},
		{"php-8.0-past-date-is-eol", php, "8.0.30", "8.0", "2023-11-26", StateEOL},
		{"php-exact-cycle", php, "7.2", "7.2", "2020-11-30", StateEOL},
		{"php-v-prefix-stripped", php, "v7.2.1", "7.2", "2020-11-30", StateEOL},
		{"php-unknown-cycle", php, "9.9.9", "", "", StateUnknown},
		{"nginx-bool-false-supported", nginx, "1.31.8", "1.31", "false", StateSupported},
		{"nginx-past-date-eol", nginx, "1.29.0", "1.29", "2026-05-13", StateEOL},
		{"empty-version", php, "", "", "", StateUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCycle, gotEOL, gotState := Classify(tt.cycles, tt.version, now)
			if gotCycle != tt.wantCycle || gotEOL != tt.wantEOL || gotState != tt.wantState {
				t.Errorf("Classify(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.version, gotCycle, gotEOL, gotState, tt.wantCycle, tt.wantEOL, tt.wantState)
			}
		})
	}
}

func TestClassifyUninterpretableEOLIsUnknown(t *testing.T) {
	cycles, _ := ParseCycles([]byte(`[{"cycle":"1.0","eol":"garbage"}]`))
	if _, _, state := Classify(cycles, "1.0.0", now); state != StateUnknown {
		t.Errorf("garbage eol should be StateUnknown, got %v", state)
	}
}

func TestProductFor(t *testing.T) {
	if p, ok := ProductFor("PHP"); !ok || p != "php" {
		t.Errorf("ProductFor(PHP) = %q,%v want php,true", p, ok)
	}
	if _, ok := ProductFor("Cloudflare"); ok {
		t.Errorf("Cloudflare is not endoflife-tracked; ProductFor should be false")
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{StateUnknown: "unknown", StateSupported: "supported", StateEOL: "eol"} {
		if s.String() != want {
			t.Errorf("State(%d).String() = %q, want %q", s, s.String(), want)
		}
	}
}

func TestEOLStatusUnknownProduct(t *testing.T) {
	a := New("", fetch.New())
	st, err := a.EOLStatus(context.Background(), "Cloudflare", "1.0")
	if err != nil {
		t.Fatalf("unknown product should not error: %v", err)
	}
	if st.IsEOL != StateUnknown || st.Product != "" {
		t.Errorf("unknown product → %+v, want empty product + StateUnknown", st)
	}
}

func TestEOLStatusFeedOffErrors(t *testing.T) {
	a := New("", fetch.New())
	st, err := a.EOLStatus(context.Background(), "PHP", "7.2")
	if err == nil {
		t.Fatal("feed off (no base URL) for a known product should error")
	}
	if st.IsEOL != StateUnknown {
		t.Errorf("feed off must stay StateUnknown, never supported; got %v", st.IsEOL)
	}
}

// Adapter wiring over httptest loopback (no internet), matching how the repo's
// fetch adapters are tested. The feed base URL is operator-supplied here.
func TestEOLStatusOverLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/php.json" {
			w.Write([]byte(phpFeed))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a := New(srv.URL, fetch.New())
	st, err := a.EOLStatus(context.Background(), "PHP", "7.2.34")
	if err != nil {
		t.Fatalf("EOLStatus: %v", err)
	}
	if st.Product != "php" || st.Cycle != "7.2" || st.IsEOL != StateEOL {
		t.Errorf("PHP 7.2.34 → %+v, want product=php cycle=7.2 eol", st)
	}
}

// bundleJSON is the endoflife API v1 bundle shape (products/full): a release name is the
// cycle, eolFrom (a date) — or isEol when there is no date — is the eol value.
const bundleJSON = `{"schema_version":"1.2.1","total":2,"result":[
  {"name":"php","releases":[
    {"name":"8.5","isEol":false,"eolFrom":"2029-12-31","latest":{"name":"8.5.12"}},
    {"name":"7.4","isEol":true,"eolFrom":"2022-11-28","latest":{"name":"7.4.33"}}]},
  {"name":"nginx","releases":[
    {"name":"1.31","isEol":false,"eolFrom":null,"latest":{"name":"1.31.8"}},
    {"name":"1.18","isEol":true,"eolFrom":null,"latest":null}]}]}`

// The bundle must classify exactly like the per-product API it replaces.
func TestParseBundleClassifiesLikePerProduct(t *testing.T) {
	perProduct := map[string]string{
		"php":   `[{"cycle":"8.5","eol":"2029-12-31","latest":"8.5.12"},{"cycle":"7.4","eol":"2022-11-28","latest":"7.4.33"}]`,
		"nginx": `[{"cycle":"1.31","eol":false,"latest":"1.31.8"},{"cycle":"1.18","eol":true}]`,
	}
	got, err := ParseBundle([]byte(bundleJSON))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	for product, v0 := range perProduct {
		want, err := ParseCycles([]byte(v0))
		if err != nil {
			t.Fatal(err)
		}
		for _, ver := range []string{"8.5.3", "7.4.33", "1.31.2", "1.18.0", "9.9"} {
			c1, d1, s1 := Classify(got[product], ver, now)
			c2, d2, s2 := Classify(want, ver, now)
			if c1 != c2 || d1 != d2 || s1 != s2 {
				t.Errorf("%s %s: bundle → (%q,%q,%v), per-product → (%q,%q,%v)", product, ver, c1, d1, s1, c2, d2, s2)
			}
		}
	}
}

// With a bundle URL every product's cycles arrive in ONE request per Adapter, not one
// per detected tech.
func TestBundleLoadsOnce(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(bundleJSON))
	}))
	defer srv.Close()
	a := NewBundle(srv.URL, fetch.New())
	for _, tech := range []string{"PHP", "Nginx", "PHP"} {
		if _, err := a.EOLStatus(context.Background(), tech, "7.4.3"); err != nil {
			t.Fatal(err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("3 lookups must fetch the bundle once, fetched %d times", n)
	}
	st, _ := a.EOLStatus(context.Background(), "PHP", "7.4.3")
	if st.Cycle != "7.4" || st.IsEOL != StateEOL || st.FetchedAt.IsZero() {
		t.Fatalf("PHP 7.4.3 = %+v, want cycle 7.4, EOL, with a fetch time", st)
	}
}

// A failed bundle fails every lookup honestly without falling back to one request per
// product; a mapped product absent from the bundle is reported as not tracked.
func TestBundleFailureAndAbsentProduct(t *testing.T) {
	var hits atomic.Int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer down.Close()
	a := NewBundle(down.URL, fetch.New())
	for _, tech := range []string{"PHP", "Nginx"} {
		if _, err := a.EOLStatus(context.Background(), tech, "7.4.3"); err == nil {
			t.Fatalf("%s: a failed bundle must surface an error, not a verdict", tech)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("a failed bundle must not be retried per product, got %d requests", n)
	}
	onlyPHP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"name":"php","releases":[{"name":"7.4","isEol":true,"eolFrom":"2022-11-28"}]}]}`))
	}))
	defer onlyPHP.Close()
	st, err := NewBundle(onlyPHP.URL, fetch.New()).EOLStatus(context.Background(), "Nginx", "1.18.0")
	if err != nil || st.Product != "" || st.IsEOL != StateUnknown {
		t.Fatalf("a product absent from the bundle must be untracked (unknown product), got %+v %v", st, err)
	}
}

// A bundle synced into the local store (within MaxAge) costs no request and its verdicts
// are labelled a snapshot of the sync time — never live.
func TestBundleFromSyncedStoreIsSnapshot(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(bundleJSON))
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
	st1, err1 := NewBundle(srv.URL, c).EOLStatus(context.Background(), "PHP", "7.4.3")
	st2, err2 := NewBundle(srv.URL, c).EOLStatus(context.Background(), "PHP", "7.4.3")
	u1, u2 := ToUnified(st1, err1), ToUnified(st2, err2)
	if u1.Freshness != unified.FreshnessLive {
		t.Fatalf("the first run fetched the bundle: want live, got %v", u1.Freshness)
	}
	if hits.Load() != 1 || u2.Freshness != unified.FreshnessSnapshot || u2.FetchedAt == "" || u2.State != u1.State {
		t.Fatalf("the second run must reuse the synced bundle as a dated snapshot with no request: hits=%d %+v", hits.Load(), u2)
	}
}

// The source fails but a synced bundle is in the store: verdicts come from it, labelled
// stale with a note — not a blanket source_unavailable.
func TestBundleStaleCopyWhenSourceFails(t *testing.T) {
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(bundleJSON))
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	if _, err := NewBundle(srv.URL, c).EOLStatus(context.Background(), "PHP", "7.4.3"); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	st, err := NewBundle(srv.URL, c).EOLStatus(context.Background(), "PHP", "7.4.3")
	u := ToUnified(st, err)
	if err != nil || u.State != unified.StateAffectedByAdvisory || u.Freshness != unified.FreshnessStale || !strings.Contains(u.Err, "stale") {
		t.Fatalf("want the stored bundle's verdict, stale, with a note: %+v %v", u, err)
	}
}

// With the bundle, a product is found by CPE — every product the bundle lists by CPE is
// covered, not only the hand-kept name map. A CPE two products share stays unknown (no
// guess), and the per-product feed, which has no identifiers, always answers unknown.
func TestEOLStatusByCPE(t *testing.T) {
	bundle := `{"result":[
	  {"name":"caddy","identifiers":[{"type":"cpe","id":"cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*"}],
	   "releases":[{"name":"2","isEol":false,"eolFrom":null}]},
	  {"name":"twin-a","identifiers":[{"type":"cpe","id":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}],"releases":[{"name":"1","isEol":true}]},
	  {"name":"twin-b","identifiers":[{"type":"cpe","id":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}],"releases":[{"name":"1","isEol":true}]}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(bundle)) }))
	defer srv.Close()
	ctx := context.Background()
	a := NewBundle(srv.URL, fetch.New())
	st, err := a.EOLStatusByCPE(ctx, "cpe:2.3:a:caddyserver:caddy:2.6.0:*:*:*:*:*:*:*", "2.6.0")
	if err != nil || st.Product != "caddy" || st.Cycle != "2" || st.IsEOL != StateSupported {
		t.Fatalf("caddy 2.6.0 by CPE = %+v %v, want product caddy, cycle 2, supported", st, err)
	}
	if amb, _ := a.EOLStatusByCPE(ctx, "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "1.0"); amb.Product != "" {
		t.Fatalf("a CPE two products share must stay unknown, got %+v", amb)
	}
	if per, _ := New("http://unused.invalid", fetch.New()).EOLStatusByCPE(ctx, "cpe:2.3:a:caddyserver:caddy:2.6.0:*:*:*:*:*:*:*", "2.6.0"); per.Product != "" {
		t.Fatalf("the per-product feed has no CPE identifiers and must answer unknown, got %+v", per)
	}
}

// Shapes seen in the live feed (06/11/2026): a coarse line with LTS sub-lines (jenkins "2"
// supported, "2.346" EOL), a coarse line with backport sub-lines (log4j), and an EOL line
// with one supported sub-line (dotnetfx "4.6" EOL, "4.6.2" supported). Values are made up.
const coarseFeed = `[
  {"cycle":"2","eol":false},
  {"cycle":"2.568","eol":false},
  {"cycle":"2.346","eol":"2022-09-07"},
  {"cycle":"4.6","eol":"2022-04-26"},
  {"cycle":"4.6.2","eol":false},
  {"cycle":"7.0","eol":false},
  {"cycle":"7.0","eol":"2024-01-01"},
  {"cycle":"8.0","eol":"2024-01-01"},
  {"cycle":"8.0","eol":"2024-02-01"}
]`

func TestClassifyPicksTheMostSpecificCycle(t *testing.T) {
	cycles, _ := ParseCycles([]byte(coarseFeed))
	tests := []struct {
		version, wantCycle string
		wantState          State
	}{
		{"2.346.1", "2.346", StateEOL},       // the coarse "2" listed first must not hide the LTS line
		{"2.568.1", "2.568", StateSupported}, // a leaf line answers for itself
		{"2.350", "2", StateUnknown},         // a supported line with sub-lines does not vouch for the rest
		{"4.6.1", "4.6", StateEOL},           // an ended line still ends what its sub-lines do not cover
		{"4.6.2.1", "4.6.2", StateSupported},
		{"7.0.1", "", StateUnknown}, // one cycle listed twice with opposite verdicts
		{"8.0.1", "8.0", StateEOL},  // listed twice but both ended: no conflict
	}
	for _, tt := range tests {
		if c, _, s := Classify(cycles, tt.version, now); c != tt.wantCycle || s != tt.wantState {
			t.Errorf("Classify(%q) = (%q, %v), want (%q, %v)", tt.version, c, s, tt.wantCycle, tt.wantState)
		}
	}
}

func TestParseBundleWithoutAnEOLVerdictIsUnknown(t *testing.T) {
	bundle, err := ParseBundle([]byte(`{"result":[{"name":"nginx","releases":[
	  {"name":"1.18"},{"name":"1.20","isEol":null,"eolFrom":null},{"name":"1.22","isEol":false}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for v, want := range map[string]State{"1.18.0": StateUnknown, "1.20.1": StateUnknown, "1.22.1": StateSupported} {
		if _, _, s := Classify(bundle["nginx"], v, now); s != want {
			t.Errorf("%s: %v, want %v — a release that states no verdict is not supported", v, s, want)
		}
	}
}

// A cycle row that cannot be read — null, nameless — could be the sub-line the version
// belongs to, so a supported verdict beside it is unknown; a row named " 1.18" or "v1.18"
// is read as 1.18.
func TestUnreadableOrOddCycleRowsNeverClear(t *testing.T) {
	for name, feed := range map[string]string{
		"null row":     `[{"cycle":"1","eol":false},null]`,
		"nameless row": `[{"cycle":"1","eol":false},{"eol":"2021-01-01"}]`,
	} {
		cycles, _ := ParseCycles([]byte(feed))
		if _, _, s := Classify(cycles, "1.20.0", now); s != StateUnknown {
			t.Errorf("%s: %v, want unknown", name, s)
		}
	}
	for _, sub := range []string{" 1.18", "v1.18", "1.18 "} {
		cycles, _ := ParseCycles([]byte(`[{"cycle":"1","eol":false},{"cycle":"` + sub + `","eol":"2021-01-01"}]`))
		if c, _, s := Classify(cycles, "1.18.0", now); s != StateEOL || c != "1.18" {
			t.Errorf("sub-cycle %q: (%q, %v), want (1.18, eol)", sub, c, s)
		}
	}
}

func TestParseBundleLeansToEnded(t *testing.T) {
	bundle, err := ParseBundle([]byte(`{"result":[
	  {"name":"a","releases":[{"name":"1.0","isEol":true,"eolFrom":"2099-01-01"},{"name":"2.0","isEol":false,"eolFrom":"2001-01-01"},{"name":"3.0","isEol":true,"eolFrom":"2001-01-01"}]},
	  {"name":"b","releases":[{"name":"1.0","isEol":true,"eolFrom":"2001-01-01"}]},
	  {"name":"b","releases":[{"name":"1.0","isEol":false}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		product, version, wantEOL string
		want                      State
	}{
		{"a", "1.0.1", "true", StateEOL},       // the feed says ended: a future date does not reopen it
		{"a", "2.0.1", "2001-01-01", StateEOL}, // a date already past ends it
		{"a", "3.0.1", "2001-01-01", StateEOL}, // both agree: the date is kept
		{"b", "1.0.1", "", StateUnknown},       // listed twice with opposite verdicts
	} {
		if _, eol, s := Classify(bundle[tt.product], tt.version, now); s != tt.want || eol != tt.wantEOL {
			t.Errorf("%s %s: (%q, %v), want (%q, %v)", tt.product, tt.version, eol, s, tt.wantEOL, tt.want)
		}
	}
}

// A technology name maps to its product whatever its case: "nginx" on a command line is Nginx.
func TestProductForIgnoresCase(t *testing.T) {
	for _, name := range []string{"Nginx", "nginx", "NGINX", " nginx "} {
		if p, ok := ProductFor(name); !ok || p != "nginx" {
			t.Errorf("ProductFor(%q) = %q, %v", name, p, ok)
		}
	}
}
