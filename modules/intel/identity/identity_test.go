package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// dictTestJSON is the real NVD 2.0 CPE API shape: products[] each wrapping a cpe object
// with cpeName + titles. It carries two versioned rows for nginx (must collapse to one
// base), a deprecated row (must be skipped), and a malformed cpeName (must be skipped).
const dictTestJSON = `{
  "resultsPerPage": 5, "startIndex": 0, "totalResults": 5, "format": "NVD_CPE", "version": "2.0",
  "products": [
    {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:nginx:nginx:1.21.0:*:*:*:*:*:*:*", "titles": [{"title": "nginx", "lang": "en"}]}},
    {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*", "titles": [{"title": "nginx", "lang": "en"}]}},
    {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*", "titles": [{"title": "Apache HTTP Server 2.4.57", "lang": "en"}]}},
    {"cpe": {"deprecated": true,  "cpeName": "cpe:2.3:a:nginx:nginx_legacy:0.1:*:*:*:*:*:*:*", "titles": [{"title": "deprecated row", "lang": "en"}]}},
    {"cpe": {"deprecated": false, "cpeName": "not a cpe string", "titles": [{"title": "junk", "lang": "en"}]}}
  ]
}`

// ambiguousDictJSON has two DIFFERENT vendors sharing the product token "widget": a
// product-only query must refuse to guess which one and return Unknown.
const ambiguousDictJSON = `{
  "products": [
    {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "titles": [{"title": "Acme Widget", "lang": "en"}]}},
    {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:globex:widget:2.0:*:*:*:*:*:*:*", "titles": [{"title": "Globex Widget", "lang": "en"}]}}
  ]
}`

// vendorTwoProductsJSON has one vendor owning two products: a vendor-only query must refuse to
// pick which product and return Unknown.
const vendorTwoProductsJSON = `{
  "products": [
    {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "titles": [{"title": "Acme Widget", "lang": "en"}]}},
    {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:acme:gadget:1.0:*:*:*:*:*:*:*", "titles": [{"title": "Acme Gadget", "lang": "en"}]}}
  ]
}`

func serveJSON(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func serve500(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func mustParse(t *testing.T, body string) []Entry {
	t.Helper()
	e, err := ParseDict([]byte(body))
	if err != nil {
		t.Fatalf("ParseDict: %v", err)
	}
	return e
}

// ---- ParseDict (pure): collapse versions, skip deprecated + malformed ----

func TestParseDict(t *testing.T) {
	e := mustParse(t, dictTestJSON)
	// 5 rows → nginx (two versions collapse to one), apache; deprecated + malformed dropped.
	if len(e) != 2 {
		t.Fatalf("want 2 base entries, got %d: %+v", len(e), e)
	}
	var nginx, apache *Entry
	for i := range e {
		switch e[i].Product {
		case "nginx":
			nginx = &e[i]
		case "http_server":
			apache = &e[i]
		}
	}
	if nginx == nil || nginx.CPE != "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*" {
		t.Fatalf("nginx base wrong: %+v", nginx)
	}
	if apache == nil || apache.Vendor != "apache" || apache.Title != "Apache HTTP Server 2.4.57" {
		t.Fatalf("apache parsed wrong: %+v", apache)
	}
}

// ---- Match (pure table) ----

func TestMatchByName(t *testing.T) {
	cpe, ev, st := Match(mustParse(t, dictTestJSON), "nginx", "", "")
	if st != StateVerified || cpe != "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*" {
		t.Fatalf("nginx by name: cpe=%q state=%v", cpe, st)
	}
	if !strings.Contains(ev, "nginx") {
		t.Fatalf("evidence must cite the dict title, got %q", ev)
	}
}

func TestMatchByFullName(t *testing.T) {
	// "Apache HTTP Server" → normalized "apache http server" == vendor+product words.
	cpe, _, st := Match(mustParse(t, dictTestJSON), "Apache HTTP Server", "", "")
	if st != StateVerified || cpe != "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" {
		t.Fatalf("apache by full name: cpe=%q state=%v", cpe, st)
	}
}

func TestMatchByVendorProduct(t *testing.T) {
	cpe, _, st := Match(mustParse(t, dictTestJSON), "", "apache", "http_server")
	if st != StateVerified || cpe != "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" {
		t.Fatalf("apache by vendor/product: cpe=%q state=%v", cpe, st)
	}
}

// The core honest contract (and the mutant target): a tech the dictionary does not know
// must return Unknown with an EMPTY cpe — never a CPE fabricated from the inputs.
func TestMatchUnknownTechNeverFabricates(t *testing.T) {
	cpe, ev, st := Match(mustParse(t, dictTestJSON), "totally-made-up-tech-xyz", "madeupvendor", "madeupproduct")
	if st != StateUnknown {
		t.Fatalf("unknown tech must be Unknown, got %v", st)
	}
	if cpe != "" {
		t.Fatalf("unknown tech must yield NO cpe (no guessing), got %q", cpe)
	}
	if ev != "" {
		t.Fatalf("unknown tech must yield no evidence, got %q", ev)
	}
}

// Vendor alone resolves ONLY when that vendor owns exactly one product base; two products under
// the same vendor is ambiguous → Unknown (the >1 path, reached via vendor rather than product).
func TestMatchByVendorOnly(t *testing.T) {
	cpe, _, st := Match(mustParse(t, dictTestJSON), "", "apache", "")
	if st != StateVerified || cpe != "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" {
		t.Fatalf("vendor-only single-product match: cpe=%q state=%v", cpe, st)
	}
	if cpe, _, st := Match(mustParse(t, vendorTwoProductsJSON), "", "acme", ""); st != StateUnknown || cpe != "" {
		t.Fatalf("vendor owning two products must be Unknown, got cpe=%q state=%v", cpe, st)
	}
}

// An ambiguous query (one product token, two vendors) must refuse to pick → Unknown.
func TestMatchAmbiguousIsUnknown(t *testing.T) {
	cpe, _, st := Match(mustParse(t, ambiguousDictJSON), "", "", "widget")
	if st != StateUnknown || cpe != "" {
		t.Fatalf("ambiguous match must be Unknown with no cpe, got cpe=%q state=%v", cpe, st)
	}
}

func TestMatchEmptyQuery(t *testing.T) {
	if cpe, _, st := Match(mustParse(t, dictTestJSON), "", "", ""); st != StateUnknown || cpe != "" {
		t.Fatalf("empty query must be Unknown with no cpe, got cpe=%q state=%v", cpe, st)
	}
}

func TestStateString(t *testing.T) {
	if StateVerified.String() != "Verified" || StateUnknown.String() != "Unknown" {
		t.Fatalf("State.String wrong: %q %q", StateVerified, StateUnknown)
	}
}

// ---- ResolveCPE over httptest (no real network) ----

func TestResolveCPELiveDict(t *testing.T) {
	r := New(serveJSON(t, dictTestJSON), fetch.New())
	cpe, _, st := r.ResolveCPE(context.Background(), "", "apache", "http_server")
	if st != StateVerified || cpe != "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" {
		t.Fatalf("live dict resolve wrong: cpe=%q state=%v", cpe, st)
	}
}

// Dict off (empty URL) → the embedded public-domain sample still resolves a known tech.
func TestResolveCPEDictOffUsesSnapshot(t *testing.T) {
	r := New("", fetch.New())
	cpe, _, st := r.ResolveCPE(context.Background(), "nginx", "", "")
	if st == StateVerified || r.Status(context.Background()).Source != "snapshot" {
		t.Fatalf("dict off: the snapshot is in use but never verifies, got cpe=%q state=%v", cpe, st)
	}
}

// Dict DOWN + an unknown tech → fail-open to the snapshot, which also does not know it
// → Unknown with no cpe. Absence is never turned into a fabricated CPE.
func TestResolveCPEFailOpenUnknownStaysUnknown(t *testing.T) {
	r := New(serve500(t), fetch.New())
	cpe, _, st := r.ResolveCPE(context.Background(), "totally-made-up-tech-xyz", "", "")
	if st != StateUnknown || cpe != "" {
		t.Fatalf("dead dict + unknown tech must be Unknown with no cpe, got cpe=%q state=%v", cpe, st)
	}
	// ...and a tech the sample knows is not verified by it either: the sample is not the dictionary.
	if cpe, _, st := r.ResolveCPE(context.Background(), "nginx", "", ""); st == StateVerified || r.Status(context.Background()).Source != "snapshot" {
		t.Fatalf("dead dict falls back to the snapshot, which never verifies, got cpe=%q state=%v", cpe, st)
	}
}

// A live dict serving junk (a proxy injecting HTML) falls back to the snapshot, no panic.
func TestResolveCPEGarbageDictFallsBack(t *testing.T) {
	r := New(serveJSON(t, "<html>Access Denied</html>"), fetch.New())
	cpe, _, st := r.ResolveCPE(context.Background(), "nginx", "", "")
	if st == StateVerified || r.Status(context.Background()).Source != "snapshot" {
		t.Fatalf("garbage dict falls back to the snapshot, which never verifies, got cpe=%q state=%v", cpe, st)
	}
}

// enrich resolves once per detection, so the dictionary must be fetched once per
// Resolver — not once per ResolveCPE call.
func TestResolveCPELoadsDictOnce(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(dictTestJSON))
	}))
	t.Cleanup(srv.Close)
	r := New(srv.URL, fetch.New())
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.ResolveCPE(context.Background(), "nginx", "", "")
		}()
	}
	wg.Wait()
	if n := hits.Load(); n != 1 {
		t.Fatalf("5 resolves must fetch the dictionary once, fetched %d times", n)
	}
}

// Status must say which dictionary is in use, so a configured live dictionary that
// failed — or served only one page of the paged NVD API — is never silent.
func TestStatus(t *testing.T) {
	onePage := `{"resultsPerPage": 2, "startIndex": 0, "totalResults": 1000, "products": [
	  {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:nginx:nginx:1.21.0:*:*:*:*:*:*:*", "titles": [{"title": "nginx", "lang": "en"}]}},
	  {"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*", "titles": [{"title": "Apache HTTP Server", "lang": "en"}]}}
	]}`
	cases := []struct {
		name        string
		url         string
		wantSource  string
		wantErr     string // substring; "" means Err must be empty
		wantPartial bool
	}{
		{"no URL uses the sample, nothing failed", "", "snapshot", "", false},
		{"live dictionary in use", serveJSON(t, dictTestJSON), "live", "", false},
		{"live down falls back and says why", serve500(t), "snapshot", "500", false},
		{"live junk falls back and says why", serveJSON(t, "<html>Access Denied</html>"), "snapshot", "unparseable", false},
		{"live with no usable entries falls back and says why", serveJSON(t, `{"products": []}`), "snapshot", "no usable", false},
		{"one page of a paged feed is reported partial", serveJSON(t, onePage), "live", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New(c.url, fetch.New()).Status(context.Background())
			if s.Source != c.wantSource || s.Partial() != c.wantPartial || s.Entries == 0 {
				t.Fatalf("got %+v (partial=%v), want source=%s partial=%v and entries>0", s, s.Partial(), c.wantSource, c.wantPartial)
			}
			if c.wantErr == "" && s.Err != "" || c.wantErr != "" && !strings.Contains(s.Err, c.wantErr) {
				t.Fatalf("Err = %q, want it to contain %q", s.Err, c.wantErr)
			}
		})
	}
}

// The embedded sample must be non-empty and well-formed, or the air-gap path is a lie.
func TestEmbeddedSnapshotUsable(t *testing.T) {
	e, err := ParseDict(cpeSnapshot)
	if err != nil {
		t.Fatalf("snapshot parse: %v", err)
	}
	if len(e) == 0 {
		t.Fatal("embedded snapshot is empty — is data/cpe-dict-snapshot.json broken?")
	}
}

// A dictionary synced into the local store (within MaxAge) costs no request, and Status
// says it is the cached copy.
func TestDictFromSyncedStoreIsCached(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(dictTestJSON))
	}))
	t.Cleanup(srv.Close)
	c := fetch.New()
	c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
	s1 := New(srv.URL, c).Status(context.Background())
	s2 := New(srv.URL, c).Status(context.Background())
	if hits.Load() != 1 || s1.Cached || !s2.Cached || s2.Entries != s1.Entries {
		t.Fatalf("the second run must reuse the synced dictionary (cached) with no request: hits=%d %+v / %+v", hits.Load(), s1, s2)
	}
}

// The source fails but a synced dictionary is in the store: identity uses it (2 bases,
// not the embedded sample) and Status names the failure.
func TestDictStaleCopyWhenSourceFails(t *testing.T) {
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(dictTestJSON))
	}))
	t.Cleanup(srv.Close)
	c := fetch.New()
	c.CacheDir = t.TempDir()
	New(srv.URL, c).Status(context.Background())
	down.Store(true)
	s := New(srv.URL, c).Status(context.Background())
	if s.Source != "live" || !s.Cached || !strings.Contains(s.Err, "503") || s.Entries != 2 {
		t.Fatalf("want the stored dictionary with the failure named, got %+v", s)
	}
}

// The embedded sample is a handful of CPE bases, not the dictionary: it never verifies an
// identity, so a curated CPE is not displaced by a sample match.
func TestEmbeddedSampleNeverVerifies(t *testing.T) {
	if cpe, _, st := New("", fetch.New()).ResolveCPE(context.Background(), "Nginx", "", ""); st == StateVerified {
		t.Fatalf("the embedded sample verified %q", cpe)
	}
}
