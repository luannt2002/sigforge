package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	if st != StateVerified || cpe != "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*" {
		t.Fatalf("snapshot resolve wrong: cpe=%q state=%v", cpe, st)
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
	// ...but a tech the public-domain sample DOES know still resolves (fail-open).
	if cpe, _, st := r.ResolveCPE(context.Background(), "nginx", "", ""); st != StateVerified || cpe == "" {
		t.Fatalf("dead dict must fall back to snapshot for a known tech, got cpe=%q state=%v", cpe, st)
	}
}

// A live dict serving junk (a proxy injecting HTML) falls back to the snapshot, no panic.
func TestResolveCPEGarbageDictFallsBack(t *testing.T) {
	r := New(serveJSON(t, "<html>Access Denied</html>"), fetch.New())
	cpe, _, st := r.ResolveCPE(context.Background(), "nginx", "", "")
	if st != StateVerified || cpe == "" {
		t.Fatalf("garbage dict must fall back to the snapshot, got cpe=%q state=%v", cpe, st)
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
