package takeoverfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// testJSON is the exact upstream schema, served from httptest — no real network.
const testJSON = `[
  {"service":"AWS/S3","cname":["s3.amazonaws.com"],"fingerprint":"The specified bucket does not exist","vulnerable":true,"status":"Vulnerable"},
  {"service":"Ghost","cname":["ghost.io"],"fingerprint":"Site unavailable\\.&#124;Failed to resolve DNS path for this host","vulnerable":true,"status":"Vulnerable"},
  {"service":"AWS/Elastic Beanstalk","cname":["elasticbeanstalk.com"],"fingerprint":"NXDOMAIN","vulnerable":true,"status":"Vulnerable"},
  {"service":"LaunchRock","cname":["launchrock.com"],"fingerprint":"HTTP_STATUS=500","vulnerable":true,"status":"Vulnerable"},
  {"service":"AWS/Load Balancer (ELB)","cname":["elb.amazonaws.com"],"fingerprint":"NXDOMAIN","vulnerable":false,"status":"Not vulnerable"},
  {"service":"Cloudfront","cname":["cloudfront.net"],"fingerprint":"ERROR: The request could not be satisfied","vulnerable":false,"status":"Edge case"}
]`

func serveJSON(t *testing.T, body string) (url string, hits *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

func serve500(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// ---- ParseFingerprints (pure) ----

func TestParseFingerprints(t *testing.T) {
	fps, err := ParseFingerprints([]byte(testJSON))
	if err != nil {
		t.Fatalf("ParseFingerprints: %v", err)
	}
	if len(fps) != 6 {
		t.Fatalf("want 6 entries, got %d", len(fps))
	}
	if fps[0].Service != "AWS/S3" || len(fps[0].CNAMEs) != 1 || !fps[0].Vulnerable {
		t.Fatalf("first entry wrong: %+v", fps[0])
	}
	// vulnerable=true but a negative status → must be downgraded to false.
	for _, fp := range fps {
		if fp.Service == "Cloudfront" && fp.Vulnerable {
			t.Fatal("an Edge case must be treated as NOT exploitable")
		}
	}
}

// ---- Load over httptest (no real network) ----

func TestLoadFromFeed(t *testing.T) {
	url, hits := serveJSON(t, testJSON)
	fps := New(url, fetch.New()).Load(context.Background())
	if len(fps) != 6 {
		t.Fatalf("want 6 entries from the live feed, got %d", len(fps))
	}
	if *hits != 1 {
		t.Fatalf("want exactly 1 fetch, got %d", *hits)
	}
}

// Empty URL (off by default) → the embedded snapshot, no network.
func TestLoadEmptyURLUsesSnapshot(t *testing.T) {
	fps := New("", fetch.New()).Load(context.Background())
	if len(fps) == 0 {
		t.Fatal("empty URL must fall back to the embedded snapshot")
	}
}

// Source down → fail open to the snapshot: a dead source must NOT blind the scan, and
// must NOT be turned into "clean". The table is still usable.
func TestLoadFailOpenToSnapshot(t *testing.T) {
	fps := New(serve500(t), fetch.New()).Load(context.Background())
	if len(fps) == 0 {
		t.Fatal("a dead source must fall back to the embedded snapshot, not go blind")
	}
	var vuln int
	for _, fp := range fps {
		if fp.Vulnerable {
			vuln++
		}
	}
	if vuln == 0 {
		t.Fatal("the embedded snapshot has no vulnerable entry — is data/fingerprints.json broken?")
	}
}

// Junk content (a proxy serving HTML) → the embedded table must still be usable.
func TestLoadGarbageFeedFallsBackToSnapshot(t *testing.T) {
	url, _ := serveJSON(t, "<html>404 not found</html>")
	fps := New(url, fetch.New()).Load(context.Background())
	if len(fps) == 0 {
		t.Fatal("a garbage feed must fall back to the snapshot")
	}
}

// ---- Match (pure, FP-discipline) ----

func fixture(t *testing.T) []FP {
	t.Helper()
	url, _ := serveJSON(t, testJSON)
	return New(url, fetch.New()).Load(context.Background())
}

func TestMatchHitNeedsBothCNAMEAndBody(t *testing.T) {
	fps := fixture(t)
	body := `<?xml version="1.0"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`
	fp, ok := Match(fps, "assets.s3.amazonaws.com.", body)
	if !ok || fp.Service != "AWS/S3" {
		t.Fatalf("must match AWS/S3, got %+v ok=%v", fp, ok)
	}
}

func TestMatchRegexAlternationEntity(t *testing.T) {
	fps := fixture(t)
	// `&#124;` is a | escaped in the upstream JSON — the branch after it must match.
	if _, ok := Match(fps, "blog.ghost.io", "Failed to resolve DNS path for this host"); !ok {
		t.Fatal("the branch after | must match")
	}
	if _, ok := Match(fps, "blog.ghost.io", "site unavailable."); !ok {
		t.Fatal("must match case-insensitively")
	}
}

// THE CLEAN CASE: a REAL site on a provider. CNAME matches but the body is a live page
// → NO report. A non-match here must NOT be read as "clean"; it is simply no evidence.
func TestMatchCleanLiveSiteOnProvider(t *testing.T) {
	fps := fixture(t)
	live := `<!doctype html><html><head><title>Acme Store</title></head><body><h1>Welcome</h1></body></html>`
	if fp, ok := Match(fps, "cdn.s3.amazonaws.com", live); ok {
		t.Fatalf("a live site on S3 must NOT be treated as takeover (wrongly matched %s)", fp.Service)
	}
	// Body matches the signature but the CNAME points elsewhere → the CNAME term is missing.
	if _, ok := Match(fps, "www.example.com", "The specified bucket does not exist"); ok {
		t.Fatal("a body match alone is not enough")
	}
}

func TestMatchRejectsNonBodyFingerprints(t *testing.T) {
	fps := fixture(t)
	// "NXDOMAIN" and "HTTP_STATUS=500" are DNS/status signals, not page content.
	if fp, ok := Match(fps, "app.elasticbeanstalk.com", "what does NXDOMAIN mean?"); ok {
		t.Fatalf("the NXDOMAIN signature must not match via body (%s)", fp.Service)
	}
	if fp, ok := Match(fps, "x.launchrock.com", "HTTP_STATUS=500"); ok {
		t.Fatalf("the HTTP_STATUS signature must not match via body (%s)", fp.Service)
	}
}

func TestMatchNotVulnerableProviderNeverHits(t *testing.T) {
	fps := fixture(t)
	// Cloudfront is an Edge case in the feed → even if the body matches, NO takeover.
	if fp, ok := Match(fps, "d123.cloudfront.net", "ERROR: The request could not be satisfied"); ok {
		t.Fatalf("a non-exploitable provider was still reported (%s)", fp.Service)
	}
}

func TestMatchSuffixNeedsLabelBoundary(t *testing.T) {
	fps := fixture(t)
	body := "The specified bucket does not exist"
	if _, ok := Match(fps, "evils3.amazonaws.com", body); ok {
		t.Fatal("the suffix must match on a label boundary, not a bare HasSuffix")
	}
	if _, ok := Match(fps, "s3.amazonaws.com", body); !ok {
		t.Fatal("an exact suffix match must count as a hit")
	}
}

func TestMatchEmptyInputs(t *testing.T) {
	if _, ok := Match(nil, "x.s3.amazonaws.com", "The specified bucket does not exist"); ok {
		t.Fatal("an empty table must not match")
	}
	fps := fixture(t)
	if _, ok := Match(fps, "", "The specified bucket does not exist"); ok {
		t.Fatal("an empty cname must not match")
	}
	if _, ok := Match(fps, "x.s3.amazonaws.com", ""); ok {
		t.Fatal("an empty body must not match")
	}
}

// ---- Provider (pure, no body, no vulnerable filter) ----

func TestProviderNamesWithoutBody(t *testing.T) {
	fps := fixture(t)
	fp, ok := Provider(fps, "assets.s3.amazonaws.com.")
	if !ok || fp.Service != "AWS/S3" {
		t.Fatalf("want AWS/S3, got %+v ok=%v", fp, ok)
	}
	// Provider does NOT filter vulnerable: an Edge case entry must still be named.
	if fp, ok := Provider(fps, "d123.cloudfront.net"); !ok || fp.Service != "Cloudfront" {
		t.Fatalf("want Cloudfront, got %+v ok=%v", fp, ok)
	}
	if _, ok := Provider(fps, "www.example.com"); ok {
		t.Fatal("a CNAME outside the table must not be identified")
	}
	if _, ok := Provider(fps, ""); ok {
		t.Fatal("an empty cname must not be identified")
	}
}

// The embedded snapshot must work with real data AND not falsely report a live page.
func TestMatchAgainstEmbeddedSnapshot(t *testing.T) {
	fps := New(serve500(t), fetch.New()).Load(context.Background()) // forces the snapshot
	if fp, ok := Match(fps, "shop.bitbucket.io", "Repository not found"); !ok || fp.Service == "" {
		t.Fatalf("the real snapshot must catch the dangling Bitbucket, ok=%v", ok)
	}
	if fp, ok := Match(fps, "shop.bitbucket.io",
		`<!doctype html><html><body>Project page is active</body></html>`); ok {
		t.Fatalf("a live page was wrongly reported as %s", fp.Service)
	}
}
