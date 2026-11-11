package jslib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// identifyRepo is a repository in the Retire.js shape with its extractors — the fingerprint half:
// patterns over a script's URL, its file name and its content, the version marked §§version§§.
// "bad" carries a pattern Go cannot compile (a look-ahead); it is skipped, the rest still work.
const identifyRepo = `{
 "jquery": {"vulnerabilities": [{"below": "3.5.0", "severity": "medium", "identifiers": {"CVE": ["CVE-2020-11022"]}}],
  "extractors": {"uri": ["/(§§version§§)/jquery(\\.min)?\\.js"], "filename": ["jquery-(§§version§§)(\\.min)?\\.js"],
   "filecontent": ["/\\*!? jQuery v(§§version§§)"]}},
 "moment.js": {"vulnerabilities": [], "extractors": {"filecontent": ["//! moment\\.js(?:[\\s\\S]{0,200}?)version : (§§version§§)"]}},
 "bad": {"vulnerabilities": [], "extractors": {"filename": ["bad-(?=x)(§§version§§)\\.js"]}}
}`

// The repository's own extractors recognise a library — and its version — from a script's URL,
// its file name or its content, each library once; ".min" is not part of a version. They come with
// the data, so what is recognised grows with the repository, and the repository is fetched once.
func TestIdentifyUsesTheRepositoryExtractors(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(identifyRepo))
	}))
	defer srv.Close()
	a := New(srv.URL, fetch.New())
	ctx := context.Background()
	for _, tc := range []struct {
		url, content string
		want         []Found
	}{
		{"https://cdn.example/ajax/libs/jquery/1.8.0/jquery.min.js", "", []Found{{"jquery", "1.8.0", "uri"}}},
		{"https://x.example/static/jquery-1.12.4.min.js", "", []Found{{"jquery", "1.12.4", "filename"}}},
		{"https://cdn.example/1.8.0/jquery-1.8.0.min.js", "/*! jQuery v1.8.0 */", []Found{{"jquery", "1.8.0", "filename"}}}, // shown by name and by content, named once
		{"https://x.example/app.js", "/*! jQuery v3.4.1 | (c) */\n//! moment.js\n//! version : 2.29.1\n", []Found{{"jquery", "3.4.1", "filecontent"}, {"moment.js", "2.29.1", "filecontent"}}},
		{"https://x.example/bad-1.0.js", "", nil},
		{"https://x.example/app.js", "", nil},
	} {
		if got := a.Identify(ctx, tc.url, tc.content); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Identify(%q) = %+v, want %+v", tc.url, got, tc.want)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("the repository must be fetched once for every lookup, got %d", hits.Load())
	}
	if r := a.LookupOne(ctx, "jquery", "1.8.0"); len(r.Vulns) != 1 {
		t.Fatalf("the identified library resolves as before: %+v", r)
	}
}
