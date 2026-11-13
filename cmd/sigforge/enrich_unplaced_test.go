package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/jslib"
)

// The text enrich prints names why a lead may not apply right under it — an advisory the version could not be
// placed against, beside one it matched — and a result whose leads carry no note prints as it always has.
func TestEnrichTextPrintsALeadsNote(t *testing.T) {
	const (
		m = `{"below":"2.0.0","identifiers":{"CVE":["CVE-2099-0001"]}}`
		u = `{"below":"@@@","identifiers":{"CVE":["CVE-2099-0002"]}}`
	)
	for _, tc := range []struct{ row, feed, want string }{
		{"T1", m, "[jslib] fakelib 1.5.0 → affected_by_advisory  source=jslib freshness=live\n" +
			"    lead CVE-2099-0001    -        cvss=- epss=- kev=false\n" +
			"looked up 1/1 · concluded 1/1 · not concluded 0 (not_checked 0, source_unavailable 0, unknown_product 0, unknown_version 0) — not concluded is not clean\n"},
		{"T4", m + "," + u, "[jslib] fakelib 1.5.0 → affected_by_advisory  source=jslib freshness=live\n" +
			"    lead CVE-2099-0001    -        cvss=- epss=- kev=false\n" +
			"    lead CVE-2099-0002    -        cvss=- epss=- kev=false\n" +
			"      note: the version could not be placed against this advisory's bounds under the npm order: whether it applies is unknown\n" +
			"looked up 1/1 · concluded 1/1 · not concluded 0 (not_checked 0, source_unavailable 0, unknown_product 0, unknown_version 0) — not concluded is not clean\n"},
	} {
		t.Run(tc.row, func(t *testing.T) {
			offline(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"fakelib":{"vulnerabilities":[` + tc.feed + `]}}`))
			}))
			defer srv.Close()
			t.Setenv(jslib.EnvRetireJSURL, srv.URL)
			null, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer null.Close()
			stdin := os.Stdin
			os.Stdin = null
			defer func() { os.Stdin = stdin }()
			out := captureStdout(t, func() { err = cmdEnrich([]string{"--jslib", "fakelib@1.5.0"}) })
			if err != nil || out != tc.want {
				t.Fatalf("err=%v\ngot:\n%s\nwant:\n%s", err, out, tc.want)
			}
		})
	}
}
