package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/osv"
)

// enrich ends with a tally that keeps looked up apart from concluded: a package the source does not list
// and a miss in its whole data were looked up yet concluded nothing, while an off or failed source looked
// nothing up — none of them is clean.
func TestEnrichTallyCountsLookedUpApartFromConcluded(t *testing.T) {
	offline(t)
	dump := osvDump(map[string]string{"npm/GHSA-1.json": npmAdvisory("GHSA-1", "lodash", "4.17.21")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r) // the PyPI dump fails to load
			return
		}
		_, _ = w.Write(dump)
	}))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	stdin := os.Stdin
	os.Stdin = null // no page
	defer func() { os.Stdin = stdin }()
	out := captureStdout(t, func() {
		err = cmdEnrich([]string{"--package", "pkg:npm/lodash@4.17.20", "--package", "pkg:npm/lodash@4.17.21", "--package", "pkg:npm/nosuch@1.0.0",
			"--package", "pkg:pypi/requests@2.0.0", "--wp-plugin", "akismet@1.0"})
	})
	const want = "looked up 3/5 · concluded 1/5 · not concluded 4 (not_checked 2, source_unavailable 1, unknown_product 1, unknown_version 0) — not concluded is not clean\n"
	if err != nil || !strings.HasSuffix(out, want) {
		t.Fatalf("enrich must end with\n%s got err=%v\n%s", want, err, out)
	}
}
