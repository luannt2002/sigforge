package kev

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// A row whose id is not a whole CVE id, or that is not an object at all, is skipped and
// counted — one bad row costs that row, never the catalog; a mistyped side field costs the field.
func TestCatalogSkipsAndCountsBadRows(t *testing.T) {
	body := `{"count":11,"dateReleased":"` + time.Now().UTC().Format(time.RFC3339) + `","vulnerabilities":[
	  {"cveID":"CVE-2021-44228","knownRansomwareCampaignUse":"Known"},
	  {"cveID":" cve-2019-0708\ufeff"},
	  {"cveID":"CVE-2019-11510","product":5},
	  {"cveID":"SRV-CVE-CVE-2021-23017"},
	  {"cveID":"CVE-2020-1472abc"},
	  {"cveID":"CVE-21-1"},
	  {"cveID":123},
	  [{"cveID":"CVE-2018-13379"}],
	  5,
	  null,
	  "CVE-2017-0144"]}`
	m, err := ParseKEV([]byte(body))
	if err != nil {
		t.Fatalf("one bad row must not cost the catalog: %v", err)
	}
	if len(m) != 3 || !m["CVE-2021-44228"].Ransomware || m["CVE-2019-0708"].CVE == "" || m["CVE-2019-11510"].CVE == "" {
		t.Fatalf("want the 3 well-formed rows only, got %+v", m)
	}
	a := New(serveJSON(t, body), "", fetch.New())
	st := a.Status(context.Background())
	if st.Source != "live" || st.Entries != 3 || st.Skipped != 8 || !strings.Contains(st.Warn, "8 rows skipped") {
		t.Fatalf("status = %+v, want the live catalog with 8 rows skipped and named", st)
	}
	if a.complete {
		t.Fatal("a catalog with skipped rows must not prove itself whole")
	}
}

// The catalog's own release date is checked: an old, future, missing or unreadable date is
// named on the status while the catalog stays in use; a current one says nothing.
func TestCatalogReleaseDate(t *testing.T) {
	row := `"vulnerabilities":[{"cveID":"CVE-2021-44228"}]`
	for name, c := range map[string]struct{ body, want string }{
		"current":    {`{"dateReleased":"` + time.Now().UTC().Format(time.RFC3339Nano) + `",` + row + `}`, ""},
		"old":        {`{"dateReleased":"2001-01-01T00:00:00.000Z",` + row + `}`, "days ago"},
		"future":     {`{"dateReleased":"2999-01-01T00:00:00Z",` + row + `}`, "in the future"},
		"missing":    {`{` + row + `}`, "no release date"},
		"unreadable": {`{"dateReleased":"last tuesday",` + row + `}`, "unreadable"},
		"mistyped":   {`{"dateReleased":20240101,` + row + `}`, "no release date"},
	} {
		t.Run(name, func(t *testing.T) {
			st := New(serveJSON(t, c.body), "", fetch.New()).Status(context.Background())
			if st.Source != "live" || st.Err != "" {
				t.Fatalf("a date problem must not cost the catalog: %+v", st)
			}
			if c.want == "" && st.Warn != "" || c.want != "" && !strings.Contains(st.Warn, c.want) {
				t.Fatalf("Warn = %q, want it to contain %q", st.Warn, c.want)
			}
		})
	}
}
