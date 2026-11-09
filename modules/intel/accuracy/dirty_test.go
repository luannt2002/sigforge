package accuracy

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// The dirty-data corpus: every malformed, partial or ambiguous input independent reviews have
// built against the sources, held as one table. No row may ever come out
// not_affected_by_advisory; a new finding is a new row here, not a one-off patch. The controls
// at the end keep the table honest: well-formed data must still reach the whole-data branch
// (not_checked with NoteNoClearance), so the strict readers stay exercised.
const lodashFixed4_17_21 = `{"id":"GHSA-35jh-r3h4-6jhm","affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
	`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`

func TestDirtyDataIsNeverClean(t *testing.T) {
	ctx := context.Background()
	serve := func(body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	eolPerProduct := func(body string) unified.Result {
		return lifecycle.ToUnified(lifecycle.New(serve(body), fetch.New()).EOLStatus(ctx, "Nginx", "1.18.0"))
	}
	eolBundleDoc := func(doc string) unified.Result {
		return lifecycle.ToUnified(lifecycle.NewBundle(serve(doc), fetch.New()).EOLStatus(ctx, "Nginx", "1.18.0"))
	}
	eolBundle := func(releases string) unified.Result {
		return eolBundleDoc(`{"result":[{"name":"nginx","releases":[` + releases + `]}]}`)
	}
	osvWith := func(dirty string) unified.Result {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		for name, body := range map[string]string{"npm/GHSA-35jh-r3h4-6jhm.json": lodashFixed4_17_21, "npm/dirty.json": dirty} {
			w, _ := zw.Create(name)
			_, _ = w.Write([]byte(body))
		}
		_ = zw.Close()
		idx, err := osv.BuildIndex(ctx, "npm", bytes.NewReader(b.Bytes()), int64(b.Len()))
		if err != nil {
			return osv.Unavailable("npm", "lodash", "4.17.21", err)
		}
		return osv.ToUnified(idx.Lookup("lodash", "4.17.21"), "npm", "lodash", "4.17.21", time.Time{})
	}
	kevAbsent := func(body string) unified.Result {
		return kev.New(serve(body), "", fetch.New()).EnrichUnified(ctx, []string{"CVE-2099-12345"})["CVE-2099-12345"]
	}
	cveNone := func(body string) unified.Result {
		return cve.ToUnified(cve.New(serve(body), fetch.New()).Lookup(ctx, "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.25.0"))
	}
	wp := func(body string) unified.Result {
		return wpcve.ToUnified(wpcve.New(serve(body)+"/{slug}", "", fetch.New()).LookupPlugin(ctx, "acme", "1.0"))
	}
	js := func(url string) unified.Result {
		return jslib.ToUnified(jslib.New(url, fetch.New()).LookupOne(ctx, "lodash", "4.17.21"))
	}
	dirty := map[string]func() unified.Result{
		"eol: cycle without eol":       func() unified.Result { return eolPerProduct(`[{"cycle":"1.18"}]`) },
		"eol: eol null":                func() unified.Result { return eolPerProduct(`[{"cycle":"1.18","eol":null}]`) },
		"eol: body null":               func() unified.Result { return eolPerProduct(`null`) },
		"eol: eol is the string false": func() unified.Result { return eolPerProduct(`[{"cycle":"1.18","eol":"false"}]`) },
		"eol: coarse cycle before specific": func() unified.Result {
			return eolPerProduct(`[{"cycle":"1","eol":false},{"cycle":"1.18","eol":"2021-01-01"}]`)
		},
		"eol: one cycle twice, disagreeing": func() unified.Result {
			return eolPerProduct(`[{"cycle":"1.18","eol":false},{"cycle":"1.18","eol":"2021-01-01"}]`)
		},
		"eol: empty cycle name":          func() unified.Result { return eolPerProduct(`[{"cycle":"","eol":false}]`) },
		"bundle: release without isEol":  func() unified.Result { return eolBundle(`{"name":"1.18"}`) },
		"bundle: isEol and eolFrom null": func() unified.Result { return eolBundle(`{"name":"1.18","isEol":null,"eolFrom":null}`) },
		"bundle: coarse release first": func() unified.Result {
			return eolBundle(`{"name":"1","isEol":false},{"name":"1.18","isEol":true,"eolFrom":"2021-01-01"}`)
		},
		"bundle: one release twice": func() unified.Result {
			return eolBundle(`{"name":"1.18","isEol":false},{"name":"1.18","isEol":true,"eolFrom":"2021-01-01"}`)
		},
		"bundle: isEol is a string":          func() unified.Result { return eolBundle(`{"name":"1.18","isEol":"false"}`) },
		"eol: null row beside a coarse line": func() unified.Result { return eolPerProduct(`[{"cycle":"1","eol":false},null]`) },
		"eol: nameless row":                  func() unified.Result { return eolPerProduct(`[{"cycle":"1","eol":false},{"eol":"2021-01-01"}]`) },
		"eol: padded sub-cycle name": func() unified.Result {
			return eolPerProduct(`[{"cycle":"1","eol":false},{"cycle":" 1.18","eol":"2021-01-01"}]`)
		},
		"eol: v-prefixed sub-cycle name": func() unified.Result {
			return eolPerProduct(`[{"cycle":"1","eol":false},{"cycle":"v1.18","eol":"2021-01-01"}]`)
		},
		"bundle: one product listed twice": func() unified.Result {
			return eolBundleDoc(`{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true,"eolFrom":"2021-01-01"}]},{"name":"nginx","releases":[{"name":"1.18","isEol":false}]}]}`)
		},
		"bundle: ended release with a future date":  func() unified.Result { return eolBundle(`{"name":"1.18","isEol":true,"eolFrom":"2099-01-01"}`) },
		"bundle: null release beside a coarse line": func() unified.Result { return eolBundle(`{"name":"1","isEol":false},null`) },
		"bundle: nameless release": func() unified.Result {
			return eolBundle(`{"name":"1","isEol":false},{"isEol":true,"eolFrom":"2021-01-01"}`)
		},
		"osv: package without a name": func() unified.Result {
			return osvWith(`{"id":"X-5","affected":[{"package":{"ecosystem":"npm","purl":"pkg:npm/lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]}`)
		},
		"osv: affected holds null": func() unified.Result { return osvWith(`{"id":"X-6","affected":[null]}`) },
		"osv: package null": func() unified.Result {
			return osvWith(`{"id":"X-7","affected":[{"package":null,"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]}`)
		},
		"osv: listed version outside the range": func() unified.Result {
			return osvWith(`{"id":"X-8","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}],"versions":["4.17.21"]}]}`)
		},
		"osv: two objects in one entry": func() unified.Result {
			return osvWith(`{"id":"X-9","affected":[]}{"id":"X-10","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]}`)
		},
		"osv: the id and the affected list split": func() unified.Result {
			return osvWith(`{"id":"X-11"}{"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]}`)
		},
		"osv: inverted range": func() unified.Result {
			return osvWith(`{"id":"X-12","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.17.0"},{"fixed":"4.16.0"}]}]}]}`)
		},
		"kev: null row the count leaves out": func() unified.Result {
			return kevAbsent(`{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"},null]}`)
		},
		"kev: id-less row the count leaves out": func() unified.Result {
			return kevAbsent(`{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"vulnerabilityName":"CVE-2099-12345 RCE"}]}`)
		},
		"kev: two ids in one row": func() unified.Result {
			return kevAbsent(`{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228 CVE-2099-12345"}]}`)
		},
		"osv: entry is null": func() unified.Result { return osvWith(`null`) },
		"osv: empty id": func() unified.Result {
			return osvWith(`{"id":"","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]}`)
		},
		"osv: affected without ranges": func() unified.Result {
			return osvWith(`{"id":"GSD-1","affected":[{"package":{"name":"lodash","ecosystem":"npm"}}]}`)
		},
		"osv: range without events": func() unified.Result {
			return osvWith(`{"id":"X-1","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"ECOSYSTEM","events":[]}]}]}`)
		},
		"osv: withdrawn is not a time": func() unified.Result {
			return osvWith(`{"id":"X-2","withdrawn":false,"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]}`)
		},
		"osv: corrupt entry":          func() unified.Result { return osvWith(`{ not json`) },
		"kev: entries short of count": func() unified.Result { return kevAbsent(`{"count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`) },
		"kev: no count":               func() unified.Result { return kevAbsent(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`) },
		"kev: null row counted": func() unified.Result {
			return kevAbsent(`{"count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228"},null]}`)
		},
		"kev: row without an id": func() unified.Result {
			return kevAbsent(`{"count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":""}]}`)
		},
		"kev: one row twice": func() unified.Result {
			return kevAbsent(`{"count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2021-44228"}]}`)
		},
		"osv: range with only a limit": func() unified.Result {
			return osvWith(`{"id":"X-3","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]},{"type":"SEMVER","events":[{"limit":"9.9.9"}]}]}]}`)
		},
		"cve: empty object":            func() unified.Result { return cveNone(`{}`) },
		"cve: null":                    func() unified.Result { return cveNone(`null`) },
		"cve: a real empty answer":     func() unified.Result { return cveNone(`{"totalResults":0,"vulnerabilities":[]}`) },
		"cve: count without the list":  func() unified.Result { return cveNone(`{"totalResults":5,"vulnerabilities":[]}`) },
		"wpcve: slug null":             func() unified.Result { return wp(`{"acme":null}`) },
		"wpcve: slug without a list":   func() unified.Result { return wp(`{"acme":{}}`) },
		"wpcve: an empty list":         func() unified.Result { return wp(`{"acme":{"vulnerabilities":[]}}`) },
		"jslib: embedded sample":       func() unified.Result { return js("") },
		"jslib: live repository miss":  func() unified.Result { return js(serve(`{"lodash":{"vulnerabilities":[{"below":"4.17.21"}]}}`)) },
		"jslib: empty repository body": func() unified.Result { return js(serve(`{}`)) },
	}
	for name, run := range dirty {
		if u := run(); u.State == unified.StateNotAffectedByAdvisory {
			t.Errorf("%s: answered not_affected", name)
		}
	}
	clean := map[string]func() unified.Result{
		"eol: supported cycle":      func() unified.Result { return eolPerProduct(`[{"cycle":"1.18","eol":false}]`) },
		"bundle: supported release": func() unified.Result { return eolBundle(`{"name":"1.18","isEol":false}`) },
		"osv: a repository-level entry beside": func() unified.Result {
			return osvWith(`{"id":"X-13","affected":[{"ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]}]}`)
		},
		"osv: whole dump":      func() unified.Result { return osvWith(lodashFixed4_17_21) },
		"kev: catalog adds up": func() unified.Result { return kevAbsent(`{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`) },
	}
	for name, run := range clean {
		if u := run(); u.State != unified.StateNotChecked || u.Err != unified.NoteNoClearance {
			t.Errorf("control %s: %v %q, want not_checked with NoteNoClearance — well-formed data must reach the whole-data branch", name, u.State, u.Err)
		}
	}
}
