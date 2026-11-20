package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// A tech the end-of-life source has no name for is asked by each of its CPEs, and the kind of answer does not depend on
// the order the DB lists them: a CPE naming a product wins, then one the bundle lists under two products (none guessed,
// no_identity), then "not listed". Of two CPEs naming two products, the first the fingerprint lists — its own order.
func TestEOLByCPEAnswerIsOrderFree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":[
		  {"name":"caddy","identifiers":[{"type":"cpe","id":"cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*"}],"releases":[{"name":"2","isEol":true}]},
		  {"name":"zed","identifiers":[{"type":"cpe","id":"cpe:2.3:a:zed:zed:*:*:*:*:*:*:*:*"}],"releases":[{"name":"2","isEol":true}]},
		  {"name":"twin-a","identifiers":[{"type":"cpe","id":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}],"releases":[{"name":"1","isEol":true}]},
		  {"name":"twin-b","identifiers":[{"type":"cpe","id":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}],"releases":[{"name":"1","isEol":true}]}]}`))
	}))
	defer srv.Close()
	const shared, absent, named = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "cpe:2.3:a:other:other:*:*:*:*:*:*:*:*", "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*"
	eolOf := func(cpes ...string) unified.Result {
		db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{"NoNameTech": {CPE: cpes}}}
		opt := Options{EOL: lifecycle.NewBundle(srv.URL, fetch.New())}
		for _, r := range EnrichUnified(context.Background(), []matcher.Detection{{Tech: "NoNameTech", Version: "2.6.0"}}, db, opt) {
			if r.Scope == "eol" {
				return r
			}
		}
		t.Fatalf("no eol result for %v", cpes)
		return unified.Result{}
	}
	const second = "cpe:2.3:a:zed:zed:*:*:*:*:*:*:*:*"
	for _, pair := range [][2]string{{named, second}, {second, named}} {
		if r := eolOf(pair[0], pair[1], absent); r.Identity != map[string]string{named: "caddy", second: "zed"}[pair[0]] {
			t.Errorf("CPEs %v naming two products: answer for %q, want the first listed", pair, r.Identity)
		}
	}
	for _, c := range []struct {
		cpes        []string
		state       unified.State
		reason, err string
	}{
		{[]string{shared, absent}, unified.StateNotChecked, unified.ReasonNoIdentity, "more than one product"},
		{[]string{absent, shared}, unified.StateNotChecked, unified.ReasonNoIdentity, "more than one product"},
		{[]string{absent, named}, unified.StateAffectedByAdvisory, "", ""},
		{[]string{named, absent}, unified.StateAffectedByAdvisory, "", ""},
		{[]string{shared, named}, unified.StateAffectedByAdvisory, "", ""},
	} {
		if r := eolOf(c.cpes...); r.State != c.state || r.Reason != c.reason || !strings.Contains(r.Err, c.err) {
			t.Errorf("CPEs %v: %s / %q, error %q — want %s / %q with %q", c.cpes, r.State, r.Reason, r.Err, c.state, c.reason, c.err)
		}
	}
}
