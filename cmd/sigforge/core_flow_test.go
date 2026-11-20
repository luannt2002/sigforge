package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// coreSources is one local server standing in for every source sigforge reads, in their own shapes, with an advisory
// planted for each identity the core flow looks up. It counts requests by path and can fail every one (down).
type coreSources struct {
	mu    sync.Mutex
	hits  map[string]int
	down  atomic.Bool
	extra atomic.Bool // the OSV source lists one more advisory, changed since the dump
	dump  []byte
}

func newCoreSources(t *testing.T) (*coreSources, *httptest.Server) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("npm/GHSA-core-0001.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-core-0001","aliases":["CVE-2099-1001"],"database_specific":{"severity":"HIGH"},` +
		`"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
	f, _ = zw.Create("npm/GHSA-core-0003.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-core-0003","aliases":["CVE-2099-1003"],` +
		`"affected":[{"package":{"name":"minimist","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.6"}]}]}]}`))
	_ = zw.Close()
	s := &coreSources{hits: map[string]int{}, dump: buf.Bytes()}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, srv
}

func (s *coreSources) count(path string) int { s.mu.Lock(); defer s.mu.Unlock(); return s.hits[path] }

func (s *coreSources) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits[r.URL.Path]++
	s.mu.Unlock()
	if s.down.Load() {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	write := func(body string) { _, _ = w.Write([]byte(body)) }
	switch r.URL.Path {
	case "/cve":
		query, _ := url.QueryUnescape(r.URL.RawQuery)
		for product, id := range map[string]string{"nginx": "CVE-2021-23017", "wordpress": "CVE-2099-2002", "php:php": "CVE-2099-2001"} {
			if strings.Contains(query, product) {
				write(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"` + id + `","metrics":{"cvssMetricV31":[` +
					`{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","baseScore":7.7,"baseSeverity":"HIGH"}}]}}}]}`)
				return
			}
		}
		write(`{"totalResults":0,"vulnerabilities":[]}`)
	case "/epss":
		write(`{"status":"OK","data":[{"cve":"CVE-2021-23017","epss":"0.500000000","percentile":"0.900000000","date":"2026-11-01"}]}`)
	case "/kev.json":
		write(`{"vulnerabilities":[{"cveID":"CVE-2021-23017","vendorProject":"F5","product":"NGINX","dateAdded":"2026-01-01"}]}`)
	case "/bundle":
		write(`{"result":[{"name":"nginx","identifiers":[{"type":"cpe","id":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}],` +
			`"releases":[{"name":"1.18","isEol":true},{"name":"1.26","isEol":false}]},` +
			`{"name":"php","identifiers":[{"type":"cpe","id":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}],` +
			`"releases":[{"name":"7.4","isEol":true,"eolFrom":"2022-11-28"}]}]}`)
	case "/cpe.json":
		write(`{"products":[{"cpe":{"cpeName":"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}},` +
			`{"cpe":{"cpeName":"cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*"}},` +
			`{"cpe":{"cpeName":"cpe:2.3:a:wordpress:wordpress:5.8.1:*:*:*:*:*:*:*"}}]}`)
	case "/retire.json":
		write(`{"jquery":{"vulnerabilities":[{"below":"1.9.0","severity":"medium","identifiers":{"CVE":["CVE-2012-6708"]}}]}}`)
	case "/wpvuln/akismet":
		write(`{"vulnerabilities":[{"id":"wp-core-1","title":"stored XSS","cve":"CVE-2099-3003","max_version":"5.0.1","max_operator":"lt"}]}`)
	case "/wporg/akismet":
		write(`{"slug":"akismet","version":"5.3","requires_php":"7.4","requires":"5.8"}`)
	case "/osv/npm/all.zip":
		w.Header().Set("Last-Modified", "Mon, 09 Nov 2026 02:00:00 GMT")
		_, _ = w.Write(s.dump)
	case "/osv/npm/modified_id.csv":
		if s.extra.Load() {
			write("2026-11-17T04:00:00Z,GHSA-core-0002\n2026-11-08T20:00:00Z,GHSA-core-0001\n")
			return
		}
		write("2026-11-08T20:00:00Z,GHSA-core-0001\n")
	case "/osv/npm/GHSA-core-0002.json":
		write(`{"id":"GHSA-core-0002","modified":"2026-11-17T04:00:00Z","aliases":["CVE-2099-1002"],"affected":[{"package":` +
			`{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.22"}]}]}]}`)
	default:
		http.NotFound(w, r)
	}
}

// holdContract checks what every unified result promises, whatever the step: nothing concluded clean (sigforge issues
// no clearance), nothing unconcluded — or only potentially affected — without one of the documented reason codes, no
// match without a lead, and every result naming its source and scope.
func holdContract(t *testing.T, step string, rs []unified.Result) {
	t.Helper()
	if len(rs) == 0 {
		t.Fatalf("%s: no result", step)
	}
	for _, r := range rs {
		id := r.Scope + " " + r.Tech + " " + r.Identity
		switch {
		case r.Source == "" || r.Scope == "":
			t.Errorf("%s: %s names no source or scope", step, id)
		case r.State == unified.StateNotAffectedByAdvisory:
			t.Errorf("%s: %s is concluded clean", step, id)
		case (!r.State.Concluded() || r.State == unified.StatePotentiallyAffected) && !slices.Contains(unified.Reasons, r.Reason):
			t.Errorf("%s: %s is %s with reason %q — want a documented reason code", step, id, r.State, r.Reason)
		case r.State == unified.StateAffectedByAdvisory && len(r.Leads) == 0:
			t.Errorf("%s: %s is affected with no lead", step, id)
		}
		if strings.HasPrefix(r.Err, "; ") || strings.HasSuffix(r.Err, "; ") || strings.Contains(r.Err, "; ; ") {
			t.Errorf("%s: %s: a note joined around nothing: %q", step, id, r.Err)
		}
		for _, l := range r.Leads {
			if l.ID == "" {
				t.Errorf("%s: %s has a lead with no id", step, id)
			}
		}
	}
}

// find returns the one result of scope for tech (or identity), failing the test when there is not exactly one.
func find1(t *testing.T, step string, rs []unified.Result, scope, who string) unified.Result {
	t.Helper()
	var got []unified.Result
	for _, r := range rs {
		if r.Scope == scope && (r.Tech == who || r.Identity == who) {
			got = append(got, r)
		}
	}
	if len(got) != 1 {
		t.Fatalf("%s: %d results of scope %s for %s, want 1", step, len(got), scope, who)
	}
	return got[0]
}

// leadIDs lists a result's lead ids.
func leadIDs(r unified.Result) []string {
	var ids []string
	for _, l := range r.Leads {
		ids = append(ids, l.ID)
	}
	return ids
}

// TestCoreFlowEndToEnd runs the operator's whole flow against every source at once — sync, sources, enrich, a run read
// from the store, the sources failing, watch before and after a new advisory, merge, verify, rollback — and holds the
// unified contract at each step: nothing concluded clean, nothing unconcluded without its reason, every planted advisory
// found, the store serving runs with no request to the catalogs.
func TestCoreFlowEndToEnd(t *testing.T) {
	offline(t)
	src, srv := newCoreSources(t)
	store := t.TempDir()
	t.Setenv(EnvCacheDir, store)
	for env, path := range map[string]string{
		cve.EnvVar: "/cve", kev.EnvEPSSURL: "/epss", kev.EnvKEVURL: "/kev.json", lifecycle.EnvBundleURL: "/bundle",
		identity.EnvCPEDictURL: "/cpe.json", jslib.EnvRetireJSURL: "/retire.json", wpcve.EnvWPVulnURL: "/wpvuln/{slug}",
		wpcve.EnvWPOrgURL: "/wporg/{slug}", osv.EnvOSVURL: "/osv",
	} {
		t.Setenv(env, srv.URL+path)
	}
	catalogs := []string{"/kev.json", "/bundle", "/cpe.json", "/retire.json", "/osv/npm/all.zip"}
	page := `{"headers":{"server":["nginx/1.18.0"],"x-powered-by":["PHP/7.4.3"]},` +
		`"html":"<meta name=\"generator\" content=\"WordPress 5.8.1\">","scriptSrcs":["/js/jquery-1.8.0.min.js"]}`
	sbom := filepath.Join(t.TempDir(), "bom.json")
	writeFile(t, sbom, `{"bomFormat":"CycloneDX","components":[{"purl":"pkg:npm/minimist@1.2.0"}]}`)
	enrich := func(step string) (string, []unified.Result) {
		t.Helper()
		stdinOf(t, page)
		var err error
		out := captureStdout(t, func() {
			err = cmdEnrich([]string{"--json", "--package", "npm:lodash@4.17.20", "--wp-plugin", "akismet@4.0", "--sbom", sbom})
		})
		var rs []unified.Result
		if jerr := json.Unmarshal([]byte(out), &rs); jerr != nil {
			t.Fatalf("%s: enrich --json printed no results array (err %v): %v\n%s", step, err, jerr, out)
		}
		holdContract(t, step, rs)
		return out, rs
	}
	keys := func(rs []unified.Result) []string {
		var k []string
		for _, r := range rs {
			k = append(k, r.Scope+"|"+r.Tech+"|"+r.Identity)
		}
		slices.Sort(k)
		return k
	}

	// 1. sync every catalog — each asked once — and the npm dump; sources reports each ok.
	out, err := runSync(t, "--osv", "npm")
	if err != nil || strings.Contains(out, "FAILED") {
		t.Fatalf("sync with every source up: %v\n%s", err, out)
	}
	for _, c := range catalogs {
		if n := src.count(c); n != 1 {
			t.Errorf("sync asked %s %d times, want once", c, n)
		}
	}
	if out = captureStdout(t, func() { err = cmdSources(nil) }); err != nil {
		t.Fatalf("sources after a good sync: %v\n%s", err, out)
	}
	for _, name := range []string{"KEV catalog", "endoflife bundle", "CPE dictionary", "Retire.js repository", "OSV npm"} {
		if !slices.ContainsFunc(strings.Split(out, "\n"), func(l string) bool {
			return strings.Contains(l, name) && strings.Contains(l, " ok — synced ")
		}) {
			t.Errorf("sources after a good sync: no ok line for %s\n%s", name, out)
		}
	}
	if strings.Contains(out, "FAILED") || strings.Contains(out, "never synced") {
		t.Errorf("sources after a good sync reports a source not ok:\n%s", out)
	}

	// 2. enrich with every source on: each planted advisory is found where it belongs.
	_, live := enrich("enrich")
	if r := find1(t, "enrich", live, "cpe", "Nginx"); r.State != unified.StateAffectedByAdvisory ||
		!slices.Equal(leadIDs(r), []string{"CVE-2021-23017"}) || r.KEV != "catalog" || !r.Leads[0].KnownExpl ||
		r.Leads[0].EPSS == nil {
		t.Errorf("nginx CVE: %+v, want CVE-2021-23017 known exploited with its EPSS", r)
	}
	if r := find1(t, "enrich", live, "eol", "Nginx"); r.State != unified.StateAffectedByAdvisory ||
		len(r.Leads) != 1 || strings.Contains(r.Leads[0].Title, " on ") {
		t.Errorf("nginx end of life: %+v, want cycle 1.18 ended (the bundle gives no date)", r)
	}
	if r := find1(t, "enrich", live, "eol", "PHP"); r.State != unified.StateAffectedByAdvisory || len(r.Leads) != 1 ||
		!strings.Contains(r.Leads[0].Title, " on 2022-11-28") {
		t.Errorf("PHP end of life: %+v, want cycle 7.4 ended on 2022-11-28", r)
	}
	for _, want := range []struct{ scope, who, lead string }{
		{"jslib", "jQuery", "CVE-2012-6708"}, {"ecosystem:npm", "lodash", "GHSA-core-0001"}, {"wordpress:plugin", "akismet", "wp-core-1"},
		{"cpe", "PHP", "CVE-2099-2001"}, {"cpe", "WordPress", "CVE-2099-2002"}, {"ecosystem:npm", "minimist", "GHSA-core-0003"},
	} {
		if r := find1(t, "enrich", live, want.scope, want.who); r.State != unified.StateAffectedByAdvisory ||
			!slices.Equal(leadIDs(r), []string{want.lead}) {
			t.Errorf("%s %s: %+v, want %s", want.scope, want.who, r, want.lead)
		}
	}

	if src.count("/wporg/akismet") == 0 {
		t.Errorf("enrich never asked WordPress.org about akismet")
	}

	// 3. runs within SIGFORGE_CACHE_MAX_AGE read the store: no request to any catalog, the same bytes each run.
	t.Setenv(EnvCacheMaxAge, "1h")
	before := map[string]int{}
	for _, c := range catalogs {
		before[c] = src.count(c)
	}
	first, stored := enrich("enrich from the store")
	again, _ := enrich("enrich from the store, again")
	for _, c := range catalogs {
		if n := src.count(c) - before[c]; n != 0 {
			t.Errorf("two runs within MAX_AGE asked %s %d times, want none", c, n)
		}
	}
	// a source asked again (CVE, EPSS, WordPress: per query, never served from the store) answers live, stamped with
	// the time of the run; everything else must match byte for byte
	same := func(raw string) string {
		var rs []unified.Result
		_ = json.Unmarshal([]byte(raw), &rs)
		for i := range rs {
			if rs[i].Freshness == unified.FreshnessLive {
				rs[i].FetchedAt = ""
			}
		}
		b, _ := json.Marshal(rs)
		return string(b)
	}
	if same(first) != same(again) {
		t.Errorf("two runs from the store differ:\n%s\n---\n%s", first, again)
	}
	if r := find1(t, "enrich from the store", stored, "ecosystem:npm", "lodash"); r.Freshness != unified.FreshnessSnapshot || r.FetchedAt == "" {
		t.Errorf("lodash from the stored dump: freshness %s fetched_at %q, want a snapshot of its sync", r.Freshness, r.FetchedAt)
	}

	// 4. every source failing: what the store holds is served stale with why, what it does not is unavailable — no
	// result lost, none read as clean.
	t.Setenv(EnvCacheMaxAge, "")
	src.down.Store(true)
	_, failing := enrich("sources down")
	src.down.Store(false)
	if !slices.Equal(keys(failing), keys(live)) {
		t.Errorf("sources down: results\n%v\nwant the same as with them up\n%v", keys(failing), keys(live))
	}
	for _, want := range []struct{ scope, who, lead string }{
		{"ecosystem:npm", "lodash", "GHSA-core-0001"}, {"ecosystem:npm", "minimist", "GHSA-core-0003"},
		{"eol", "Nginx", ""}, {"eol", "PHP", ""}, {"jslib", "jQuery", "CVE-2012-6708"},
	} {
		r := find1(t, "sources down", failing, want.scope, want.who)
		if r.Freshness != unified.FreshnessStale || r.Err == "" || len(r.Leads) == 0 || (want.lead != "" && r.Leads[0].ID != want.lead) {
			t.Errorf("%s %s with its catalog down: %+v, want the stored copy's lead %q, stale, with why", want.scope, want.who, r, want.lead)
		}
	}
	for _, scope := range []string{"cpe", "wordpress:plugin"} {
		who := map[string]string{"cpe": "Nginx", "wordpress:plugin": "akismet"}[scope]
		if r := find1(t, "sources down", failing, scope, who); r.State != unified.StateSourceUnavailable || r.Reason != unified.ReasonSourceError {
			t.Errorf("%s %s with its source down: %s (%s), want source_unavailable (source_error)", scope, who, r.State, r.Reason)
		}
	}

	// 5. watch records the first answers, then names the advisory a later sync brings — and fails on it when asked.
	state := filepath.Join(t.TempDir(), "watch.json")
	if out = captureStdout(t, func() { err = cmdWatch([]string{"--state", state, "--package", "npm:lodash@4.17.20"}) }); err != nil ||
		!strings.Contains(out, "first run: 1 lead(s) on 1 identit(ies) recorded") {
		t.Fatalf("first watch: %v\n%s\nwant the one lead recorded, exit 0", err, out)
	}
	if st, serr := os.Lstat(state); serr != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		t.Fatalf("first watch left no state file: %v", serr)
	}
	src.extra.Store(true)
	if out, err = runSync(t, "--osv", "npm"); err != nil {
		t.Fatalf("sync of the changed advisory: %v\n%s", err, out)
	}
	out = captureStdout(t, func() {
		err = cmdWatch([]string{"--state", state, "--package", "npm:lodash@4.17.20", "--fail-on-new"})
	})
	if err == nil || !strings.Contains(out, "NEW") || !strings.Contains(out, "GHSA-core-0002") || strings.Contains(out, "GONE") {
		t.Errorf("watch after a new advisory: err %v\n%s\nwant NEW GHSA-core-0002, exit non-zero, nothing gone", err, out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "NEW") && strings.Contains(l, "GHSA-core-0001") {
			t.Errorf("watch after a new advisory names the lead it already had as new: %q", l)
		}
	}

	// 6. publish, verify, publish again, roll back, verify: the DB rolled back is the one first published.
	dir := t.TempDir()
	db, a, b := filepath.Join(dir, "db.json"), filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
	merge := func(srcs ...string) {
		args := []string{"--out", db, "--manifest", filepath.Join(dir, "m.json")}
		for i, s := range srcs {
			args = append(args, "--source", string(rune('a'+i))+"="+s)
		}
		if out := captureStdout(t, func() { err = cmdMerge(args) }); err != nil {
			t.Fatalf("merge %v: %v\n%s", srcs, err, out)
		}
	}
	verify := func(step string) {
		if out := captureStdout(t, func() { err = cmdVerify([]string{db}) }); err != nil || !strings.HasPrefix(out, "ok:") {
			t.Errorf("verify %s: %v\n%s", step, err, out)
		}
	}
	merge(a)
	verify("after the first merge")
	firstDB, _ := os.ReadFile(db)
	merge(a, b)
	if out := captureStdout(t, func() { err = cmdRollback([]string{db}) }); err != nil {
		t.Fatalf("rollback: %v\n%s", err, out)
	}
	verify("after rollback")
	if rolled, _ := os.ReadFile(db); !bytes.Equal(rolled, firstDB) {
		t.Errorf("the DB rolled back is not the one first published")
	}
}
