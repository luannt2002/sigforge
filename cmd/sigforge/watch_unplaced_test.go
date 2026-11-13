package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// The first watch run after the upgrade that keeps an advisory the version cannot be placed against beside
// one it matched: the state an earlier release wrote holds only the matched lead, so the advisory the old
// rule hid is named NEW once (with --fail-on-new the run fails) and recorded; the next run names nothing.
// A first run proper records both leads and names nothing NEW.
func TestWatchNamesALeadTheOldRuleHidNewOnce(t *testing.T) {
	for _, src := range []struct {
		name, env, path, body, flag, ident, key, matched, unplaced string
	}{
		{"jslib", jslib.EnvRetireJSURL, "",
			`{"fakelib":{"vulnerabilities":[{"below":"2.0.0","identifiers":{"CVE":["CVE-2099-0001"]}},{"below":"@@@","identifiers":{"CVE":["CVE-2099-0002"]}}]}}`,
			"--jslib", "fakelib@1.5.0", "jslib fakelib@1.5.0", "CVE-2099-0001", "CVE-2099-0002"},
		{"wpcve", wpcve.EnvWPVulnURL, "/{kind}/{slug}",
			`{"acme":{"vulnerabilities":[{"id":"WPV-M","title":"m","min_version":"1.0","max_version":"2.0"},{"id":"WPV-U","title":"u","max_version":"trunk"}]}}`,
			"--wp-plugin", "acme@1.5", "wordpress:plugin acme@1.5", "WPV-M", "WPV-U"},
		{"osv", osv.EnvOSVURL, "",
			string(osvDump(map[string]string{"npm/X-M.json": npmAdvisory("X-M", "demo", "9.0.0"), "npm/X-U.json": npmAdvisory("X-U", "demo", "@@@")})),
			"--package", "pkg:npm/demo@1.0.0", "ecosystem:npm demo@1.0.0", "X-M", "X-U"},
	} {
		t.Run(src.name, func(t *testing.T) {
			offline(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(src.body)) }))
			defer srv.Close()
			t.Setenv(src.env, srv.URL+src.path)
			state := filepath.Join(t.TempDir(), "watch.json")
			writeFile(t, state, `{"updated":"2026-11-01T00:00:00Z","leads":{"`+src.key+`":["`+src.matched+`"]},"seen":["`+src.key+`"]}`)
			out, err := watchOut(t, "--state", state, "--fail-on-new", src.flag, src.ident)
			if want := "NEW   " + src.key + "  " + src.unplaced + "\n"; out != want || err == nil || !strings.Contains(err.Error(), "1 new lead(s)") {
				t.Fatalf("the first run after the upgrade must name the lead the old rule hid NEW and fail: err=%v\n%s", err, out)
			}
			if got, want := stateLeads(t, state), map[string][]string{src.key: {src.matched, src.unplaced}}; !reflect.DeepEqual(got, want) {
				t.Fatalf("the state must record both leads: got %v, want %v", got, want)
			}
			if out, err := watchOut(t, "--state", state, "--fail-on-new", src.flag, src.ident); err != nil || out != "" {
				t.Fatalf("the run after names nothing: err=%v\n%s", err, out)
			}
			fresh := filepath.Join(t.TempDir(), "watch.json")
			if out, err := watchOut(t, "--state", fresh, "--fail-on-new", src.flag, src.ident); err != nil || strings.Contains(out, "NEW") ||
				!strings.Contains(out, "first run: 2 lead(s) on 1 identit(ies) recorded") {
				t.Fatalf("a first run proper records both leads, nothing NEW: err=%v\n%s", err, out)
			}
		})
	}
}
