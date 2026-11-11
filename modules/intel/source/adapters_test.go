package source

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/diff"
	"github.com/luannt2002/sigforge/modules/intel/merge"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// All three Normalize functions are pure and are tested on real-shaped fixtures —
// no network is used anywhere in this package's tests.

func TestWebappanalyzerNormalizeBareMap(t *testing.T) {
	raw := []byte(`{
		"Nginx":   {"cats":[22],"headers":{"Server":"nginx"},"implies":"Reverse proxy","cpe":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
		"Angular": {"cats":[12],"dom":{"[ng-version]":{"attributes":{"ng-version":"([\\d.]+)"}}}}
	}`)
	set, err := (&webappanalyzer{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 {
		t.Fatalf("want 2 entries, got %d", len(set))
	}
	ng := set["Nginx"]
	if got := ng.Headers["Server"]; len(got) != 1 || got[0] != "nginx" {
		t.Fatalf("Nginx Server = %v", got)
	}
	if len(ng.Implies) != 1 || ng.Implies[0] != "Reverse proxy" {
		t.Fatalf("Nginx implies (string→list) = %v", ng.Implies)
	}
	// cpe is a single string in the source and must survive as a one-element list,
	// not drop the whole entry on decode.
	if len(ng.Cats) != 1 || ng.Cats[0] != 22 {
		t.Fatalf("Nginx cats = %v", ng.Cats)
	}
	if len(ng.CPE) != 1 || ng.CPE[0] != "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*" {
		t.Fatalf("Nginx cpe (string→list) = %v", ng.CPE)
	}
	if len(set["Angular"].CPE) != 0 {
		t.Fatalf("Angular has no cpe in source, got %v", set["Angular"].CPE)
	}
	if ng.Provenance != "webappanalyzer" || ng.License != "GPL-3.0" {
		t.Fatalf("tags = %q/%q", ng.Provenance, ng.License)
	}
	if len(set["Angular"].Dom) == 0 {
		t.Fatal("Angular dom should carry through")
	}
}

func TestWebappanalyzerNormalizeWrapped(t *testing.T) {
	raw := []byte(`{"technologies":{"X":{"cats":[1]}},"categories":{"1":{"name":"CMS"}}}`)
	set, err := (&webappanalyzer{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 {
		t.Fatalf("want only the technology, got %d: %v", len(set), keys(set))
	}
	if _, ok := set["X"]; !ok {
		t.Fatalf("missing X; got %v", keys(set))
	}
}

func TestNucleiNormalize(t *testing.T) {
	raw := []byte(`id: nginx-detect
info:
  name: Nginx
  classification:
    cpe: cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*
  tags: tech,nginx
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        part: header
        words:
          - "Server: nginx"
      - type: regex
        part: body
        regex:
          - "nginx/([0-9.]+)"
`)
	set, err := (&nuclei{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	fp, ok := set["Nginx"]
	if !ok {
		t.Fatalf("Nginx not normalized; got %v", keys(set))
	}
	if got := fp.Headers["Server"]; len(got) != 1 || got[0] != "nginx" {
		t.Fatalf("header marker = %v", got)
	}
	if !contains(fp.HTML, "nginx/([0-9.]+)") {
		t.Fatalf("body regex marker missing: %v", fp.HTML)
	}
	if fp.Provenance != "nuclei" || fp.License != "MIT" {
		t.Fatalf("tags = %q/%q", fp.Provenance, fp.License)
	}
	if len(fp.CPE) != 1 || fp.CPE[0] != "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*" {
		t.Fatalf("nuclei classification cpe = %v", fp.CPE)
	}
}

func TestNucleiNormalizeNoMappableErrors(t *testing.T) {
	raw := []byte(`id: dsl-only
info:
  name: Thing
http:
  - matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
`)
	if _, err := (&nuclei{}).Normalize(raw); err == nil {
		t.Fatal("a template with no mappable marker must error, not fabricate one")
	}
}

// A template whose strictness comes from matchers-condition: and must NOT be
// emitted as a weak OR-set; it is quarantined. A plain OR template beside it still
// emits, so one lossy doc never poisons the rest of the batch.
func TestNucleiQuarantineAndCondition(t *testing.T) {
	raw := []byte(`id: strict-and
info:
  name: StrictAnd
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "foo"
      - type: word
        part: body
        words:
          - "bar"
---
id: simple-or
info:
  name: SimpleOr
http:
  - method: GET
    matchers:
      - type: word
        part: body
        words:
          - "baz"
`)
	set, err := (&nuclei{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, bad := set["StrictAnd"]; bad {
		t.Fatalf("matchers-condition=and template must be quarantined, not emitted as OR: %v", keys(set))
	}
	if _, ok := set["SimpleOr"]; !ok {
		t.Fatalf("simple OR template must still emit: %v", keys(set))
	}
}

func TestNucleiUnsupportedReasons(t *testing.T) {
	cases := []struct {
		doc  string
		want string
	}{
		{"matchers-condition: and\nmatchers:\n  - type: word", "unsupported: matchers-condition=and"},
		{"matchers:\n  - type: word\n    condition: and", "unsupported: condition=and"},
		{"matchers:\n  - type: word\n    negative: true", "unsupported: negative"},
		{"http:\n  - method: GET\n  - method: POST", "unsupported: multi-request"},
		{"matchers:\n  - type: word\n    condition: or\n    words:\n      - a", ""},
		{"matchers-condition: or\nmatchers:\n  - type: word", ""},
	}
	for _, c := range cases {
		if got := nucleiUnsupported(c.doc); got != c.want {
			t.Errorf("nucleiUnsupported(%q) = %q, want %q", c.doc, got, c.want)
		}
	}
}

func TestWhatwebNormalize(t *testing.T) {
	raw := []byte(`Plugin.define do
  name "Nginx"
  description "nginx web server"
  matches [
    { :text => "Powered by nginx" },
    { :regexp => /nginx-module/ },
    { :version => /nginx\/([\d.]+)/ },
    { :ghdb => 'intitle:"nginx"' },
  ]
end
`)
	set, err := (&whatweb{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	fp, ok := set["Nginx"]
	if !ok {
		t.Fatalf("Nginx not normalized; got %v", keys(set))
	}
	if !contains(fp.HTML, "Powered by nginx") {
		t.Fatalf(":text marker missing: %v", fp.HTML)
	}
	if !contains(fp.HTML, "nginx-module") {
		t.Fatalf(":regexp marker missing: %v", fp.HTML)
	}
	if !contains(fp.HTML, `nginx\/([\d.]+)\;version:\1`) {
		t.Fatalf(":version → versioned marker missing: %v", fp.HTML)
	}
	if fp.Provenance != "whatweb" || fp.License != "GPL-2.0-or-later" {
		t.Fatalf("tags = %q/%q", fp.Provenance, fp.License)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// conditionKeys renders an entry's requires/requiresCategory/excludes as written to JSON, the
// keys a consumer reads, so a test checks the contract rather than Go field names.
func conditionKeys(fp schema.Fingerprint) string {
	b, _ := json.Marshal(fp)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	return fmt.Sprintf("%s %s %s", m["requires"], m["requiresCategory"], m["excludes"])
}

// A requires/requiresCategory/excludes value the matcher cannot evaluate quarantines its entry
// with a counted, logged reason: emitted without its condition it would fire where the
// source's rule never would. Readable conditions (requires also as a bare string) are kept.
func TestWebappanalyzerQuarantinesUnreadableConditions(t *testing.T) {
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)

	set, err := (&webappanalyzer{}).Normalize([]byte(`{
		"Gated":    {"html": "gated", "requires": "WordPress", "requiresCategory": [6], "excludes": ["Other"]},
		"Plain":    {"html": "plain"},
		"NumReq":   {"html": "a", "requires": 5},
		"BlankReq": {"html": "b", "requires": [" "]},
		"ObjExcl":  {"html": "c", "excludes": {"Other": true}},
		"NamedCat": {"html": "d", "requiresCategory": ["Ecommerce"]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"NumReq", "BlankReq", "ObjExcl", "NamedCat"} {
		if _, ok := set[name]; ok {
			t.Errorf("%s emitted without its condition, want quarantined", name)
		}
	}
	if _, ok := set["Plain"]; !ok {
		t.Error("an entry without conditions must still be emitted")
	}
	if got, want := conditionKeys(set["Gated"]), `["WordPress"] [6] ["Other"]`; got != want {
		t.Errorf("Gated conditions = %s, want %s", got, want)
	}
	out := logged.String()
	for _, want := range []string{"quarantined 4 ", "NumReq: requires", "BlankReq: requires", "ObjExcl: excludes", "NamedCat: requiresCategory"} {
		if !strings.Contains(out, want) {
			t.Errorf("quarantine log lacks %q: %q", want, out)
		}
	}
}

// The conditions survive the publish path: merge (the winning entry keeps its own), the
// on-disk JSON round trip, and a diff that reports a condition-only change.
func TestWebappanalyzerConditionsSurviveMergeJSONAndDiff(t *testing.T) {
	set, err := (&webappanalyzer{}).Normalize([]byte(`{
		"Dependent": {"html": "dependent-marker", "requires": ["Needed"], "requiresCategory": [6], "excludes": ["Rival"]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	lower := map[string]schema.Fingerprint{"Dependent": {HTML: schema.StringList{"other-marker"}}}
	merged := merge.Merge(nil,
		merge.Source{Name: "webappanalyzer", Trust: 2, Set: set},
		merge.Source{Name: "lower", Trust: 1, Set: lower})
	b, err := (&schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: merged}).JSON()
	if err != nil {
		t.Fatal(err)
	}
	back, err := schema.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := conditionKeys(back.Fingerprints["Dependent"]), `["Needed"] [6] ["Rival"]`; got != want {
		t.Errorf("after merge + JSON round trip: %s, want %s", got, want)
	}
	if !diff.Diff(back, back).Empty() {
		t.Error("identical DBs must diff empty")
	}
	changed, err := schema.Parse(bytes.Replace(b, []byte(`"Needed"`), []byte(`"Elsewhere"`), 1))
	if err != nil {
		t.Fatal(err)
	}
	if got := diff.Diff(back, changed).Changed; len(got) != 1 || got[0] != "Dependent" {
		t.Errorf("a requires-only change must show as changed, got %v", got)
	}
}

// The quarantine's edges: null is an absent condition, not an unreadable one; a bare category
// number and a blank name after a readable one are unreadable; the log speaks only when an entry
// is quarantined, a single one included.
func TestWebappanalyzerQuarantineEdges(t *testing.T) {
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)
	normalize := func(doc string) map[string]schema.Fingerprint {
		t.Helper()
		logged.Reset()
		set, err := (&webappanalyzer{}).Normalize([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		return set
	}

	set := normalize(`{"Plain": {"html": "plain"}, "Null": {"html": "n", "requires": null, "requiresCategory": null, "excludes": null}}`)
	if fp, ok := set["Null"]; !ok || len(fp.Requires)+len(fp.RequiresCategory)+len(fp.Excludes) > 0 {
		t.Errorf("null conditions: emitted=%v %+v, want emitted with none", ok, fp)
	}
	if logged.Len() > 0 {
		t.Errorf("nothing quarantined, yet logged %q", logged.String())
	}
	for name, doc := range map[string]string{
		"BareCat":   `{"html": "b", "requiresCategory": 6}`,
		"LateBlank": `{"html": "c", "requires": ["WordPress", " "]}`,
	} {
		if _, ok := normalize(`{"Plain": {"html": "plain"}, "` + name + `": ` + doc + `}`)[name]; ok {
			t.Errorf("%s emitted, want quarantined", name)
		}
		if !strings.Contains(logged.String(), "quarantined 1 ") {
			t.Errorf("%s: quarantine log %q, want a count of 1", name, logged.String())
		}
	}
}
