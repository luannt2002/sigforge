package source

import "testing"

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
