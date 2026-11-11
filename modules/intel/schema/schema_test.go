package schema

import (
	"encoding/json"
	"testing"
)

func TestStringListAcceptsStringOrArray(t *testing.T) {
	var single Fingerprint
	if err := json.Unmarshal([]byte(`{"html":"/wp-content/"}`), &single); err != nil {
		t.Fatalf("string form: %v", err)
	}
	if len(single.HTML) != 1 || single.HTML[0] != "/wp-content/" {
		t.Fatalf("string form got %v", single.HTML)
	}
	var multi Fingerprint
	if err := json.Unmarshal([]byte(`{"html":["a","b"]}`), &multi); err != nil {
		t.Fatalf("array form: %v", err)
	}
	if len(multi.HTML) != 2 {
		t.Fatalf("array form got %v", multi.HTML)
	}
}

func TestParseAndValidate(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"good", `{"schema_version":"1.0.0","fingerprints":{"Nginx":{"cats":[22]}}}`, true},
		{"minor bump same major", `{"schema_version":"1.9.0","fingerprints":{"Nginx":{}}}`, true},
		{"incompatible major", `{"schema_version":"2.0.0","fingerprints":{"Nginx":{}}}`, false},
		{"missing version", `{"fingerprints":{"Nginx":{}}}`, false},
		{"empty set", `{"schema_version":"1.0.0","fingerprints":{}}`, false},
		{"empty name", `{"schema_version":"1.0.0","fingerprints":{"":{}}}`, false},
		{"not json", `{`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.in))
			if (err == nil) != c.ok {
				t.Fatalf("ok=%v, err=%v", c.ok, err)
			}
		})
	}
}

// TestValidateRejectsBrokenRegex guards fix #4: a malformed regex in any pattern
// field must fail validation (naming the field), not pass and get silently dropped
// by the matcher. Valid patterns, and empty presence signals, must still pass.
func TestValidateRejectsBrokenRegex(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"good html regex", `{"schema_version":"1.0.0","fingerprints":{"X":{"html":"foo(bar)"}}}`, true},
		{"empty presence pattern", `{"schema_version":"1.0.0","fingerprints":{"X":{"cookies":{"SID":""}}}}`, true},
		{"broken html regex", `{"schema_version":"1.0.0","fingerprints":{"X":{"html":"foo(bar"}}}`, false},
		{"broken header regex", `{"schema_version":"1.0.0","fingerprints":{"X":{"headers":{"Server":"a(b"}}}}`, false},
		{"broken version_regex", `{"schema_version":"1.0.0","fingerprints":{"X":{"version_regex":["v([)"]}}}`, false},
		{"broken dom text regex", `{"schema_version":"1.0.0","fingerprints":{"X":{"dom":{"#x":{"text":"a(b"}}}}}`, false},
		{"broken dom attribute regex", `{"schema_version":"1.0.0","fingerprints":{"X":{"dom":{"#x":{"attributes":{"data-v":"a(b"}}}}}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.in))
			if (err == nil) != c.ok {
				t.Fatalf("ok=%v, err=%v", c.ok, err)
			}
		})
	}
}

func TestJSONRoundTrip(t *testing.T) {
	in := `{"schema_version":"1.0.0","fingerprints":{"Nginx":{"cats":[22],"headers":{"Server":"nginx"}}}}`
	db, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatalf("re-parse rendered DB: %v", err)
	}
}

// TestCapturesVersion locks the one definition of "can extract a version" that the
// refresh gate and the coverage report share: each pattern field counts, a pattern
// without the version suffix does not.
func TestCapturesVersion(t *testing.T) {
	v := `x/([\d.]+)\;version:\1`
	cases := []struct {
		name string
		fp   Fingerprint
		want bool
	}{
		{"version_regex alternate", Fingerprint{VersionRegex: []string{v}}, true},
		{"header suffix", Fingerprint{Headers: map[string]StringList{"Server": {v}}}, true},
		{"cookie suffix", Fingerprint{Cookies: map[string]StringList{"sid": {v}}}, true},
		{"meta suffix", Fingerprint{Meta: map[string]StringList{"generator": {v}}}, true},
		{"html suffix", Fingerprint{HTML: StringList{v}}, true},
		{"scriptSrc suffix", Fingerprint{ScriptSrc: StringList{v}}, true},
		{"detection only", Fingerprint{HTML: StringList{"marker"}, Headers: map[string]StringList{"Server": {"x"}}}, false},
		{"empty", Fingerprint{}, false},
	}
	for _, c := range cases {
		if got := c.fp.CapturesVersion(); got != c.want {
			t.Errorf("%s: CapturesVersion = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestHasDetection locks the one definition of "can detect its tech on its own" that
// the refresh gate uses: each channel the matcher evaluates counts by itself, while
// implies, version_regex and metadata never detect (an implied-only tech such as the
// baseline's Node.js is found only through another tech).
func TestHasDetection(t *testing.T) {
	cases := []struct {
		name string
		fp   Fingerprint
		want bool
	}{
		{"header", Fingerprint{Headers: map[string]StringList{"Server": {"demo"}}}, true},
		{"cookie presence", Fingerprint{Cookies: map[string]StringList{"demo_sid": {""}}}, true},
		{"meta", Fingerprint{Meta: map[string]StringList{"generator": {"Demo"}}}, true},
		{"html", Fingerprint{HTML: StringList{"demo-marker"}}, true},
		{"scriptSrc", Fingerprint{ScriptSrc: StringList{`demo\.js`}}, true},
		{"dom", Fingerprint{Dom: json.RawMessage(`{"#demo-app":{"exists":""}}`)}, true},
		{"implies only", Fingerprint{Implies: StringList{"PHP"}}, false},
		{"version_regex only", Fingerprint{VersionRegex: []string{`demo/([\d.]+)\;version:\1`}}, false},
		{"metadata only", Fingerprint{Cats: []int{27}, CPE: []string{"cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"}, Confidence: 50, Provenance: "baseline", License: "Apache-2.0"}, false},
		{"empty", Fingerprint{}, false},
	}
	for _, c := range cases {
		if got := c.fp.HasDetection(); got != c.want {
			t.Errorf("%s: HasDetection = %v, want %v", c.name, got, c.want)
		}
	}
}

// requires/requiresCategory/excludes keep their Wappalyzer JSON names through a parse/render
// round trip (requires also in its string form) and, being conditions on other detections,
// never count as a detection channel.
func TestConditionsRoundTripAndAreNotDetection(t *testing.T) {
	db, err := Parse([]byte(`{"schema_version":"1.0.0","fingerprints":{"Gated":{"requires":"WordPress","requiresCategory":[6],"excludes":["Other"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.JSON()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	fp := back.Fingerprints["Gated"]
	got, _ := json.Marshal(fp)
	if want := `{"requires":["WordPress"],"requiresCategory":[6],"excludes":["Other"]}`; string(got) != want {
		t.Errorf("round trip = %s, want %s", got, want)
	}
	if fp.HasDetection() {
		t.Error("conditions alone must not count as a detection channel")
	}
}
