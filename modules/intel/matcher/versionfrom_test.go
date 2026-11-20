package matcher

import (
	"encoding/json"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// A detection names the page field its version came from — every one of them the site's own, spoofable
// claim — so a consumer can weigh a banner apart from a script file name. When two fields capture the same
// version the higher-ranked one is named (only claims of the chosen version count); a version found by a version pattern is "pattern"; no version, no field.
func TestDetectionVersionFrom(t *testing.T) {
	fps := map[string]schema.Fingerprint{
		"Nginx":   {Headers: map[string]schema.StringList{"Server": {`nginx/([\d.]+)\;version:\1`}}},
		"WP":      {Meta: map[string]schema.StringList{"generator": {`WordPress ([\d.]+)\;version:\1`}}, HTML: schema.StringList{`wp-content/ver=([\d.]+)\;version:\1`}},
		"jQuery":  {ScriptSrc: schema.StringList{`jquery-([\d.]+)\.js\;version:\1`}},
		"Angular": {Dom: json.RawMessage(`{"[ng-version]":{"attributes":{"ng-version":"([\\d.]+)\\;version:\\1"}}}`)},
		"PHP":     {Cookies: map[string]schema.StringList{"PHPSESSID": {""}}, VersionRegex: []string{`PHP/([\d.]+)\;version:\1`}},
		"Bare":    {HTML: schema.StringList{`bare-marker`}},
		"Multi":   {Headers: map[string]schema.StringList{"X-Multi": {`multi/([\d.]+)\;version:\1`}}, HTML: schema.StringList{`multi-v([\d.]+)\;version:\1`}},
	}
	page := Page{
		Headers:    map[string][]string{"server": {"nginx/1.18.0"}, "x-multi": {"multi/2.4"}},
		Cookies:    []string{"PHPSESSID=x"},
		HTML:       `<meta name="generator" content="WordPress 6.4.2"> wp-content/ver=6.4.2 <div ng-version="16.2.0"></div> PHP/8.2.1 bare-marker multi-v2.4.7`,
		ScriptSrcs: []string{"/js/jquery-3.7.1.js"},
	}
	want := map[string][2]string{
		"Nginx": {"1.18.0", "header"}, "WP": {"6.4.2", "meta"}, "jQuery": {"3.7.1", "scriptSrc"},
		"Angular": {"16.2.0", "dom"}, "PHP": {"8.2.1", "pattern"}, "Bare": {"", ""},
		"Multi": {"2.4.7", "html"}, // the header's 2.4 ranks higher, but 2.4.7 is the version chosen
	}
	got := Match(db(fps), page)
	for tech, w := range want {
		d, ok := find(got, tech)
		if !ok || d.Version != w[0] || d.VersionFrom != w[1] {
			t.Errorf("%s = %q from %q (found %v), want %q from %q", tech, d.Version, d.VersionFrom, ok, w[0], w[1])
		}
	}
}
