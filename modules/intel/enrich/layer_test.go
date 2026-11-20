package enrich

import (
	"context"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// Behind an edge, a version read from a response header or cookie may be the edge's: each result of that tech says
// so, naming the edge, and keeps its state; the edge's own results carry layer edge. With no edge in front, or a
// version read from the page itself, nothing is noted.
func TestVersionReadBehindAnEdgeSaysSo(t *testing.T) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{
		"Cloudflare": {Cats: []int{31}, Headers: map[string]schema.StringList{"cf-ray": {""}}},
		"EdgeCache":  {Cats: []int{31}, Headers: map[string]schema.StringList{"x-edge": {`edge/([\d.]+)\;version:\1`}}},
		"PHP":        {Cats: []int{27}, Headers: map[string]schema.StringList{"x-powered-by": {`PHP/([\d.]+)\;version:\1`}}},
		"AppCookie":  {Cats: []int{18}, Cookies: map[string]schema.StringList{"app_ver": {`([\d.]+)\;version:\1`}}},
		"jQuery":     {Cats: []int{59}, ScriptSrc: schema.StringList{`jquery-([\d.]+)\.js\;version:\1`}},
	}}
	run := func(headers map[string][]string) map[string][]string {
		page := matcher.Page{Headers: headers, Cookies: []string{"app_ver=3.2"}, ScriptSrcs: []string{"/jquery-1.8.0.js"}}
		notes := map[string][]string{}
		for _, r := range EnrichUnified(context.Background(), matcher.Match(db, page), db, Options{}) {
			notes[r.Tech] = append(notes[r.Tech], r.Layer+"|"+r.Err)
		}
		return notes
	}
	behind := run(map[string][]string{"cf-ray": {"1"}, "x-edge": {"edge/2.1"}, "x-powered-by": {"PHP/7.4.3"}})
	alone := run(map[string][]string{"x-powered-by": {"PHP/7.4.3"}})
	for _, tech := range []string{"PHP", "AppCookie", "Cloudflare", "EdgeCache", "jQuery"} {
		if len(behind[tech]) == 0 {
			t.Fatalf("%s: no result behind the edge — every check below would pass on nothing", tech)
		}
	}
	for _, tech := range []string{"PHP", "AppCookie"} {
		if len(alone[tech]) == 0 {
			t.Fatalf("%s: no result with no edge in front", tech)
		}
	}
	for tech, from := range map[string]string{"PHP": "header", "AppCookie": "cookie"} {
		for _, n := range behind[tech] {
			if !strings.Contains(n, "version read from a response "+from+" behind Cloudflare, EdgeCache") || strings.HasPrefix(n, "edge|") {
				t.Errorf("%s behind Cloudflare: %q, want a note naming the %s and the edge, no layer", tech, n, from)
			}
		}
	}
	for _, edge := range []string{"Cloudflare", "EdgeCache"} { // EdgeCache's own version is read from a header too
		for _, n := range behind[edge] {
			if !strings.HasPrefix(n, "edge|") || strings.Contains(n, "behind") {
				t.Errorf("%s: %q, want layer edge and no behind note", edge, n)
			}
		}
	}
	for _, n := range behind["jQuery"] {
		if strings.Contains(n, "behind") {
			t.Errorf("jQuery read from the page: %q, want no behind note", n)
		}
	}
	for _, tech := range []string{"PHP", "AppCookie"} {
		for _, n := range alone[tech] {
			if strings.Contains(n, "behind") {
				t.Errorf("%s with no edge in front: %q, want no behind note", tech, n)
			}
		}
	}
}
