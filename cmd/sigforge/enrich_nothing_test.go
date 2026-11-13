package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stdinOf makes s the command's stdin until the test ends.
func stdinOf(t *testing.T, s string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stdin")
	writeFile(t, p, s)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = orig; f.Close() })
}

// enrich with no page on stdin (empty or blank) and no inventory flag looks nothing up: it fails saying so,
// --json too, rather than print "no detections" / [] that a timer reads as quiet; an empty --sbom value, as
// an unset variable leaves it, is no flag. A page that matches nothing ({}) and any one inventory flag keep
// the old outcome.
func TestEnrichFailsWithNothingToLookUp(t *testing.T) {
	offline(t)
	var err error
	for _, in := range []string{"", " \n\t"} {
		for _, args := range [][]string{nil, {"--json"}, {"--sbom", ""}, {"--json", "--sbom", ""}} {
			stdinOf(t, in)
			out := captureStdout(t, func() { err = cmdEnrich(args) })
			if err == nil || !strings.Contains(err.Error(), "nothing to look up") || out != "" {
				t.Errorf("enrich %q with stdin %q must fail saying there is nothing to look up and print nothing: err=%v\n%s", args, in, err, out)
			}
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{{nil, "no detections\n"}, {[]string{"--json"}, "[]\n"}} {
		stdinOf(t, "{}")
		out := captureStdout(t, func() { err = cmdEnrich(c.args) })
		if err != nil || out != c.want {
			t.Errorf("a page that matches nothing is still a page: enrich %q < {} = err %v, %q; want %q", c.args, err, out, c.want)
		}
	}
	sbom := filepath.Join(t.TempDir(), "bom.json")
	writeFile(t, sbom, `{"bomFormat":"CycloneDX","components":[{"purl":"pkg:npm/lodash@4.17.20"}]}`)
	for _, args := range [][]string{
		{"--package", "pkg:npm/lodash@4.17.20"}, {"--sbom", sbom}, {"--wp-plugin", "akismet@1.0"}, {"--wp-theme", "astra@3.0"}, {"--jslib", "jquery@3.4.0"},
	} {
		stdinOf(t, "")
		out := captureStdout(t, func() { err = cmdEnrich(args) })
		if err != nil || !strings.Contains(out, "looked up") {
			t.Errorf("one inventory flag is something to look up: enrich %q = err %v\n%s", args, err, out)
		}
	}
}
