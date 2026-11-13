package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// A --fetch that fails names the command it ran under: refresh shares merge's fetch step, yet its errors say refresh.
func TestFetchErrorNamesItsCommand(t *testing.T) {
	offline(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "not json") }))
	defer srv.Close()
	for _, c := range []struct {
		name string
		run  func([]string) error
	}{{"merge", cmdMerge}, {"refresh", cmdRefresh}} {
		for fetch, why := range map[string]string{
			"nosuch":                    `unknown --fetch source "nosuch"`,
			"webappanalyzer":            `fetch "webappanalyzer"`, // no URL: the source is off
			"webappanalyzer=" + srv.URL: `normalize "webappanalyzer"`,
		} {
			dir := t.TempDir()
			err := c.run([]string{"--out", filepath.Join(dir, "db.json"), "--fetch", fetch, "--manifest", filepath.Join(dir, "m.json")})
			if want := c.name + ": " + why; err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Errorf("%s --fetch %s: err = %v, want one starting %q", c.name, fetch, err, want)
			}
		}
	}
}
