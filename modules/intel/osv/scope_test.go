package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// A lookup's scope is its key in watch, so one lookup is named one way whether OSV answers it, fails or is off: the
// ecosystem's own name with its distro release kept, whatever space the ecosystem came with (a purl written
// "pkg: pypi/x@1.0"); an ecosystem OSV does not support keeps the name it was given.
func TestLookupScopeIsOneWhetherOSVAnswersFailsOrIsOff(t *testing.T) {
	dumps := map[string][]byte{}
	for eco, entry := range map[string]string{
		"PyPI":   `{"id":"PYSEC-1","affected":[{"package":{"name":"foo","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}`,
		"Debian": advBackport,
	} {
		r, _ := makeZip(t, map[string]string{eco + "/a.json": entry})
		dumps["/"+eco+"/all.zip"] = mustBytes(r)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := dumps[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	ctx := context.Background()
	on, off, down := New(srv.URL, fetch.New()).Lookuper(), New("", fetch.New()).Lookuper(), New("http://127.0.0.1:1", fetch.New()).Lookuper()
	for _, tc := range []struct {
		eco, version, scope string
		answered            bool // OSV on looks it up in its dump
	}{
		{"pypi", "1.0", "ecosystem:PyPI", true},
		{" pypi", "1.0", "ecosystem:PyPI", true},
		{"PyPI ", "1.0", "ecosystem:PyPI", true},
		{"debian:12", "1:1.5-1", "ecosystem:Debian:12", true},
		{" Debian:11", "1.9-3", "ecosystem:Debian:11", true},
		{"debian", "1.9-3", "ecosystem:Debian", false}, // no release: never looked up
		{"maven", "1.0", "ecosystem:Maven", false},     // its dump missing: source_unavailable
		{" foo", "1.0", "ecosystem:foo", false},        // not an OSV ecosystem
	} {
		u := on(ctx, tc.eco, "foo", tc.version)
		if u.LookedUp() != tc.answered {
			t.Errorf("%q with OSV on: looked up = %v, want %v (%+v)", tc.eco, u.LookedUp(), tc.answered, u)
		}
		for path, scope := range map[string]string{"on": u.Scope, "off": off(ctx, tc.eco, "foo", tc.version).Scope, "down": down(ctx, tc.eco, "foo", tc.version).Scope} {
			if scope != tc.scope {
				t.Errorf("%q with OSV %s: scope %q, want %q", tc.eco, path, scope, tc.scope)
			}
		}
	}
}
