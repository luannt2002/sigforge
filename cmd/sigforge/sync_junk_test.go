package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/osv"
)

// answer is what a fake source sends with status 200; cut announces more bytes than it sends, as a transfer
// broken off midway.
type answer struct {
	body string
	cut  bool
}

// fakeSource answers each path with what is set for it at the moment of the request and counts the requests.
type fakeSource struct {
	mu   sync.Mutex
	ans  map[string]answer
	hits map[string]int
}

func newFakeSource() *fakeSource {
	return &fakeSource{ans: map[string]answer{}, hits: map[string]int{}}
}

func (f *fakeSource) set(path string, a answer) { f.mu.Lock(); defer f.mu.Unlock(); f.ans[path] = a }

func (f *fakeSource) count(path string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.hits[path] }

func (f *fakeSource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	a, ok := f.ans[r.URL.Path]
	f.hits[r.URL.Path]++
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if a.cut {
		w.Header().Set("Content-Length", strconv.Itoa(len(a.body)+1000))
	}
	_, _ = io.WriteString(w, a.body) // no []byte copy of the body, which a test measuring what sync allocates would count
}

// storeFiles names every file in the store with its content hash — the sync status file aside, since a sync
// records its outcome there whatever happens.
func storeFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == statusFile {
			return err
		}
		b, err := os.ReadFile(p)
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(dir, p)
		out[rel] = hex.EncodeToString(sum[:])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func runSync(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = cmdSync(args) })
	return out, err
}

// failedReason is what sync printed after FAILED for the one source it reports failing.
func failedReason(out string) string {
	_, why, _ := strings.Cut(out, "FAILED: ")
	why, _, _ = strings.Cut(why, "\n")
	return why
}

const proxyPage = "<html><body>proxy login required</body></html>"

// A catalog source answering 200 with a body a run could not use — one the parser a run reads it with refuses or finds
// no entry in: a proxy's HTML page, a JSON body of another shape or with no entry, an empty body — or breaking a
// transfer off fails that source in sync and in sources, and the store keeps the copy it held, byte for byte; a
// readable new copy then replaces it. Each sync asks once.
func TestSyncKeepsTheStoredCatalogWhenTheAnswerIsNotReadable(t *testing.T) {
	catalogs := []struct {
		env, good, next string
		parse           func([]byte) error // the parser a run reads the catalog with: what sync must report when it errs
	}{
		{jslib.EnvRetireJSURL,
			`{"fakelib":{"vulnerabilities":[{"below":"2.0.0","identifiers":{"CVE":["CVE-2099-3000"]}}]}}`,
			`{"fakelib":{"vulnerabilities":[{"below":"3.0.0","identifiers":{"CVE":["CVE-2099-3001"]}}]}}`,
			func(b []byte) error { _, err := jslib.ParseRepo(b); return err }},
		{kev.EnvKEVURL,
			`{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`,
			`{"count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2023-4966"}]}`,
			func(b []byte) error { _, err := kev.ParseKEV(b); return err }},
		{lifecycle.EnvBundleURL,
			`{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true}]}]}`,
			`{"result":[{"name":"nginx","releases":[{"name":"1.18","isEol":true},{"name":"1.26","isEol":false}]}]}`,
			func(b []byte) error { _, err := lifecycle.ParseBundle(b); return err }},
		{identity.EnvCPEDictURL,
			`{"totalResults":1,"products":[{"cpe":{"cpeName":"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}}]}`,
			`{"totalResults":2,"products":[{"cpe":{"cpeName":"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}},{"cpe":{"cpeName":"cpe:2.3:a:f5:nginx:1.26.0:*:*:*:*:*:*:*"}}]}`,
			func(b []byte) error { _, err := identity.ReadDict(bytes.NewReader(b)); return err }},
	}
	// what sync says of a body the parser reads whole and finds no entry in; the EOL parser refuses such a bundle itself
	empty := map[string]string{kev.EnvKEVURL: "lists no entries", jslib.EnvRetireJSURL: "lists no libraries", identity.EnvCPEDictURL: "lists no usable CPE entries"}
	junk := []struct {
		name string
		ans  answer
	}{
		{"an HTML page", answer{body: proxyPage}},
		{"a JSON body of another shape", answer{body: `{"unexpected": true, "items": [1, 2, 3]}`}},
		{"a JSON body with no entry", answer{body: `{}`}},
		{"an empty body", answer{}},
		{"a transfer broken off", answer{body: `{"count":1,"vulner`, cut: true}},
	}
	for _, c := range catalogs {
		for _, j := range junk {
			t.Run(c.env+"/"+j.name, func(t *testing.T) {
				offline(t)
				store := t.TempDir()
				t.Setenv(EnvCacheDir, store)
				src := newFakeSource()
				srv := httptest.NewServer(src)
				defer srv.Close()
				t.Setenv(c.env, srv.URL+"/catalog.json")

				src.set("/catalog.json", answer{body: c.good})
				if out, err := runSync(t); err != nil {
					t.Fatalf("a readable catalog must sync: %v\n%s", err, out)
				}
				before := storeFiles(t, store)
				src.set("/catalog.json", j.ans)
				out, err := runSync(t)
				if err == nil || !strings.Contains(out, "FAILED") || strings.Contains(out, "ok —") {
					t.Fatalf("an answer a run could not use must fail the source, never be reported ok: err=%v\n%s", err, out)
				}
				// a transfer broken off never reaches the parser; any other answer is refused, word for word, for what the
				// parser says, or as listing no entry when the parser reads it whole
				want := empty[c.env]
				if perr := c.parse([]byte(j.ans.body)); perr != nil {
					want = perr.Error()
				}
				if why := failedReason(out); !j.ans.cut && why != fmt.Sprintf("fetch: %q: unusable body: %s", srv.URL+"/catalog.json", want) {
					t.Fatalf("sync must say word for word why the answer is unusable: the parser says %q, sync says %q", want, why)
				}
				if after := storeFiles(t, store); !reflect.DeepEqual(after, before) {
					t.Fatalf("the store must keep the copy it held, byte for byte:\nbefore %v\nafter  %v", before, after)
				}
				if out := captureStdout(t, func() { err = cmdSources(nil) }); err == nil || !strings.Contains(out, "FAILED") {
					t.Fatalf("sources must report the source as failing: err=%v\n%s", err, out)
				}

				src.set("/catalog.json", answer{body: c.next})
				if out, err := runSync(t); err != nil || !strings.Contains(out, "ok —") {
					t.Fatalf("a readable new copy must sync: %v\n%s", err, out)
				}
				bodies, _ := filepath.Glob(filepath.Join(store, "*.body"))
				if len(bodies) != 1 {
					t.Fatalf("want the one stored copy, found %v", bodies)
				}
				if b, _ := os.ReadFile(bodies[0]); string(b) != c.next {
					t.Fatalf("a readable new copy must replace the stored one; the store holds %q", b)
				}
				if n := src.count("/catalog.json"); n != 3 {
					t.Fatalf("each sync asks the source once: %d requests for 3 syncs", n)
				}
			})
		}
	}
}

func npmDump(t *testing.T, id, fixed string) string {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	f, err := zw.Create("npm/" + id + ".json")
	if err == nil {
		_, err = f.Write([]byte(`{"id":"` + id + `","affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
			`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]}]}`))
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// An OSV dump no run could use — an HTML page, a JSON body, an empty body, a zip cut short, a zip with no advisory,
// a transfer broken off — fails the sync and the sources check, and the stored dump and the index cut from it stay
// byte for byte; a readable new dump then replaces both. Each sync asks for the dump once.
func TestSyncKeepsTheStoredDumpWhenTheNewOneIsNotReadable(t *testing.T) {
	good, next := npmDump(t, "GHSA-1", "4.17.21"), npmDump(t, "GHSA-2", "4.17.22")
	for _, j := range []struct {
		name string
		ans  answer
		why  string // the reason sync must give: what reading the dump fails on, "no advisories" only for one read whole
	}{
		{"an HTML page", answer{body: proxyPage}, "zip: not a valid zip file"},
		{"a JSON body", answer{body: `{"unexpected": true, "items": [1, 2, 3]}`}, "zip: not a valid zip file"},
		{"an empty body", answer{}, "osv: empty dump"},
		{"a zip cut short", answer{body: good[:len(good)/2]}, "zip: not a valid zip file"},
		{"a zip with no advisory", answer{body: "PK\x05\x06" + strings.Repeat("\x00", 18)}, "osv: dump produced no advisories"},
		{"a transfer broken off", answer{body: good[:len(good)/2], cut: true}, "unexpected EOF"},
	} {
		t.Run(j.name, func(t *testing.T) {
			offline(t)
			store := t.TempDir()
			t.Setenv(EnvCacheDir, store)
			src := newFakeSource() // no modified_id.csv: a mirror of dumps only, so each sync takes the dump whole
			srv := httptest.NewServer(src)
			defer srv.Close()
			t.Setenv(osv.EnvOSVURL, srv.URL)

			src.set("/npm/all.zip", answer{body: good})
			if out, err := runSync(t, "--osv", "npm"); err != nil {
				t.Fatalf("a readable dump must sync: %v\n%s", err, out)
			}
			before := storeFiles(t, store)
			if idx, _ := filepath.Glob(filepath.Join(store, "*.idx.gz")); len(idx) != 1 || len(before) != 3 {
				t.Fatalf("the synced dump must sit in the store with its meta and the index cut from it, no other file beside the sync status: %v", before)
			}
			src.set("/npm/all.zip", j.ans)
			want := fmt.Sprintf("osv npm: fetch: %q: unusable body: %s", srv.URL+"/npm/all.zip", j.why)
			if j.ans.cut {
				want = fmt.Sprintf("osv npm: fetch: read %q: %s", srv.URL+"/npm/all.zip", j.why)
			}
			if out, err := runSync(t, "--osv", "npm"); err == nil || !strings.Contains(out, "FAILED") {
				t.Fatalf("an unreadable dump must fail the sync: err=%v\n%s", err, out)
			} else if why := failedReason(out); why != want {
				t.Fatalf("sync must say word for word what is wrong with the dump:\nwant %q\ngot  %q", want, why)
			}
			if after := storeFiles(t, store); !reflect.DeepEqual(after, before) {
				t.Fatalf("the stored dump and its index must stay byte for byte:\nbefore %v\nafter  %v", before, after)
			}
			var err error
			if out := captureStdout(t, func() { err = cmdSources(nil) }); err == nil || !strings.Contains(out, "FAILED") {
				t.Fatalf("sources must report the dump as failing: err=%v\n%s", err, out)
			}

			src.set("/npm/all.zip", answer{body: next})
			if out, err := runSync(t, "--osv", "npm"); err != nil {
				t.Fatalf("a readable new dump must sync: %v\n%s", err, out)
			}
			after := storeFiles(t, store)
			names := func(m map[string]string) (n []string) {
				for k := range m {
					n = append(n, k)
				}
				return n
			}
			if len(after) != len(before) {
				t.Fatalf("the new dump must replace the old one and its index, nothing left beside them: before %v, after %v", names(before), names(after))
			}
			bodies, _ := filepath.Glob(filepath.Join(store, "*.body"))
			if b, _ := os.ReadFile(bodies[0]); len(bodies) != 1 || string(b) != next {
				t.Fatalf("the readable new dump must replace the stored one: %v", bodies)
			}
			if n := src.count("/npm/all.zip"); n != 3 {
				t.Fatalf("each sync asks for the dump once: %d requests for 3 syncs", n)
			}
		})
	}
}

// sync checks the CPE dictionary without taking the saved file whole into memory: one broken at its second product
// fails the source while sync allocates less than half the dictionary's size.
func TestSyncChecksTheCPEDictionaryAsItStreams(t *testing.T) {
	offline(t)
	t.Setenv(EnvCacheDir, t.TempDir())
	product := `{"cpe":{"cpeName":"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}}`
	body := `{"products":[` + product + `,7` + strings.Repeat(","+product, 400_000) + `]}`
	src := newFakeSource()
	src.set("/dict.json", answer{body: body})
	srv := httptest.NewServer(src)
	defer srv.Close()
	t.Setenv(identity.EnvCPEDictURL, srv.URL+"/dict.json")

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out, err := runSync(t)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(out, "FAILED") {
		t.Fatalf("a dictionary broken at its second product must fail the source: err=%v\n%s", err, out)
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > uint64(len(body))/2 {
		t.Fatalf("sync allocated %d bytes to check a %d-byte dictionary: it must read the dictionary as it streams", n, len(body))
	}
}
