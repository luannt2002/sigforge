package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/kev"
)

// A link someone put in place of the archived manifest is restored as the same link, never as a copy: no file rollback
// writes holds what the link points to, so a reader who cannot read that file still cannot.
func TestRollbackNeverPublishesWhatALinkPointsTo(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	a, b, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "db.json")
	writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
	for _, src := range []string{a, b} {
		captureStdout(t, func() {
			if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + src}); err != nil {
				t.Fatal(err)
			}
		})
	}
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "TOP-SECRET\n")
	if err := os.Chmod(victim, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(os.Remove(db+".prev.manifest.json"), os.Symlink(victim, db+".prev.manifest.json")); err != nil {
		t.Fatal(err)
	}
	var err error
	captureStdout(t, func() { err = cmdRollback([]string{db}) })
	if err != nil {
		t.Fatalf("rollback = %v", err)
	}
	if got, err := os.Readlink(db + ".manifest.json"); err != nil || got != victim {
		t.Errorf("the manifest is %q (%v), want the archived link restored as it was", got, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() || p == victim {
			continue
		}
		if b, _ := os.ReadFile(p); strings.Contains(string(b), "TOP-SECRET") {
			t.Errorf("%s, a plain file, holds what the link points to", e.Name())
		}
	}
}

// A release published as links — the DB, its sidecar and its manifest each a link into releases/ — is archived as those
// links and rolled back to them: each name is the same link again, its target as it was written.
func TestRollbackRestoresALinkedReleaseAsLinks(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	a, b, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "db.json")
	writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
	if err := os.Mkdir(filepath.Join(dir, "releases"), 0o755); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		if err := cmdMerge([]string{"--out", filepath.Join(dir, "releases", "v1.json"), "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + a}); err != nil {
			t.Fatal(err)
		}
	})
	for _, ext := range []string{"", ".sha256", ".manifest.json"} {
		if err := os.Symlink("releases/v1.json"+ext, db+ext); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	captureStdout(t, func() {
		if err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + b}); err == nil {
			err = cmdRollback([]string{db})
		}
	})
	if err != nil {
		t.Fatalf("merge then rollback of a release published as links = %v", err)
	}
	for _, ext := range []string{"", ".sha256", ".manifest.json"} {
		if got, err := os.Readlink(db + ext); err != nil || got != "releases/v1.json"+ext {
			t.Errorf("db.json%s after rollback links to %q (%v), want releases/v1.json%s", ext, got, err, ext)
		}
	}
}

// sync never reads its status file through a link someone put in the store: the status written is sync's own, and
// nothing of what the link pointed to reaches it.
func TestSyncStatusIsNeverReadThroughALink(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	store := t.TempDir()
	t.Setenv(EnvCacheDir, store)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`))
	}))
	defer ok.Close()
	t.Setenv(kev.EnvKEVURL, ok.URL)
	victim := filepath.Join(t.TempDir(), "victim.json")
	writeFile(t, victim, `{"db-password-holder":{"error":"TOPSECRET-VALUE"}}`)
	if err := os.Symlink(victim, filepath.Join(store, statusFile)); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() { _ = cmdSync(nil) })
	got, _ := os.ReadFile(filepath.Join(store, statusFile))
	if strings.Contains(string(got), "TOPSECRET") || strings.Contains(string(got), "db-password-holder") {
		t.Errorf("the status file carries what the link pointed to:\n%s", got)
	}
}

// sync says a source FAILED when the store did not keep its copy, whatever the source answered: the store is what
// sync is for.
func TestSyncFailsWhenTheStoreKeepsNoCopy(t *testing.T) {
	for _, s := range syncSources {
		t.Setenv(s.env, "")
	}
	store := t.TempDir()
	t.Setenv(EnvCacheDir, store)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`))
	}))
	defer ok.Close()
	t.Setenv(kev.EnvKEVURL, ok.URL)
	sum := sha256.Sum256([]byte(ok.URL))
	body := filepath.Join(store, hex.EncodeToString(sum[:])+".body")
	if err := os.MkdirAll(filepath.Join(body, "in-the-way"), 0o755); err != nil { // the copy cannot be renamed into place
		t.Fatal(err)
	}
	var err error
	out := captureStdout(t, func() { err = cmdSync(nil) })
	if err == nil || !strings.Contains(out, "FAILED") || strings.Contains(out, "bytes in the store") {
		t.Errorf("sync with a store that kept no copy: err %v, output:\n%s\nwant the source FAILED, never ok", err, out)
	}
	out = captureStdout(t, func() { err = cmdSources(nil) })
	if err == nil || !strings.Contains(out, "FAILED") {
		t.Errorf("sources after that sync: err %v, output:\n%s\nwant the source FAILED", err, out)
	}
}

// watch never reads its state through a link: the state is watch's own, and what it reads it writes back.
func TestWatchStateIsNeverReadThroughALink(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.json")
	writeFile(t, victim, `{"seen":["TOPSECRET"]}`)
	state := filepath.Join(dir, "state.json")
	if err := os.Symlink(victim, state); err != nil {
		t.Fatal(err)
	}
	var err error
	captureStdout(t, func() { err = cmdWatch([]string{"--state", state, "--package", "npm:lodash@4.17.20"}) })
	if err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("watch with its state a link = %v, want it refused naming the link", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != `{"seen":["TOPSECRET"]}` {
		t.Errorf("the link's target was changed: %q", got)
	}
}

// rollback restores the manifest archived with the DB, and with none archived leaves the current one as it was —
// never an empty manifest.
func TestRollbackRestoresTheArchivedManifest(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	a, b, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "db.json")
	writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
	merge := func(srcs ...string) {
		args := []string{"--out", db, "--manifest", filepath.Join(dir, "m.json")}
		for i, s := range srcs {
			args = append(args, "--source", string(rune('a'+i))+"="+s)
		}
		captureStdout(t, func() {
			if err := cmdMerge(args); err != nil {
				t.Fatal(err)
			}
		})
	}
	rollback := func() {
		captureStdout(t, func() {
			if err := cmdRollback([]string{db}); err != nil {
				t.Fatal(err)
			}
		})
	}
	merge(a)
	first, _ := os.ReadFile(db + ".manifest.json")
	merge(a, b)
	rollback()
	if got, _ := os.ReadFile(db + ".manifest.json"); len(first) == 0 || string(got) != string(first) {
		t.Errorf("manifest after rollback:\n%s\nwant the archived one:\n%s", got, first)
	}
	merge(a, b)
	if err := os.Remove(db + ".prev.manifest.json"); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(db + ".manifest.json")
	rollback()
	if got, _ := os.ReadFile(db + ".manifest.json"); len(current) == 0 || string(got) != string(current) {
		t.Errorf("with no manifest archived, rollback changed the current one to:\n%s", got)
	}
}

// The CPE dictionary is synced as a download: when the store cannot keep its meta, the source is FAILED, never ok.
func TestSyncFailsWhenTheStoreKeepsNoDictionary(t *testing.T) {
	offline(t)
	store := t.TempDir()
	t.Setenv(EnvCacheDir, store)
	src := newFakeSource()
	src.set("/dict.json", answer{body: `{"products":[{"cpe":{"cpeName":"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}}]}`})
	srv := httptest.NewServer(src)
	defer srv.Close()
	t.Setenv(identity.EnvCPEDictURL, srv.URL+"/dict.json")
	sum := sha256.Sum256([]byte(srv.URL + "/dict.json"))
	if err := os.MkdirAll(filepath.Join(store, hex.EncodeToString(sum[:])+".meta", "in-the-way"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := runSync(t)
	if err == nil || !strings.Contains(out, "FAILED") || strings.Contains(out, "bytes in the store") {
		t.Errorf("sync of a dictionary the store kept no meta for: err %v, output:\n%s\nwant FAILED", err, out)
	}
}

// What a refused rollback says comes only from sigforge's own files: when the archived DB or checksum is a link, the
// error names the link and nothing read through it — not the target's first word, its length, nor its digest.
func TestRollbackSaysNothingOfALinksTarget(t *testing.T) {
	offline(t)
	secret := strings.Repeat("ab12", 16) // 64 hex characters: it parses as a digest
	for _, linked := range []string{".prev.sha256", ".prev"} {
		dir := t.TempDir()
		a, b, db := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json"), filepath.Join(dir, "db.json")
		writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
		writeFile(t, b, `{"schema_version":"1.0.0","fingerprints":{"ProbeB":{"html":["marker-b"]}}}`)
		for _, src := range []string{a, b} {
			captureStdout(t, func() {
				if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + src}); err != nil {
					t.Fatal(err)
				}
			})
		}
		victim := filepath.Join(dir, "victim")
		writeFile(t, victim, secret+"  more\n")
		if err := errors.Join(os.Remove(db+linked), os.Symlink(victim, db+linked)); err != nil {
			t.Fatal(err)
		}
		var err error
		captureStdout(t, func() { err = cmdRollback([]string{db}) })
		sum := sha256.Sum256([]byte(secret + "  more\n"))
		if err == nil {
			t.Fatalf("rollback with %s a link to the victim succeeded", linked)
		}
		// none of these can be part of the temporary directory's name the error also shows
		for _, leak := range []string{secret, hex.EncodeToString(sum[:]), "want ", "got ", "hex digest"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("rollback with %s a link says %q, which comes from the link's target: %v", linked, leak, err)
			}
		}
	}
	// both files sigforge's own: the refusal quotes the digests, as it always did
	dir := t.TempDir()
	db := filepath.Join(dir, "db.json")
	for _, m := range []string{"marker-a", "marker-b"} {
		src := filepath.Join(dir, m+".json")
		writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"Probe":{"html":["`+m+`"]}}}`)
		captureStdout(t, func() {
			if err := cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "x=" + src}); err != nil {
				t.Fatal(err)
			}
		})
	}
	writeFile(t, db+".prev.sha256", secret+"  db.json.prev\n")
	var err error
	captureStdout(t, func() { err = cmdRollback([]string{db}) })
	if err == nil || !strings.Contains(err.Error(), "want "+secret) || !strings.Contains(err.Error(), "got ") {
		t.Errorf("rollback over its own mismatched checksum = %v, want both digests quoted", err)
	}
}
