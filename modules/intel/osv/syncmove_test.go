package osv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// When the index cut from a new dump cannot be moved beside it (a directory standing where it goes makes the move
// fail), Sync still keeps the dump and drops that index: no temp index is left in the store.
func TestSyncLeavesNoTempIndexWhenTheIndexCannotBeMoved(t *testing.T) {
	r1, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	r2, _ := makeZip(t, map[string]string{"npm/GHSA-new.json": lodashAdv("GHSA-new", "4.17.22", "")})
	var dump atomic.Value
	dump.Store(mustBytes(r1))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r) // a mirror of dumps only: each sync takes the dump whole
			return
		}
		_, _ = w.Write(dump.Load().([]byte))
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	ctx := context.Background()
	if _, err := New(srv.URL, c).Sync(ctx, "npm"); err != nil {
		t.Fatal(err)
	}
	idx, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.idx.gz"))
	if len(idx) != 1 {
		t.Fatalf("want the dump's index, found %v", idx)
	}
	if err := os.Remove(idx[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(idx[0], "in-the-way"), 0o755); err != nil {
		t.Fatal(err)
	}
	dump.Store(mustBytes(r2))
	if _, err := New(srv.URL, c).Sync(ctx, "npm"); err != nil {
		t.Fatalf("the new dump is readable, so the sync succeeds though its index cannot be kept: %v", err)
	}
	bodies, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.body"))
	if len(bodies) != 1 {
		t.Fatalf("want the one stored dump, found %v", bodies)
	}
	if b, _ := os.ReadFile(bodies[0]); !bytes.Equal(b, mustBytes(r2)) {
		t.Fatal("the new dump must be the one in the store")
	}
	left, _ := filepath.Glob(filepath.Join(c.CacheDir, ".sigforge-*")) // the temporary files fsio makes
	if old, _ := filepath.Glob(filepath.Join(c.CacheDir, "download-*")); len(old) != 0 || len(left) != 0 {
		left = append(left, old...)
		t.Fatalf("an index that could not be moved must not be left in the store: %v", left)
	}
}

// A sync is for the store: when the store cannot keep the dump's meta (a directory standing where it goes), the dump
// a run would read is not this sync's, so Sync fails instead of reporting its size.
func TestSyncFailsWhenTheStoreKeepsNoCopy(t *testing.T) {
	r1, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(mustBytes(r1))
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	sum := sha256.Sum256([]byte(srv.URL + "/npm/all.zip"))
	if err := os.MkdirAll(filepath.Join(c.CacheDir, hex.EncodeToString(sum[:])+".meta", "in-the-way"), 0o755); err != nil {
		t.Fatal(err)
	}
	if n, err := New(srv.URL, c).Sync(context.Background(), "npm"); err == nil {
		t.Fatalf("Sync with a store that cannot keep the meta = %d bytes, nil; want an error", n)
	}
}

// An index whose build did not finish (cancelled) is never put in the store: no index file, no temporary file is left.
func TestUnfinishedIndexIsNeverKept(t *testing.T) {
	r, size := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	idx := filepath.Join(dir, "dump.zip.idx.gz")
	if _, err := buildIndex(ctx, "npm", r, size, func(*record) bool { return true }, idx, "stamp"); err == nil {
		t.Fatal("a cancelled build must fail")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("a cancelled build left %v in the store", left)
	}
}

// The stored dump and its index keep the mode v0.5.0 gave them: readable by their owner only.
func TestStoredDumpAndIndexAreOwnerOnly(t *testing.T) {
	r1, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(mustBytes(r1))
	}))
	defer srv.Close()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	if _, err := New(srv.URL, c).Sync(context.Background(), "npm"); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{"*.body", "*.idx.gz"} {
		got, _ := filepath.Glob(filepath.Join(c.CacheDir, pattern))
		if len(got) != 1 {
			t.Fatalf("%s: %v", pattern, got)
		}
		if st, err := os.Stat(got[0]); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want mode 0600", pattern, st, err)
		}
	}
}

// An index whose rows could not all be written is never put in the store.
func TestIndexWithAWriteErrorIsNeverKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.zip.idx.gz")
	w := newIndexWriter(path, "stamp")
	if w == nil {
		t.Fatal("no index writer")
	}
	w.err = errors.New("a row could not be written")
	w.finish(true)
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("an index with a write error left %v in the store", left)
	}
}

// placeCut moves only the plain index the cut left: a link put in its place is removed, never placed beside the dump.
func TestPlaceCutPlacesOnlyThePlainIndex(t *testing.T) {
	dir := t.TempDir()
	dump, cut := filepath.Join(dir, "dump.body"), filepath.Join(dir, ".sigforge-x.tmp.idx.gz")
	placeCut(cut, dump, true) // no cut at all: nothing to place, nothing to break
	if err := os.WriteFile(filepath.Join(dir, "elsewhere"), []byte("idx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", cut); err != nil {
		t.Fatal(err)
	}
	placeCut(cut, dump, true)
	if _, err := os.Lstat(dump + ".idx.gz"); !os.IsNotExist(err) {
		t.Errorf("a link in place of the cut was placed beside the dump: %v", err)
	}
	if _, err := os.Lstat(cut); !os.IsNotExist(err) {
		t.Errorf("the link in place of the cut was left: %v", err)
	}
	if err := os.WriteFile(cut, []byte("idx"), 0o600); err != nil {
		t.Fatal(err)
	}
	placeCut(cut, dump, true)
	if st, err := os.Lstat(dump + ".idx.gz"); err != nil || !st.Mode().IsRegular() {
		t.Errorf("the plain cut was not placed: %v, %v", st, err)
	}
}
