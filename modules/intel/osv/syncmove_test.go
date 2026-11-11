package osv

import (
	"bytes"
	"context"
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
	if left, _ := filepath.Glob(filepath.Join(c.CacheDir, "download-*")); len(left) != 0 {
		t.Fatalf("an index that could not be moved must not be left in the store: %v", left)
	}
}
