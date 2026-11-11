package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// A body the caller's check refuses never enters the store: GetChecked fails naming why, DownloadChecked hands back
// the stored copy flagged Stale with why (or fails when nothing is stored) — the store keeps the copy it held, with
// no temp file left beside it.
func TestCheckedFetchKeepsARefusedBodyOutOfTheStore(t *testing.T) {
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	refused := errors.New("not the catalog")
	checkBody := func(b []byte) error {
		if string(b) != "good" {
			return refused
		}
		return nil
	}
	checkFile := func(p string) error {
		b, err := os.ReadFile(p)
		if err == nil {
			err = checkBody(b)
		}
		return err
	}
	ctx := context.Background()
	stored := func(t *testing.T, c *Client, url string) string {
		t.Helper()
		entries, _ := os.ReadDir(c.CacheDir)
		path, _, _, ok := c.Stored(url)
		b, _ := os.ReadFile(path)
		if !ok || len(entries) != 2 {
			t.Fatalf("want the one stored copy and its meta, found %d files", len(entries))
		}
		return string(b)
	}

	c := New()
	c.CacheDir = t.TempDir()
	body.Store("good")
	if _, err := c.GetChecked(ctx, srv.URL+"/get", checkBody); err != nil {
		t.Fatal(err)
	}
	body.Store("<html>proxy login</html>")
	if _, err := c.GetChecked(ctx, srv.URL+"/get", checkBody); !errors.Is(err, refused) {
		t.Fatalf("a refused body must be an error naming why, got %v", err)
	}
	if got := stored(t, c, srv.URL+"/get"); got != "good" {
		t.Fatalf("the store must keep its copy, holds %q", got)
	}

	c.CacheDir = t.TempDir()
	if _, _, _, err := c.DownloadChecked(ctx, srv.URL+"/dl", 1<<20, checkFile); err == nil {
		t.Fatal("with nothing stored, a refused body must be an error")
	}
	if entries, _ := os.ReadDir(c.CacheDir); len(entries) != 0 {
		t.Fatalf("a refused body must leave nothing in the store, found %d files", len(entries))
	}
	body.Store("good")
	if _, _, release, err := c.DownloadChecked(ctx, srv.URL+"/dl", 1<<20, checkFile); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	body.Store("")
	path, m, release, err := c.DownloadChecked(ctx, srv.URL+"/dl", 1<<20, checkFile)
	defer release()
	if b, _ := os.ReadFile(path); err != nil || !m.Stale || !strings.Contains(m.Err, refused.Error()) || string(b) != "good" {
		t.Fatalf("a refused body must leave the stored copy, flagged stale with why: err=%v meta=%+v body=%q", err, m, b)
	}
	if got := stored(t, c, srv.URL+"/dl"); got != "good" {
		t.Fatalf("the store must keep its copy, holds %q", got)
	}
}
