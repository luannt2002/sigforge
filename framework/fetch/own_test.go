package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A stored copy is sigforge's own file: a link put in its place is never read — the source is asked instead.
func TestStoredCopyIsNeverReadThroughALink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("fresh")) }))
	defer srv.Close()
	c := New()
	c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
	ctx := context.Background()
	if _, err := c.Get(ctx, srv.URL); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := c.cachePaths(srv.URL)
	if err := os.Remove(body); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, body); err != nil {
		t.Fatal(err)
	}
	got, _, err := c.GetMeta(ctx, srv.URL)
	if err != nil || string(got) == "SECRET" {
		t.Errorf("GetMeta with the stored copy a link = %q, %v — want the source's answer, never the link's target", got, err)
	}
}

// Kept reads the store back: no store, no copy, a copy older than asked, or a copy whose body is a link is no copy
// kept; the copy a fetch just stored is.
func TestKeptReadsTheStoreBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("body")) }))
	defer srv.Close()
	ctx := context.Background()
	if err := New().Kept(srv.URL, time.Now()); err == nil || !strings.Contains(err.Error(), "no store") {
		t.Errorf("Kept with no store = %v, want an error naming it", err)
	}
	c := New()
	c.CacheDir = t.TempDir()
	start := time.Now()
	if err := c.Kept(srv.URL, start); err == nil {
		t.Errorf("Kept before any fetch = nil, want no copy")
	}
	if _, err := c.Get(ctx, srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := c.Kept(srv.URL, start); err != nil {
		t.Errorf("Kept of the copy just fetched = %v", err)
	}
	if err := c.Kept(srv.URL, start.Add(time.Hour)); err == nil {
		t.Errorf("Kept of a copy older than asked = nil, want an error")
	}
	body, _ := c.cachePaths(srv.URL)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(os.Remove(body), os.Symlink(victim, body)); err != nil {
		t.Fatal(err)
	}
	if err := c.Kept(srv.URL, start); err == nil {
		t.Errorf("Kept with the body a link = nil, want no copy")
	}
}

// A store directory not made yet is made on the first write, so the first fetch is kept.
func TestStoreIsMadeOnTheFirstWrite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("body")) }))
	defer srv.Close()
	c := New()
	c.CacheDir = filepath.Join(t.TempDir(), "not", "made")
	start := time.Now()
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := c.Kept(srv.URL, start); err != nil {
		t.Errorf("the first fetch into a store not made yet was not kept: %v", err)
	}
}

// The meta of a stored copy is the store's own file too: a link in its place — even to a meta that reads right — is no
// entry.
func TestStoredMetaIsNeverReadThroughALink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("body")) }))
	defer srv.Close()
	c := New()
	c.CacheDir = t.TempDir()
	start := time.Now()
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	_, meta := c.cachePaths(srv.URL)
	elsewhere := filepath.Join(t.TempDir(), "meta")
	b, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(os.WriteFile(elsewhere, b, 0o600), os.Remove(meta), os.Symlink(elsewhere, meta)); err != nil {
		t.Fatal(err)
	}
	if err := c.Kept(srv.URL, start); err == nil {
		t.Errorf("Kept with the meta a link = nil, want no entry")
	}
}
