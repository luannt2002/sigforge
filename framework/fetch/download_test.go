package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const dump = "a whole-ecosystem dump, far larger than a catalog in real life"

// A dump goes into the store once: the next run revalidates it (If-None-Match → 304) and
// reads the stored file, so an unchanged dump costs one header exchange, not its size again.
func TestDownloadStoresAndRevalidates(t *testing.T) {
	var hits, bodies atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		bodies.Add(1)
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(dump))
	}))
	defer srv.Close()
	c := New()
	c.CacheDir = t.TempDir()
	for i := 0; i < 2; i++ {
		path, m, release, err := c.Download(context.Background(), srv.URL, 1<<20)
		if err != nil || m.Cached {
			t.Fatalf("run %d: %v cached=%v; the source answers, so it is not a cached serve", i, err, m.Cached)
		}
		if b, _ := os.ReadFile(path); string(b) != dump {
			t.Fatalf("run %d: file holds %q", i, b)
		}
		release()
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("run %d: a stored dump must survive release: %v", i, err)
		}
	}
	if hits.Load() != 2 || bodies.Load() != 1 {
		t.Fatalf("want 2 requests and 1 body sent, got %d requests and %d bodies", hits.Load(), bodies.Load())
	}
}

func TestDownloadServesYoungStoreWithoutRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(dump))
	}))
	defer srv.Close()
	defer func(f func() time.Time) { now = f }(now)
	t0 := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	now = func() time.Time { return t0 }
	c := New()
	c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
	if _, _, release, err := c.Download(context.Background(), srv.URL, 1<<20); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	now = func() time.Time { return t0.Add(30 * time.Minute) }
	path, m, release, err := c.Download(context.Background(), srv.URL, 1<<20)
	defer release()
	if b, _ := os.ReadFile(path); err != nil || !m.Cached || !m.FetchedAt.Equal(t0) || string(b) != dump || hits.Load() != 1 {
		t.Fatalf("a young stored dump must be served with no request: cached=%v at=%v hits=%d err=%v", m.Cached, m.FetchedAt, hits.Load(), err)
	}
}

func TestDownloadServesStaleOnSourceFailure(t *testing.T) {
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(dump))
	}))
	defer srv.Close()
	c := New()
	c.CacheDir = t.TempDir()
	if _, _, release, err := c.Download(context.Background(), srv.URL, 1<<20); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	down.Store(true)
	path, m, release, err := c.Download(context.Background(), srv.URL, 1<<20)
	defer release()
	if b, _ := os.ReadFile(path); err != nil || !m.Stale || !strings.Contains(m.Err, "503") || string(b) != dump {
		t.Fatalf("a failing source must yield the stored dump flagged stale, got %+v err=%v", m, err)
	}
}

// Without a store the dump is a temp file, gone once the caller releases it.
func TestDownloadWithoutStoreIsTemporary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(dump)) }))
	defer srv.Close()
	path, _, release, err := New().Download(context.Background(), srv.URL, 1<<20)
	if b, _ := os.ReadFile(path); err != nil || string(b) != dump {
		t.Fatalf("got %q, %v", b, err)
	}
	release()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a temp dump must be removed on release, stat: %v", err)
	}
}

// Over the ceiling is refused — up front when announced, mid-stream when not — and leaves
// nothing behind in the store.
func TestDownloadRefusesOverCeiling(t *testing.T) {
	big := strings.Repeat("x", 4096)
	announced := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(big)))
		_, _ = w.Write([]byte(big))
	}))
	defer announced.Close()
	streamed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush() // no Content-Length: the size shows only while reading
		_, _ = w.Write([]byte(big))
	}))
	defer streamed.Close()
	c := New()
	c.CacheDir = t.TempDir()
	for _, u := range []string{announced.URL, streamed.URL} {
		if _, _, release, err := c.Download(context.Background(), u, 1024); err == nil || !strings.Contains(err.Error(), "ceiling") {
			release()
			t.Fatalf("%s: want a ceiling error, got %v", u, err)
		} else if u == announced.URL && !strings.Contains(err.Error(), "4096 bytes") {
			t.Fatalf("an announced oversize must be refused from its Content-Length, before reading: %v", err)
		}
	}
	if entries, _ := os.ReadDir(c.CacheDir); len(entries) != 0 {
		t.Fatalf("a refused dump must leave nothing in the store, found %d entries", len(entries))
	}
}

// A dump outlasts the per-request timeout meant for small catalogs; it is bounded by the
// caller's context instead.
func TestDownloadOutlivesClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("part one, "))
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("part two"))
	}))
	defer srv.Close()
	c := New()
	c.HTTP.Timeout = 100 * time.Millisecond
	path, _, release, err := c.Download(context.Background(), srv.URL, 1<<20)
	defer release()
	if b, _ := os.ReadFile(path); err != nil || string(b) != "part one, part two" {
		t.Fatalf("a slow dump must complete within the context, got %q %v", b, err)
	}
}

// A dump goes through the same 429 hold-off as every other request.
func TestDownloadHonorsHoldOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := New()
	_, _, release, _ := c.Download(context.Background(), srv.URL, 1<<20)
	release()
	_, _, release, err := c.Download(context.Background(), srv.URL, 1<<20)
	release()
	if !errors.Is(err, ErrRateLimited) || hits.Load() != 1 {
		t.Fatalf("a host that answered 429 must not be asked again: err=%v hits=%d", err, hits.Load())
	}
}
