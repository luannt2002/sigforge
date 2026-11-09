package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These tests use httptest's in-process loopback server, not a real network.

func TestGetSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	b, err := New().Get(context.Background(), srv.URL)
	if err != nil || string(b) != "hello" {
		t.Fatalf("Get = %q, %v", b, err)
	}
}

func TestGetEmptyURL(t *testing.T) {
	if _, err := New().Get(context.Background(), "  "); err == nil {
		t.Fatal("empty url must error")
	}
}

func TestGetNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := New().Get(context.Background(), srv.URL); err == nil {
		t.Fatal("404 must error")
	}
}

func TestGetSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 100))
	}))
	defer srv.Close()
	c := New()
	c.MaxBytes = 10
	if _, err := c.Get(context.Background(), srv.URL); err == nil {
		t.Fatal("over-limit body must error")
	}
}

// A host that answered 429 asked to be left alone: the client must send it nothing more
// until its Retry-After has passed — one 429 must not become N more requests.
func TestRateLimitedHostIsNotHammered(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := New()
	for i := 0; i < 3; i++ {
		_, _ = c.Get(context.Background(), srv.URL+"/q?i="+strconv.Itoa(i))
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("after a 429 the host must get no more requests during Retry-After, got %d", n)
	}
}

// The held-off request is reported as rate limited (honestly not sent), and a different
// host is unaffected.
func TestHeldOffRequestSaysRateLimited(t *testing.T) {
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer limited.Close()
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fine")) }))
	defer ok.Close()
	c := New()
	_, _ = c.Get(context.Background(), limited.URL)
	if _, err := c.Get(context.Background(), limited.URL); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("a held-off request must report ErrRateLimited, got %v", err)
	}
	if b, err := c.Get(context.Background(), ok.URL); err != nil || string(b) != "fine" {
		t.Fatalf("another host must be unaffected, got %q %v", b, err)
	}
}

// Retry-After: 0 means the wait is already over, so the next request goes out.
func TestRetryAfterZeroSendsAgain(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := New()
	_, _ = c.Get(context.Background(), srv.URL)
	_, _ = c.Get(context.Background(), srv.URL)
	if n := hits.Load(); n != 2 {
		t.Fatalf("Retry-After: 0 must not hold the host off, got %d requests", n)
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"30", 30 * time.Second},
		{"0", 0},
		{"", defaultHoldOff},
		{"soon", defaultHoldOff},
		{"-5", defaultHoldOff},
		{now.Add(2 * time.Minute).Format(http.TimeFormat), 2 * time.Minute},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
	}
	for _, c := range cases {
		if got := retryAfter(c.in, now); got != c.want {
			t.Errorf("retryAfter(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// Stats counts what each host was actually sent and what the 429 hold-off kept back, so a
// run can show how much it asked of every source instead of leaving that unseen.
func TestStatsCountsSentAndHeldOff(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }))
	defer ok.Close()
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer limited.Close()
	c := New()
	for i := 0; i < 3; i++ {
		_, _ = c.Get(context.Background(), ok.URL)
		_, _ = c.Get(context.Background(), limited.URL)
	}
	s := c.Stats()
	okHost, limHost := strings.TrimPrefix(ok.URL, "http://"), strings.TrimPrefix(limited.URL, "http://")
	if s[okHost] != (HostStats{Sent: 3}) {
		t.Errorf("ok host = %+v, want 3 sent", s[okHost])
	}
	if s[limHost] != (HostStats{Sent: 1, HeldOff: 2}) {
		t.Errorf("rate-limited host = %+v, want 1 sent then 2 held off", s[limHost])
	}
}

// With a cache dir, a repeat fetch revalidates instead of re-downloading: the client
// sends If-None-Match with the stored ETag and, on 304, returns the stored body.
func TestConditionalGetReusesBodyOn304(t *testing.T) {
	var full, revalidated atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			revalidated.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("catalog-v1"))
	}))
	defer srv.Close()
	c := New()
	c.CacheDir = t.TempDir()
	for i := 0; i < 2; i++ {
		b, err := c.Get(context.Background(), srv.URL)
		if err != nil || string(b) != "catalog-v1" {
			t.Fatalf("fetch %d = %q, %v; want the catalog body", i+1, b, err)
		}
	}
	if full.Load() != 1 || revalidated.Load() != 1 {
		t.Fatalf("want 1 full download then 1 revalidation (304), got %d full / %d revalidated", full.Load(), revalidated.Load())
	}
}

// When the source changes, revalidation brings the new body and the cache follows it.
func TestConditionalGetPicksUpChange(t *testing.T) {
	version := "v1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		etag := `"` + version + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte("catalog-" + version))
	}))
	defer srv.Close()
	c := New()
	c.CacheDir = t.TempDir()
	_, _ = c.Get(context.Background(), srv.URL)
	version = "v2"
	if b, err := c.Get(context.Background(), srv.URL); err != nil || string(b) != "catalog-v2" {
		t.Fatalf("a changed source must be downloaded again, got %q %v", b, err)
	}
	if b, _ := c.Get(context.Background(), srv.URL); string(b) != "catalog-v2" {
		t.Fatalf("the cache must now hold v2, got %q", b)
	}
}

// Without a cache dir nothing is stored and no conditional header is sent (old behavior).
func TestNoCacheDirSendsNoValidator(t *testing.T) {
	var sawValidator atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			sawValidator.Store(true)
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()
	c := New()
	_, _ = c.Get(context.Background(), srv.URL)
	_, _ = c.Get(context.Background(), srv.URL)
	if sawValidator.Load() {
		t.Fatal("no cache dir must mean no conditional request")
	}
}

// With MaxAge, a stored body younger than MaxAge is served from the local store with NO
// request, and GetMeta says so (Cached + the time it was fetched) so a caller labels it a
// snapshot, never live. Older than MaxAge it is revalidated with the source.
func TestGetMetaServesYoungStoreWithoutRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("catalog")) // no ETag: the store must keep it anyway
	}))
	defer srv.Close()
	defer func(f func() time.Time) { now = f }(now)
	t0 := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	now = func() time.Time { return t0 }

	c := New()
	c.CacheDir, c.MaxAge = t.TempDir(), time.Hour
	if _, m, err := c.GetMeta(context.Background(), srv.URL); err != nil || m.Cached {
		t.Fatalf("first fetch must go to the source, got cached=%v err=%v", m.Cached, err)
	}
	now = func() time.Time { return t0.Add(30 * time.Minute) }
	b, m, err := c.GetMeta(context.Background(), srv.URL)
	if err != nil || string(b) != "catalog" || !m.Cached || !m.FetchedAt.Equal(t0) {
		t.Fatalf("a 30-minute-old store must be served as cached from %v, got %q cached=%v at=%v err=%v", t0, b, m.Cached, m.FetchedAt, err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("a young store must cost no request, source saw %d", n)
	}
	if s := c.Stats()[strings.TrimPrefix(srv.URL, "http://")]; s.Sent != 1 || s.Cached != 1 {
		t.Fatalf("stats = %+v, want 1 sent and 1 served from the store", s)
	}
	now = func() time.Time { return t0.Add(2 * time.Hour) }
	if _, m, _ := c.GetMeta(context.Background(), srv.URL); m.Cached || hits.Load() != 2 {
		t.Fatalf("a store older than MaxAge must be refetched, got cached=%v hits=%d", m.Cached, hits.Load())
	}
}

// When the source fails, a catalog caller still gets the stored copy — flagged Stale with
// the failure — instead of losing a synced catalog to a passing outage (stale-if-error).
// A per-query Get still reports the failure.
func TestGetMetaServesStaleOnSourceFailure(t *testing.T) {
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("catalog"))
	}))
	defer srv.Close()
	c := New()
	c.CacheDir = t.TempDir() // MaxAge 0: every call asks the source
	if _, _, err := c.GetMeta(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	b, m, err := c.GetMeta(context.Background(), srv.URL)
	if err != nil || string(b) != "catalog" || !m.Cached || !m.Stale || !strings.Contains(m.Err, "503") {
		t.Fatalf("a failing source must yield the stored copy flagged stale with the error, got %q %+v %v", b, m, err)
	}
	if _, err := c.Get(context.Background(), srv.URL); err == nil {
		t.Fatal("a per-query Get must still report the failure")
	}
}
