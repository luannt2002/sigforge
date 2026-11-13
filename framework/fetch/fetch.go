// Package fetch is the tool's bounded HTTP GET client for pulling a source's raw
// data at the operator's command. It hardcodes no URL, vendor or endpoint — the
// caller supplies the URL — and it is pure infrastructure: it handles bytes over
// HTTP and knows nothing about fingerprints, so it never imports a domain package
// under modules/.
//
// It is deliberately small and honest: a non-2xx status is an error that names the
// code, and a body larger than the configured ceiling is an error rather than an
// unbounded read, so a hostile or misconfigured endpoint cannot exhaust memory.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luannt2002/sigforge/framework/fsio"
)

const (
	// DefaultTimeout bounds one fetch end to end.
	DefaultTimeout = 60 * time.Second
	// DefaultMaxBytes caps the response body (64 MiB — comfortably above the
	// largest known fingerprint dataset, far below anything that threatens RAM).
	DefaultMaxBytes int64 = 64 << 20
)

// ErrRateLimited marks a request that was NOT sent because its host answered 429 and
// the wait it asked for has not passed.
var ErrRateLimited = errors.New("rate limited")

// now is the clock (a test seam).
var now = time.Now

// defaultHoldOff is how long a host is left alone after a 429 that names no wait: one
// full window of the strictest public-feed limit documented (5 requests per 30s).
const defaultHoldOff = 30 * time.Second

// Client is a reusable bounded GET client. The zero value is not ready; use New.
type Client struct {
	HTTP     *http.Client
	MaxBytes int64
	// CacheDir, when set, keeps each fetched body with its ETag / Last-Modified and
	// revalidates on the next fetch (If-None-Match / If-Modified-Since): an unchanged
	// source answers 304 and is not downloaded again. The server confirms every reuse, so
	// a cached body is never served stale. Empty = no cache (every fetch downloads).
	CacheDir string
	// MaxAge, with CacheDir, lets GetMeta serve a stored body younger than MaxAge without
	// a request (a synced snapshot). Zero = always ask the source. Get ignores it.
	MaxAge time.Duration

	mu      sync.Mutex
	holdOff map[string]time.Time // host → send nothing before this time (it answered 429)
	stats   map[string]HostStats
}

// HostStats is what one host was asked: requests actually sent, and requests the 429
// hold-off kept back. A run that cannot count its requests cannot show it is not spamming.
type HostStats struct {
	Sent    int
	HeldOff int
	Cached  int // served from the local store within MaxAge — no request
}

// Stats returns a copy of the per-host request counts so far.
func (c *Client) Stats() map[string]HostStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]HostStats, len(c.stats))
	for h, s := range c.stats {
		out[h] = s
	}
	return out
}

func (c *Client) countCached(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stats == nil {
		c.stats = map[string]HostStats{}
	}
	st := c.stats[host]
	st.Cached++
	c.stats[host] = st
}

// count records one outcome for host; the caller holds c.mu.
func (c *Client) count(host string, held bool) {
	if c.stats == nil {
		c.stats = map[string]HostStats{}
	}
	s := c.stats[host]
	if held {
		s.HeldOff++
	} else {
		s.Sent++
	}
	c.stats[host] = s
}

// Do sends req unless its host answered 429 and the Retry-After it named has not
// passed, and records a fresh 429 — so one rate-limit answer never turns into N more
// requests to a host that asked to be left alone. Every request goes through here.
func (c *Client) Do(req *http.Request) (*http.Response, error) { return c.do(req, c.HTTP) }

func (c *Client) do(req *http.Request, hc *http.Client) (*http.Response, error) {
	host := req.URL.Host
	c.mu.Lock()
	until := c.holdOff[host]
	held := time.Now().Before(until)
	c.count(host, held)
	c.mu.Unlock()
	if held {
		return nil, fmt.Errorf("%w: %s asked to wait until %s", ErrRateLimited, host, until.UTC().Format(time.RFC3339))
	}
	resp, err := hc.Do(req)
	if err == nil && resp.StatusCode == http.StatusTooManyRequests {
		now := time.Now()
		c.mu.Lock()
		if c.holdOff == nil {
			c.holdOff = map[string]time.Time{}
		}
		c.holdOff[host] = now.Add(retryAfter(resp.Header.Get("Retry-After"), now))
		c.mu.Unlock()
	}
	return resp, err
}

// retryAfter reads a Retry-After header — delay-seconds or an HTTP-date — and falls
// back to defaultHoldOff when it is missing or unreadable.
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
		return 0
	}
	return defaultHoldOff
}

// New returns a Client with the default timeout and size ceiling.
func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: DefaultTimeout}, MaxBytes: DefaultMaxBytes}
}

// Meta says where a GetMeta body came from, so a caller labels it honestly: Cached means
// it was served from the local store without asking the source — a snapshot as of
// FetchedAt; otherwise the source was asked now.
type Meta struct {
	Cached    bool
	FetchedAt time.Time
	Stale     bool   // the source failed, so this is the stored copy kept past its freshness
	Err       string // why the source failed when Stale
}

// Get fetches url and returns its body, or an honest error: an empty URL, a
// transport failure, a non-2xx status (with the code), or a body over MaxBytes. It
// always asks the source; a stored body is reused only when the source answers 304.
func (c *Client) Get(ctx context.Context, url string) ([]byte, error) {
	return c.GetChecked(ctx, url, nil)
}

// GetChecked is Get that stores a new body only when check accepts it: a body check refuses is
// an error, and the store keeps the copy it held. On a 304 check reads the stored copy again: one
// it refuses is an error, and loses its validators so the next fetch downloads a whole copy.
func (c *Client) GetChecked(ctx context.Context, url string, check func([]byte) error) ([]byte, error) {
	b, _, err := c.get(ctx, url, false, check)
	return b, err
}

// GetMeta is Get for a whole catalog a caller loads once: with MaxAge set, a stored body
// younger than MaxAge is returned WITHOUT a request (Meta.Cached), so a synced catalog
// costs a scan nothing — and the caller must report it as a snapshot of Meta.FetchedAt.
func (c *Client) GetMeta(ctx context.Context, url string) ([]byte, Meta, error) {
	return c.get(ctx, url, true, nil)
}

// GetMetaChecked is GetMeta that stores a new body only when check accepts it, as GetChecked does: a
// body check refuses counts as the source failing, so the stored copy comes back flagged Stale. On a
// 304 check reads the stored copy again: one it refuses is an error, never a stale copy, and loses its
// validators. A stored copy served within MaxAge, or flagged Stale, comes back unchecked: the caller
// checks what it reads.
func (c *Client) GetMetaChecked(ctx context.Context, url string, check func([]byte) error) ([]byte, Meta, error) {
	return c.get(ctx, url, true, check)
}

// catalog marks a GetMeta call: MaxAge applies, and a failing source falls back to the
// stored copy (stale-if-error) instead of erroring.
func (c *Client) get(ctx context.Context, url string, catalog bool, check func([]byte) error) ([]byte, Meta, error) {
	if strings.TrimSpace(url) == "" {
		return nil, Meta{}, errors.New("fetch: empty url")
	}
	max := c.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, Meta{}, fmt.Errorf("fetch: request %q: %w", url, err)
	}
	cached := c.loadCached(url)
	if catalog && cached != nil && c.MaxAge > 0 && now().Sub(cached.fetchedAt) < c.MaxAge {
		c.countCached(req.URL.Host)
		return cached.body, Meta{Cached: true, FetchedAt: cached.fetchedAt}, nil
	}
	req.Header.Set("User-Agent", "sigforge-fetch")
	if cached != nil {
		revalidate(req, cached.cacheMeta)
	}
	resp, err := c.Do(req)
	if err != nil {
		return staleOr(catalog, cached, fmt.Errorf("fetch: get %q: %w", url, err))
	}
	defer resp.Body.Close()
	at := now().UTC()
	if resp.StatusCode == http.StatusNotModified && cached != nil {
		if check != nil {
			if err := check(cached.body); err != nil {
				return nil, Meta{}, c.unusable(url, cached.fetchedAt, err)
			}
		}
		c.storeMeta(url, cached.cacheMeta, at) // the source just confirmed it is current
		return cached.body, Meta{FetchedAt: at}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return staleOr(catalog, cached, fmt.Errorf("fetch: get %q: status %d", url, resp.StatusCode))
	}
	// Read one byte past the ceiling so an over-limit body is detected, not silently truncated.
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, Meta{}, fmt.Errorf("fetch: read %q: %w", url, err)
	}
	if int64(len(b)) > max {
		return nil, Meta{}, fmt.Errorf("fetch: %q body exceeds %d bytes", url, max)
	}
	if check != nil {
		if err := check(b); err != nil {
			return staleOr(catalog, cached, fmt.Errorf("fetch: %q: unusable body: %w", url, err))
		}
	}
	c.storeCached(url, resp.Header, b, at)
	return b, Meta{FetchedAt: at}, nil
}

// Download is GetMeta for a body too large to hold in memory (a whole-ecosystem dump): it
// streams url to a file of at most max bytes and returns its path. With CacheDir the file is
// the store's copy — kept, revalidated (304), served within MaxAge without a request, and
// returned flagged Stale when the source fails; without, it is a temp file. The caller calls
// release when done reading (it removes a temp file, keeps a stored one). The transfer is
// bounded by ctx, not by the client's Timeout, which is sized for small catalogs.
func (c *Client) Download(ctx context.Context, url string, max int64) (path string, m Meta, release func(), err error) {
	return c.DownloadChecked(ctx, url, max, nil)
}

// DownloadChecked is Download that moves a new body into the store only when check accepts the
// file holding it: a body check refuses is removed and counts as the source failing, so the
// stored copy stays as it was. On a 304 check reads the stored copy again, as GetChecked does.
func (c *Client) DownloadChecked(ctx context.Context, url string, max int64, check func(path string) error) (path string, m Meta, release func(), err error) {
	release = func() {}
	if strings.TrimSpace(url) == "" {
		return "", Meta{}, release, errors.New("fetch: empty url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", Meta{}, release, fmt.Errorf("fetch: request %q: %w", url, err)
	}
	stored, meta, at := c.storedFile(url)
	if stored != "" && c.MaxAge > 0 && now().Sub(at) < c.MaxAge {
		c.countCached(req.URL.Host)
		return stored, Meta{Cached: true, FetchedAt: at}, release, nil
	}
	fail := func(err error) (string, Meta, func(), error) {
		if stored == "" {
			return "", Meta{}, release, err
		}
		return stored, Meta{Cached: true, Stale: true, FetchedAt: at, Err: err.Error()}, release, nil
	}
	req.Header.Set("User-Agent", "sigforge-fetch")
	if stored != "" {
		revalidate(req, meta)
	}
	hc := *c.HTTP
	hc.Timeout = 0
	resp, err := c.do(req, &hc)
	if err != nil {
		return fail(fmt.Errorf("fetch: get %q: %w", url, err))
	}
	defer resp.Body.Close()
	fetched := now().UTC()
	if resp.StatusCode == http.StatusNotModified && stored != "" {
		if check != nil {
			if err := check(stored); err != nil {
				return "", Meta{}, release, c.unusable(url, at, err)
			}
		}
		c.storeMeta(url, meta, fetched)
		return stored, Meta{FetchedAt: fetched}, release, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fail(fmt.Errorf("fetch: get %q: status %d", url, resp.StatusCode))
	}
	if resp.ContentLength > max {
		return fail(fmt.Errorf("fetch: %q is %d bytes, over the %d byte ceiling", url, resp.ContentLength, max))
	}
	dir := c.CacheDir
	if dir == "" {
		dir = os.TempDir()
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return fail(err)
	}
	tmp, err := os.CreateTemp(dir, "download-*")
	if err != nil {
		return fail(err)
	}
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, max+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		err = fmt.Errorf("fetch: %q body exceeds the %d byte ceiling", url, max)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return fail(fmt.Errorf("fetch: read %q: %w", url, err))
	}
	if check != nil {
		if err := check(tmp.Name()); err != nil {
			os.Remove(tmp.Name())
			return fail(fmt.Errorf("fetch: %q: unusable body: %w", url, err))
		}
	}
	removeTmp := func() { os.Remove(tmp.Name()) }
	if c.CacheDir == "" {
		return tmp.Name(), Meta{FetchedAt: fetched}, removeTmp, nil
	}
	bodyPath, _ := c.cachePaths(url)
	if err := os.Rename(tmp.Name(), bodyPath); err != nil {
		removeTmp()
		return fail(err) // with a store, the returned path is always the store's copy
	}
	c.storeMeta(url, cacheMeta{URL: url, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}, fetched)
	return bodyPath, Meta{FetchedAt: fetched}, release, nil
}

// unusable drops the validators of url's stored copy, which check refused on a 304, so the next fetch
// downloads a whole copy instead of being told again that this one is current.
func (c *Client) unusable(url string, at time.Time, err error) error {
	c.storeMeta(url, cacheMeta{URL: url}, at)
	return fmt.Errorf("fetch: %q: stored copy unusable: %w", url, err)
}

func revalidate(req *http.Request, m cacheMeta) {
	if m.ETag != "" {
		req.Header.Set("If-None-Match", m.ETag)
	}
	if m.LastModified != "" {
		req.Header.Set("If-Modified-Since", m.LastModified)
	}
}

// staleOr gives a catalog caller the stored copy, flagged Stale with the failure, when
// the source fails — a passing outage must not drop a synced catalog (stale-if-error,
// RFC 5861). Per-query callers, and callers with nothing stored, get the error.
func staleOr(catalog bool, cached *cachedBody, err error) ([]byte, Meta, error) {
	if !catalog || cached == nil {
		return nil, Meta{}, err
	}
	return cached.body, Meta{Cached: true, Stale: true, FetchedAt: cached.fetchedAt, Err: err.Error()}, nil
}

// cacheMeta is what a cached body needs to be revalidated.
type cacheMeta struct {
	URL          string `json:"url"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	FetchedAt    string `json:"fetched_at,omitempty"` // when the source last served or confirmed it (RFC3339)
}

type cachedBody struct {
	cacheMeta
	body      []byte
	fetchedAt time.Time // zero for an entry without a fetch time: never young enough for MaxAge
}

func (c *Client) cachePaths(url string) (body, meta string) {
	sum := sha256.Sum256([]byte(url))
	base := filepath.Join(c.CacheDir, hex.EncodeToString(sum[:]))
	return base + ".body", base + ".meta"
}

// loadCached returns the stored body for url, or nil when there is no usable entry.
func (c *Client) loadCached(url string) *cachedBody {
	path, m, at := c.storedFile(url)
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return &cachedBody{cacheMeta: m, body: b, fetchedAt: at}
}

// storedFile returns the path of url's stored body with its meta and fetch time, or "" when
// there is no usable entry.
func (c *Client) storedFile(url string) (path string, m cacheMeta, at time.Time) {
	if c.CacheDir == "" {
		return "", cacheMeta{}, time.Time{}
	}
	bodyPath, metaPath := c.cachePaths(url)
	mb, err := os.ReadFile(metaPath)
	if err != nil || json.Unmarshal(mb, &m) != nil || m.URL != url {
		return "", cacheMeta{}, time.Time{}
	}
	if _, err := os.Stat(bodyPath); err != nil {
		return "", cacheMeta{}, time.Time{}
	}
	at, _ = time.Parse(time.RFC3339, m.FetchedAt)
	return bodyPath, m, at
}

// storeCached keeps a fetched body with its validators and fetch time — validators let
// the next Get revalidate, the time lets GetMeta serve it within MaxAge. It writes the
// body first and the meta last, so a half-written entry is never used. A failed write
// only loses the optimisation, never the fetch, so errors are dropped.
func (c *Client) storeCached(url string, h http.Header, b []byte, at time.Time) {
	if c.CacheDir == "" || os.MkdirAll(c.CacheDir, 0o755) != nil {
		return
	}
	bodyPath, _ := c.cachePaths(url)
	if fsio.WriteAtomic(bodyPath, b, 0o644) == nil {
		c.storeMeta(url, cacheMeta{URL: url, ETag: h.Get("ETag"), LastModified: h.Get("Last-Modified")}, at)
	}
}

// Stored reports the store's copy of url without asking the source: its path, when the source last
// served or confirmed it, and the Last-Modified it gave; ok is false when there is none.
func (c *Client) Stored(url string) (path string, fetchedAt time.Time, lastModified string, ok bool) {
	p, m, at := c.storedFile(url)
	return p, at, m.LastModified, p != ""
}

// Confirm records that url's stored copy is current as of now — what a 304 does — for a caller that
// brought the copy up to date another way; false when there is no stored copy.
func (c *Client) Confirm(url string) bool {
	p, m, _ := c.storedFile(url)
	if p == "" {
		return false
	}
	c.storeMeta(url, m, now().UTC())
	return true
}

func (c *Client) storeMeta(url string, m cacheMeta, at time.Time) {
	m.FetchedAt = at.UTC().Format(time.RFC3339)
	mb, err := json.Marshal(m)
	if err != nil {
		return
	}
	_, metaPath := c.cachePaths(url)
	_ = fsio.WriteAtomic(metaPath, mb, 0o644)
}
