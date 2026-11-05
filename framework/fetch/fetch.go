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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultTimeout bounds one fetch end to end.
	DefaultTimeout = 60 * time.Second
	// DefaultMaxBytes caps the response body (64 MiB — comfortably above the
	// largest known fingerprint dataset, far below anything that threatens RAM).
	DefaultMaxBytes int64 = 64 << 20
)

// Client is a reusable bounded GET client. The zero value is not ready; use New.
type Client struct {
	HTTP     *http.Client
	MaxBytes int64
}

// New returns a Client with the default timeout and size ceiling.
func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: DefaultTimeout}, MaxBytes: DefaultMaxBytes}
}

// Get fetches url and returns its body, or an honest error: an empty URL, a
// transport failure, a non-2xx status (with the code), or a body over MaxBytes.
func (c *Client) Get(ctx context.Context, url string) ([]byte, error) {
	if strings.TrimSpace(url) == "" {
		return nil, errors.New("fetch: empty url")
	}
	max := c.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch: request %q: %w", url, err)
	}
	req.Header.Set("User-Agent", "sigforge-fetch")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: get %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch: get %q: status %d", url, resp.StatusCode)
	}
	// Read one byte past the ceiling so an over-limit body is detected, not silently truncated.
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("fetch: read %q: %w", url, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("fetch: %q body exceeds %d bytes", url, max)
	}
	return b, nil
}
