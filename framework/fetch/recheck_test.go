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
	"time"
)

// A 304 says the source's copy did not change, not that the store's copy is usable: the check runs again on the
// stored copy. One it refuses is an error naming it unusable — never served, not even as a stale copy — and loses its
// validators, so the next ask downloads a whole copy. One it accepts is served as before.
func TestNotModifiedRechecksTheStoredCopy(t *testing.T) {
	var conditional atomic.Int32 // requests that carried a validator
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 09 Nov 2026 00:00:00 GMT")
		body := "<html>proxy login</html>"
		if strings.HasSuffix(r.URL.Path, "/good") {
			body = "good"
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	refused := errors.New("not the catalog")
	checkBody := func(b []byte) error {
		if string(b) != "good" {
			return refused
		}
		return nil
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		get  func(c *Client, url string) (string, Meta, error)
	}{
		{"GetChecked", func(c *Client, u string) (string, Meta, error) {
			b, err := c.GetChecked(ctx, u, checkBody)
			return string(b), Meta{}, err
		}},
		{"GetMetaChecked", func(c *Client, u string) (string, Meta, error) {
			b, m, err := c.GetMetaChecked(ctx, u, checkBody)
			return string(b), m, err
		}},
		{"DownloadChecked", func(c *Client, u string) (string, Meta, error) {
			p, m, release, err := c.DownloadChecked(ctx, u, 1<<20, func(p string) error {
				b, err := os.ReadFile(p)
				if err == nil {
					err = checkBody(b)
				}
				return err
			})
			defer release()
			b, _ := os.ReadFile(p)
			return string(b), m, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New()
			c.CacheDir = t.TempDir()
			good := srv.URL + "/" + tc.name + "/good"
			if _, err := c.Get(ctx, good); err != nil {
				t.Fatal(err)
			}
			if body, m, err := tc.get(c, good); err != nil || body != "good" || m.Stale {
				t.Fatalf("a stored copy the check accepts is served on a 304: body=%q meta=%+v err=%v", body, m, err)
			}

			junk := srv.URL + "/" + tc.name + "/junk"
			if _, err := c.Get(ctx, junk); err != nil { // an unchecked fetch stored the proxy page, as an older run did
				t.Fatal(err)
			}
			asked := conditional.Load()
			body, m, err := tc.get(c, junk)
			if conditional.Load() != asked+1 {
				t.Fatal("the stored copy must be revalidated with the source")
			}
			if !errors.Is(err, refused) || !strings.Contains(err.Error(), "stored copy unusable") || body != "" || m.Stale {
				t.Fatalf("a stored copy the check refuses must be an error naming it unusable, never served: body=%q meta=%+v err=%v", body, m, err)
			}
			if _, kept, _ := c.storedFile(junk); kept.URL != junk || kept.ETag != "" || kept.LastModified != "" {
				t.Fatalf("the refused copy must stay without its validators, kept %+v", kept)
			}
			_, _, _ = tc.get(c, junk)
			if conditional.Load() != asked+1 {
				t.Fatal("the next ask must download a whole copy, not revalidate the refused one")
			}
		})
	}
}

// GetMetaChecked checks a body only when it is new, or when a 304 brings the stored copy back. A stored copy served
// within MaxAge with no request, or flagged Stale because the source failed, comes back as stored, check unrun: the
// caller checks what it reads.
func TestMetaCheckedServesAStoredCopyUnchecked(t *testing.T) {
	var hits atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if down.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("<html>proxy login</html>"))
	}))
	defer srv.Close()
	ctx := context.Background()
	c := New()
	c.CacheDir = t.TempDir()
	if _, err := c.Get(ctx, srv.URL); err != nil { // an unchecked fetch stored the proxy page, as an older run did
		t.Fatal(err)
	}
	checks := 0
	check := func([]byte) error { checks++; return errors.New("not the catalog") }
	c.MaxAge = time.Hour
	if b, m, err := c.GetMetaChecked(ctx, srv.URL, check); err != nil || string(b) != "<html>proxy login</html>" || !m.Cached || m.Stale || hits.Load() != 1 {
		t.Fatalf("within MaxAge the stored copy comes back with no request: body=%q meta=%+v err=%v requests=%d", b, m, err, hits.Load())
	}
	c.MaxAge = 0
	down.Store(true)
	if b, m, err := c.GetMetaChecked(ctx, srv.URL, check); err != nil || string(b) != "<html>proxy login</html>" || !m.Stale || !strings.Contains(m.Err, "status 500") || hits.Load() != 2 {
		t.Fatalf("with the source down the stored copy comes back flagged Stale: body=%q meta=%+v err=%v requests=%d", b, m, err, hits.Load())
	}
	if checks != 0 {
		t.Fatalf("a stored copy served without a new body or a 304 must come back unchecked, check ran %d times", checks)
	}
}
