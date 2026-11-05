package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
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
