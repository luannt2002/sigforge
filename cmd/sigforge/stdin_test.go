package main

import (
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// A page on stdin larger than the ceiling is refused before it is read whole — match and enrich exit 1 naming the
// ceiling and print nothing — instead of being held in memory however large; a page within the ceiling is read as before.
func TestStdinOverTheCeilingIsRefused(t *testing.T) {
	offline(t)
	old := maxStdinBytes
	maxStdinBytes = 16
	t.Cleanup(func() { maxStdinBytes = old })
	for name, run := range map[string]func() error{
		"match":  func() error { return cmdMatch(nil) },
		"enrich": func() error { return cmdEnrich(nil) },
	} {
		stdinOf(t, `{"html":"0123456789"}`) // 21 bytes
		var err error
		out := captureStdout(t, func() { err = run() })
		if err == nil || !strings.Contains(err.Error(), "16 bytes") || out != "" {
			t.Errorf("%s with stdin over the ceiling: err=%v out=%q, want a refusal naming the ceiling and no output", name, err, out)
		}
		stdinOf(t, `{"html":"01234"}`) // 16 bytes: at the ceiling
		if err := run(); err != nil {
			t.Errorf("%s with stdin at the ceiling must run: %v", name, err)
		}
	}
}

// The stdin ceiling is the one a fetched body has — 64 MiB, the figure the docs and changelog give.
func TestStdinCeilingIsTheFetchCeiling(t *testing.T) {
	if maxStdinBytes != fetch.DefaultMaxBytes {
		t.Errorf("stdin ceiling = %d, want the fetch ceiling %d", maxStdinBytes, fetch.DefaultMaxBytes)
	}
	if fetch.DefaultMaxBytes != 64<<20 {
		t.Errorf("fetch ceiling = %d, want 64 MiB (the figure the docs give)", fetch.DefaultMaxBytes)
	}
}
