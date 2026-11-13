package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// A sync after the first one reads only the head of modified_id.csv and fetches the records changed
// since the dump — never the dump again — and a run then answers from dump + those records: a new
// advisory is found, a withdrawn one is gone. Too many changes, or an old dump, mean a full download.
func TestSyncFetchesOnlyChangedRecords(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": `{"id":"GHSA-old","affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`})
	dump := mustBytes(r)
	var mu sync.Mutex
	csv := ""
	records := map[string]string{}
	var zips, csvs, recs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch p := req.URL.Path; {
		case p == "/npm/all.zip":
			zips.Add(1)
			w.Header().Set("Last-Modified", "Mon, 09 Nov 2026 02:00:00 GMT")
			_, _ = w.Write(dump)
		case p == "/npm/modified_id.csv":
			csvs.Add(1)
			_, _ = w.Write([]byte(csv))
		case strings.HasPrefix(p, "/npm/") && strings.HasSuffix(p, ".json"):
			recs.Add(1)
			body, ok := records[strings.TrimSuffix(strings.TrimPrefix(p, "/npm/"), ".json")]
			if !ok {
				http.NotFound(w, req)
				return
			}
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	sync := func() {
		t.Helper()
		if _, err := New(srv.URL, c).Sync(ctx, "npm"); err != nil {
			t.Fatal(err)
		}
	}
	look := func(v string) unified.Result {
		rc := fetch.New()
		rc.CacheDir, rc.MaxAge = c.CacheDir, time.Hour
		return New(srv.URL, rc).Lookuper()(ctx, "npm", "lodash", v)
	}
	set := func(newCSV string, recsNow map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		csv, records = newCSV, recsNow
	}

	sync() // no stored dump yet: the full one
	if zips.Load() != 1 {
		t.Fatalf("first sync: %d dump downloads, want 1", zips.Load())
	}
	// the dump was taken whole hours ago: only the incremental sync can make it current again
	metas, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.meta"))
	for _, mp := range metas {
		var m map[string]any
		b, _ := os.ReadFile(mp)
		if json.Unmarshal(b, &m) == nil && strings.HasSuffix(fmt.Sprint(m["url"]), "/npm/all.zip") {
			m["fetched_at"] = time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
			b, _ = json.Marshal(m)
			_ = os.WriteFile(mp, b, 0o644)
		}
	}
	newAdv := `{"id":"GHSA-new","modified":"2026-11-09T04:00:00Z","affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.22"}]}]}]}`
	set("2026-11-09T04:00:00Z,GHSA-new\n2026-11-08T20:00:00Z,GHSA-old\n", map[string]string{"GHSA-new": newAdv})
	sync()
	if zips.Load() != 1 || csvs.Load() != 1 || recs.Load() != 1 {
		t.Fatalf("incremental sync: dump %d (want 1), csv %d (want 1), records %d (want 1)", zips.Load(), csvs.Load(), recs.Load())
	}
	if u := look("4.17.21"); u.State != unified.StateAffectedByAdvisory || len(u.Leads) != 1 || u.Leads[0].ID != "GHSA-new" {
		t.Fatalf("a run after the incremental sync = %+v, want affected by GHSA-new", u)
	}
	if zips.Load() != 1 {
		t.Fatalf("the run must read the store, not download the dump again: %d downloads", zips.Load())
	}
	sync() // nothing new since the last mark: one csv read, no record
	if csvs.Load() != 2 || recs.Load() != 1 {
		t.Fatalf("idle sync: csv %d (want 2), records %d (want 1)", csvs.Load(), recs.Load())
	}
	set("2026-11-09T05:00:00Z,GHSA-new\n2026-11-09T04:00:00Z,GHSA-new\n", map[string]string{
		"GHSA-new": strings.Replace(newAdv, `"modified"`, `"withdrawn":"2020-01-01T00:00:00Z","modified"`, 1)})
	sync()
	if u := look("4.17.21"); u.State == unified.StateAffectedByAdvisory {
		t.Fatalf("a withdrawn advisory must be gone after the next sync: %+v", u)
	}
	old := incrementalLimit
	incrementalLimit = 1
	defer func() { incrementalLimit = old }()
	set("2026-11-09T07:00:00Z,GHSA-a\n2026-11-09T06:00:00Z,GHSA-b\n2026-11-08T20:00:00Z,GHSA-old\n", map[string]string{})
	sync()
	if zips.Load() != 2 {
		t.Fatalf("more changes than the limit must mean a full download: %d dump downloads, want 2", zips.Load())
	}
}

// osvMirror serves one npm dump, its changed-records list and the records, each settable while it runs.
type osvMirror struct {
	mu           sync.Mutex
	dump         []byte
	csv          string
	records      map[string]string
	recordStatus int // non-zero: every record request answers this status
	csvClaim     int // non-zero: the list claims this Content-Length, more than it sends (cut off)
	zips, recs   atomic.Int32
}

func (m *osvMirror) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch p := req.URL.Path; {
	case p == "/npm/all.zip":
		m.zips.Add(1)
		w.Header().Set("Last-Modified", "Mon, 09 Nov 2026 02:00:00 GMT")
		_, _ = w.Write(m.dump)
	case p == "/npm/modified_id.csv":
		if m.csvClaim != 0 {
			w.Header().Set("Content-Length", fmt.Sprint(m.csvClaim))
		}
		_, _ = w.Write([]byte(m.csv))
	case strings.HasSuffix(p, ".json"):
		m.recs.Add(1)
		body, ok := m.records[strings.TrimSuffix(strings.TrimPrefix(p, "/npm/"), ".json")]
		switch {
		case m.recordStatus != 0:
			w.WriteHeader(m.recordStatus)
		case !ok:
			http.NotFound(w, req)
		default:
			_, _ = w.Write([]byte(body))
		}
	default:
		http.NotFound(w, req)
	}
}

func (m *osvMirror) set(f func()) { m.mu.Lock(); defer m.mu.Unlock(); f() }

// mirrorRun syncs from m into a fresh store (the first sync done, then aged so the next one is
// incremental) and returns how to sync again, look lodash up, and age the stored dump.
func mirrorRun(t *testing.T, m *osvMirror) (syncNow func() error, look func(string) unified.Result, age func(time.Duration)) {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	ctx := context.Background()
	c := fetch.New()
	c.CacheDir = t.TempDir()
	syncNow = func() error { _, err := New(srv.URL, c).Sync(ctx, "npm"); return err }
	look = func(v string) unified.Result {
		rc := fetch.New()
		rc.CacheDir, rc.MaxAge = c.CacheDir, time.Hour
		return New(srv.URL, rc).Lookuper()(ctx, "npm", "lodash", v)
	}
	age = func(d time.Duration) {
		metas, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.meta"))
		for _, mp := range metas {
			var meta map[string]any
			b, _ := os.ReadFile(mp)
			if json.Unmarshal(b, &meta) == nil && strings.HasSuffix(fmt.Sprint(meta["url"]), "/npm/all.zip") {
				meta["fetched_at"] = time.Now().Add(-d).UTC().Format(time.RFC3339)
				b, _ = json.Marshal(meta)
				_ = os.WriteFile(mp, b, 0o644)
			}
		}
		bodies, _ := filepath.Glob(filepath.Join(c.CacheDir, "*.body"))
		for _, p := range bodies {
			_ = os.Chtimes(p, time.Now().Add(-d), time.Now().Add(-d))
		}
	}
	if err := syncNow(); err != nil {
		t.Fatal(err)
	}
	age(3 * time.Hour)
	return syncNow, look, age
}

func lodashAdv(id, fixed, extra string) string {
	return `{"id":"` + id + `"` + extra + `,"affected":[{"package":{"name":"lodash","ecosystem":"npm"},` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]}]}`
}

// A record the list names exists by definition: a mirror answering 404 for it holds dumps only, so the
// dump is taken whole — never read as a deletion that would make a real advisory disappear.
func TestSyncTakesTheDumpWholeWhenAListedRecordIsMissing(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	m := &osvMirror{dump: mustBytes(r)}
	syncNow, look, _ := mirrorRun(t, m)
	m.set(func() { m.csv, m.records = "2026-11-09T04:00:00Z,GHSA-old\n", map[string]string{} })
	if err := syncNow(); err != nil {
		t.Fatal(err)
	}
	if m.zips.Load() != 2 {
		t.Fatalf("a missing record must mean the whole dump: %d dump downloads, want 2", m.zips.Load())
	}
	if u := look("4.17.20"); u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("GHSA-old is still in the dump; got %+v", u)
	}
}

// A broken answer fails the sync — the stored dump and its overlay stay as they were, and the
// status file says so — instead of quietly costing a whole download. The list is read only down to
// the mark: what lies below is already in the dump.
func TestSyncFailsOnABrokenChangeAnswer(t *testing.T) {
	for _, tc := range []struct {
		name, csv string
		status    int
		wantErr   bool
	}{
		{"record answers 500", "2026-11-09T04:00:00Z,GHSA-new\n", http.StatusInternalServerError, true},
		{"list opens with a header", "modified,id\n2026-11-09T04:00:00Z,GHSA-new\n", 0, true},
		// an answer that is not the list fails as one that cannot be read: it never passes for "no change"
		{"empty body", "", 0, true},
		{"blank lines only", "\n \n", 0, true},
		{"an HTML page without a comma", "<html><body>proxy login required</body></html>\n", 0, true},
		{"a JSON error without a comma", `{"error":"not found"}`, 0, true},
		{"a line without a comma above the mark", "2026-11-09T04:00:00Z,GHSA-new\nGHSA-x\n2026-11-08T20:00:00Z,GHSA-old\n", 0, true},
		{"blank lines around the list are skipped", "\n2026-11-09T04:00:00Z,GHSA-new\n \t\n2026-11-08T20:00:00Z,GHSA-old\n", 0, false},
		{"garbage below the mark is never read", "2026-11-09T04:00:00Z,GHSA-new\n2026-11-08T20:00:00Z,GHSA-old\nnot-a-time,GHSA-x\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
			m := &osvMirror{dump: mustBytes(r)}
			syncNow, _, _ := mirrorRun(t, m)
			m.set(func() {
				m.csv, m.recordStatus = tc.csv, tc.status
				m.records = map[string]string{"GHSA-new": lodashAdv("GHSA-new", "4.17.22", "")}
			})
			if err := syncNow(); (err != nil) != tc.wantErr {
				t.Fatalf("sync err = %v, want error %v", err, tc.wantErr)
			}
			if m.zips.Load() != 1 {
				t.Fatalf("%d dump downloads, want only the first", m.zips.Load())
			}
		})
	}
}

// A list that cannot be read to its end fails with the read error itself: a list cut off is never taken
// as whole (the mark would pass records not fetched), and a line too long to read is not "lists no record".
func TestSyncFailsOnAListItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name, csv string
		claim     int
		want      string
	}{
		{"cut off after a record", "2026-11-09T04:00:00Z,GHSA-new\n", 1 << 10, "unexpected EOF"},
		{"a line too long to read", strings.Repeat("x", 70000) + ",GHSA-new\n", 0, "token too long"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
			m := &osvMirror{dump: mustBytes(r)}
			syncNow, _, _ := mirrorRun(t, m)
			m.set(func() {
				m.csv, m.csvClaim = tc.csv, tc.claim
				m.records = map[string]string{"GHSA-new": lodashAdv("GHSA-new", "4.17.22", "")}
			})
			if err := syncNow(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("sync err = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

// The first overlay starts an hour before the dump's Last-Modified: a record changed while the dump
// was being written may be missing from it.
func TestFirstOverlayReachesBackBeforeTheDump(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	m := &osvMirror{dump: mustBytes(r)}
	syncNow, look, _ := mirrorRun(t, m)
	m.set(func() {
		m.csv = "2026-11-09T01:30:00Z,GHSA-late\n2026-11-08T20:00:00Z,GHSA-old\n"
		m.records = map[string]string{"GHSA-late": lodashAdv("GHSA-late", "4.17.23", "")}
	})
	if err := syncNow(); err != nil {
		t.Fatal(err)
	}
	if u := look("4.17.22"); u.State != unified.StateAffectedByAdvisory || len(u.Leads) != 1 || u.Leads[0].ID != "GHSA-late" {
		t.Fatalf("a record modified 30 minutes before the dump's Last-Modified must be fetched; got %+v", u)
	}
}

// An overlay patches the dump it was made for: once the dump is taken whole again, the old overlay
// is not laid over the new dump.
func TestOverlayOfAnotherDumpIsNotApplied(t *testing.T) {
	r, _ := makeZip(t, map[string]string{"npm/GHSA-old.json": lodashAdv("GHSA-old", "4.17.21", "")})
	m := &osvMirror{dump: mustBytes(r)}
	syncNow, look, age := mirrorRun(t, m)
	m.set(func() {
		m.csv = "2026-11-09T04:00:00Z,GHSA-new\n"
		m.records = map[string]string{"GHSA-new": lodashAdv("GHSA-new", "4.17.22", "")}
	})
	if err := syncNow(); err != nil {
		t.Fatal(err)
	}
	if u := look("4.17.21"); u.State != unified.StateAffectedByAdvisory {
		t.Fatalf("the overlay must add GHSA-new; got %+v", u)
	}
	r2, _ := makeZip(t, map[string]string{"npm/GHSA-new.json": lodashAdv("GHSA-new", "4.17.21", `,"summary":"fixed earlier"`)})
	m.set(func() { m.dump = mustBytes(r2) })
	age(fullEvery + time.Hour)
	if err := syncNow(); err != nil {
		t.Fatal(err)
	}
	if m.zips.Load() != 2 {
		t.Fatalf("an old dump must be taken whole: %d downloads, want 2", m.zips.Load())
	}
	if u := look("4.17.21"); u.State == unified.StateAffectedByAdvisory {
		t.Fatalf("the new dump says 4.17.21 is fixed; the old overlay must not say otherwise: %+v", u)
	}
	// the next incremental sync starts the new dump's own overlay, so what it fetches is applied
	age(3 * time.Hour)
	m.set(func() {
		m.csv = "2026-11-09T05:00:00Z,GHSA-new2\n"
		m.records = map[string]string{"GHSA-new2": lodashAdv("GHSA-new2", "4.17.30", "")}
	})
	if err := syncNow(); err != nil {
		t.Fatal(err)
	}
	if u := look("4.17.21"); u.State != unified.StateAffectedByAdvisory || len(u.Leads) != 1 || u.Leads[0].ID != "GHSA-new2" {
		t.Fatalf("a record fetched after the dump was taken whole again must be applied: %+v", u)
	}
}
