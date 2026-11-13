package osv

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/fsio"
)

// A stored dump is kept current without being downloaded again: OSV rebuilds the dumps all the
// time (so asking for the dump again almost always means its whole size), but it also lists every
// record by its modified time, newest first, in <ecosystem>/modified_id.csv, and serves each record
// on its own at <ecosystem>/<id>.json. A sync reads that list down to the last record it fetched
// and puts each changed record in an overlay beside the dump; a run reads the dump's index with the
// overlay on top. The dump is taken whole again once it is older than fullEvery, or when more than
// incrementalLimit records changed, which also starts a fresh overlay.
var (
	incrementalLimit = 500
	fullEvery        = 24 * time.Hour
)

// markSlack is how far before the dump's Last-Modified the first overlay starts: a record modified
// while the dump was being written may be missing from it, and fetching one twice is harmless.
const markSlack = time.Hour

// errMissing is a 404 from the source: a mirror holding dumps only has no changed-records list and no
// per-record files, so the dump is taken whole. A record the list names exists by definition.
var errMissing = errors.New("not found")

// overlayMark ties an overlay to the dump it patches and records how far the list was read.
type overlayMark struct {
	Stamp string `json:"stamp"`
	Mark  string `json:"mark"`
}

func overlayDir(zipPath string) string { return zipPath + ".overlay" }

func readMark(dir string) overlayMark {
	var m overlayMark
	if b, err := os.ReadFile(filepath.Join(dir, "mark.json")); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// syncChanged brings the stored dump at zipPath up to date from the changed-records list. It
// reports false (and no error) when the dump should be taken whole instead; an error is a broken
// answer that fails the sync, leaving the store as it was.
func (a *Adapter) syncChanged(ctx context.Context, eco, zipPath, lastModified string, fetchedAt time.Time) (bool, error) {
	st, err := os.Stat(zipPath)
	if err != nil {
		return false, err
	}
	dir := overlayDir(zipPath)
	m := readMark(dir)
	if m.Stamp != dumpStamp(st) { // none yet, or an overlay of another dump
		_ = os.RemoveAll(dir)
		start := fetchedAt
		if t, err := http.ParseTime(lastModified); err == nil {
			start = t
		}
		m = overlayMark{Stamp: dumpStamp(st), Mark: start.Add(-markSlack).UTC().Format(time.RFC3339Nano)}
	}
	since, err := time.Parse(time.RFC3339Nano, m.Mark)
	if err != nil {
		return false, nil
	}
	ids, newest, err := a.changedSince(ctx, eco, since)
	if errors.Is(err, errMissing) || (err == nil && len(ids) > incrementalLimit) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	for _, id := range ids {
		if err := a.fetchRecord(ctx, eco, id, dir); errors.Is(err, errMissing) {
			return false, nil
		} else if err != nil {
			return false, err
		}
	}
	if newest.After(since) {
		m.Mark = newest.UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return false, err
	}
	return true, fsio.WriteAtomic(filepath.Join(dir, "mark.json"), b, 0o644) // last: a sync cut short fetches again
}

// changedSince reads modified_id.csv down to since and returns the ids changed after it (each once)
// and the newest time listed. It stops reading past incrementalLimit ids: the caller goes whole.
func (a *Adapter) changedSince(ctx context.Context, eco string, since time.Time) ([]string, time.Time, error) {
	resp, err := a.get(ctx, a.baseURL+"/"+url.PathEscape(eco)+"/modified_id.csv")
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	var ids []string
	var newest time.Time
	seen := map[string]bool{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		at, id, ok := strings.Cut(text, ",")
		if !ok { // an HTML page or an error body in place of the list: not "no change"
			return nil, time.Time{}, fmt.Errorf("osv %s: changed-records list: a line is not \"time,id\"", eco)
		}
		t, err := time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("osv %s: changed-records list: %w", eco, err)
		}
		if newest.IsZero() {
			newest = t
		}
		if !t.After(since) {
			break // newest first: everything below is already in the dump or the overlay
		}
		if id = strings.TrimSpace(id); id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
		if len(ids) > incrementalLimit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, time.Time{}, err
	}
	if newest.IsZero() { // the list holds every record of the ecosystem: an empty one was not read
		return nil, time.Time{}, fmt.Errorf("osv %s: changed-records list lists no record", eco)
	}
	return ids, newest, nil
}

// fetchRecord puts one changed record's JSON in the overlay.
func (a *Adapter) fetchRecord(ctx context.Context, eco, id, dir string) error {
	resp, err := a.get(ctx, a.baseURL+"/"+url.PathEscape(eco)+"/"+url.PathEscape(id)+".json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxEntryBytes+1))
	if err != nil {
		return err
	}
	return fsio.WriteAtomic(filepath.Join(dir, fileName(id)+".json"), b, 0o644)
}

// get asks the source through the client's choke point; a non-2xx answer is an error, errMissing for a 404.
func (a *Adapter) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sigforge-fetch")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, fmt.Errorf("osv: get %q: %w", u, errMissing)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("osv: get %q: status %d", u, resp.StatusCode)
	}
	return resp, nil
}

// fileName keeps an id safe as a file name.
func fileName(id string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' || ('0' <= r && r <= '9') || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') {
			return r
		}
		return '_'
	}, id)
}

// applyOverlay puts the overlay of the dump at zipPath over idx: a changed record replaces every
// row of its id, a withdrawn one takes them away. An overlay record that cannot be read
// counts as an unreadable entry, so the data is not provably whole.
func applyOverlay(idx *Index, zipPath string, st os.FileInfo, eco string, keep func(*record) bool) {
	dir := overlayDir(zipPath)
	if readMark(dir).Stamp != dumpStamp(st) {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	changed := map[string]bool{}
	var add []record
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || name == "mark.json" {
			continue
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			idx.skipped++
			continue
		}
		recs, id, err := decodeEntry(f, eco)
		f.Close()
		if err != nil {
			idx.skipped++
			continue
		}
		changed[id] = true
		add = append(add, recs...)
	}
	if len(changed) == 0 {
		return
	}
	for k, rows := range idx.byName {
		kept := rows[:0]
		for _, r := range rows {
			if changed[r.id] {
				idx.count--
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) == 0 {
			delete(idx.byName, k)
		} else {
			idx.byName[k] = kept
		}
	}
	for i := range add {
		if keep(&add[i]) {
			idx.add(&add[i])
		}
	}
}
