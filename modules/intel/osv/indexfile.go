package osv

import (
	"compress/gzip"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A dump is reduced once and its rows kept beside it in the store (<dump>.idx.gz), so a run
// reads that file instead of decompressing and parsing the whole dump again — Ubuntu's is 8GB
// of JSON, about three minutes. The file is stamped with the dump's size and mtime and is cut
// again whenever the stored dump changes.
const indexFormat = "sigforge-osv-index/10" // bump whenever a row field changes, so older files are cut again

var errStaleIndex = errors.New("osv: index file was cut from another dump")

type indexHeader struct{ Format, Dump string }

// indexRow is a record as the index file holds it (gob encodes exported fields only).
type indexRow struct {
	Pkg, Ecosystem, ID, CVE, Severity string
	Ranges                            []indexRange
	Versions, VulnKeys                []string
	Truncated, Listed                 bool
	Score                             *float64
	Vector, Published, Floor          string
	CWE                               []string
	Skipped                           int // set only on the final row, which has no Pkg: the dump's unreadable entries
}

type indexRange struct{ Typ, Introduced, Fixed, LastAffected string }

func dumpStamp(fi os.FileInfo) string {
	return fmt.Sprintf("%d-%d", fi.Size(), fi.ModTime().UnixNano())
}

// releaseRows keeps the rows a lookup in ecosystem can use: all of them, or for a release
// ("Debian:12") that release's rows and the release-less ones.
func releaseRows(ecosystem string) func(*record) bool {
	if !strings.Contains(ecosystem, ":") {
		return func(*record) bool { return true }
	}
	return func(r *record) bool {
		return strings.EqualFold(r.ecosystem, ecosystem) || !strings.Contains(r.ecosystem, ":")
	}
}

func newIndex(eco string) *Index {
	return &Index{Ecosystem: eco, BuiltAt: time.Now(), byName: make(map[string][]record, 4096)}
}

// buildIndex reduces the dump into an index of the rows keep accepts; with cachePath set it
// also writes every row there for later runs (best effort: a failed write loses the cache,
// never the run).
func buildIndex(ctx context.Context, eco string, r io.ReaderAt, size int64, keep func(*record) bool, cachePath, stamp string) (*Index, error) {
	idx := newIndex(eco)
	w := newIndexWriter(cachePath, stamp)
	skipped, err := reduceZip(ctx, r, size, eco, func(rec *record) error {
		if keep(rec) {
			idx.add(rec)
		}
		w.put(rec)
		return nil
	})
	idx.skipped = skipped
	w.putSkipped(skipped)
	w.finish(err == nil)
	if err != nil {
		return nil, err
	}
	return idx, nil
}

// readIndexFile loads the rows keep accepts from the index cut from the dump with stamp. Any
// error — missing, cut from another dump, another format, damaged — means: cut it again.
func readIndexFile(path, stamp, eco string, keep func(*record) bool) (*Index, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec, err := indexDecoder(f, stamp)
	if err != nil {
		return nil, err
	}
	idx := newIndex(eco)
	trailer := false
	for {
		var row indexRow
		err := dec.Decode(&row)
		if errors.Is(err, io.EOF) && trailer {
			return idx, nil
		}
		if errors.Is(err, io.EOF) {
			return nil, errors.New("osv: index file has no trailer row: its unreadable count is unknown")
		}
		if err != nil {
			return nil, err
		}
		if row.Pkg == "" {
			idx.skipped, trailer = row.Skipped, true
			continue
		}
		rec := row.record()
		if keep(&rec) {
			idx.add(&rec)
		}
	}
}

// indexDecoder reads the header and returns the decoder positioned at the first row.
func indexDecoder(f *os.File, stamp string) (*gob.Decoder, error) {
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	dec := gob.NewDecoder(gz)
	var h indexHeader
	if err := dec.Decode(&h); err != nil {
		return nil, err
	}
	if h.Format != indexFormat || h.Dump != stamp {
		return nil, errStaleIndex
	}
	return dec, nil
}

// indexWriter streams rows to a temp file renamed into place on success. A nil writer (no
// cache path, or the file could not be created) ignores every call.
type indexWriter struct {
	path string
	f    *os.File
	gz   *gzip.Writer
	enc  *gob.Encoder
	err  error
}

func newIndexWriter(path, stamp string) *indexWriter {
	if path == "" {
		return nil
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil
	}
	w := &indexWriter{path: path, f: f, gz: gzip.NewWriter(f)}
	w.enc = gob.NewEncoder(w.gz)
	w.err = w.enc.Encode(indexHeader{Format: indexFormat, Dump: stamp})
	return w
}

func (w *indexWriter) put(r *record) {
	if w == nil || w.err != nil {
		return
	}
	w.err = w.enc.Encode(rowOf(r))
}

// putSkipped writes the trailer row: how many dump entries could not be read.
func (w *indexWriter) putSkipped(n int) {
	if w == nil || w.err != nil {
		return
	}
	w.err = w.enc.Encode(indexRow{Skipped: n})
}

func (w *indexWriter) finish(ok bool) {
	if w == nil {
		return
	}
	if err := w.gz.Close(); w.err == nil {
		w.err = err
	}
	if err := w.f.Close(); w.err == nil {
		w.err = err
	}
	if ok && w.err == nil && os.Rename(w.f.Name(), w.path) == nil {
		return
	}
	os.Remove(w.f.Name())
}

func rowOf(r *record) indexRow {
	row := indexRow{Pkg: r.pkg, Ecosystem: r.ecosystem, ID: r.id, CVE: r.cve, Severity: r.severity, Versions: r.versions, VulnKeys: r.vulnKeys, Truncated: r.truncated, Listed: r.listed, Score: r.score, Vector: r.vector, Published: r.published, Floor: r.floor, CWE: r.cwe}
	for _, g := range r.ranges {
		row.Ranges = append(row.Ranges, indexRange{Typ: g.typ, Introduced: g.introduced, Fixed: g.fixed, LastAffected: g.lastAffected})
	}
	return row
}

func (row indexRow) record() record {
	r := record{pkg: row.Pkg, ecosystem: row.Ecosystem, id: row.ID, cve: row.CVE, severity: row.Severity, versions: row.Versions, vulnKeys: row.VulnKeys, truncated: row.Truncated, listed: row.Listed, score: row.Score, vector: row.Vector, published: row.Published, floor: row.Floor, cwe: row.CWE}
	for _, g := range row.Ranges {
		r.ranges = append(r.ranges, affectedRange{typ: g.Typ, introduced: g.Introduced, fixed: g.Fixed, lastAffected: g.LastAffected})
	}
	return r
}
