// Command sigforge is the operator's tool over the fingerprint data files:
//
//	sigforge baseline                             emit the embedded curated baseline
//	sigforge merge --out DB [--source n=p ...]    merge baseline + normalized sources into one DB
//	    [--fetch name[=url] ...] [--manifest F]     ...optionally fetching third-party sources
//	                                                 (writes <DB>.sha256 + <DB>.manifest.json;
//	                                                  archives the prior DB to <DB>.prev*)
//	sigforge refresh --out DB [--source/--fetch ..] re-sync into DB only if no regression vs the
//	    [--allow-removed N]                          current DB (else keep current, rc≠0)
//	sigforge validate FILE                        check a DB's schema version and shape
//	sigforge verify FILE                          check a merged DB: sidecar + schema + manifest compat
//	sigforge rollback DB                          restore the one prior snapshot from <DB>.prev*
//	sigforge diff OLD.json NEW.json               report techs a re-sync added/removed/changed
//	sigforge eol [--explain] TECH VERSION         report a version's end-of-life status (feed off by default)
//	sigforge cve [--explain] CPE VERSION           report known CVE leads for a CPE+version (feed off by default)
//	sigforge inspect [--db F] TECH                data-only lookup of one technology (no match, no network)
//	sigforge match [--db F] [--explain]           match a JSON Page read from stdin, with per-detection evidence
//
// A --source is a local normalized DB file the operator supplies. A --fetch pulls
// a third-party source adapter (webappanalyzer/nuclei/whatweb) at the operator's
// command: the URL comes from the flag (name=url) or the source's env var (e.g.
// SIGFORGE_SOURCE_WEBAPPANALYZER_URL) — never hardcoded, off by default. Earlier
// --source/--fetch flags outrank later ones, and the baseline outranks them all.
// Each fetch records its synced version in the DB entries and in a SYNC-MANIFEST
// file. Fetched third-party data is operator-generated and never vendored here.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/luannt2002/sigforge/modules/intel/feedset"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/define"
	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/framework/fsio"
	"github.com/luannt2002/sigforge/modules/intel/baseline"
	"github.com/luannt2002/sigforge/modules/intel/coverage"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/diff"
	"github.com/luannt2002/sigforge/modules/intel/enrich"
	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/merge"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/refresh"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/source"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "baseline":
		err = cmdBaseline()
	case "merge":
		err = cmdMerge(os.Args[2:])
	case "sync":
		err = cmdSync(os.Args[2:])
	case "sources":
		err = cmdSources(os.Args[2:])
	case "watch":
		err = cmdWatch(os.Args[2:])
	case "refresh":
		err = cmdRefresh(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "rollback":
		err = cmdRollback(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "eol":
		err = cmdEOL(os.Args[2:])
	case "cve":
		err = cmdCVE(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "match":
		err = cmdMatch(os.Args[2:])
	case "coverage":
		err = cmdCoverage(os.Args[2:])
	case "enrich":
		err = cmdEnrich(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", define.ServiceName, os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, define.ServiceName+":", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sigforge — fingerprint data platform

usage:
  sigforge baseline
  sigforge merge --out DB [--source name=path ...] [--fetch name[=url] ...] [--manifest FILE]
  sigforge refresh --out DB [--source ...] [--fetch ...] [--allow-removed N]   (re-sync only if no regression; else keep current, exit non-zero)
  sigforge sync [--osv ECOSYSTEM ...]   (refresh every configured catalog, and the named OSV dumps, into SIGFORGE_CACHE_DIR; with SIGFORGE_CACHE_MAX_AGE later runs use it with no request)
  sigforge sources [--max-age D]   (each source the last sync left: ok / FAILED (why) / never synced / off; exit 1 when one in use is failing or older than D)
  sigforge watch --state FILE [--fail-on-new] [--package REF ...] [--sbom FILE] [--wp-plugin ...] [--jslib ...]   (re-check an inventory after sync: NEW / GONE leads since the last run)
  sigforge validate FILE
  sigforge verify FILE   (checks the DB against its <FILE>.sha256 sidecar + schema + <FILE>.manifest.json compat)
  sigforge rollback FILE (restores the prior snapshot from <FILE>.prev*, if valid)
  sigforge diff OLD.json NEW.json
  sigforge eol [--explain] TECH VERSION
  sigforge cve [--explain] CPE VERSION
  sigforge inspect [--db FILE] TECH
  sigforge match [--db FILE] [--explain]   (reads a JSON Page from stdin)
  sigforge enrich [--db FILE] [--json] [--package REF ...] [--sbom FILE] [--wp-plugin slug@ver ...] [--wp-theme slug@ver ...] [--jslib name@ver ...]
                         (reads a JSON Page from stdin, empty = none; match + every given identity → unified intel)
  sigforge coverage [--db FILE] [--json]   (how much of a DB can reach a CVE lookup / extract a version)

fetch sources (operator-gated, off by default; URL from the flag or the source env var):
  webappanalyzer  Wappalyzer-schema JSON   license GPL-3.0            SIGFORGE_SOURCE_WEBAPPANALYZER_URL
  nuclei          tech-detect templates    license MIT               SIGFORGE_SOURCE_NUCLEI_URL
  whatweb         plugins (Ruby)           license GPL-2.0-or-later   SIGFORGE_SOURCE_WHATWEB_URL

eol feed (operator-gated, off by default; endoflife.date data is MIT):
  endoflife       version→end-of-life      license MIT               SIGFORGE_SOURCE_ENDOFLIFE_URL

cve feed (operator-gated, off by default; NVD CVE API shape, public-domain data):
  cve             CPE+version→known CVEs                             SIGFORGE_SOURCE_CVE_URL

enrich feeds (operator-gated, off by default; used by the enrich pipeline only):
  kev             CVE→exploitation signal (CISA KEV)                 SIGFORGE_SOURCE_KEV_URL
  epss            CVE→exploitation probability (FIRST.org EPSS)      SIGFORGE_SOURCE_EPSS_URL
  cpe-dict        tech→verified CPE identity (NVD CPE dictionary)    SIGFORGE_SOURCE_CPE_DICT_URL
`)
}

func cmdBaseline() error {
	b := append(baseline.Bytes(), '\n')
	_, err := os.Stdout.Write(b)
	return err
}

// sourceFlag collects repeatable --source name=path values in order.
type sourceFlag []struct{ name, path string }

func (s *sourceFlag) String() string { return "" }

func (s *sourceFlag) Set(v string) error {
	name, path, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(path) == "" {
		return fmt.Errorf("want name=path, got %q", v)
	}
	*s = append(*s, struct{ name, path string }{strings.TrimSpace(name), strings.TrimSpace(path)})
	return nil
}

// fetchFlag collects repeatable --fetch name[=url] values in order. A missing url
// falls back to the source's env var at resolution time.
type fetchFlag []struct{ name, url string }

func (f *fetchFlag) String() string { return "" }

func (f *fetchFlag) Set(v string) error {
	name, url, _ := strings.Cut(v, "=")
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("want name or name=url, got %q", v)
	}
	*f = append(*f, struct{ name, url string }{name, strings.TrimSpace(url)})
	return nil
}

func cmdMerge(args []string) error {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	out := fs.String("out", "", "output DB file (required)")
	manifest := fs.String("manifest", "SYNC-MANIFEST.json", "per-source sync-marker file updated on --fetch")
	var srcs sourceFlag
	fs.Var(&srcs, "source", "a normalized local source as name=path (repeatable; earlier = higher trust)")
	var fetches fetchFlag
	fs.Var(&fetches, "fetch", "fetch+normalize a third-party source as name[=url] (repeatable; off unless given)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("merge: --out is required")
	}
	merged, syncMan, err := buildMerged(srcs, fetches, *manifest)
	if err != nil {
		return err
	}
	if err := publish(*out, merged); err != nil {
		return err
	}
	return recordSync(syncMan, *manifest)
}

// buildMerged combines the embedded baseline with the --source files and --fetch
// sources (in flag order, earlier = higher trust) into one in-memory DB. It writes
// nothing — not even the sync manifest, which it returns unsaved (nil when nothing was
// fetched) — so both `merge` and `refresh` can build the same candidate without
// touching disk, and record a sync only once its DB is actually published.
func buildMerged(srcs sourceFlag, fetches fetchFlag, manifestPath string) (*schema.DB, *source.Manifest, error) {
	base, err := baseline.DB()
	if err != nil {
		return nil, nil, err
	}
	sources := make([]merge.Source, 0, len(srcs)+len(fetches))
	for _, s := range srcs {
		db, err := schema.LoadFile(s.path)
		if err != nil {
			return nil, nil, fmt.Errorf("source %q: %w", s.name, err)
		}
		sources = append(sources, merge.Source{Name: s.name, Set: db.Fingerprints})
	}
	var syncMan *source.Manifest
	if len(fetches) > 0 {
		fetched, m, err := runFetches(fetches, manifestPath)
		if err != nil {
			return nil, nil, err
		}
		sources = append(sources, fetched...)
		syncMan = m
	}
	for i := range sources { // assign descending trust from flag order
		sources[i].Trust = len(sources) - i
	}
	return &schema.DB{
		SchemaVersion: schema.SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Fingerprints:  merge.Merge(base.Fingerprints, sources...),
	}, syncMan, nil
}

// recordSync saves the sync manifest after a successful publish; nil means no source
// was fetched, so there is nothing to record.
func recordSync(m *source.Manifest, path string) error {
	if m == nil {
		return nil
	}
	if err := m.Save(path); err != nil {
		return fmt.Errorf("write sync manifest: %w", err)
	}
	return nil
}

// publish writes merged to out as a trusted snapshot: it first archives the snapshot
// currently at out to <out>.prev* (so `rollback` can restore it), then writes the DB,
// its SHA-256 sidecar (tamper/drift detection for `verify`) and a governance manifest
// (which build produced it, over which sources, with the content hash). The manifest
// uses merged.GeneratedAt so it describes exactly these bytes.
func publish(out string, merged *schema.DB) error {
	b, err := merged.JSON()
	if err != nil {
		return err
	}
	content := append(b, '\n')
	if err := archivePrev(out); err != nil {
		return err
	}
	if err := fsio.WriteAtomic(out, content, 0o644); err != nil {
		return err
	}
	sum := merge.Checksum(content)
	if err := fsio.WriteAtomic(merge.SidecarPath(out), merge.FormatSidecar(sum, filepath.Base(out)), 0o644); err != nil {
		return err
	}
	man, err := merge.BuildManifest(merged, sum, merged.GeneratedAt).JSON()
	if err != nil {
		return err
	}
	return fsio.WriteAtomic(merge.ManifestPath(out), man, 0o644)
}

// archivePrev snapshots the DB currently at out (and its sidecar/manifest, when present)
// to <out>.prev* before a merge overwrites it. First merge (no file at out) archives
// nothing; an older DB without a sidecar/manifest archives whatever it does have.
func archivePrev(out string) error {
	if _, err := os.Stat(out); err != nil {
		return nil // nothing to archive (first merge, or out missing)
	}
	prev := out + ".prev"
	for _, f := range []struct{ src, dst string }{
		{out, prev},
		{merge.SidecarPath(out), merge.SidecarPath(prev)},
		{merge.ManifestPath(out), merge.ManifestPath(prev)},
	} {
		data, err := os.ReadFile(f.src)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("merge: archive %q: %w", f.src, err)
		}
		if err := fsio.WriteAtomic(f.dst, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// cmdRollback restores the one previous snapshot archived at <out>.prev* by the last
// overwriting merge. It refuses unless the archived DB still matches its own .prev sidecar
// and parses clean through schema validation — a corrupt or missing archive is never
// rolled back blind.
//
// Honest limit: this is a single-step, file-based rollback (one .prev generation), not a
// versioned history. The next merge overwrites .prev, and rolling back twice is a no-op.
func cmdRollback(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("rollback: want exactly one FILE (the merged DB to restore)")
	}
	out := args[0]
	prev := out + ".prev"
	data, err := fsio.Read(prev)
	if err != nil {
		return fmt.Errorf("rollback: no previous snapshot %q — nothing to roll back", prev)
	}
	sidecar, err := fsio.Read(merge.SidecarPath(prev))
	if err != nil {
		return fmt.Errorf("rollback: previous snapshot has no checksum %q — refusing blind rollback", merge.SidecarPath(prev))
	}
	want, err := merge.ParseSidecar(sidecar)
	if err != nil {
		return fmt.Errorf("rollback: %w", err)
	}
	if got := merge.Checksum(data); got != want {
		return fmt.Errorf("rollback: previous snapshot is CORRUPT (checksum mismatch) — refusing to restore\n  want %s\n  got  %s", want, got)
	}
	db, err := schema.Parse(data)
	if err != nil {
		return fmt.Errorf("rollback: previous snapshot fails schema validation — refusing to restore: %w", err)
	}
	// Restore DB + sidecar (+ manifest when archived). Each write is atomic on its own; the
	// three are not jointly transactional, but each flips old→new cleanly.
	if err := fsio.WriteAtomic(out, data, 0o644); err != nil {
		return err
	}
	if err := fsio.WriteAtomic(merge.SidecarPath(out), sidecar, 0o644); err != nil {
		return err
	}
	if man, err := os.ReadFile(merge.ManifestPath(prev)); err == nil {
		if err := fsio.WriteAtomic(merge.ManifestPath(out), man, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("ok: rolled back %s to the previous snapshot — schema %s, %d fingerprints (checksum + schema verified)\n",
		out, db.SchemaVersion, len(db.Fingerprints))
	return nil
}

// runFetches resolves, fetches and normalizes each --fetch source, stamps the
// synced version onto its entries, and returns the sync manifest updated but UNSAVED —
// the caller records it only after the DB is published. No URL (flag or env) means the
// source is off and errors — nothing is fetched silently.
func runFetches(fetches fetchFlag, manifestPath string) ([]merge.Source, *source.Manifest, error) {
	client := newClient()
	ctx := context.Background()
	man, err := source.LoadManifest(manifestPath)
	if err != nil {
		return nil, nil, err
	}
	out := make([]merge.Source, 0, len(fetches))
	for _, f := range fetches {
		url := f.url
		if url == "" {
			url = strings.TrimSpace(os.Getenv(source.EnvVar(f.name)))
		}
		src, ok := source.New(f.name, url, client)
		if !ok {
			return nil, nil, fmt.Errorf("merge: unknown --fetch source %q", f.name)
		}
		raw, err := src.Fetch(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("merge: fetch %q: %w", f.name, err)
		}
		set, err := src.Normalize(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("merge: normalize %q: %w", f.name, err)
		}
		now := time.Now()
		version := source.Version(url, now)
		source.Stamp(set, src.Name(), src.License(), version)
		out = append(out, merge.Source{Name: src.Name(), Set: set})
		man.Upsert(source.ManifestRow{
			Source:     src.Name(),
			URL:        url,
			Version:    version,
			FetchedAt:  now.UTC().Format(time.RFC3339),
			EntryCount: len(set),
			License:    src.License(),
		})
	}
	return out, man, nil
}

// cmdRefresh orchestrates one honest re-sync: build a candidate DB (same baseline +
// sources + fetch path as `merge`) in memory, validate it, diff it against the live DB
// at --out, and publish ONLY when no regression is found. A candidate that is schema-
// invalid, or that would drop fingerprints past --allow-removed, or that would strip a
// kept tech's CPE, version signal or every detection channel, is refused: the live DB is
// left untouched and the command exits non-zero, printing exactly what regressed. Nothing
// is written until the gate passes, so a bad re-sync can never overwrite good data.
func cmdRefresh(args []string) error {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	out := fs.String("out", "", "the live DB to refresh in place (required)")
	manifest := fs.String("manifest", "SYNC-MANIFEST.json", "per-source sync-marker file updated on --fetch")
	allowRemoved := fs.Int("allow-removed", 0, "fingerprints the refresh may drop before it counts as a regression (operator vouches for intended removals)")
	var srcs sourceFlag
	fs.Var(&srcs, "source", "a normalized local source as name=path (repeatable; earlier = higher trust)")
	var fetches fetchFlag
	fs.Var(&fetches, "fetch", "fetch+normalize a third-party source as name[=url] (repeatable; off unless given)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("refresh: --out is required")
	}

	candidate, syncMan, err := buildMerged(srcs, fetches, *manifest)
	if err != nil {
		return err
	}
	// Validate before the candidate can replace a good DB — a broken regex or bad
	// envelope is refused here (current kept), not published then caught at verify.
	if err := schema.Validate(candidate); err != nil {
		return fmt.Errorf("refresh: candidate invalid — keeping current DB: %w", err)
	}

	// The live DB is the baseline to regress against; a missing one is the first publish
	// (nothing to lose), so current is nil and the gate passes.
	current, err := loadCurrentOrNil(*out)
	if err != nil {
		return err
	}

	rep := refresh.Gate(current, candidate, *allowRemoved)
	fmt.Printf("refresh %s: candidate has +%d added, -%d removed, ~%d changed\n", *out, rep.Added, rep.Removed, rep.Changed)
	if !rep.OK() {
		for _, f := range rep.Findings {
			fmt.Printf("  REGRESSION %-18s %s\n", f.Reason, f.Tech)
		}
		return fmt.Errorf("refresh: REGRESSION — %d check(s) failed, keeping current DB (use --allow-removed=N only for removals you intend)", len(rep.Findings))
	}
	if err := publish(*out, candidate); err != nil {
		return err
	}
	if err := recordSync(syncMan, *manifest); err != nil {
		return err
	}
	if current == nil {
		fmt.Printf("ok: published %s — %d fingerprints (first publish, no prior snapshot to archive)\n",
			*out, len(candidate.Fingerprints))
		return nil
	}
	fmt.Printf("ok: published %s — %d fingerprints, prior snapshot archived to %s.prev (no regression)\n",
		*out, len(candidate.Fingerprints), *out)
	return nil
}

// loadCurrentOrNil loads the DB at path, or returns nil when the file does not exist
// (the first refresh has no current DB to compare against). Other read/parse errors
// surface — a present-but-broken live DB must not be treated as "nothing to lose".
func loadCurrentOrNil(path string) (*schema.DB, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return schema.LoadFile(path)
}

// cmdDiff loads two DBs and prints what a re-sync added/removed/changed between
// them. It always exits 0 (a report, not a gate).
func cmdDiff(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("diff: want exactly OLD.json NEW.json")
	}
	oldDB, err := schema.LoadFile(args[0])
	if err != nil {
		return fmt.Errorf("diff: old %q: %w", args[0], err)
	}
	newDB, err := schema.LoadFile(args[1])
	if err != nil {
		return fmt.Errorf("diff: new %q: %w", args[1], err)
	}
	r := diff.Diff(oldDB, newDB)
	fmt.Printf("diff %s → %s: +%d added, -%d removed, ~%d changed\n",
		args[0], args[1], len(r.Added), len(r.Removed), len(r.Changed))
	printList("added", r.Added)
	printList("removed", r.Removed)
	printList("changed", r.Changed)
	if r.Empty() {
		fmt.Println("(identical)")
	}
	return nil
}

func printList(label string, names []string) {
	for _, n := range names {
		fmt.Printf("  %-8s %s\n", label, n)
	}
}

// cmdEOL maps a tech+version to its end-of-life status via the operator-supplied
// endoflife feed (SIGFORGE_SOURCE_ENDOFLIFE_URL). Off by default: no URL errors.
// With --explain it also prints the version→product→cycle→eol reasoning and the
// feed source behind the status — unknown stays unknown, never "supported".
func cmdEOL(args []string) error {
	fs := flag.NewFlagSet("eol", flag.ContinueOnError)
	explain := fs.Bool("explain", false, "print the version→cycle→eol reasoning and the feed source behind the status")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("eol: want exactly TECH VERSION")
	}
	tech, version := fs.Arg(0), fs.Arg(1)
	a := feedset.NewEOL(newClient())
	st, err := a.EOLStatus(context.Background(), tech, version)
	if err != nil {
		return fmt.Errorf("eol: %w", err)
	}
	if st.Product == "" {
		fmt.Printf("%s %s: unknown (not tracked at endoflife.date)\n", tech, version)
		if *explain {
			fmt.Print(explainEOL(st, tech))
		}
		return nil
	}
	fmt.Printf("%s %s → product=%s cycle=%s eol=%s status=%s\n",
		tech, version, st.Product, orDash(st.Cycle), orDash(st.EOLDate), st.IsEOL)
	if *explain {
		fmt.Print(explainEOL(st, tech))
	}
	return nil
}

// explainEOL returns the version→product→cycle→eol reasoning behind a status, plus
// the feed attribution. It adds no judgement the feed did not make; unknown stays
// unknown, never dressed up as "supported".
func explainEOL(st lifecycle.Status, tech string) string {
	if st.Product == "" {
		return fmt.Sprintf("  why:    no endoflife.date product is mapped for %q → unknown, never 'supported'\n", tech)
	}
	if st.Cycle == "" {
		return fmt.Sprintf("  why:    version %s maps to product %q but matched no release cycle in the feed → unknown, never 'supported'\n", st.Version, st.Product)
	}
	return fmt.Sprintf("  why:    version %s maps to product %q; cycle %q owns it (a cycle is a version prefix), eol field = %s → status %s\n"+
		"  source: endoflife.date (license %s); detected version is spoofable → LEAD to corroborate, not proof\n",
		st.Version, st.Product, st.Cycle, orDash(st.EOLDate), st.IsEOL, lifecycle.License)
}

// cmdCVE maps a CPE+version to known CVE leads via the operator-supplied CVE feed
// (SIGFORGE_SOURCE_CVE_URL, NVD CVE API shape). Off by default: no URL errors. It
// prints only to stdout — no feed data is persisted, so nothing third-party is
// committed. Absence is reported honestly, never as "safe".
func cmdCVE(args []string) error {
	fs := flag.NewFlagSet("cve", flag.ContinueOnError)
	explain := fs.Bool("explain", false, "print why each lead applies: the CPE+version queried, who matched the ranges, and the LEAD-not-proof caveat")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("cve: want exactly CPE VERSION")
	}
	cpe, version := fs.Arg(0), fs.Arg(1)
	c := cve.New(os.Getenv(cve.EnvVar), newClient())
	res, err := c.Lookup(context.Background(), cpe, version)
	if err != nil {
		return fmt.Errorf("cve: %w", err)
	}
	switch res.State {
	case cve.StateUnknown:
		fmt.Printf("%s %s: unknown — not checked (no CPE to query); this is NOT 'no CVEs'\n", cpe, version)
	case cve.StateNoKnownCVE:
		fmt.Printf("%s %s: feed returned no CVE — a LEAD-negative, NOT a safety guarantee (CPE/coverage/version all fallible)\n", res.CPE, version)
	default:
		fmt.Printf("%s %s → %d CVE LEAD(s) (version is spoofable — corroborate):\n", res.CPE, version, len(res.CVEs))
		for _, v := range res.CVEs {
			fmt.Printf("  %-16s CVSS %.1f %-8s source=%s\n", v.ID, v.CVSS, orDash(v.Severity), orDash(v.Source))
		}
	}
	if *explain {
		fmt.Print(explainCVE(res))
	}
	return nil
}

// explainCVE returns the WHY behind a CVE lookup: how the CPE+version was queried,
// who matched the version ranges, and the LEAD-not-proof boundary. It adds no
// judgement the feed did not make — NVD matches the version against its configured
// ranges server-side, so sigforge reports the query, not a re-derived min/max.
func explainCVE(res cve.Result) string {
	if res.State == cve.StateUnknown {
		return "  why:    no CPE to query, so the feed was NOT checked — this is 'unknown', never 'no CVEs = safe'\n"
	}
	return fmt.Sprintf("  why:    CPE queried exactly as the feed attested it (vendor:product never guessed), detected version substituted into the CPE version field\n"+
		"  query:  virtualMatchString=%s\n"+
		"  ranges: NVD applied its own configured version ranges server-side; sigforge does not re-derive min/max here\n"+
		"  caveat: every row is a LEAD (detected version is spoofable; CPE mapping and NVD coverage are fallible), never proof of exploitability\n",
		res.CPE)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// loadDBorBaseline returns the DB at path, or the embedded curated baseline when
// no path is given. Both inspect and match read data only — no network.
func loadDBorBaseline(path string) (*schema.DB, error) {
	if path == "" {
		return baseline.DB()
	}
	return schema.LoadFile(path)
}

// cmdInspect prints the stored facts about one technology: its categories, CPE(s)
// (with the vendor/product the CPE encodes), provenance and license. It runs no
// match and makes no network call — the cheapest, surest explain path.
func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dbPath := fs.String("db", "", "DB file to inspect (default: embedded baseline)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("inspect: want exactly one TECH")
	}
	tech := fs.Arg(0)
	db, err := loadDBorBaseline(*dbPath)
	if err != nil {
		return err
	}
	fp, ok := db.Fingerprints[tech]
	if !ok {
		return fmt.Errorf("inspect: technology %q not found in DB", tech)
	}
	fmt.Printf("technology: %s\n", tech)
	if len(fp.Cats) > 0 {
		fmt.Printf("categories: %v\n", fp.Cats)
	}
	for _, c := range fp.CPE {
		vendor, product := cpeVendorProduct(c)
		fmt.Printf("cpe:        %s (vendor=%s product=%s)\n", c, orDash(vendor), orDash(product))
	}
	fmt.Printf("provenance: %s", orDash(fp.Provenance))
	if fp.ProvenanceVersion != "" {
		fmt.Printf(" @ %s", fp.ProvenanceVersion)
	}
	fmt.Println()
	fmt.Printf("license:    %s\n", orDash(fp.License))
	if len(fp.Implies) > 0 {
		fmt.Printf("implies:    %s\n", strings.Join(fp.Implies, ", "))
	}
	return nil
}

// cpeVendorProduct reads the vendor and product fields of a CPE 2.3 URI
// (cpe:2.3:part:vendor:product:...), the only identity the schema stores.
func cpeVendorProduct(cpe string) (vendor, product string) {
	p := strings.Split(cpe, ":")
	if len(p) > 3 {
		vendor = p[3]
	}
	if len(p) > 4 {
		product = p[4]
	}
	return vendor, product
}

// cmdMatch runs the matcher over a JSON Page read from stdin and prints each
// detection. With --explain it also prints the field/pattern/matched evidence that
// made every detection fire — the traceback a consumer needs to judge the lead.
func cmdMatch(args []string) error {
	fs := flag.NewFlagSet("match", flag.ContinueOnError)
	dbPath := fs.String("db", "", "DB file to match against (default: embedded baseline)")
	explain := fs.Bool("explain", false, "print the field/pattern/matched evidence behind each detection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := loadDBorBaseline(*dbPath)
	if err != nil {
		return err
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("match: read stdin: %w", err)
	}
	var page matcher.Page
	if err := json.Unmarshal(in, &page); err != nil {
		return fmt.Errorf("match: decode Page JSON from stdin: %w", err)
	}
	dets := matcher.Match(db, page)
	if len(dets) == 0 {
		fmt.Println("no detections")
		return nil
	}
	for _, d := range dets {
		line := d.Tech
		if d.Version != "" {
			line += " " + d.Version
		}
		fmt.Printf("%s  (confidence %d", line, d.Confidence)
		if d.Provenance != "" {
			fmt.Printf(", %s/%s", d.Provenance, orDash(d.License))
		}
		fmt.Println(")")
		if !*explain {
			continue
		}
		if len(d.Evidence) == 0 {
			fmt.Println("    (implied — no direct evidence)")
		}
		for _, e := range d.Evidence {
			fmt.Printf("    %-10s pattern=%q matched=%q\n", e.Field, e.Pattern, e.Matched)
		}
	}
	return nil
}

// cmdEnrich runs the full breadth→depth pipeline over a JSON Page from stdin: it
// matches the page, then for each detection resolves identity and queries the CVE,
// EOL and KEV feeds — ALL operator-gated via env URLs (off by default). With no env
// set every feed is off and the output is honest not_checked, with no network and no
// request to any target. It prints []unified.Result as a table, or JSON with --json.
func cmdEnrich(args []string) error {
	fs := flag.NewFlagSet("enrich", flag.ContinueOnError)
	dbPath := fs.String("db", "", "DB file to match against (default: embedded baseline)")
	asJSON := fs.Bool("json", false, "emit the unified results as JSON instead of a table")
	sbomPath := fs.String("sbom", "", "a CycloneDX JSON SBOM: every component's purl is looked up in the OSV source")
	var packages, wpPlugins, wpThemes, jsLibs listFlag
	fs.Var(&packages, "package", "a package to look up in the OSV source: a purl (pkg:npm/lodash@4.17.20) or ecosystem:name@version (repeatable)")
	fs.Var(&wpPlugins, "wp-plugin", "a WordPress plugin as slug@version (repeatable)")
	fs.Var(&wpThemes, "wp-theme", "a WordPress theme as slug@version (repeatable)")
	fs.Var(&jsLibs, "jslib", "a JavaScript library as name@version, beyond those the page reveals (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := loadDBorBaseline(*dbPath)
	if err != nil {
		return err
	}
	inp, skipped, err := buildEnrichInput(packages, *sbomPath, wpPlugins, wpThemes, jsLibs)
	if err != nil {
		return fmt.Errorf("enrich: %w", err)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "note: %d SBOM component(s) without a usable purl were not looked up\n", skipped)
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("enrich: read stdin: %w", err)
	}
	var page matcher.Page // empty stdin = no page: only the packages / plugins / libraries given
	if len(bytes.TrimSpace(in)) > 0 {
		if err := json.Unmarshal(in, &page); err != nil {
			return fmt.Errorf("enrich: decode Page JSON from stdin: %w", err)
		}
	}

	ctx := context.Background()
	client := newClient()
	set := feedset.New(client)
	results := enrich.EnrichUnifiedExt(ctx, matcher.Match(db, page), db, inp, set.Options)
	for _, note := range set.Notes(ctx) { // stderr keeps --json clean
		fmt.Fprintln(os.Stderr, note)
	}
	if note := requestsNote(client.Stats()); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}

	if *asJSON {
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	printEnrich(results)
	return nil
}

// newClient is the one place the CLI builds its fetch client, so every command shares
// the same opt-in disk cache (SIGFORGE_CACHE_DIR; unset = no cache, every fetch downloads).
func newClient() *fetch.Client {
	c, note := feedset.Client()
	if note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	return c
}

// EnvCacheDir names the operator's cache directory for fetched sources.
const EnvCacheDir = feedset.EnvCacheDir

// EnvCacheMaxAge is how long a synced catalog in SIGFORGE_CACHE_DIR is used without asking
// its source (a Go duration, e.g. 24h). Unset = every run asks (304 when unchanged).
const EnvCacheMaxAge = feedset.EnvCacheMaxAge

// syncCatalog stores one catalog and returns its size. The CPE dictionary may outgrow the in-memory
// body cap, so it is streamed to the store — as the identity resolver itself reads it — like an OSV dump.
// It puts a new copy in the store only once the parser a run reads the catalog with accepts it and finds an entry in it.
func syncCatalog(ctx context.Context, client *fetch.Client, s syncSource, u string) (int64, error) {
	if s.env != identity.EnvCPEDictURL {
		b, err := client.GetChecked(ctx, u, s.check)
		return int64(len(b)), err
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	path, meta, release, err := client.DownloadChecked(dctx, u, 2<<30, func(p string) error {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		e, err := identity.ReadDict(f) // decodes the saved file as it reads it, as the resolver loads it, not reading it whole first
		if err == nil && len(e) == 0 {
			err = errors.New("lists no usable CPE entries")
		}
		return err
	})
	defer release()
	if err == nil && meta.Stale {
		err = errors.New(meta.Err) // the store kept its copy: the source did not answer, or the check refused its answer
	}
	if err != nil {
		return 0, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

type syncSource struct {
	name, env string
	check     func([]byte) error // what a run needs of the catalog: its parser reads it and finds an entry
}

// syncSources are the catalogs a run loads whole and once — the ones a synced store can
// serve with no request. Per-query sources (CVE, per-product EOL, EPSS) are not here.
var syncSources = []syncSource{
	{"endoflife bundle", lifecycle.EnvBundleURL, func(b []byte) error { _, err := lifecycle.ParseBundle(b); return err }},
	{"KEV catalog", kev.EnvKEVURL, func(b []byte) error {
		m, err := kev.ParseKEV(b)
		if err == nil && len(m) == 0 {
			err = errors.New("lists no entries")
		}
		return err
	}},
	{"Retire.js repository", jslib.EnvRetireJSURL, func(b []byte) error {
		m, err := jslib.ParseRepo(b)
		if err == nil && len(m) == 0 {
			err = errors.New("lists no libraries")
		}
		return err
	}},
	{"CPE dictionary", identity.EnvCPEDictURL, nil}, // checked in syncCatalog, which decodes the saved file as it reads it
}

// cmdSync refreshes every configured catalog — and, with --osv, each named ecosystem's OSV
// dump — into the local store, always asking each source (304 when unchanged), and reports
// each outcome. A failed source keeps whatever the store already holds and makes the
// command exit non-zero.
func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	var osvEcos listFlag
	fs.Var(&osvEcos, "osv", "OSV ecosystem whose dump to keep in the store (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("sync: unexpected argument %q (sources come from %s and the source URL variables)", fs.Arg(0), EnvCacheDir)
	}
	client := newClient()
	client.MaxAge = 0 // a sync always asks the source
	if client.CacheDir == "" {
		return fmt.Errorf("sync: set %s to the local store directory", EnvCacheDir)
	}
	ctx := context.Background()
	var configured, failed int
	outcomes := map[string]error{}
	defer func() { recordSyncStatus(client.CacheDir, outcomes) }()
	for _, s := range syncSources {
		u := strings.TrimSpace(os.Getenv(s.env))
		if u == "" {
			fmt.Printf("  %-22s off (%s not set)\n", s.name, s.env)
			continue
		}
		configured++
		size, err := syncCatalog(ctx, client, s, u)
		outcomes[s.name] = err
		if err != nil {
			failed++
			fmt.Printf("  %-22s FAILED: %v\n", s.name, err)
			continue
		}
		fmt.Printf("  %-22s ok — %d bytes in the store\n", s.name, size)
	}
	for _, eco := range osvEcos {
		name := "OSV " + eco
		u := strings.TrimSpace(os.Getenv(osv.EnvOSVURL))
		if u == "" {
			fmt.Printf("  %-22s off (%s not set)\n", name, osv.EnvOSVURL)
			continue
		}
		configured++
		n, err := osv.New(u, client).Sync(ctx, eco)
		outcomes[name] = err
		if err != nil {
			failed++
			fmt.Printf("  %-22s FAILED: %v\n", name, err)
			continue
		}
		fmt.Printf("  %-22s ok — %d bytes in the store\n", name, n)
	}
	if note := requestsNote(client.Stats()); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	switch {
	case configured == 0:
		return fmt.Errorf("sync: no catalog source is configured")
	case failed > 0:
		return fmt.Errorf("sync: %d of %d source(s) failed — runs keep what the store already holds", failed, configured)
	}
	return nil
}

// requestsNote renders the run's per-host request counts in host order, so an operator
// sees how much each source was asked; "" when nothing went out.
func requestsNote(stats map[string]fetch.HostStats) string {
	if len(stats) == 0 {
		return ""
	}
	hosts := make([]string, 0, len(stats))
	for h := range stats {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	parts := make([]string, len(hosts))
	for i, h := range hosts {
		s := stats[h]
		parts[i] = fmt.Sprintf("%s=%d sent", h, s.Sent)
		if s.HeldOff > 0 {
			parts[i] += fmt.Sprintf(" (%d held off after a 429)", s.HeldOff)
		}
		if s.Cached > 0 {
			parts[i] += fmt.Sprintf(" (%d served from the local store)", s.Cached)
		}
	}
	return "requests: " + strings.Join(parts, ", ")
}

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

// Set refuses a value that names nothing (an unset "$NAME@$VER"): looked up, its answer would let watch drop kept leads.
func (l *listFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if name, _ := splitAtVersion(v); name == "" {
		return errors.New("empty name (an unset variable?)")
	}
	*l = append(*l, v)
	return nil
}

// buildEnrichInput turns the enrich flags into the identities the page does not reveal:
// packages of any ecosystem (purls or ecosystem:name@version, plus every component of a
// CycloneDX SBOM), WordPress plugins/themes and JS libraries — each once. skipped counts
// SBOM components that carry no usable purl.
func buildEnrichInput(packages []string, sbomPath string, wpPlugins, wpThemes, jsLibs []string) (inp enrich.EnrichInput, skipped int, err error) {
	seen := map[enrich.PkgRef]bool{}
	addPkg := func(r enrich.PkgRef) {
		if !seen[r] {
			seen[r] = true
			inp.Packages = append(inp.Packages, r)
		}
	}
	for _, s := range packages {
		r, err := enrich.ParsePackageRef(s)
		if err != nil {
			return inp, 0, err
		}
		addPkg(r)
	}
	if sbomPath != "" {
		b, err := os.ReadFile(sbomPath)
		if err != nil {
			return inp, 0, err
		}
		refs, n, err := enrich.ParseCycloneDX(b)
		if err != nil {
			return inp, 0, err
		}
		for _, r := range refs {
			addPkg(r)
		}
		skipped = n
	}
	for _, s := range wpPlugins {
		slug, ver := splitAtVersion(s)
		inp.WPSlugs = append(inp.WPSlugs, enrich.WPRef{Slug: slug, Version: ver, Kind: "plugin"})
	}
	for _, s := range wpThemes {
		slug, ver := splitAtVersion(s)
		inp.WPSlugs = append(inp.WPSlugs, enrich.WPRef{Slug: slug, Version: ver, Kind: "theme"})
	}
	for _, s := range jsLibs {
		name, ver := splitAtVersion(s)
		inp.JSLibs = append(inp.JSLibs, enrich.LibRef{Name: name, Version: ver})
	}
	return inp, skipped, nil
}

// splitAtVersion splits "name@version" at its last "@" ("@" at 0 is an npm scope only with a "/": "@scope/name").
func splitAtVersion(s string) (name, version string) {
	if at := strings.LastIndex(s, "@"); at > 0 || at == 0 && !strings.Contains(s, "/") {
		return s[:at], s[at+1:]
	}
	return s, ""
}

// printEnrich renders the unified results as a table, surfacing the honesty signals a
// consumer must not collapse: state, source, freshness, the per-lead KEV/EPSS signal,
// and any note (CPE provenance, version-conflict, why a source was not checked).
func printEnrich(results []unified.Result) {
	if len(results) == 0 {
		fmt.Println("no detections")
		return
	}
	for _, r := range results {
		fmt.Printf("[%s] %s %s → %s", r.Scope, orDash(r.Identity), orDash(r.Version), r.State)
		if r.Source != "" {
			fmt.Printf("  source=%s", r.Source)
		}
		if r.Freshness != unified.FreshnessUnknown {
			fmt.Printf(" freshness=%s", r.Freshness)
		}
		fmt.Println()
		if r.Err != "" {
			fmt.Printf("    note: %s\n", r.Err)
		}
		for _, l := range r.Leads {
			fmt.Printf("    lead %-16s %-8s cvss=%s epss=%s kev=%t\n",
				l.ID, orDash(l.Severity), orDash(l.CVSS), scoreStr(l.EPSS), l.KnownExpl)
		}
	}
	c := coverage.Results(results)
	fmt.Printf("answered %d/%d · unanswered %d (not_checked %d, source_unavailable %d, unknown_product %d, unknown_version %d) — unanswered is not clean\n",
		c.Answered, c.Total, c.Unanswered, c.ByState["not_checked"], c.ByState["source_unavailable"],
		c.ByState["unknown_product"], c.ByState["unknown_version"])
}

// cmdCoverage reports how much of a DB can reach a CVE lookup or extract a version,
// and names the detection-only entries — a gap counted instead of hidden.
func cmdCoverage(args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	dbPath := fs.String("db", "", "DB file to measure (default: embedded baseline)")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := loadDBorBaseline(*dbPath)
	if err != nil {
		return err
	}
	r := coverage.DB(db)
	if *asJSON {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	fmt.Printf("%d fingerprints · %d with attested CPE (CVE-lookup ready) · %d candidate-CPE only (unverified) · %d capture a version\n",
		r.Fingerprints, r.WithCPE, r.CandidateOnly, r.WithVersion)
	fmt.Printf("%d detection-only (no CPE, no version): %s\n", len(r.Blind), strings.Join(r.Blind, ", "))
	fmt.Printf("by provenance: %s\n", countsStr(r.ByProvenance))
	fmt.Printf("by license:    %s\n", countsStr(r.ByLicense))
	return nil
}

// countsStr renders a count map in key order so the report is deterministic.
func countsStr(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, m[k])
	}
	return strings.Join(parts, " ")
}

func scoreStr(s *float64) string {
	if s == nil {
		return "-"
	}
	return strconv.FormatFloat(*s, 'f', -1, 64)
}

func cmdValidate(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("validate: want exactly one FILE")
	}
	db, err := schema.LoadFile(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("ok: schema %s, %d fingerprints\n", db.SchemaVersion, len(db.Fingerprints))
	return nil
}

// cmdVerify proves, before a consumer trusts a merged DB, that it still hashes to the
// SHA-256 recorded in its `<file>.sha256` sidecar (no tamper/drift since merge) and
// still parses clean through schema.Parse — which runs the full schema.Validate,
// regex compilation included, so a checksum-valid DB carrying a broken regex is caught
// here as drift rather than silently dropped at match time. A missing sidecar is
// reported as "no checksum", never treated as OK; any mismatch exits non-zero.
//
// It then reads the governance manifest (<file>.manifest.json): a DB whose manifest
// records an incompatible schema/engine MAJOR, or whose recorded content hash does not
// describe this DB, is refused (INCOMPATIBLE / MISMATCH, exit non-zero). A missing
// manifest is a warning — integrity is still checked, but it is not a trusted snapshot.
//
// Honest limit: SHA-256 here detects accidental drift and naive tampering only. It is
// NOT authenticity — an attacker who rewrites both the DB and its sidecar passes. Real
// signing (a key the operator trusts, e.g. TUF/Sigstore) is out of scope.
func cmdVerify(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("verify: want exactly one FILE")
	}
	dbPath := args[0]
	data, err := fsio.Read(dbPath)
	if err != nil {
		return err
	}
	sidecar, err := fsio.Read(merge.SidecarPath(dbPath))
	if err != nil {
		return fmt.Errorf("verify: no checksum sidecar %q — integrity NOT verified (this is not 'ok')", merge.SidecarPath(dbPath))
	}
	want, err := merge.ParseSidecar(sidecar)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	sum := merge.Checksum(data)
	if sum != want {
		return fmt.Errorf("verify: CHECKSUM MISMATCH — TAMPER/DRIFT detected\n  want %s\n  got  %s", want, sum)
	}
	db, err := schema.Parse(data)
	if err != nil {
		return fmt.Errorf("verify: checksum matches but schema is invalid (DRIFT): %w", err)
	}

	// Governance: a trusted snapshot carries a manifest. Confirm a compatible build
	// produced it and that it describes THIS DB; a missing manifest is a warning (integrity
	// still checked), never a clean "ok".
	manPath := merge.ManifestPath(dbPath)
	manBytes, manErr := fsio.Read(manPath)
	if manErr != nil {
		fmt.Printf("ok: %s — sha256 matches sidecar, schema %s, %d fingerprints\n", dbPath, db.SchemaVersion, len(db.Fingerprints))
		fmt.Printf("WARNING: no manifest %q — compatibility/provenance NOT verified (integrity checked, but this is not a trusted snapshot)\n", manPath)
		fmt.Println("note: sha256 proves integrity/drift only, NOT authenticity — real signing (TUF/Sigstore) is out of scope")
		return nil
	}
	man, err := merge.ParseManifest(manBytes)
	if err != nil {
		return fmt.Errorf("verify: manifest %q: %w", manPath, err)
	}
	if err := man.Compatible(); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if man.ContentSHA256 != "" && man.ContentSHA256 != sum {
		return fmt.Errorf("verify: manifest/DB MISMATCH — manifest content_sha256 does not describe this DB\n  manifest %s\n  db       %s", man.ContentSHA256, sum)
	}
	fmt.Printf("ok: %s — sha256 matches sidecar, manifest compatible (schema %s, engine %s), %d fingerprints\n",
		dbPath, man.SchemaVersion, man.EngineVersion, len(db.Fingerprints))
	fmt.Println("note: sha256 proves integrity/drift only, NOT authenticity — real signing (TUF/Sigstore) is out of scope")
	return nil
}
