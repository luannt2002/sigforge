// Command sigforge is the operator's tool over the fingerprint data files:
//
//	sigforge baseline                             emit the embedded curated baseline
//	sigforge merge --out DB [--source n=p ...]    merge baseline + normalized sources into one DB
//	    [--fetch name[=url] ...] [--manifest F]     ...optionally fetching third-party sources
//	sigforge validate FILE                        check a DB's schema version and shape
//	sigforge verify FILE                          check a merged DB against its .sha256 sidecar + schema
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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/define"
	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/framework/fsio"
	"github.com/luannt2002/sigforge/modules/intel/baseline"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/diff"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/merge"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/source"
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
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
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
  sigforge validate FILE
  sigforge verify FILE   (checks the DB against its <FILE>.sha256 sidecar + schema)
  sigforge diff OLD.json NEW.json
  sigforge eol [--explain] TECH VERSION
  sigforge cve [--explain] CPE VERSION
  sigforge inspect [--db FILE] TECH
  sigforge match [--db FILE] [--explain]   (reads a JSON Page from stdin)

fetch sources (operator-gated, off by default; URL from the flag or the source env var):
  webappanalyzer  Wappalyzer-schema JSON   license GPL-3.0            SIGFORGE_SOURCE_WEBAPPANALYZER_URL
  nuclei          tech-detect templates    license MIT               SIGFORGE_SOURCE_NUCLEI_URL
  whatweb         plugins (Ruby)           license GPL-2.0-or-later   SIGFORGE_SOURCE_WHATWEB_URL

eol feed (operator-gated, off by default; endoflife.date data is MIT):
  endoflife       version→end-of-life      license MIT               SIGFORGE_SOURCE_ENDOFLIFE_URL

cve feed (operator-gated, off by default; NVD CVE API shape, public-domain data):
  cve             CPE+version→known CVEs                             SIGFORGE_SOURCE_CVE_URL
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

	base, err := baseline.DB()
	if err != nil {
		return err
	}

	// Local --source files, then fetched sources, in flag order; earlier = higher trust.
	sources := make([]merge.Source, 0, len(srcs)+len(fetches))
	for _, s := range srcs {
		db, err := schema.LoadFile(s.path)
		if err != nil {
			return fmt.Errorf("merge: source %q: %w", s.name, err)
		}
		sources = append(sources, merge.Source{Name: s.name, Set: db.Fingerprints})
	}
	if len(fetches) > 0 {
		fetched, err := runFetches(fetches, *manifest)
		if err != nil {
			return err
		}
		sources = append(sources, fetched...)
	}
	for i := range sources { // assign descending trust from flag order
		sources[i].Trust = len(sources) - i
	}

	merged := &schema.DB{
		SchemaVersion: schema.SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Fingerprints:  merge.Merge(base.Fingerprints, sources...),
	}
	b, err := merged.JSON()
	if err != nil {
		return err
	}
	content := append(b, '\n')
	if err := fsio.WriteAtomic(*out, content, 0o644); err != nil {
		return err
	}
	// Emit a SHA-256 sidecar so a consumer can detect tamper/drift (see `verify`).
	sum := merge.Checksum(content)
	return fsio.WriteAtomic(merge.SidecarPath(*out), merge.FormatSidecar(sum, filepath.Base(*out)), 0o644)
}

// runFetches resolves, fetches and normalizes each --fetch source, stamps the
// synced version onto its entries, and updates the sync manifest. No URL (flag or
// env) means the source is off and errors — nothing is fetched silently.
func runFetches(fetches fetchFlag, manifestPath string) ([]merge.Source, error) {
	client := fetch.New()
	ctx := context.Background()
	man, err := source.LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	out := make([]merge.Source, 0, len(fetches))
	for _, f := range fetches {
		url := f.url
		if url == "" {
			url = strings.TrimSpace(os.Getenv(source.EnvVar(f.name)))
		}
		src, ok := source.New(f.name, url, client)
		if !ok {
			return nil, fmt.Errorf("merge: unknown --fetch source %q", f.name)
		}
		raw, err := src.Fetch(ctx)
		if err != nil {
			return nil, fmt.Errorf("merge: fetch %q: %w", f.name, err)
		}
		set, err := src.Normalize(raw)
		if err != nil {
			return nil, fmt.Errorf("merge: normalize %q: %w", f.name, err)
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
	if err := man.Save(manifestPath); err != nil {
		return nil, fmt.Errorf("merge: write manifest: %w", err)
	}
	return out, nil
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
	a := lifecycle.New(os.Getenv(lifecycle.EnvVar), fetch.New())
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
	c := cve.New(os.Getenv(cve.EnvVar), fetch.New())
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
	if got := merge.Checksum(data); got != want {
		return fmt.Errorf("verify: CHECKSUM MISMATCH — TAMPER/DRIFT detected\n  want %s\n  got  %s", want, got)
	}
	db, err := schema.Parse(data)
	if err != nil {
		return fmt.Errorf("verify: checksum matches but schema is invalid (DRIFT): %w", err)
	}
	fmt.Printf("ok: %s — sha256 matches sidecar, schema %s, %d fingerprints\n", dbPath, db.SchemaVersion, len(db.Fingerprints))
	fmt.Println("note: sha256 proves integrity/drift only, NOT authenticity — real signing (TUF/Sigstore) is out of scope")
	return nil
}
