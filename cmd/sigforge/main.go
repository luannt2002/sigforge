// Command sigforge is the operator's tool over the fingerprint data files:
//
//	sigforge baseline                             emit the embedded curated baseline
//	sigforge merge --out DB [--source n=p ...]    merge baseline + normalized sources into one DB
//	    [--fetch name[=url] ...] [--manifest F]     ...optionally fetching third-party sources
//	sigforge validate FILE                        check a DB's schema version and shape
//	sigforge diff OLD.json NEW.json               report techs a re-sync added/removed/changed
//	sigforge eol TECH VERSION                     report a version's end-of-life status (feed off by default)
//	sigforge cve CPE VERSION                       report known CVE leads for a CPE+version (feed off by default)
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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/define"
	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/framework/fsio"
	"github.com/luannt2002/sigforge/modules/intel/baseline"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/diff"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
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
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "eol":
		err = cmdEOL(os.Args[2:])
	case "cve":
		err = cmdCVE(os.Args[2:])
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
  sigforge diff OLD.json NEW.json
  sigforge eol TECH VERSION
  sigforge cve CPE VERSION

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
	return fsio.WriteAtomic(*out, append(b, '\n'), 0o644)
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
func cmdEOL(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("eol: want exactly TECH VERSION")
	}
	a := lifecycle.New(os.Getenv(lifecycle.EnvVar), fetch.New())
	st, err := a.EOLStatus(context.Background(), args[0], args[1])
	if err != nil {
		return fmt.Errorf("eol: %w", err)
	}
	if st.Product == "" {
		fmt.Printf("%s %s: unknown (not tracked at endoflife.date)\n", args[0], args[1])
		return nil
	}
	fmt.Printf("%s %s → product=%s cycle=%s eol=%s status=%s\n",
		args[0], args[1], st.Product, orDash(st.Cycle), orDash(st.EOLDate), st.IsEOL)
	return nil
}

// cmdCVE maps a CPE+version to known CVE leads via the operator-supplied CVE feed
// (SIGFORGE_SOURCE_CVE_URL, NVD CVE API shape). Off by default: no URL errors. It
// prints only to stdout — no feed data is persisted, so nothing third-party is
// committed. Absence is reported honestly, never as "safe".
func cmdCVE(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("cve: want exactly CPE VERSION")
	}
	c := cve.New(os.Getenv(cve.EnvVar), fetch.New())
	res, err := c.Lookup(context.Background(), args[0], args[1])
	if err != nil {
		return fmt.Errorf("cve: %w", err)
	}
	switch res.State {
	case cve.StateUnknown:
		fmt.Printf("%s %s: unknown — not checked (no CPE to query); this is NOT 'no CVEs'\n", args[0], args[1])
	case cve.StateNoKnownCVE:
		fmt.Printf("%s %s: feed returned no CVE — a LEAD-negative, NOT a safety guarantee (CPE/coverage/version all fallible)\n", res.CPE, args[1])
	default:
		fmt.Printf("%s %s → %d CVE LEAD(s) (version is spoofable — corroborate):\n", res.CPE, args[1], len(res.CVEs))
		for _, v := range res.CVEs {
			fmt.Printf("  %-16s CVSS %.1f %-8s source=%s\n", v.ID, v.CVSS, orDash(v.Severity), orDash(v.Source))
		}
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
