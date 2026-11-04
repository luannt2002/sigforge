// Command sigforge is the operator's tool over the fingerprint data files:
//
//	sigforge baseline                           emit the embedded curated baseline
//	sigforge merge --out DB [--source n=p ...]  merge baseline + normalized sources into one DB
//	sigforge validate FILE                      check a DB's schema version and shape
//
// A --source is a local normalized DB file the operator supplies; earlier
// --source flags outrank later ones, and the baseline outranks them all. Remote
// fetch/normalize adapters are a later phase and are intentionally absent: no
// source URL or vendor is hardcoded, and no third-party data is vendored into
// this repo.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/fsio"
	"github.com/luannt2002/sigforge/modules/intel/baseline"
	"github.com/luannt2002/sigforge/modules/intel/merge"
	"github.com/luannt2002/sigforge/modules/intel/schema"
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
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "sigforge: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sigforge:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sigforge — fingerprint data platform

usage:
  sigforge baseline
  sigforge merge --out DB [--source name=path ...]
  sigforge validate FILE
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

func cmdMerge(args []string) error {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	out := fs.String("out", "", "output DB file (required)")
	var srcs sourceFlag
	fs.Var(&srcs, "source", "a normalized source as name=path (repeatable; earlier = higher trust)")
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
	sources := make([]merge.Source, 0, len(srcs))
	for i, s := range srcs {
		db, err := schema.LoadFile(s.path)
		if err != nil {
			return fmt.Errorf("merge: source %q: %w", s.name, err)
		}
		sources = append(sources, merge.Source{Name: s.name, Trust: len(srcs) - i, Set: db.Fingerprints})
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
