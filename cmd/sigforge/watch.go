package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/fsio"
	"github.com/luannt2002/sigforge/modules/intel/enrich"
	"github.com/luannt2002/sigforge/modules/intel/feedset"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// watchMaxAge is how long watch reads the synced store without asking a source when
// SIGFORGE_CACHE_MAX_AGE is unset: it runs right after sync, and `sources --max-age` flags a stale store.
const watchMaxAge = 24 * time.Hour

// watchState is what the last watch run saw: for each looked-up identity, the leads it had.
type watchState struct {
	Updated string              `json:"updated"`
	Leads   map[string][]string `json:"leads"`
	// Seen is every identity a source has answered for: an identity's first answer is recorded, not news.
	Seen []string `json:"seen,omitempty"`
}

// cmdWatch re-checks an inventory — the packages, SBOM, plugins and libraries a site runs — against
// the sources as they are now (run it after sync) and names what changed since its last run: a new
// advisory for something in use is NEW, one no longer listed is GONE, and what a source did not answer
// for is UNCHECKED (its leads kept, not GONE). An identity's first answer — on the first run, after a
// run nothing answered, or for a package added later — is recorded (FIRST), not NEW. With
// --fail-on-new a NEW lead fails the command, so a timer or monitor can alarm on it; a run no source
// answered for anything fails too, and a run with nothing to look up fails without touching the state.
func cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	statePath := fs.String("state", "", "file keeping what the last run saw (required)")
	failOnNew := fs.Bool("fail-on-new", false, "exit non-zero when a new lead appears")
	sbomPath := fs.String("sbom", "", "a CycloneDX JSON SBOM of the inventory")
	var packages, wpPlugins, wpThemes, jsLibs listFlag
	fs.Var(&packages, "package", "a package in the inventory: a purl or ecosystem:name@version (repeatable)")
	fs.Var(&wpPlugins, "wp-plugin", "a WordPress plugin as slug@version (repeatable)")
	fs.Var(&wpThemes, "wp-theme", "a WordPress theme as slug@version (repeatable)")
	fs.Var(&jsLibs, "jslib", "a JavaScript library as name@version (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *statePath == "" {
		return fmt.Errorf("watch: --state is required")
	}
	inp, skipped, err := buildEnrichInput(packages, *sbomPath, wpPlugins, wpThemes, jsLibs)
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "note: %d SBOM component(s) without a usable purl were not looked up\n", skipped)
	}
	ctx := context.Background()
	client := newClient()
	if client.CacheDir == "" {
		fmt.Fprintf(os.Stderr, "note: %s is unset: every run downloads each OSV dump whole; point watch at the store sync keeps\n", EnvCacheDir)
	} else if strings.TrimSpace(os.Getenv(EnvCacheMaxAge)) == "" {
		client.MaxAge = watchMaxAge
	}
	set := feedset.New(client)
	now, answered, unchecked := leadsByIdentity(enrich.EnrichUnifiedExt(ctx, nil, nil, inp, set.Options))
	for _, note := range set.Notes(ctx) {
		fmt.Fprintln(os.Stderr, note)
	}
	// a run that looked nothing up knows nothing: a diff against it would report every kept lead GONE and erase them
	if len(answered)+len(unchecked) == 0 {
		return fmt.Errorf("watch: nothing to look up: the inventory has no package, plugin, theme, library or SBOM component with a usable purl; the state is left as it was")
	}

	var prev watchState
	b, err := os.ReadFile(*statePath)
	first := os.IsNotExist(err)
	if err != nil && !first {
		return fmt.Errorf("watch: %w", err)
	}
	if !first {
		if err := json.Unmarshal(b, &prev); err != nil {
			return fmt.Errorf("watch: %s is not a watch state: %w", *statePath, err)
		}
	}
	seen := map[string]bool{}
	for _, key := range prev.Seen {
		seen[key] = true
	}
	for key := range unchecked {
		if ids, ok := prev.Leads[key]; ok {
			now[key] = ids // unknown this run, not gone
		}
	}
	news := 0
	if first {
		n := 0
		for _, ids := range now {
			n += len(ids)
		}
		fmt.Printf("first run: %d lead(s) on %d identit(ies) recorded; later runs name what changes\n", n, len(now))
	} else {
		for _, key := range sortedKeys(now, prev.Leads) {
			if !seen[key] {
				fmt.Printf("FIRST  %s  %d lead(s) recorded (its first answer)\n", key, len(now[key]))
				continue
			}
			for _, id := range minus(now[key], prev.Leads[key]) {
				news++
				fmt.Printf("NEW   %s  %s\n", key, id)
			}
			for _, id := range minus(prev.Leads[key], now[key]) {
				fmt.Printf("GONE  %s  %s\n", key, id)
			}
		}
	}
	for _, key := range sortedKeys(unchecked) {
		fmt.Printf("UNCHECKED  %s  (the source did not answer: its leads are kept as they were)\n", key)
	}
	for key := range answered {
		seen[key] = true
	}
	out, err := json.MarshalIndent(watchState{Updated: time.Now().UTC().Format(time.RFC3339), Leads: now, Seen: sortedKeys(seen)}, "", "  ")
	if err != nil {
		return err
	}
	if err := fsio.WriteAtomic(*statePath, out, 0o644); err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	if len(answered) == 0 && len(unchecked) > 0 {
		return fmt.Errorf("watch: no source answered for any of the %d identit(ies) looked up", len(unchecked))
	}
	if *failOnNew && news > 0 {
		return fmt.Errorf("watch: %d new lead(s)", news)
	}
	return nil
}

// leadsByIdentity keys each actionable result's lead ids by what was looked up, and splits the
// identities into those a source answered for and those it did not (unavailable, or off): their
// leads are unknown this run.
func leadsByIdentity(rs []unified.Result) (leads map[string][]string, answered, unchecked map[string]bool) {
	out, answered, unchecked := map[string][]string{}, map[string]bool{}, map[string]bool{}
	for _, r := range rs {
		key := r.Scope + " " + r.Identity + "@" + r.Version
		if r.Answered() {
			answered[key] = true
		} else {
			unchecked[key] = true
		}
		if !r.State.Applicable() {
			continue
		}
		for _, l := range r.Leads {
			out[key] = append(out[key], l.ID)
		}
	}
	for k, ids := range out {
		sort.Strings(ids)
		out[k] = ids
	}
	return out, answered, unchecked
}

func minus(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}

func sortedKeys[V any](maps ...map[string]V) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range maps {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}
