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
	"github.com/luannt2002/sigforge/modules/intel/jslib"
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
// advisory for something in use is NEW, and one a whole answer no longer lists is GONE. UNCHECKED names
// an identity a source did not answer for, and one whose answer cannot rule out a recorded lead it
// leaves out (data the source cannot prove whole, a version it could not compare): the lead is kept,
// not GONE. An identity with leads that is no longer in the inventory is REMOVED: its leads leave the
// state, and listed again they are NEW. An identity's first answer — on the first run, after a run
// nothing answered, or for a package added later — is recorded (FIRST), not NEW. With --fail-on-new a
// NEW lead fails the command, so a timer or monitor can alarm on it; a run no source answered for
// anything fails too, leaving an existing state as it was, and a run with nothing to look up fails
// without touching the state. The embedded Retire.js sample is not a source: a run only it answered
// for is one no source answered for, records nothing it said and fails naming it; beside a source's
// answer, the sample's answer counts as any other.
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
	// shortcut: unified.Result does not carry jslib.Result.Sample, so watch wires the JS source itself; move the flag into feedset when another caller needs it
	js, sampled := jslib.New(os.Getenv(jslib.EnvRetireJSURL), client), map[string]bool{}
	set.Options.JS = func(ctx context.Context, name, version string) unified.Result {
		res := js.LookupOne(ctx, name, version)
		u := jslib.ToUnified(res)
		if res.Sample {
			sampled[u.Scope+" "+u.Identity+"@"+u.Version] = true
		}
		return u
	}
	rs := enrich.EnrichUnifiedExt(ctx, nil, nil, inp, set.Options)
	now, answered, unchecked, notWhole := leadsByIdentity(rs)
	onlySample, why := len(answered) > 0, ""
	for key := range answered {
		onlySample = onlySample && sampled[key]
	}
	if onlySample { // the sample ships in the binary: a run only it answered for is a run no source answered for
		for key := range answered {
			unchecked[key] = true
			delete(now, key)
		}
		answered, notWhole = map[string]bool{}, map[string]string{}
		why = " (only the embedded Retire.js sample answered: it ships in the binary and is not a source)"
	}
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
	carryReleaseLessKeys(prev.Leads, seen, rs)
	for key := range unchecked {
		if ids := minus(prev.Leads[key], now[key]); len(ids) > 0 {
			now[key] = append(now[key], ids...) // unknown this run, not gone
			sort.Strings(now[key])
		}
	}
	kept := map[string]string{}
	for key, why := range notWhole {
		if ids := minus(prev.Leads[key], now[key]); len(ids) > 0 {
			now[key] = append(now[key], ids...) // absent from an answer that cannot rule them out, not gone
			sort.Strings(now[key])
			kept[key] = fmt.Sprintf("%s: %d lead(s) absent from its answer are kept", why, len(ids))
		}
	}
	news := 0
	if first {
		n := 0
		for _, ids := range now {
			n += len(ids)
		}
		fmt.Printf("first run: %d lead(s) on %d identit(ies) recorded; later runs name what changes\n", n, len(now))
	} else if len(answered) > 0 { // a run no source answered for knows of no change
		for _, key := range sortedKeys(now, prev.Leads) {
			if !answered[key] && !unchecked[key] {
				fmt.Printf("REMOVED  %s  %d lead(s) dropped: it is no longer in the inventory\n", key, len(prev.Leads[key]))
				continue
			}
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
	for _, key := range sortedKeys(kept) {
		fmt.Printf("UNCHECKED  %s  (%s)\n", key, kept[key])
	}
	if len(answered) == 0 && !first { // the state it would write could only lose what the last answers recorded
		return fmt.Errorf("watch: no source answered for any of the %d identit(ies) looked up%s; the state is left as it was", len(unchecked), why)
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
		return fmt.Errorf("watch: no source answered for any of the %d identit(ies) looked up%s", len(unchecked), why)
	}
	if *failOnNew && news > 0 {
		return fmt.Errorf("watch: %d new lead(s)", news)
	}
	return nil
}

// leadsByIdentity keys each actionable result's lead ids by what was looked up, and splits the
// identities into those a source answered for and those it did not (unavailable, or off): their
// leads are unknown this run. An answered identity whose answer cannot rule a lead out — from data the
// source cannot prove whole, or for a version it could not compare — is in notWhole with why.
func leadsByIdentity(rs []unified.Result) (leads map[string][]string, answered, unchecked map[string]bool, notWhole map[string]string) {
	out, answered, unchecked, notWhole := map[string][]string{}, map[string]bool{}, map[string]bool{}, map[string]string{}
	for _, r := range rs {
		key := r.Scope + " " + r.Identity + "@" + r.Version
		switch {
		case !r.LookedUp():
			unchecked[key] = true
		case r.State == unified.StateUnknownVersion:
			answered[key], notWhole[key] = true, "the source could not compare the version with its advisories"
		case !r.FullData:
			answered[key], notWhole[key] = true, "the source cannot prove its data whole"
		default:
			answered[key] = true
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
	return out, answered, unchecked, notWhole
}

// carryReleaseLessKeys reads a state written while a distro key held no release — one "ecosystem:Debian n@v" for
// every release. In any run, the first after the upgrade or a later one, each release key the state does not hold
// yet whose release-less key (the distro is the scope up to its first ":", as Ubuntu's release "22.04:LTS" holds
// one) is still in the state takes that key's leads and Seen, and the key leaves the state: its leads are neither
// dropped nor named NEW.
func carryReleaseLessKeys(leads map[string][]string, seen map[string]bool, rs []unified.Result) {
	from := map[string]string{} // a release key → the release-less key it takes over
	for _, r := range rs {
		eco, ok := strings.CutPrefix(r.Scope, "ecosystem:")
		distro, _, released := strings.Cut(eco, ":")
		id := " " + r.Identity + "@" + r.Version
		key, old := r.Scope+id, "ecosystem:"+distro+id
		if ok && released && len(leads[key]) == 0 && !seen[key] {
			from[key] = old
		}
	}
	for key, old := range from {
		if len(leads[old]) > 0 {
			leads[key] = leads[old]
		}
		if seen[old] {
			seen[key] = true
		}
	}
	for _, old := range from {
		delete(leads, old)
		delete(seen, old)
	}
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
