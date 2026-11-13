package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// modelRuns and modelSeed fix what the model test generates, so a failing run replays as it failed.
const modelRuns, modelSeed = 500, 20261110

// modelPool is every lead id a generated run draws from: four, so the identities of a run often share an advisory.
var modelPool = []string{"S-1", "S-2", "S-3", "S-4"}

// modelIdentity is one identity of a generated run: how it stood in the state before the run and what its source
// says now.
type modelIdentity struct {
	kind             string
	debian           bool // a Debian package, its OSV dump read whole; else a WordPress plugin, the feed never whole
	name             string
	listed, answered bool // in the inventory; its source looks it up
	seenBefore       bool
	before, feed     []string // its leads in the state before the run; the advisories its source lists for its version
	pastFix          []string // advisories the dump lists for the package with a fix before its version: no lead
}

func (m modelIdentity) key() string {
	if m.debian && m.answered {
		return "ecosystem:Debian:12 " + m.name + "@1.0-1" // looked up with its release
	}
	if m.debian {
		return "ecosystem:Debian " + m.name + "@1.0-1"
	}
	return "wordpress:plugin " + m.name + "@4.0"
}

// modelKind is one of the ten kinds of TestWatchNamesEachIdentityOfARunOnItsOwn, its leads drawn from modelPool.
type modelKind struct {
	name                         string
	scopes                       string // D: a Debian package; W: a WordPress plugin
	listed, answered, seenBefore bool
	sets                         func(r *rand.Rand) (before, feed []string)
}

var modelKinds = []modelKind{
	{"NEW", "D", true, true, true, func(r *rand.Rand) ([]string, []string) {
		added := someOf(r, modelPool)
		before := anyOf(r, setMinus(modelPool, added))
		return before, setUnion(before, added)
	}},
	{"GONE", "D", true, true, true, func(r *rand.Rand) ([]string, []string) {
		gone := someOf(r, modelPool)
		feed := anyOf(r, setMinus(modelPool, gone))
		return setUnion(feed, gone), feed
	}},
	{"unchanged", "DW", true, true, true, func(r *rand.Rand) ([]string, []string) {
		ids := someOf(r, modelPool)
		return ids, ids
	}},
	{"UNCHECKED, its source down", "DW", true, false, true, func(r *rand.Rand) ([]string, []string) { return someOf(r, modelPool), nil }},
	{"UNCHECKED, its data not whole", "W", true, true, true, func(r *rand.Rand) ([]string, []string) {
		kept := someOf(r, modelPool)
		feed := anyOf(r, setMinus(modelPool, kept))
		return setUnion(feed, kept), feed
	}},
	{"REMOVED", "DW", false, false, true, func(r *rand.Rand) ([]string, []string) { return someOf(r, modelPool), nil }},
	{"FIRST", "DW", true, true, false, func(r *rand.Rand) ([]string, []string) { return nil, someOf(r, modelPool) }},
	{"no lead, answered whole", "D", true, true, false, nil},
	{"no lead, its data not whole", "W", true, true, false, nil},
	{"no lead, its source down", "DW", true, false, false, nil},
}

// anyOf draws a subset of from, each id on a coin; someOf draws one with at least one id.
func anyOf(r *rand.Rand, from []string) []string {
	var out []string
	for _, id := range from {
		if r.Intn(2) == 0 {
			out = append(out, id)
		}
	}
	return out
}

func someOf(r *rand.Rand, from []string) []string {
	for {
		if ids := anyOf(r, from); len(ids) > 0 {
			return ids
		}
	}
}

// setMinus and setUnion are the model's own, so it shares no helper with watch.go.
func setMinus(a, b []string) []string {
	var out []string
	for _, id := range a {
		if !slices.Contains(b, id) {
			out = append(out, id)
		}
	}
	return out
}

func setUnion(a, b []string) []string {
	out := append(slices.Clone(a), setMinus(b, a)...)
	slices.Sort(out)
	return out
}

// modelDraw draws one run of 3–5 identities, each of a kind drawn on its own. One run in ten lists only identities
// that left the inventory and one in ten only identities no source answers for, so both rules that hold for a whole
// run come up often; one in five is a first run.
func modelDraw(r *rand.Rand) (ids []modelIdentity, first, failOnNew bool) {
	first, failOnNew = r.Intn(5) == 0, r.Intn(4) > 0
	kinds := modelKinds
	switch r.Intn(10) {
	case 0:
		kinds = slices.DeleteFunc(slices.Clone(modelKinds), func(k modelKind) bool { return k.listed })
	case 1:
		kinds = slices.DeleteFunc(slices.Clone(modelKinds), func(k modelKind) bool { return k.answered })
	}
	for i := range 3 + r.Intn(3) {
		k := kinds[r.Intn(len(kinds))]
		m := modelIdentity{kind: k.name, debian: k.scopes[r.Intn(len(k.scopes))] == 'D', name: strings.Repeat(string(rune('a'+i)), 3),
			listed: k.listed, answered: k.answered, seenBefore: k.seenBefore && !first}
		if k.sets != nil {
			m.before, m.feed = k.sets(r)
		}
		if first {
			m.before = nil
		}
		if m.debian && m.listed && m.answered && r.Intn(2) == 0 { // half the packages also sit in advisories fixed before their version
			m.pastFix = anyOf(r, setMinus(modelPool, m.feed))
		}
		ids = append(ids, m)
	}
	return ids, first, failOnNew
}

// alone is what the contract says one identity prints, records and counts as NEW, whatever stands beside it.
func (m modelIdentity) alone() (lines, recorded []string, seen bool, news int) {
	key := m.key()
	switch {
	case !m.listed: // it left the inventory — REMOVED when it had leads; they leave the state, it stays seen
		if len(m.before) > 0 {
			lines = []string{fmt.Sprintf("REMOVED  %s  %d lead(s) dropped: it is no longer in the inventory", key, len(m.before))}
		}
		return lines, nil, m.seenBefore, 0
	case !m.answered: // not looked up (its source off or down) — UNCHECKED, its leads kept as they were
		return []string{"UNCHECKED  " + key + "  (the source did not answer: its leads are kept as they were)"}, m.before, m.seenBefore, 0
	case !m.seenBefore: // its first answer is where it stands: recorded, never NEW
		if len(m.feed) > 0 {
			lines = []string{fmt.Sprintf("FIRST  %s  %d lead(s) recorded (its first answer)", key, len(m.feed))}
		}
		return lines, m.feed, true, 0
	}
	for _, id := range setMinus(m.feed, m.before) {
		lines = append(lines, "NEW   "+key+"  "+id)
	}
	news = len(lines)
	absent := setMinus(m.before, m.feed)
	if m.debian { // an answer from a whole OSV dump: what it leaves out is GONE
		for _, id := range absent {
			lines = append(lines, "GONE  "+key+"  "+id)
		}
		return lines, m.feed, true, news
	}
	// an answer without whole data (WordPress here) never makes a lead GONE: what it leaves out is kept
	if len(absent) > 0 {
		lines = append(lines, fmt.Sprintf("UNCHECKED  %s  (the source cannot prove its data whole: %d lead(s) absent from its answer are kept)", key, len(absent)))
	}
	return lines, setUnion(m.feed, absent), true, news
}

// modelRun puts the identities of a run together, each reckoned alone, then applies the rules that hold for the
// whole run. keep says the state file must be left as it was (or, on a first run, not made).
func modelRun(ids []modelIdentity, first, failOnNew bool) (lines []string, wantErr string, leads map[string][]string, seen []string, keep bool) {
	leads = map[string][]string{}
	looked, answered, news := 0, 0, 0
	for _, m := range ids {
		l, recorded, s, n := m.alone()
		lines, news = append(lines, l...), news+n
		if len(recorded) > 0 {
			leads[m.key()] = recorded
		}
		if s {
			seen = append(seen, m.key())
		}
		if m.listed {
			looked++
			if m.answered {
				answered++
			}
		}
	}
	slices.Sort(seen)
	if looked == 0 { // nothing to look up: fails and prints nothing
		return nil, "nothing to look up", nil, nil, true
	}
	if answered == 0 { // no source answered: it knows of no change, names only what it could not check
		lines = slices.DeleteFunc(lines, func(l string) bool { return strings.HasPrefix(l, "REMOVED") })
		wantErr, keep = fmt.Sprintf("no source answered for any of the %d identit(ies) looked up", looked), !first
	} else if failOnNew && news > 0 {
		wantErr = fmt.Sprintf("watch: %d new lead(s)", news)
	}
	if first { // one line counts what the first run records, in place of naming each identity FIRST
		n := 0
		for _, recorded := range leads {
			n += len(recorded)
		}
		lines = slices.DeleteFunc(lines, func(l string) bool { return strings.HasPrefix(l, "FIRST") })
		lines = append(lines, fmt.Sprintf("first run: %d lead(s) on %d identit(ies) recorded; later runs name what changes", n, len(leads)))
	}
	return lines, wantErr, leads, seen, keep
}

// modelState is the state file's shape, read apart from watch.go's own type.
type modelState struct {
	Updated string              `json:"updated"`
	Leads   map[string][]string `json:"leads"`
	Seen    []string            `json:"seen,omitempty"`
}

func modelDescribe(ids []modelIdentity, first, failOnNew bool) string {
	s := fmt.Sprintf("first run %v, --fail-on-new %v:", first, failOnNew)
	for _, m := range ids {
		s += fmt.Sprintf("\n  %s (%s): listed %v, answered %v, seen before %v, leads before %v, its source lists %v, fixed before its version %v",
			m.key(), m.kind, m.listed, m.answered, m.seenBefore, m.before, m.feed, m.pastFix)
	}
	return s
}

// Generated runs of 3–5 identities — each of a kind drawn on its own from the ten in modelKinds, their leads from
// one pool of four ids so identities share advisories, first runs and both whole-run rules among them — print, fail
// on and record what a model written from the contract says: each identity reckoned alone (alone), then the rules
// for the whole run (modelRun). Lines are compared sorted: their order is not in the contract.
func TestWatchAgreesWithAPerIdentityModel(t *testing.T) {
	offline(t)
	var dump, feed atomic.Value // the run's Debian dump; the WordPress feed's answers by slug, 502 for any other
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/Debian/all.zip" {
			_, _ = w.Write(dump.Load().([]byte))
			return
		}
		body, ok := feed.Load().(map[string]string)[strings.TrimPrefix(r.URL.Path, "/plugin/")]
		if !ok {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	t.Setenv(osv.EnvOSVURL, srv.URL)
	t.Setenv(wpcve.EnvWPVulnURL, srv.URL+"/{kind}/{slug}")
	dir := t.TempDir()
	r := rand.New(rand.NewSource(modelSeed))
	for run := range modelRuns {
		ids, first, failOnNew := modelDraw(r)
		state := filepath.Join(dir, fmt.Sprintf("run-%d.json", run))
		args, answers := []string{"--state", state}, map[string]string{}
		// a dump with no advisory is no answer at all (source_unavailable): one for a package not in the inventory
		entries := map[string]string{"Debian/X-0.json": `{"id":"X-0","affected":[{"package":{"name":"zzz","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]}]}]}`}
		if failOnNew {
			args = append(args, "--fail-on-new")
		}
		prev := modelState{Updated: "2026-11-01T00:00:00Z", Leads: map[string][]string{}}
		for _, m := range ids {
			if len(m.before) > 0 {
				prev.Leads[m.key()] = m.before
			}
			if m.seenBefore {
				prev.Seen = append(prev.Seen, m.key())
			}
			switch {
			case !m.listed:
			case !m.debian:
				args = append(args, "--wp-plugin", m.name+"@4.0")
				if m.answered {
					var vulns []string
					for _, id := range m.feed {
						vulns = append(vulns, `{"id":"`+id+`","title":"XSS","min_version":"1.0","max_version":"5.0"}`)
					}
					answers[m.name] = "{}" // the feed does not list the slug: answered, unknown to it
					if vulns != nil {
						answers[m.name] = `{"` + m.name + `":{"vulnerabilities":[` + strings.Join(vulns, ",") + `]}}`
					}
				}
			case m.answered:
				args = append(args, "--package", "pkg:deb/debian/"+m.name+"@1.0-1?distro=debian-12")
			default:
				args = append(args, "--package", "pkg:deb/debian/"+m.name+"@1.0-1") // no release: OSV does not answer for it
			}
		}
		for _, id := range modelPool {
			var affected []string
			for _, m := range ids {
				if !m.debian || !m.listed || !m.answered {
					continue
				}
				fixed := "2.0-1"
				switch {
				case slices.Contains(m.feed, id):
				case slices.Contains(m.pastFix, id):
					fixed = "0.5-1"
				default:
					continue
				}
				affected = append(affected, `{"package":{"name":"`+m.name+`","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"`+fixed+`"}]}]}`)
			}
			if affected != nil {
				entries["Debian/"+id+".json"] = `{"id":"` + id + `","affected":[` + strings.Join(affected, ",") + `]}`
			}
		}
		before, err := json.Marshal(prev)
		if err != nil {
			t.Fatal(err)
		}
		if !first {
			writeFile(t, state, string(before))
		}
		dump.Store(osvDump(entries))
		feed.Store(answers)

		out, err := watchOut(t, args...)
		lines, wantErr, leads, seen, keep := modelRun(ids, first, failOnNew)
		got := strings.SplitAfter(out, "\n")
		if got[len(got)-1] == "" {
			got = got[:len(got)-1]
		}
		want := make([]string, len(lines))
		for i, l := range lines {
			want[i] = l + "\n"
		}
		slices.Sort(got)
		slices.Sort(want)
		var bad []string
		if !slices.Equal(got, want) {
			bad = append(bad, fmt.Sprintf("lines\n got %q\nwant %q", got, want))
		}
		if (err == nil) != (wantErr == "") || err != nil && !strings.Contains(err.Error(), wantErr) {
			bad = append(bad, fmt.Sprintf("err = %v, want one naming %q (no error if empty)", err, wantErr))
		}
		raw, rerr := os.ReadFile(state)
		var after modelState
		switch {
		case keep && first:
			if !os.IsNotExist(rerr) {
				bad = append(bad, fmt.Sprintf("a state file was made (read err=%v):\n%s", rerr, raw))
			}
		case keep:
			if rerr != nil || string(raw) != string(before) {
				bad = append(bad, fmt.Sprintf("the state must be left as it was, byte for byte (read err=%v):\n%s", rerr, raw))
			}
		case rerr != nil || json.Unmarshal(raw, &after) != nil || strings.Contains(string(raw), "null") ||
			!maps.EqualFunc(after.Leads, leads, slices.Equal[[]string]) || !slices.Equal(after.Seen, seen):
			bad = append(bad, fmt.Sprintf("state (read err=%v):\n%s\nwant leads %v, seen %v", rerr, raw, leads, seen))
		}
		if bad != nil {
			t.Fatalf("run %d of seed %d — %s\n%s", run, modelSeed, modelDescribe(ids, first, failOnNew), strings.Join(bad, "\n"))
		}
	}
}
