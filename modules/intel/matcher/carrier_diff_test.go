package matcher

import (
	"encoding/json"
	"maps"
	"math/rand/v2"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// The carrier index in excludedBy is fast but easy to get subtly wrong: each source of carriers
// it misses (implies, requires, requiresCategory, a category held by an implied, gated or
// multi-category tech) drops or adds a label on some page. This test holds it to a plain
// pairwise reference on random DBs and pages, so a missed source fails here as a class rather
// than one table row at a time. Small cases vary every list; big cases make the derived carrier
// lists (techs holding one required category, techs implying one target) as long as on real pages.
func TestCarrierIndexAgreesWithPairwise(t *testing.T) {
	agree := func(kind string, i int, c carrierCase, shrink bool) (map[string]*hit, map[string][]string) {
		got, want, resolved, ref := c.labels()
		if got == want {
			return resolved, ref
		}
		if !shrink { // a big case fails through a long list, so no small case shows it: name what differs
			t.Fatalf("%s %d (rebuilt from its seed): Match labels %q, pairwise reference %q; every other tech agrees",
				kind, i, labelDiff(got, want), labelDiff(want, got))
		}
		m := shrinkCarrierCase(c)
		mg, mw, _, _ := m.labels()
		t.Fatalf("%s %d: Match labels %q, pairwise reference %q\nminimal: db %s html %q\n  Match     %q\n  reference %q",
			kind, i, got, want, m.db(), m.html(), mg, mw)
		return nil, nil
	}
	r := rand.New(rand.NewPCG(2026, 1112))
	var dims [len(carrierDimNames)]int
	const cases = 10000
	for i := 0; i < cases; i++ {
		resolved, ref := agree("case", i, genCarrierCase(r), true)
		countCarrierDims(&dims, resolved, ref)
	}
	rb := rand.New(rand.NewPCG(2026, 1113))
	var bigDims [len(carrierBigDimNames)]int
	const bigCases = 24
	for i := 0; i < bigCases; i++ {
		resolved, ref := agree("big case", i, genBigCarrierCase(rb), false)
		countBigCarrierDims(&bigDims, resolved, ref)
	}
	for k, name := range carrierDimNames {
		t.Logf("%-62s %4d / %d cases", name, dims[k], cases)
		if dims[k] == 0 {
			t.Errorf("generator never produced %q: the test no longer covers it", name)
		}
	}
	for k, name := range carrierBigDimNames {
		t.Logf("%-62s %4d / %d big cases", name, bigDims[k], bigCases)
		if bigDims[k] == 0 {
			t.Errorf("generator never produced %q: the test no longer covers it", name)
		}
	}
}

// carrierCase is one random DB of techs T0..Tn and a page holding the own match of the techs in on.
type carrierCase struct {
	fps map[string]schema.Fingerprint
	on  map[string]bool
}

func carrierToken(name string) string { return "m-" + strings.ToLower(name) + "-k" }

// genCarrierCase draws 3-12 techs over 12 categories with random cats, requires (some with a \;
// suffix), requiresCategory, excludes and implies. cats, requires and requiresCategory run up to 6
// entries, excludes up to 3 and implies up to 7, past the longest lists in real data, so a carrier
// index reading only a list's first k entries fails. Implies only climb levels 0-4, so a chain has
// at most 4 steps, the depth expandImplies always reaches, and the resolved set is deterministic.
func genCarrierCase(r *rand.Rand) carrierCase {
	n := 3 + r.IntN(10)
	names := make([]string, n)
	level := make([]int, n)
	for i := range names {
		names[i] = "T" + strconv.Itoa(i)
		level[i] = r.IntN(5)
	}
	refs := func(k int, tag string) schema.StringList {
		var out schema.StringList
		for _, i := range r.Perm(n)[:min(k, n)] {
			s := names[i]
			if r.IntN(4) == 0 {
				s += `\;` + tag
			}
			out = append(out, s)
		}
		return out
	}
	cats := func(k int) []int {
		var out []int
		for _, c := range r.Perm(12)[:k] {
			out = append(out, c+1)
		}
		return out
	}
	c := carrierCase{fps: make(map[string]schema.Fingerprint, n), on: make(map[string]bool, n)}
	for i, name := range names {
		fp := schema.Fingerprint{HTML: schema.StringList{carrierToken(name)}}
		if r.IntN(2) == 0 { // half the techs have no cats, so long lists do not meet every gate
			fp.Cats = cats(1 + r.IntN(6))
		}
		if r.IntN(3) == 0 {
			fp.Requires = refs(1+r.IntN(6), "confidence:50")
		}
		if r.IntN(3) == 0 {
			fp.RequiresCategory = cats(1 + r.IntN(6))
		}
		if r.IntN(3) == 0 {
			fp.Excludes = refs(1+r.IntN(3), "version:2")
		}
		var up []string
		for j := range names {
			if level[j] > level[i] {
				up = append(up, names[j])
			}
		}
		if r.IntN(2) == 0 {
			for _, j := range r.Perm(len(up))[:min(1+r.IntN(7), len(up))] {
				s := up[j]
				if r.IntN(5) == 0 {
					s += `\;confidence:50`
				}
				fp.Implies = append(fp.Implies, s)
			}
		}
		c.fps[name] = fp
		if r.IntN(5) < 3 {
			c.on[name] = true
		}
	}
	return c
}

// genBigCarrierCase builds a page of 60-200 techs over 1-3 categories: a pool of direct techs that
// all imply X, but one, and all hold category c, but another one; T requires c. Excluders label
// every pool tech except those two, so exactly one unlabeled carrier, at a random place in each
// derived list, keeps X and T unlabeled, and a carrier index reading only part of a list labels them.
func genBigCarrierCase(r *rand.Rand) carrierCase {
	np := 57 + r.IntN(139)
	c := 1 + r.IntN(3)
	uImpl := r.IntN(np)                     // the only unlabeled implier of X; holds no c
	uCat := (uImpl + 1 + r.IntN(np-1)) % np // the only unlabeled holder of c; does not imply X
	excluders := make([]string, 1+r.IntN(3))
	bc := carrierCase{fps: make(map[string]schema.Fingerprint, np+5), on: make(map[string]bool, np+5)}
	add := func(name string, fp schema.Fingerprint, on bool) {
		fp.HTML = schema.StringList{carrierToken(name)}
		bc.fps[name] = fp
		if on {
			bc.on[name] = true
		}
	}
	for i := range excluders {
		excluders[i] = "E" + strconv.Itoa(i)
	}
	for i := 0; i < np; i++ {
		var fp schema.Fingerprint
		for _, k := range r.Perm(3) {
			if k+1 == c && i != uImpl || k+1 != c && r.IntN(2) == 0 {
				fp.Cats = append(fp.Cats, k+1)
			}
		}
		if i != uCat {
			fp.Implies = schema.StringList{"X"}
			if r.IntN(5) == 0 {
				fp.Implies[0] += `\;confidence:50`
			}
		}
		name := "P" + strconv.Itoa(i)
		if i != uImpl && i != uCat {
			e := excluders[r.IntN(len(excluders))]
			ex := bc.fps[e]
			ex.Excludes = append(ex.Excludes, name)
			bc.fps[e] = ex
		}
		add(name, fp, true)
	}
	for _, e := range excluders {
		add(e, bc.fps[e], true)
	}
	add("X", schema.Fingerprint{}, false)
	add("T", schema.Fingerprint{RequiresCategory: []int{c}}, true)
	return bc
}

// labels renders "tech<labels" for every detection of Match, and for every tech resolveConditions
// resolves from the same own matches (one html pattern each, confidence 100, as Match records
// it) as labeled by the pairwise reference.
func (c carrierCase) labels() (got, want string, resolved map[string]*hit, ref map[string][]string) {
	db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: c.fps}
	hits := make(map[string]*hit)
	for name := range c.on {
		hits[name] = &hit{conf: 100, fp: c.fps[name]}
	}
	resolved = resolveConditions(db, hits)
	ref = refExcludedBy(resolved)
	tag := func(name string, by []string) string {
		if len(by) == 0 {
			return name
		}
		return name + "<" + strings.Join(by, ",")
	}
	var g, w []string
	for _, d := range Match(db, Page{HTML: c.html()}) {
		g = append(g, tag(d.Tech, d.ExcludedBy))
	}
	for name := range resolved {
		w = append(w, tag(name, ref[name]))
	}
	sort.Strings(g)
	sort.Strings(w)
	return strings.Join(g, " "), strings.Join(w, " "), resolved, ref
}

// labelDiff keeps the "tech<labels" entries of a that b lacks.
func labelDiff(a, b string) string {
	in := make(map[string]bool)
	for _, f := range strings.Fields(b) {
		in[f] = true
	}
	var out []string
	for _, f := range strings.Fields(a) {
		if !in[f] {
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

func (c carrierCase) html() string {
	var page []string
	for name := range c.on {
		page = append(page, carrierToken(name))
	}
	sort.Strings(page)
	return strings.Join(page, " ")
}

func (c carrierCase) db() string {
	b, _ := json.Marshal(c.fps)
	return string(b)
}

func (c carrierCase) clone() carrierCase {
	d := carrierCase{fps: make(map[string]schema.Fingerprint, len(c.fps)), on: make(map[string]bool, len(c.on))}
	for k, v := range c.fps {
		d.fps[k] = v
	}
	for k, v := range c.on {
		d.on[k] = v
	}
	return d
}

// smaller lists every case one step smaller: a tech removed, its own match removed, or one entry
// of its cats, implies, requires, requiresCategory or excludes removed.
func (c carrierCase) smaller() []carrierCase {
	var out []carrierCase
	names := make([]string, 0, len(c.fps))
	for name := range c.fps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		d := c.clone()
		delete(d.fps, name)
		delete(d.on, name)
		out = append(out, d)
		if c.on[name] {
			d := c.clone()
			delete(d.on, name)
			out = append(out, d)
		}
		edit := func(f func(*schema.Fingerprint)) {
			d := c.clone()
			fp := d.fps[name]
			f(&fp)
			d.fps[name] = fp
			out = append(out, d)
		}
		fp := c.fps[name]
		for i := range fp.Cats {
			edit(func(f *schema.Fingerprint) { f.Cats = slices.Delete(slices.Clone(f.Cats), i, i+1) })
		}
		for i := range fp.Implies {
			edit(func(f *schema.Fingerprint) { f.Implies = slices.Delete(slices.Clone(f.Implies), i, i+1) })
		}
		for i := range fp.Requires {
			edit(func(f *schema.Fingerprint) { f.Requires = slices.Delete(slices.Clone(f.Requires), i, i+1) })
		}
		for i := range fp.RequiresCategory {
			edit(func(f *schema.Fingerprint) {
				f.RequiresCategory = slices.Delete(slices.Clone(f.RequiresCategory), i, i+1)
			})
		}
		for i := range fp.Excludes {
			edit(func(f *schema.Fingerprint) { f.Excludes = slices.Delete(slices.Clone(f.Excludes), i, i+1) })
		}
	}
	return out
}

// shrinkCarrierCase takes smaller cases while Match and the reference still disagree, so a failure
// prints a DB and page small enough to read and to paste as a conditionRows row.
func shrinkCarrierCase(c carrierCase) carrierCase {
	for shrunk := true; shrunk; {
		shrunk = false
		for _, d := range c.smaller() {
			if got, want, _, _ := d.labels(); got != want {
				c, shrunk = d, true
				break
			}
		}
	}
	return c
}

// carrierDimNames are the shapes the generator must produce for a missed carrier source to show;
// a gate dimension counts only when a labeled tech meets that gate, so a lost carrier moves a label.
// From index 12 on, a dimension counts only when the edit it names moves a label of the reference:
// those are the cases a carrier index that skips that part of the list gets wrong.
var carrierDimNames = [...]string{
	"some label",
	"label inherited through implies",
	"label inherited through a requires/requiresCategory gate",
	"label carried over >=2 implies steps",
	"gate met by a labeled and an unlabeled tech",
	"requiresCategory with >=2 categories",
	"required category at position >=2 met",
	"gate met through a tech's cat at position >=2",
	"category gate met by an implied tech",
	"category gate met by another gated tech",
	"requires and requiresCategory together",
	"requires with a \\; suffix met",
	"an excludes entry after the first decides a label",
	"an implies with a \\; suffix decides a label",
	"the last of 3 requires decides a label",
	"the last of 4 requires decides a label",
	"the last of 5 requires decides a label",
	"the last of 6 requires decides a label",
	"the last of 3 requiresCategory decides a label",
	"the last of 4 requiresCategory decides a label",
	"the last of 5 requiresCategory decides a label",
	"the last of 6 requiresCategory decides a label",
	"the last of 3 cats decides a label",
	"the last of 4 cats decides a label",
	"the last of 5 cats decides a label",
	"the last of 6 cats decides a label",
	"the last of 3 implies decides a label",
	"the last of 4 implies decides a label",
	"the last of 5 implies decides a label",
	"the last of 6 implies decides a label",
	"the last of 7 implies decides a label",
}

// carrierDimLast is the index of "the last of 3 requires"; requiresCategory and cats follow, 4 each,
// then implies, n = 3..7.
const carrierDimLast = 14

func countCarrierDims(dims *[len(carrierDimNames)]int, resolved map[string]*hit, ref map[string][]string) {
	var seen [len(carrierDimNames)]bool
	excluded := make(map[string]bool)
	for name, h := range resolved {
		for _, raw := range h.fp.Excludes {
			if e := refName(raw); e != name {
				excluded[e] = true
			}
		}
	}
	gated := func(h *hit) bool { return len(h.fp.Requires)+len(h.fp.RequiresCategory) > 0 }
	for tn, th := range resolved {
		if len(ref[tn]) > 0 {
			seen[0] = true
			if !excluded[tn] {
				seen[1] = seen[1] || th.implied
				seen[2] = seen[2] || !th.implied
			}
		}
		if th.implied {
			for _, vh := range resolved {
				seen[3] = seen[3] || vh.implied && len(ref[tn]) > 0 && refImplies(vh.fp, tn)
			}
			continue
		}
		if !gated(th) {
			continue
		}
		labeled, unlabeled := false, false
		for sn, sh := range resolved {
			if refMeets(sn, sh.fp, th.fp) {
				labeled = labeled || len(ref[sn]) > 0
				unlabeled = unlabeled || len(ref[sn]) == 0
			}
		}
		if !labeled {
			continue
		}
		seen[4] = seen[4] || unlabeled
		seen[5] = seen[5] || len(th.fp.RequiresCategory) >= 2
		seen[10] = seen[10] || len(th.fp.Requires) > 0 && len(th.fp.RequiresCategory) > 0
		for i, c := range th.fp.RequiresCategory {
			for sn, sh := range resolved {
				if k := slices.Index(sh.fp.Cats, c); k >= 0 {
					seen[6] = seen[6] || i > 0
					seen[7] = seen[7] || k > 0
					seen[8] = seen[8] || sh.implied
					seen[9] = seen[9] || sn != tn && gated(sh)
				}
			}
		}
		for _, raw := range th.fp.Requires {
			seen[11] = seen[11] || strings.Contains(raw, `\;`) && resolved[refName(raw)] != nil
		}
	}
	if len(ref) > 0 { // with no label anywhere, no edit of a list can move one
		suffixed := func(raw string) bool { return strings.Contains(raw, `\;`) }
		for name, h := range resolved {
			moves := func(d int, edit func(*schema.Fingerprint)) {
				if !seen[d] && movesLabel(resolved, ref, name, edit) {
					seen[d] = true
				}
			}
			if len(h.fp.Excludes) >= 2 {
				moves(12, func(f *schema.Fingerprint) { f.Excludes = f.Excludes[:1] })
			}
			if slices.ContainsFunc(h.fp.Implies, suffixed) {
				moves(13, func(f *schema.Fingerprint) { f.Implies = slices.DeleteFunc(slices.Clone(f.Implies), suffixed) })
			}
			if n := len(h.fp.Requires); n >= 3 && n <= 6 {
				moves(carrierDimLast+n-3, func(f *schema.Fingerprint) { f.Requires = f.Requires[:n-1] })
			}
			if n := len(h.fp.RequiresCategory); n >= 3 && n <= 6 {
				moves(carrierDimLast+4+n-3, func(f *schema.Fingerprint) { f.RequiresCategory = f.RequiresCategory[:n-1] })
			}
			if n := len(h.fp.Cats); n >= 3 && n <= 6 {
				moves(carrierDimLast+8+n-3, func(f *schema.Fingerprint) { f.Cats = f.Cats[:n-1] })
			}
			if n := len(h.fp.Implies); n >= 3 && n <= 7 {
				moves(carrierDimLast+12+n-3, func(f *schema.Fingerprint) { f.Implies = f.Implies[:n-1] })
			}
		}
	}
	for k, s := range seen {
		if s {
			dims[k]++
		}
	}
}

// carrierBigDimNames are the shapes big cases must produce: a derived carrier list of 51+ techs,
// past any cut a carrier index might take at 50, in which one unlabeled carrier decides a label.
var carrierBigDimNames = [...]string{
	"a target implied by >=51 techs, one unlabeled implier decides its label",
	"a category held by >=51 techs, one unlabeled holder decides a gate's label",
}

func countBigCarrierDims(dims *[len(carrierBigDimNames)]int, resolved map[string]*hit, ref map[string][]string) {
	var seen [len(carrierBigDimNames)]bool
	decides := func(d int, cs []string, edit func(*schema.Fingerprint)) {
		if len(cs) < 51 {
			return
		}
		for _, s := range cs {
			if !seen[d] && len(ref[s]) == 0 && movesLabel(resolved, ref, s, edit) {
				seen[d] = true
			}
		}
	}
	for tn, th := range resolved {
		var impliers, holders []string
		for sn, sh := range resolved {
			if refImplies(sh.fp, tn) {
				impliers = append(impliers, sn)
			}
		}
		if th.implied || len(th.fp.Requires)+len(th.fp.RequiresCategory) > 0 {
			decides(0, impliers, func(f *schema.Fingerprint) {
				f.Implies = slices.DeleteFunc(slices.Clone(f.Implies), func(raw string) bool { return refName(raw) == tn })
			})
		}
		if th.implied {
			continue
		}
		for _, c := range th.fp.RequiresCategory {
			holders = holders[:0]
			for sn, sh := range resolved {
				if slices.Contains(sh.fp.Cats, c) {
					holders = append(holders, sn)
				}
			}
			decides(1, holders, func(f *schema.Fingerprint) {
				f.Cats = slices.DeleteFunc(slices.Clone(f.Cats), func(x int) bool { return x == c })
			})
		}
	}
	for k, s := range seen {
		if s {
			dims[k]++
		}
	}
}

// movesLabel reports whether the reference labels change once edit is applied to tech name's
// fingerprint alone, the resolved set left as it is.
func movesLabel(resolved map[string]*hit, ref map[string][]string, name string, edit func(*schema.Fingerprint)) bool {
	alt := maps.Clone(resolved)
	h := *resolved[name]
	edit(&h.fp)
	alt[name] = &h
	return !maps.EqualFunc(refExcludedBy(alt), ref, slices.Equal[[]string])
}

// refExcludedBy, refImplies and refMeets are excludedBy, implies and meets of the pairwise matcher r7
// (matcher.go sha256 515e875e85f836f4d1254ac66d262e27162bf9a19b23849fe0d35788874ae58e), renamed
// only: every tech is tested against every other, slow on a large page but plain to read.
func refExcludedBy(resolved map[string]*hit) map[string][]string {
	by := make(map[string]map[string]bool)
	add := func(tech, excluder string) bool {
		if tech == excluder || by[tech][excluder] {
			return false
		}
		if by[tech] == nil {
			by[tech] = make(map[string]bool)
		}
		by[tech][excluder] = true
		return true
	}
	for name, h := range resolved {
		for _, raw := range h.fp.Excludes {
			if e := refName(raw); resolved[e] != nil {
				add(e, name)
			}
		}
	}
	if len(by) == 0 {
		return nil
	}
	// carried: present only through the techs that carry it — implied, or admitted by its gate.
	carried := func(h *hit) bool {
		return h.implied || len(h.fp.Requires) > 0 || len(h.fp.RequiresCategory) > 0
	}
	// carries: s implies name, or s meets the gate that admitted name's own match.
	carries := func(s string, sh *hit, name string, h *hit) bool {
		return refImplies(sh.fp, name) || !h.implied && refMeets(s, sh.fp, h.fp)
	}
	// supported: carried by an unlabeled tech that is itself not carried, or supported.
	supported := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for name, h := range resolved {
			if !carried(h) || supported[name] {
				continue
			}
			for s, sh := range resolved {
				if by[s] == nil && (!carried(sh) || supported[s]) && carries(s, sh, name, h) {
					supported[name], changed = true, true
					break
				}
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for name, h := range resolved {
			if !carried(h) || supported[name] {
				continue
			}
			for s, sh := range resolved {
				if carries(s, sh, name, h) {
					for e := range by[s] {
						changed = add(name, e) || changed
					}
				}
			}
		}
	}
	out := make(map[string][]string, len(by))
	for tech, set := range by {
		for e := range set {
			out[tech] = append(out[tech], e)
		}
		sort.Strings(out[tech])
	}
	return out
}

func refImplies(fp schema.Fingerprint, name string) bool {
	for _, raw := range fp.Implies {
		if refName(raw) == name {
			return true
		}
	}
	return false
}

// refMeets is requirementMet for one tech: whether tech s, with fingerprint sfp, meets fp's gate by
// being required itself or having a required category.
func refMeets(s string, sfp, fp schema.Fingerprint) bool {
	for _, raw := range fp.Requires {
		if refName(raw) == s {
			return true
		}
	}
	for _, c := range sfp.Cats {
		if slices.Contains(fp.RequiresCategory, c) {
			return true
		}
	}
	return false
}
