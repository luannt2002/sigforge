// Package accuracy measures whether sigforge's detection + enrichment produce
// CORRECT values, not merely present ones. Its job is the "prove value is correct"
// deliverable: a golden set scored for precision/recall, oracle pairs that lock the
// CVE/EOL parsers to real authoritative shapes, and adversarial negatives that must
// NOT fire. The measurement lives in accuracy_test.go; this file is only the metric
// math, kept separate so it is itself unit-tested.
package accuracy

import (
	"fmt"
	"sort"
	"strings"
)

// Score is the confusion-matrix tally of one or more detection runs against a
// known-true set of technology names.
type Score struct {
	TruePositive  int
	FalsePositive int
	FalseNegative int
}

// Add folds one run's detected names and its known-true names into the score.
func (s *Score) Add(detected, truth []string) {
	want := make(map[string]bool, len(truth))
	for _, t := range truth {
		want[t] = true
	}
	seen := make(map[string]bool, len(detected))
	for _, d := range detected {
		if seen[d] {
			continue
		}
		seen[d] = true
		if want[d] {
			s.TruePositive++
		} else {
			s.FalsePositive++
		}
	}
	for _, t := range truth {
		if !seen[t] {
			s.FalseNegative++
		}
	}
}

// Precision is TP/(TP+FP): the share of detections that were real. 1.0 means no
// false positive. An empty run (nothing detected, nothing expected) is 1.0.
func (s Score) Precision() float64 {
	d := s.TruePositive + s.FalsePositive
	if d == 0 {
		return 1.0
	}
	return float64(s.TruePositive) / float64(d)
}

// Recall is TP/(TP+FN): the share of known-true techs that were found. 1.0 means
// nothing was missed.
func (s Score) Recall() float64 {
	d := s.TruePositive + s.FalseNegative
	if d == 0 {
		return 1.0
	}
	return float64(s.TruePositive) / float64(d)
}

// Report is a PER-TECHNOLOGY confusion tally over a whole fixture corpus. It answers
// what the aggregate Score cannot: which techs are actually measured, which still
// miss, and which have no fixture at all (the coverage gap). Honest measurement needs
// the gap: an aggregate 1.0 over a handful of techs is not 1.0 over the whole set.
type Report struct {
	tech map[string]*Score
}

// NewReport returns an empty per-tech report.
func NewReport() *Report { return &Report{tech: map[string]*Score{}} }

func (r *Report) at(name string) *Score {
	s := r.tech[name]
	if s == nil {
		s = &Score{}
		r.tech[name] = s
	}
	return s
}

// Add folds one fixture's detected and known-true names into the per-tech tally,
// mirroring Score.Add exactly (detected names de-duped). A detection in truth is a
// per-tech TP, one not in truth a per-tech FP, a truth never detected a per-tech FN.
func (r *Report) Add(detected, truth []string) {
	want := make(map[string]bool, len(truth))
	for _, t := range truth {
		want[t] = true
	}
	seen := make(map[string]bool, len(detected))
	for _, d := range detected {
		if seen[d] {
			continue
		}
		seen[d] = true
		if want[d] {
			r.at(d).TruePositive++
		} else {
			r.at(d).FalsePositive++
		}
	}
	for _, t := range truth {
		if !seen[t] {
			r.at(t).FalseNegative++
		}
	}
}

// Total micro-averages every tech into one score — identical to a single Score fed
// the same runs, so the aggregate gate and the per-tech breakdown stay consistent.
func (r *Report) Total() Score {
	var s Score
	for _, t := range r.tech {
		s.TruePositive += t.TruePositive
		s.FalsePositive += t.FalsePositive
		s.FalseNegative += t.FalseNegative
	}
	return s
}

// CoverageGap returns the universe techs that NO positive fixture exercises (never
// appeared as known-true: zero TP and zero FN), sorted. These are the honest blind
// spots — the harness makes no accuracy claim about them.
func (r *Report) CoverageGap(universe []string) []string {
	var gap []string
	for _, name := range universe {
		if s := r.tech[name]; s == nil || s.TruePositive+s.FalseNegative == 0 {
			gap = append(gap, name)
		}
	}
	sort.Strings(gap)
	return gap
}

// Render formats the per-tech table plus the coverage-gap summary as text for the
// harness to print under `go test -v`. Every number comes from the runs folded in,
// never hard-coded.
func (r *Report) Render(universe []string) string {
	names := make([]string, 0, len(r.tech))
	for n := range r.tech {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	fmt.Fprintf(&b, "%-26s %3s %3s %3s  %6s %6s\n", "TECH", "TP", "FP", "FN", "prec", "recall")
	for _, n := range names {
		s := r.tech[n]
		fmt.Fprintf(&b, "%-26s %3d %3d %3d  %6.3f %6.3f\n",
			n, s.TruePositive, s.FalsePositive, s.FalseNegative, s.Precision(), s.Recall())
	}
	gap := r.CoverageGap(universe)
	fmt.Fprintf(&b, "COVERAGE: %d/%d baseline techs have a fixture, %d gap\n",
		len(universe)-len(gap), len(universe), len(gap))
	if len(gap) > 0 {
		fmt.Fprintf(&b, "GAP (no fixture, accuracy unmeasured): %s\n", strings.Join(gap, ", "))
	}
	return b.String()
}
