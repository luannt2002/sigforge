// Package accuracy measures whether sigforge's detection + enrichment produce
// CORRECT values, not merely present ones. Its job is the "prove value is correct"
// deliverable: a golden set scored for precision/recall, oracle pairs that lock the
// CVE/EOL parsers to real authoritative shapes, and adversarial negatives that must
// NOT fire. The measurement lives in accuracy_test.go; this file is only the metric
// math, kept separate so it is itself unit-tested.
package accuracy

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
