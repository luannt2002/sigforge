package accuracy

import (
	"strings"
	"testing"
)

// TestScore checks the metric math itself (the harness depends on it being right).
func TestScore(t *testing.T) {
	var s Score
	s.Add([]string{"Nginx", "PHP", "Ghost"}, []string{"Nginx", "PHP", "jQuery"}) // 2 TP, 1 FP (Ghost), 1 FN (jQuery)
	if s.TruePositive != 2 || s.FalsePositive != 1 || s.FalseNegative != 1 {
		t.Fatalf("tally = %+v, want TP=2 FP=1 FN=1", s)
	}
	if got := s.Precision(); got != 2.0/3.0 {
		t.Errorf("precision = %.3f, want %.3f", got, 2.0/3.0)
	}
	if got := s.Recall(); got != 2.0/3.0 {
		t.Errorf("recall = %.3f, want %.3f", got, 2.0/3.0)
	}

	// duplicate detections are counted once.
	var d Score
	d.Add([]string{"Nginx", "Nginx"}, []string{"Nginx"})
	if d.TruePositive != 1 || d.FalsePositive != 0 {
		t.Errorf("dup tally = %+v, want TP=1 FP=0", d)
	}

	// empty-vs-empty is a clean 1.0 / 1.0 (clean minimal site).
	var e Score
	e.Add(nil, nil)
	if e.Precision() != 1.0 || e.Recall() != 1.0 {
		t.Errorf("empty run precision/recall = %.1f/%.1f, want 1.0/1.0", e.Precision(), e.Recall())
	}
}

// TestReport checks the per-tech tally, the coverage gap, and that Total matches a
// flat Score fed the same runs.
func TestReport(t *testing.T) {
	r := NewReport()
	r.Add([]string{"Nginx", "PHP", "Ghost"}, []string{"Nginx", "PHP", "jQuery"}) // Nginx/PHP TP, Ghost FP, jQuery FN
	r.Add(nil, nil)                                                              // a clean negative: no effect
	r.Add([]string{"React"}, nil)                                                // a false positive on a negative fixture

	if got := r.tech["Nginx"]; got.TruePositive != 1 || got.FalsePositive != 0 || got.FalseNegative != 0 {
		t.Errorf("Nginx = %+v, want TP=1", *got)
	}
	if got := r.tech["jQuery"]; got.FalseNegative != 1 {
		t.Errorf("jQuery = %+v, want FN=1", *got)
	}
	if got := r.tech["React"]; got.FalsePositive != 1 {
		t.Errorf("React = %+v, want FP=1", *got)
	}

	// Total must equal a flat Score over the same inputs.
	tot := r.Total()
	if tot.TruePositive != 2 || tot.FalsePositive != 2 || tot.FalseNegative != 1 {
		t.Errorf("total = %+v, want TP=2 FP=2 FN=1", tot)
	}

	// Coverage gap: a universe tech never seen as truth is a gap; React (FP-only) is a
	// gap too (no positive fixture), but Nginx/PHP/jQuery are covered.
	gap := r.CoverageGap([]string{"Nginx", "PHP", "jQuery", "React", "Apache"})
	want := []string{"Apache", "React"}
	if strings.Join(gap, ",") != strings.Join(want, ",") {
		t.Errorf("coverage gap = %v, want %v", gap, want)
	}

	if out := r.Render([]string{"Nginx", "Apache"}); !strings.Contains(out, "COVERAGE:") || !strings.Contains(out, "Apache") {
		t.Errorf("Render missing coverage summary:\n%s", out)
	}
}
