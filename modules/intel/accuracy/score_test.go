package accuracy

import "testing"

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
