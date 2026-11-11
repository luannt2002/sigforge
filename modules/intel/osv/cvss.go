package osv

import (
	"math"
	"strings"
)

// cvss3Weights are the CVSS v3.x base-metric weights from the specification (FIRST, v3.1 §7.4);
// PR has a second weight when the scope changes.
var cvss3Weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"PR": {"N": 0.85, "L": 0.62, "H": 0.27},
	"UI": {"N": 0.85, "R": 0.62},
	"S":  {"U": 0, "C": 0},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// cvss3BaseScore computes the base score of a CVSS v3.0 / v3.1 vector. ok is false for any
// other version (v4 needs the specification's lookup tables) and for a vector that does not
// state each base metric exactly once with a defined value; temporal and environmental
// metrics are ignored, as they do not enter the base score.
func cvss3BaseScore(vector string) (score float64, ok bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 2 || (parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, found := strings.Cut(p, ":")
		if !found {
			return 0, false
		}
		if _, base := cvss3Weights[k]; !base {
			continue
		}
		if _, dup := m[k]; dup {
			return 0, false
		}
		if _, valid := cvss3Weights[k][v]; !valid {
			return 0, false
		}
		m[k] = v
	}
	if len(m) != len(cvss3Weights) {
		return 0, false
	}
	w := func(k string) float64 { return cvss3Weights[k][m[k]] }
	changed := m["S"] == "C"
	pr := w("PR")
	if changed && m["PR"] == "L" {
		pr = 0.68
	} else if changed && m["PR"] == "H" {
		pr = 0.5
	}
	iss := 1 - (1-w("C"))*(1-w("I"))*(1-w("A"))
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * w("AV") * w("AC") * pr * w("UI")
	if changed {
		return roundUp1(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp1(math.Min(impact+exploitability, 10)), true
}

// roundUp1 is the specification's Roundup (v3.1 Appendix A): the smallest one-decimal number
// not below x, computed on integers so float error cannot add a tenth.
func roundUp1(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// cvssBand is the specification's qualitative rating of a base score, "" for 0.0 (none).
func cvssBand(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}
