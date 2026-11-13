package matcher

import (
	"sort"
	"strconv"
	"strings"
	"testing"
)

// conditionRows: combinations of requires / requiresCategory, implies and excludes, one synthetic
// DB and page per row. want is leads(): detected() plus any version ("@2.1") and a confidence
// below 100 ("%50"). Implies chains stay within 4 steps, the depth expandImplies always reaches.
var conditionRows = []struct{ name, db, html, want string }{
	// No gate, no excludes.
	{"A1 own match", `{"T":{"html":"m-t-k"}}`, `m-t-k`, "T"},
	{"A2 implied", `{"X":{"html":"m-x-k","implies":"T"},"T":{}}`, `m-x-k`, "T* X"},
	{"A3 implied and own match: the own match stands", `{"X":{"html":"m-x-k","implies":"T"},"T":{"html":"m-t-k"}}`, `m-x-k m-t-k`, "T X"},
	{"A4 implied through two steps", `{"X":{"html":"m-x-k","implies":"M"},"M":{"implies":"T"},"T":{}}`, `m-x-k`, "M* T* X"},
	{"A5 implier gated and unmet", `{"G":{"html":"m-g-k","requires":"R","implies":"T"},"R":{"html":"m-r-k"},"T":{}}`, `m-g-k`, ""},

	// requires; the gated tech has its own match on the page.
	{"G1 required tech detected", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R"}}`, `m-r-k m-t-k`, "R T"},
	{"G2 required tech implied", `{"X":{"html":"m-x-k","implies":"R"},"R":{},"T":{"html":"m-t-k","requires":"R"}}`, `m-x-k m-t-k`, "R* T X"},
	{"G3 required tech absent", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R"}}`, `m-t-k`, ""},
	{"G4 own match implies its requirement", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R","implies":"R"}}`, `m-t-k`, ""},
	{"G5 own match held back, implied by another tech", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k-([\\d.]+)\\;version:\\1","requires":"R"},"X":{"html":"m-x-k","implies":"T\\;confidence:50"}}`, `m-t-k-2.1 m-x-k`, "T*%50 X"},
	{"G6 own match held back, implied through two steps", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R"},"X":{"html":"m-x-k","implies":"M"},"M":{"implies":"T"}}`, `m-t-k m-x-k`, "M* T* X"},
	{"G7 own match held back, implier gated and unmet", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R"},"G":{"html":"m-g-k","requires":"R","implies":"T"}}`, `m-t-k m-g-k`, ""},
	{"G8 implied, its own implies meet its gate", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R","implies":"R"},"X":{"html":"m-x-k","implies":"T"}}`, `m-t-k m-x-k`, "R* T X"},
	{"G9 gate met and implied", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R"},"X":{"html":"m-x-k","implies":"T"}}`, `m-r-k m-t-k m-x-k`, "R T X"},
	{"G10a requires chain settles", `{"R":{"html":"m-r-k"},"M":{"html":"m-m-k","requires":"R"},"T":{"html":"m-t-k","requires":"M"}}`, `m-r-k m-m-k m-t-k`, "M R T"},
	{"G10b requires chain without its root", `{"R":{"html":"m-r-k"},"M":{"html":"m-m-k","requires":"R"},"T":{"html":"m-t-k","requires":"M"}}`, `m-m-k m-t-k`, ""},
	{"G11 required tech gated, present only implied", `{"R":{"html":"m-r-k"},"G":{"requires":"R"},"X":{"html":"m-x-k","implies":"G"},"T":{"html":"m-t-k","requires":"G"}}`, `m-x-k m-t-k`, "G* T X"},
	{"G12 any one required tech suffices", `{"R1":{"html":"m-ra-k"},"R2":{"html":"m-rb-k"},"T":{"html":"m-t-k","requires":["R1","R2"]}}`, `m-rb-k m-t-k`, "R2 T"},
	{"G13a requires and requiresCategory: the category suffices", `{"C":{"html":"m-c-k","cats":[6]},"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R","requiresCategory":[6]}}`, `m-c-k m-t-k`, "C T"},
	{"G13b requires and requiresCategory: the tech suffices", `{"C":{"html":"m-c-k","cats":[6]},"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R","requiresCategory":[6]}}`, `m-r-k m-t-k`, "R T"},
	{"G13c requires and requiresCategory both unmet", `{"C":{"html":"m-c-k","cats":[6]},"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R","requiresCategory":[6]}}`, `m-t-k`, ""},
	{"G14 required tech not in the DB", `{"T":{"html":"m-t-k","requires":"Ghost"}}`, `m-t-k`, ""},
	{"G15 requires cycle", `{"P":{"html":"m-p-k","requires":"Q"},"Q":{"html":"m-q-k","requires":"P"}}`, `m-p-k m-q-k`, ""},

	// requires; the gated tech has no own match.
	{"H1 implied, requirement unmet", `{"R":{"html":"m-r-k"},"T":{"requires":"R"},"X":{"html":"m-x-k","implies":"T"}}`, `m-x-k`, "T* X"},
	{"H2 implied, requirement met", `{"R":{"html":"m-r-k"},"T":{"requires":"R"},"X":{"html":"m-x-k","implies":"T"}}`, `m-x-k m-r-k`, "R T* X"},
	{"H3 implied, implies its own requirement", `{"R":{"html":"m-r-k"},"T":{"requires":"R","implies":"R"},"X":{"html":"m-x-k","implies":"T"}}`, `m-x-k`, "R* T* X"},
	{"H4 implied through two steps, requirement unmet", `{"R":{"html":"m-r-k"},"T":{"requires":"R"},"X":{"html":"m-x-k","implies":"M"},"M":{"implies":"T"}}`, `m-x-k`, "M* T* X"},
	{"H5 implier gated and unmet", `{"R":{"html":"m-r-k"},"T":{"requires":"R"},"G":{"html":"m-g-k","requires":"R","implies":"T"}}`, `m-g-k`, ""},

	// requiresCategory.
	{"C1 a detected tech has the category", `{"S":{"html":"m-s-k","cats":[6]},"T":{"html":"m-t-k","cats":[41],"requiresCategory":[6]}}`, `m-s-k m-t-k`, "S T"},
	{"C2 an implied tech has the category", `{"X":{"html":"m-x-k","cats":[80],"implies":"S"},"S":{"cats":[6]},"T":{"html":"m-t-k","cats":[41],"requiresCategory":[6]}}`, `m-x-k m-t-k`, "S* T X"},
	{"C3 no tech has the category", `{"S":{"html":"m-s-k","cats":[6]},"T":{"html":"m-t-k","cats":[41],"requiresCategory":[6]}}`, `m-t-k`, ""},
	{"C4 own category is the required one", `{"T":{"html":"m-t-k","cats":[6],"requiresCategory":[6]}}`, `m-t-k`, ""},
	{"C5 own category, implied by another tech", `{"T":{"html":"m-t-k","cats":[6],"requiresCategory":[6]},"X":{"html":"m-x-k","implies":"T"}}`, `m-t-k m-x-k`, "T X"},
	{"C6 own match held back, implied by another tech", `{"T":{"html":"m-t-k","cats":[41],"requiresCategory":[6]},"X":{"html":"m-x-k","implies":"T"}}`, `m-t-k m-x-k`, "T* X"},
	{"C7 implied, no own match on the page", `{"T":{"html":"m-t-k","cats":[41],"requiresCategory":[6]},"X":{"html":"m-x-k","implies":"T"}}`, `m-x-k`, "T* X"},

	// excludes on ungated techs.
	{"L1 excluder absent", `{"A":{"html":"m-a-k","excludes":"T"},"T":{"html":"m-t-k"}}`, `m-t-k`, "T"},
	{"L2 excluder detected", `{"A":{"html":"m-a-k","excludes":"T"},"T":{"html":"m-t-k"}}`, `m-a-k m-t-k`, "A T<A"},
	{"L3 excluded tech present through implies", `{"A":{"html":"m-a-k","excludes":"T"},"C":{"html":"m-c-k","implies":"T"},"T":{}}`, `m-a-k m-c-k`, "A C T*<A"},
	{"L4 implied only by a labeled tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"T"},"T":{}}`, `m-a-k m-b-k`, "A B<A T*<A"},
	{"L5 implied also by an unlabeled tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"T"},"D":{"html":"m-d-k","implies":"T"},"T":{}}`, `m-a-k m-b-k m-d-k`, "A B<A D T*"},
	{"L6 label over two implies steps", `{"A":{"html":"m-a-k","excludes":"L"},"L":{"html":"m-l-k","implies":"U"},"U":{"implies":"T"},"T":{}}`, `m-a-k m-l-k`, "A L<A T*<A U*<A"},
	{"L7 implied excluder", `{"E":{"html":"m-e-k","implies":"A"},"A":{"excludes":"B"},"B":{"html":"m-b-k"}}`, `m-e-k m-b-k`, "A* B<A E"},
	{"L8 tech excluding itself", `{"S":{"html":"m-s-k","excludes":"S"}}`, `m-s-k`, "S"},
	{"L9 inherited label naming the tech itself", `{"A":{"html":"m-a-k","implies":"B"},"B":{"excludes":"A"}}`, `m-a-k`, "A<B B*"},
	{"L10 mutual excludes", `{"P":{"html":"m-p-k","excludes":"Q"},"Q":{"html":"m-q-k","excludes":"P"}}`, `m-p-k m-q-k`, "P<Q Q<P"},
	{"L11 own match never inherits", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"T"},"T":{"html":"m-t-k"}}`, `m-a-k m-b-k m-t-k`, "A B<A T"},
	{"L12 supported through an unlabeled implied tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"T"},"D":{"html":"m-d-k","implies":"U"},"U":{"implies":"T"},"T":{}}`, `m-a-k m-b-k m-d-k`, "A B<A D T* U*"},
	{"L13 excluded tech present only through implies passes its label on", `{"A":{"html":"m-a-k","excludes":"B"},"C":{"html":"m-c-k","implies":"B"},"B":{"implies":"BL"},"BL":{}}`, `m-a-k m-c-k`, "A B*<A BL*<A C"},
	{"L14a excluder held back by its gate excludes nothing", `{"G":{"html":"m-g-k","requires":"R","excludes":"T"},"R":{"html":"m-r-k"},"T":{"html":"m-t-k"}}`, `m-g-k m-t-k`, "T"},
	{"L14b gated excluder admitted", `{"G":{"html":"m-g-k","requires":"R","excludes":"T"},"R":{"html":"m-r-k"},"T":{"html":"m-t-k"}}`, `m-g-k m-r-k m-t-k`, "G R T<G"},
	{"L15 labels of two impliers are united", `{"A":{"html":"m-a-k","excludes":"B"},"C":{"html":"m-c-k","excludes":"D"},"B":{"html":"m-b-k","implies":"T"},"D":{"html":"m-d-k","implies":"T"},"T":{}}`, `m-a-k m-b-k m-c-k m-d-k`, "A B<A C D<C T*<A,C"},
	{"L16 mutual excludes reach each one's implies", `{"A":{"html":"m-a-k","excludes":"B","implies":"C"},"B":{"html":"m-b-k","excludes":"A","implies":"D"},"C":{},"D":{}}`, `m-a-k m-b-k`, "A<B B<A C*<B D*<A"},
	{"L17 labels do not chain through excluders", `{"C":{"html":"m-c-k","excludes":"A"},"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k"}}`, `m-a-k m-b-k m-c-k`, "A<C B<A C"},

	// gate × labels: a gated tech carries its labels when only labeled techs meet its gate.
	{"X1 requires met only by a labeled tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k"},"T":{"html":"m-t-k","requires":"B"}}`, `m-a-k m-b-k m-t-k`, "A B<A T<A"},
	{"X1c requiresCategory met only by a labeled tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","cats":[6]},"T":{"html":"m-t-k","requiresCategory":[6]}}`, `m-a-k m-b-k m-t-k`, "A B<A T<A"},
	{"X2 edition requires and excludes its base", `{"Base":{"html":"m-base-k"},"Ed":{"html":"m-ed-k","requires":"Base","excludes":"Base"}}`, `m-base-k m-ed-k`, "Base<Ed Ed"},
	{"X3 implied gated excluder", `{"R":{"html":"m-r-k"},"G":{"html":"m-g-k","requires":"R","excludes":"B"},"X":{"html":"m-x-k","implies":"G"},"B":{"html":"m-b-k"}}`, `m-g-k m-x-k m-b-k`, "B<G G* X"},
	{"X4 gated tech implied only by a labeled tech", `{"A":{"html":"m-a-k","excludes":"X"},"X":{"html":"m-x-k","implies":"G"},"G":{"html":"m-g-k","requires":"R"},"R":{"html":"m-r-k"}}`, `m-a-k m-x-k m-g-k`, "A G*<A X<A"},
	{"X5 requires met by an unlabeled tech", `{"A":{"html":"m-a-k","excludes":"T"},"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R"}}`, `m-a-k m-r-k m-t-k`, "A R T<A"},
	{"X6 requires met only by a labeled implied tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"R"},"R":{},"T":{"html":"m-t-k","requires":"R"}}`, `m-a-k m-b-k m-t-k`, "A B<A R*<A T<A"},
	{"X6c requiresCategory met only by a labeled implied tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"S"},"S":{"cats":[6]},"T":{"html":"m-t-k","requiresCategory":[6]}}`, `m-a-k m-b-k m-t-k`, "A B<A S*<A T<A"},
	{"X7 requires met also by an unlabeled tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k"},"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":["B","R"]}}`, `m-a-k m-b-k m-r-k m-t-k`, "A B<A R T"},
	{"X7c requiresCategory met also by an unlabeled tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","cats":[6]},"C":{"html":"m-c-k","cats":[6]},"T":{"html":"m-t-k","requiresCategory":[6]}}`, `m-a-k m-b-k m-c-k m-t-k`, "A B<A C T"},
	{"X7m requires met by a labeled tech, requiresCategory by an unlabeled one", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k"},"C":{"html":"m-c-k","cats":[6]},"T":{"html":"m-t-k","requires":"B","requiresCategory":[6]}}`, `m-a-k m-b-k m-c-k m-t-k`, "A B<A C T"},
	{"X8 requires met by two labeled techs: labels united", `{"A":{"html":"m-a-k","excludes":"B"},"C":{"html":"m-c-k","excludes":"D"},"B":{"html":"m-b-k"},"D":{"html":"m-d-k"},"T":{"html":"m-t-k","requires":["B","D"]}}`, `m-a-k m-b-k m-c-k m-d-k m-t-k`, "A B<A C D<C T<A,C"},
	{"X9 label along a requires chain", `{"A":{"html":"m-a-k","excludes":"R"},"R":{"html":"m-r-k"},"M":{"html":"m-m-k","requires":"R"},"T":{"html":"m-t-k","requires":"M"}}`, `m-a-k m-r-k m-m-k m-t-k`, "A M<A R<A T<A"},
	{"X10 label from requires on to implies", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k"},"T":{"html":"m-t-k","requires":"B","implies":"U"},"U":{}}`, `m-a-k m-b-k m-t-k`, "A B<A T<A U*<A"},
	{"X11 gated tech also implied by an unlabeled tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k"},"T":{"html":"m-t-k","requires":"B"},"X":{"html":"m-x-k","implies":"T"}}`, `m-a-k m-b-k m-t-k m-x-k`, "A B<A T X"},
	{"X12 requires met by an implied tech an unlabeled tech supports", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"R"},"D":{"html":"m-d-k","implies":"R"},"R":{},"T":{"html":"m-t-k","requires":"R"}}`, `m-a-k m-b-k m-d-k m-t-k`, "A B<A D R* T"},
	{"X13 requires met by a gated tech an unlabeled tech supports", `{"A":{"html":"m-a-k","excludes":"R"},"R":{"html":"m-r-k"},"Q":{"html":"m-q-k"},"M":{"html":"m-m-k","requires":["R","Q"]},"T":{"html":"m-t-k","requires":"M"}}`, `m-a-k m-q-k m-r-k m-m-k m-t-k`, "A M Q R<A T"},
	{"X14 own category met through an implies from a labeled tech", `{"A":{"html":"m-a-k","excludes":"X"},"X":{"html":"m-x-k","implies":"T"},"T":{"html":"m-t-k","cats":[6],"requiresCategory":[6]}}`, `m-a-k m-t-k m-x-k`, "A T<A X<A"},
	{"X15 own implies met through an implies from a labeled tech", `{"A":{"html":"m-a-k","excludes":"X"},"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R","implies":"R"},"X":{"html":"m-x-k","implies":"T"}}`, `m-a-k m-t-k m-x-k`, "A R*<A T<A X<A"},
	{"X16 implied gated tech: a tech meeting its gate does not support it", `{"A":{"html":"m-a-k","excludes":"X"},"R":{"html":"m-r-k"},"T":{"requires":"R"},"X":{"html":"m-x-k","implies":"T"}}`, `m-a-k m-r-k m-x-k`, "A R T*<A X<A"},

	// References carrying a \; suffix.
	{"S1 requires with a suffix", `{"R":{"html":"m-r-k"},"T":{"html":"m-t-k","requires":"R\\;confidence:50"}}`, `m-r-k m-t-k`, "R T"},
	{"S2 excludes with a suffix", `{"A":{"html":"m-a-k","excludes":"T\\;version:2"},"T":{"html":"m-t-k"}}`, `m-a-k m-t-k`, "A T<A"},
	{"S3 implies with a suffix passes the label on", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"T\\;confidence:50"},"T":{}}`, `m-a-k m-b-k`, "A B<A T*<A%50"},
	{"S4 implies with a suffix supports", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"T"},"D":{"html":"m-d-k","implies":"T\\;confidence:50"},"T":{}}`, `m-a-k m-b-k m-d-k`, "A B<A D T*"},
	{"S5 requires with a suffix met only by a labeled tech", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k"},"T":{"html":"m-t-k","requires":"B\\;confidence:50"}}`, `m-a-k m-b-k m-t-k`, "A B<A T<A"},
	{"P2 implies with confidence:0 supports", `{"A":{"html":"m-a-k","excludes":"B"},"B":{"html":"m-b-k","implies":"T"},"D":{"html":"m-d-k","implies":"T\\;confidence:0"},"T":{}}`, `m-a-k m-b-k m-d-k`, "A B<A D T*"},
}

// Each row runs 50 times: map iteration order must never decide a result.
func TestConditionTable(t *testing.T) {
	for _, r := range conditionRows {
		d := parse(t, r.db)
		t.Run(r.name, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				if got := leads(Match(d, Page{HTML: r.html})); got != r.want {
					t.Fatalf("run %d: detected %q, want %q", i, got, r.want)
				}
			}
		})
	}
}

// leads is detected() with each detection's version ("@2.1") and a confidence below 100 ("%50").
func leads(dets []Detection) string {
	out := make([]string, 0, len(dets))
	for _, d := range dets {
		s := detected([]Detection{d})
		if d.Version != "" {
			s += "@" + d.Version
		}
		if d.Confidence != 100 {
			s += "%" + strconv.Itoa(d.Confidence)
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}
