package lifecycle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// now is a fixed clock so "past" and "future" eol dates are deterministic.
var now = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

// phpFeed is a trimmed real-shape endoflife.date php feed: eol as date strings.
const phpFeed = `[
  {"cycle":"8.3","eol":"2027-12-31","latest":"8.3.0"},
  {"cycle":"8.0","eol":"2023-11-26","latest":"8.0.30"},
  {"cycle":"7.2","eol":"2020-11-30","latest":"7.2.34"}
]`

// nginxFeed uses the bool form of eol (current cycles never expire in the feed).
const nginxFeed = `[
  {"cycle":"1.31","eol":false,"latest":"1.31.8"},
  {"cycle":"1.29","eol":"2026-05-13","latest":"1.29.8"}
]`

func TestClassify(t *testing.T) {
	php, _ := ParseCycles([]byte(phpFeed))
	nginx, _ := ParseCycles([]byte(nginxFeed))

	tests := []struct {
		name      string
		cycles    []Cycle
		version   string
		wantCycle string
		wantEOL   string
		wantState State
	}{
		{"php-7.2-patch-is-eol", php, "7.2.34", "7.2", "2020-11-30", StateEOL},
		{"php-8.3-is-supported", php, "8.3.1", "8.3", "2027-12-31", StateSupported},
		{"php-8.0-past-date-is-eol", php, "8.0.30", "8.0", "2023-11-26", StateEOL},
		{"php-exact-cycle", php, "7.2", "7.2", "2020-11-30", StateEOL},
		{"php-v-prefix-stripped", php, "v7.2.1", "7.2", "2020-11-30", StateEOL},
		{"php-unknown-cycle", php, "9.9.9", "", "", StateUnknown},
		{"nginx-bool-false-supported", nginx, "1.31.8", "1.31", "false", StateSupported},
		{"nginx-past-date-eol", nginx, "1.29.0", "1.29", "2026-05-13", StateEOL},
		{"empty-version", php, "", "", "", StateUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCycle, gotEOL, gotState := Classify(tt.cycles, tt.version, now)
			if gotCycle != tt.wantCycle || gotEOL != tt.wantEOL || gotState != tt.wantState {
				t.Errorf("Classify(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.version, gotCycle, gotEOL, gotState, tt.wantCycle, tt.wantEOL, tt.wantState)
			}
		})
	}
}

func TestClassifyUninterpretableEOLIsUnknown(t *testing.T) {
	cycles, _ := ParseCycles([]byte(`[{"cycle":"1.0","eol":"garbage"}]`))
	if _, _, state := Classify(cycles, "1.0.0", now); state != StateUnknown {
		t.Errorf("garbage eol should be StateUnknown, got %v", state)
	}
}

func TestProductFor(t *testing.T) {
	if p, ok := ProductFor("PHP"); !ok || p != "php" {
		t.Errorf("ProductFor(PHP) = %q,%v want php,true", p, ok)
	}
	if _, ok := ProductFor("Cloudflare"); ok {
		t.Errorf("Cloudflare is not endoflife-tracked; ProductFor should be false")
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{StateUnknown: "unknown", StateSupported: "supported", StateEOL: "eol"} {
		if s.String() != want {
			t.Errorf("State(%d).String() = %q, want %q", s, s.String(), want)
		}
	}
}

func TestEOLStatusUnknownProduct(t *testing.T) {
	a := New("", fetch.New())
	st, err := a.EOLStatus(context.Background(), "Cloudflare", "1.0")
	if err != nil {
		t.Fatalf("unknown product should not error: %v", err)
	}
	if st.IsEOL != StateUnknown || st.Product != "" {
		t.Errorf("unknown product → %+v, want empty product + StateUnknown", st)
	}
}

func TestEOLStatusFeedOffErrors(t *testing.T) {
	a := New("", fetch.New())
	st, err := a.EOLStatus(context.Background(), "PHP", "7.2")
	if err == nil {
		t.Fatal("feed off (no base URL) for a known product should error")
	}
	if st.IsEOL != StateUnknown {
		t.Errorf("feed off must stay StateUnknown, never supported; got %v", st.IsEOL)
	}
}

// Adapter wiring over httptest loopback (no internet), matching how the repo's
// fetch adapters are tested. The feed base URL is operator-supplied here.
func TestEOLStatusOverLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/php.json" {
			w.Write([]byte(phpFeed))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a := New(srv.URL, fetch.New())
	st, err := a.EOLStatus(context.Background(), "PHP", "7.2.34")
	if err != nil {
		t.Fatalf("EOLStatus: %v", err)
	}
	if st.Product != "php" || st.Cycle != "7.2" || st.IsEOL != StateEOL {
		t.Errorf("PHP 7.2.34 → %+v, want product=php cycle=7.2 eol", st)
	}
}
