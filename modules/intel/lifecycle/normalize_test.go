package lifecycle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// Odd cycle names seen in hand-edited feeds — a capital V, a zero-width space or BOM, a
// decimal comma — still name the cycle a version belongs to.
func TestClassifyNormalizesOddCycleNames(t *testing.T) {
	cycles, err := ParseCycles([]byte(`[
	  {"cycle":"V1.18","eol":"2021-01-01"},
	  {"cycle":"1\u200b.20","eol":false},
	  {"cycle":"\ufeff1.22","eol":false},
	  {"cycle":"1,24","eol":"2022-01-01"}]`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		version, wantCycle string
		want               State
	}{
		{"1.18.0", "1.18", StateEOL},
		{"V1.18.0", "1.18", StateEOL}, // the same normalization applies to the version it is compared with
		{"1.20.3", "1.20", StateSupported},
		{"1.22.1", "1.22", StateSupported},
		{"1.24.0", "1.24", StateEOL},
	} {
		if c, _, s := Classify(cycles, tt.version, now); c != tt.wantCycle || s != tt.want {
			t.Errorf("Classify(%q) = (%q, %v), want (%q, %v)", tt.version, c, s, tt.wantCycle, tt.want)
		}
	}
}

// A bundle that lists one product under names differing only in case or stray spaces is one
// product: found by its id, and its CPE is not ambiguous.
func TestBundleMergesProductNamesByCase(t *testing.T) {
	cpe := `"identifiers":[{"type":"cpe","id":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":[
		  {"name":"Nginx",` + cpe + `,"releases":[{"name":"1.18","isEol":true}]},
		  {"name":" nginx\u200b",` + cpe + `,"releases":[{"name":"1.20","isEol":false}]}]}`))
	}))
	defer srv.Close()
	a := NewBundle(srv.URL, fetch.New())
	ctx := context.Background()
	if st, err := a.EOLStatus(ctx, "Nginx", "1.18.0"); err != nil || st.Product != "nginx" || st.IsEOL != StateEOL {
		t.Fatalf("Nginx 1.18.0 = %+v %v, want product nginx, eol", st, err)
	}
	if st, err := a.EOLStatus(ctx, "nginx", "1.20.1"); err != nil || st.Cycle != "1.20" || st.IsEOL != StateSupported {
		t.Fatalf("nginx 1.20.1 = %+v %v, want the second listing's cycle 1.20, supported", st, err)
	}
	if st, err := a.EOLStatusByCPE(ctx, "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", "1.18.0"); err != nil || st.Product != "nginx" {
		t.Fatalf("by CPE = %+v %v, want product nginx: names differing in case are one product, not two", st, err)
	}
}
