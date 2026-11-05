package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// nvdSample is a trimmed, real-shape NVD CVE API 2.0 response for
// virtualMatchString=cpe:2.3:a:f5:nginx:1.18.0 (recorded 2026-11-04). It exercises
// both severity locations: CVE-2021-23017 carries a v3.1 metric (severity inside
// cvssData) and a v2 metric; CVE-2021-3618 is reduced to a v2-only metric (severity
// at the metric level) to prove the v2 path.
const nvdSample = `{
  "totalResults": 2,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-23017",
        "metrics": {
          "cvssMetricV31": [
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "3.1", "baseScore": 7.7, "baseSeverity": "HIGH"}}
          ],
          "cvssMetricV2": [
            {"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "MEDIUM",
             "cvssData": {"version": "2.0", "baseScore": 6.8}}
          ]
        }
      }
    },
    {
      "cve": {
        "id": "CVE-2021-3618",
        "metrics": {
          "cvssMetricV2": [
            {"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "MEDIUM",
             "cvssData": {"version": "2.0", "baseScore": 5.8}}
          ]
        }
      }
    }
  ]
}`

func TestParse(t *testing.T) {
	got, err := Parse([]byte(nvdSample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []CVE{
		{ID: "CVE-2021-23017", CVSS: 7.7, Severity: "HIGH", Source: "nvd@nist.gov"},  // v3.1 preferred over v2
		{ID: "CVE-2021-3618", CVSS: 5.8, Severity: "MEDIUM", Source: "nvd@nist.gov"}, // v2-only: severity at metric level
	}
	if len(got) != len(want) {
		t.Fatalf("Parse returned %d CVEs, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("CVE[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseEmptyResponseIsNoCVEs(t *testing.T) {
	got, err := Parse([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty response → %d CVEs, want 0", len(got))
	}
}

func TestWithVersion(t *testing.T) {
	tests := []struct {
		cpe, version, want string
	}{
		{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0", "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"},
		{"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}, // no version → unchanged
		{"nginx:nginx", "1.18.0", "nginx:nginx"},                                         // not a CPE 2.3 → unchanged
	}
	for _, tt := range tests {
		if got := withVersion(tt.cpe, tt.version); got != tt.want {
			t.Errorf("withVersion(%q,%q) = %q, want %q", tt.cpe, tt.version, got, tt.want)
		}
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{StateUnknown: "unknown", StateNoKnownCVE: "no-known-cve", StateHasCVE: "has-cve"} {
		if s.String() != want {
			t.Errorf("State(%d).String() = %q, want %q", s, s.String(), want)
		}
	}
}

// --- honesty: absence is never "safe" ---

func TestLookupEmptyCPEIsUnknownNotChecked(t *testing.T) {
	a := New("https://example.invalid", fetch.New())
	res, err := a.Lookup(context.Background(), "", "1.18.0")
	if err != nil {
		t.Fatalf("empty CPE should not error: %v", err)
	}
	if res.State != StateUnknown || len(res.CVEs) != 0 {
		t.Errorf("empty CPE → %+v, want StateUnknown + no CVEs", res)
	}
}

func TestLookupFeedOffErrorsAndStaysUnknown(t *testing.T) {
	a := New("", fetch.New())
	res, err := a.Lookup(context.Background(), "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0")
	if err == nil {
		t.Fatal("feed off (no base URL) must error, not silently report no CVEs")
	}
	if res.State != StateUnknown {
		t.Errorf("feed off must stay StateUnknown (never no-known-cve/safe); got %v", res.State)
	}
}

// Adapter wiring over an httptest loopback (no internet), matching how the repo's
// fetch adapters are tested. The base URL is operator-supplied here.
func TestLookupOverLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("virtualMatchString") {
		case "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*":
			w.Write([]byte(nvdSample))
		default:
			w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
		}
	}))
	defer srv.Close()

	a := New(srv.URL, fetch.New())

	res, err := a.Lookup(context.Background(), "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.State != StateHasCVE || len(res.CVEs) != 2 || res.CVEs[0].ID != "CVE-2021-23017" {
		t.Errorf("vulnerable version → %+v, want StateHasCVE with CVE-2021-23017", res)
	}

	// A patched version the feed knows nothing about → no-known-cve, NOT unknown, NOT safe.
	patched, err := a.Lookup(context.Background(), "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.27.4")
	if err != nil {
		t.Fatalf("Lookup patched: %v", err)
	}
	if patched.State != StateNoKnownCVE || len(patched.CVEs) != 0 {
		t.Errorf("patched version → %+v, want StateNoKnownCVE + no CVEs", patched)
	}
}
