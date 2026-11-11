package cve

import (
	"reflect"
	"testing"
)

// NVD's weakness ids and publication date ride on the CVE; its placeholders
// (NVD-CWE-noinfo, NVD-CWE-Other) are not weaknesses and are dropped.
func TestParseReadsWeaknessesAndPublished(t *testing.T) {
	got, err := Parse([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-1","published":"2099-01-02T03:04:05.000",` +
		`"weaknesses":[{"description":[{"lang":"en","value":"CWE-79"},{"lang":"en","value":"NVD-CWE-noinfo"}]},{"description":[{"lang":"en","value":"CWE-79"}]}],` +
		`"metrics":{}}}]}`))
	if err != nil || len(got) != 1 {
		t.Fatalf("Parse = %v, %v", got, err)
	}
	if got[0].CWE != "CWE-79" || got[0].Published != "2099-01-02T03:04:05.000" {
		t.Fatalf("CVE = %+v, want CWE-79 once and the published date", got[0])
	}
	if l := ToUnified(Result{CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", Version: "1", State: StateHasCVE, CVEs: got}, nil).Leads; len(l) != 1 ||
		!reflect.DeepEqual(l[0].CWE, []string{"CWE-79"}) || l[0].Published != "2099-01-02T03:04:05.000" {
		t.Fatalf("lead = %+v", l)
	}
}

// The weakness and date fields are extras: a malformed one costs that CVE its CWE or date, never
// the page (v0.4 did not read them, so it must not start failing on them).
func TestParseIsLenientOnWeaknessesAndPublished(t *testing.T) {
	got, err := Parse([]byte(`{"totalResults":2,"vulnerabilities":[` +
		`{"cve":{"id":"CVE-2099-1","published":20990102,"weaknesses":[{"description":[{"value":79}]}],"metrics":{}}},` +
		`{"cve":{"id":"CVE-2099-2","weaknesses":{"oops":true},"metrics":{}}}]}`))
	if err != nil || len(got) != 2 || got[0].CWE != "" || got[0].Published != "" || got[1].CWE != "" {
		t.Fatalf("Parse = %+v, %v; want both CVEs, without CWE or date", got, err)
	}
}
