package kev

import (
	"context"
	"reflect"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
)

// A KEV lead carries what CISA asks of the operator — the action and its due date — and the
// weakness ids the catalog names.
func TestKEVLeadCarriesRemediation(t *testing.T) {
	url := serveJSON(t, `{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2",`+
		`"vulnerabilityName":"Log4Shell","dateAdded":"2021-12-10","dueDate":"2021-12-24","requiredAction":"Apply updates per vendor instructions.",`+
		`"knownRansomwareCampaignUse":"Known","cwes":["CWE-502","CWE-400"]}]}`)
	u := New(url, "", fetch.New()).EnrichUnified(context.Background(), []string{"CVE-2021-44228"})["CVE-2021-44228"]
	if len(u.Leads) != 1 {
		t.Fatalf("leads = %+v", u.Leads)
	}
	l := u.Leads[0]
	if l.DueDate != "2021-12-24" || l.RequiredAction != "Apply updates per vendor instructions." || !reflect.DeepEqual(l.CWE, []string{"CWE-502", "CWE-400"}) {
		t.Fatalf("lead = %+v, want the due date, the required action and the CWEs", l)
	}
}
