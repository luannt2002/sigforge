package cve

import (
	"errors"
	"testing"
)

// A per-query, paged API cannot prove its data whole: no cve answer sets FullData, on any branch, so a CVE missing
// from one is never read as gone.
func TestToUnifiedNeverClaimsWholeData(t *testing.T) {
	cves := []CVE{{ID: "CVE-2099-0001"}}
	for name, c := range map[string]struct {
		res Result
		err error
	}{
		"feed off":         {Result{CPE: "cpe:2.3:a:x:y"}, ErrFeedOff},
		"source broke":     {Result{CPE: "cpe:2.3:a:x:y"}, errors.New("status 500")},
		"no CPE":           {Result{State: StateUnknown}, nil},
		"no CVE":           {Result{State: StateNoKnownCVE, CPE: "cpe:2.3:a:x:y", Version: "1.0"}, nil},
		"CVEs, version":    {Result{State: StateHasCVE, CPE: "cpe:2.3:a:x:y", Version: "1.0", CVEs: cves, Total: 1}, nil},
		"CVEs, no version": {Result{State: StateHasCVE, CPE: "cpe:2.3:a:x:y", CVEs: cves, Total: 1}, nil},
		"one page of many": {Result{State: StateHasCVE, CPE: "cpe:2.3:a:x:y", Version: "1.0", CVEs: cves, Total: 40, Partial: true}, nil},
	} {
		if u := ToUnified(c.res, c.err); u.FullData {
			t.Errorf("%s: FullData = true (state %v), want false: the cve source cannot prove its data whole", name, u.State)
		}
	}
}
