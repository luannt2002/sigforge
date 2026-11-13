package enrich

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/schema"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

const (
	noteUnplacedOSV = "the version could not be placed against this advisory's affected ranges or versions: whether it applies is unknown"
	noteOutside     = "the version is older than every version this package's advisories name and reaches this advisory only through its from-the-start range: it may not be one of this package's releases — confirm before relying on it"
)

// On a platform's release path an OSV advisory the release cannot be placed against is a doubt like one reached
// only from the start: keepDoubtsApart moves it, with its note, into the potentially-affected result beside the
// matches, and that result names each distinct reason once. Shopware 5.7.17 looked up in shopware/core through a
// real OSV dump (floor 6.0.0): m a match by OSV's rule, o reached only from the start, u a fixed bound OSV cannot
// read. Cases K1–K4 below.
func TestReleaseUnplacedAdvisoryIsKeptApartWithItsReason(t *testing.T) {
	adv := func(id, events, versions string) string {
		return `{"id":"` + id + `","affected":[{"package":{"name":"shopware/core","ecosystem":"Packagist"},` +
			`"ranges":[{"type":"ECOSYSTEM","events":[` + events + `]}],"versions":[` + versions + `]}]}`
	}
	m := adv("GHSA-m", `{"introduced":"0"},{"fixed":"6.4.0"}`, ``)
	o := adv("GHSA-o", `{"introduced":"0"},{"fixed":"6.4.0"}`, `"6.0.0","6.1.0"`)
	u := adv("GHSA-u", `{"introduced":"0"},{"fixed":"@@@"}`, `"6.0.0"`)
	for _, tc := range []struct {
		row  string
		feed []string
		want []string // state:leads:Err of each shopware/core result ("*" not placed, "?" outside the listed releases)
	}{
		{"K1", []string{m, u}, []string{"affected_by_advisory:GHSA-m:", "potentially_affected:GHSA-u*:" + noteUnplacedOSV}},
		{"K2", []string{m, o, u}, []string{"affected_by_advisory:GHSA-m:", "potentially_affected:GHSA-o?,GHSA-u*:" + noteOutside + "; " + noteUnplacedOSV}},
		{"K3", []string{u}, []string{"potentially_affected:GHSA-u*:the version could not be placed against the package's advisories: whether they apply is unknown"}},
		{"K4", []string{o}, []string{"potentially_affected:GHSA-o?:" + noteOutside}},
	} {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for i, body := range tc.feed {
			w, _ := zw.Create(string(rune('a'+i)) + ".json")
			_, _ = w.Write([]byte(body))
		}
		_ = zw.Close()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(buf.Bytes()) }))
		_, release := osv.New(srv.URL, fetch.New()).Lookupers()
		db := &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: map[string]schema.Fingerprint{}}
		var got []string
		for _, r := range EnrichUnified(context.Background(), []matcher.Detection{{Tech: "Shopware", Version: "5.7.17"}}, db, Options{OSVRelease: release}) {
			if r.Source != "osv" || r.Identity != "shopware/core" {
				continue
			}
			var ids []string
			for _, l := range r.Leads {
				switch l.Note {
				case "":
					ids = append(ids, l.ID)
				case noteUnplacedOSV:
					ids = append(ids, l.ID+"*")
				case noteOutside:
					ids = append(ids, l.ID+"?")
				default:
					ids = append(ids, l.ID+"!"+l.Note)
				}
			}
			got = append(got, r.State.String()+":"+strings.Join(ids, ",")+":"+r.Err)
		}
		srv.Close()
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: shopware/core results = %q, want %q", tc.row, got, tc.want)
		}
	}
}

// A lead the source doubts (a note) is no firmer than potentially, whatever its result's state: it neither hides a
// later OSV lead that pins the same advisory nor survives as a repeat of one already named as doubtfully. Rows P1–P3.
func TestDropRepeatedReadsANotedLeadAsADoubt(t *testing.T) {
	lead := func(id, cve, note string) unified.Lead { return unified.Lead{ID: id, CVE: []string{cve}, Note: note} }
	const doubt = "the version could not be placed against this advisory's bounds under the npm order: whether it applies is unknown"
	for _, tc := range []struct {
		row  string
		rs   []unified.Result
		want []string // source:leads of what is kept
	}{
		{"P1", []unified.Result{
			{Source: "jslib", State: unified.StateAffectedByAdvisory, Leads: []unified.Lead{lead("CVE-1", "CVE-1", ""), lead("CVE-2", "CVE-2", doubt)}},
			{Source: "osv", State: unified.StateAffectedByAdvisory, Leads: []unified.Lead{lead("GHSA-x", "CVE-2", "")}},
		}, []string{"jslib:CVE-1,CVE-2", "osv:GHSA-x"}},
		{"P2", []unified.Result{
			{Source: "jslib", State: unified.StateAffectedByAdvisory, Leads: []unified.Lead{lead("CVE-1", "CVE-1", "")}},
			{Source: "osv", State: unified.StateAffectedByAdvisory, Leads: []unified.Lead{lead("GHSA-y", "CVE-1", "")}},
		}, []string{"jslib:CVE-1"}},
		{"P3", []unified.Result{
			{Source: "jslib", State: unified.StatePotentiallyAffected, Leads: []unified.Lead{lead("CVE-2", "CVE-2", doubt)}},
			{Source: "osv", State: unified.StateAffectedByAdvisory, Leads: []unified.Lead{lead("GHSA-m", "CVE-9", ""), lead("GHSA-z", "CVE-2", "unplaced")}},
		}, []string{"jslib:CVE-2", "osv:GHSA-m"}},
	} {
		var got []string
		for _, r := range dropRepeated(tc.rs) {
			var ids []string
			for _, l := range r.Leads {
				ids = append(ids, l.ID)
			}
			got = append(got, r.Source+":"+strings.Join(ids, ","))
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: kept %v, want %v", tc.row, got, tc.want)
		}
	}
}
