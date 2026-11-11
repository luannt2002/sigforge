package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

func acmeAdv(id, events, versions string) string {
	return `{"id":"` + id + `","affected":[{"package":{"name":"acme/core","ecosystem":"Packagist"},` +
		`"ranges":[{"type":"ECOSYSTEM","events":[` + events + `]}],"versions":[` + versions + `]}]}`
}

// A release below the floor that OSV's own rule cannot place must answer as the package lookup does, or the lead is lost on the release path.
func TestReleaseBelowTheFloorKeepsAnUnplacedAdvisory(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, events, listed, below string }{
		{"fixed unreadable", `{"introduced":"0"},{"fixed":"@@@"}`, "6.0.0", "5.0.0"},
		{"limit unreadable", `{"introduced":"0"},{"limit":"@@@"}`, "7.0.0", "6.5.0"},
	} {
		entries := map[string]string{"Packagist/GHSA-u.json": acmeAdv("GHSA-u", tc.events, `"`+tc.listed+`"`)}
		idx := buildIdx(t, "Packagist", entries)
		pkg, rel := idx.Lookup("acme/core", tc.below), idx.lookup("", "acme/core", tc.below, true)
		if !rel.BelowListed || rel.Status != StatusUnknown || !rel.PackageKnown || len(rel.Vulns) != 1 || rel.Vulns[0].ID != "GHSA-u" ||
			rel.Status != pkg.Status || !reflect.DeepEqual(rel.Vulns, pkg.Vulns) {
			t.Errorf("%s: release %s = %+v, want unplaced with GHSA-u as the package lookup %+v", tc.name, tc.below, rel, pkg)
		}

		r, _ := makeZip(t, entries)
		body := mustBytes(r)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
		defer srv.Close()
		pkgLook, relLook := New(srv.URL, fetch.New()).Lookupers()
		p, u := pkgLook(ctx, "Packagist", "acme/core", tc.below), relLook(ctx, "Packagist", "acme/core", tc.below)
		if u.State != unified.StatePotentiallyAffected || len(u.Leads) != 1 || u.Leads[0].ID != "GHSA-u" ||
			u.State != p.State || !reflect.DeepEqual(u.Leads, p.Leads) {
			t.Errorf("%s: release lookup %s = %v %+v, want the package lookup's %v %+v", tc.name, tc.below, u.State, u.Leads, p.State, p.Leads)
		}
		if u := relLook(ctx, "Packagist", "acme/core", tc.listed); u.State != unified.StateAffectedByAdvisory || len(u.Leads) != 1 || u.Leads[0].ID != "GHSA-u" {
			t.Errorf("%s: release %s is listed: %v %+v, want affected by GHSA-u", tc.name, tc.listed, u.State, u.Leads)
		}
	}
}

// Below the floor, ranges that order the version and keep it out must stay a miss: unknown here would be a false lead.
func TestReleaseBelowTheFloorPlacedOutsideStaysAMiss(t *testing.T) {
	idx := buildIdx(t, "Packagist", map[string]string{
		"Packagist/GHSA-c.json": acmeAdv("GHSA-c", `{"introduced":"6.0.0"},{"fixed":"6.2.0"}`, `"6.0.0","6.1.0"`),
		"Packagist/GHSA-d.json": acmeAdv("GHSA-d", `{"introduced":"5.5.0"},{"fixed":"5.6.0"}`, ``),
	})
	rel := idx.lookup("", "acme/core", "5.0.0", true)
	if !rel.BelowListed || rel.Status != StatusNoKnownVuln || len(rel.Vulns) != 0 {
		t.Fatalf("release 5.0.0 = %+v, want below the floor and no advisory", rel)
	}
	if u := ToUnified(rel, "Packagist", "acme/core", "5.0.0", time.Time{}); u.State != unified.StateNotChecked || u.Err != unified.NoteNoClearance || len(u.Leads) != 0 {
		t.Errorf("release 5.0.0 = %v %q %+v, want no lead and no clearance", u.State, u.Err, u.Leads)
	}
}
