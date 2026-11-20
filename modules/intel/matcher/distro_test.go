package matcher

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// A version read from a distro's package build keeps the upstream number the banner shows, and the detection names
// the distro: its package may carry fixes the upstream version does not (a backport), so the number alone cannot
// settle an advisory. A build that is not a distro package, or a distro named in another header than the one the
// version came from, names none.
func TestDistroBuildFromBanner(t *testing.T) {
	fps := map[string]schema.Fingerprint{
		"Apache": {Headers: map[string]schema.StringList{"Server": {`Apache(?:$|/([\d.]+)|[^/-])\;version:\1`}}},
		"Nginx":  {Headers: map[string]schema.StringList{"Server": {`nginx(?:/([\d.]+))?\;version:\1`}}},
		"PHP":    {Headers: map[string]schema.StringList{"X-Powered-By": {`PHP(?:/([\d.]+))?\;version:\1`}}},
	}
	for _, c := range []struct {
		headers               map[string][]string
		tech, version, distro string
	}{
		{map[string][]string{"server": {"nginx/1.18.0 (Ubuntu)"}}, "Nginx", "1.18.0", "Ubuntu"},
		{map[string][]string{"server": {"Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips"}}, "Apache", "2.4.6", "CentOS"},
		{map[string][]string{"server": {"Apache/2.4.6 (Red Hat Enterprise Linux)"}}, "Apache", "2.4.6", "Red Hat Enterprise Linux"},
		{map[string][]string{"server": {"Apache/2.4.38 (Debian)"}}, "Apache", "2.4.38", "Debian"},
		{map[string][]string{"x-powered-by": {"PHP/7.4.3-4ubuntu2.19"}}, "PHP", "7.4.3", "Ubuntu"},
		{map[string][]string{"x-powered-by": {"PHP/7.2.24-0ubuntu0.18.04.17"}}, "PHP", "7.2.24", "Ubuntu"},
		{map[string][]string{"x-powered-by": {"PHP/7.3.31-1~deb10u1"}}, "PHP", "7.3.31", "Debian"},
		{map[string][]string{"x-powered-by": {"PHP/7.4.33+deb11u3"}}, "PHP", "7.4.33", "Debian"},
		// not a distro package build
		{map[string][]string{"server": {"Apache/2.4.57 (Win64) OpenSSL/3.1.1"}}, "Apache", "2.4.57", ""},
		{map[string][]string{"server": {"Apache/2.4.41 (Unix)"}}, "Apache", "2.4.41", ""},
		{map[string][]string{"server": {"nginx/1.25.3"}}, "Nginx", "1.25.3", ""},
		{map[string][]string{"x-powered-by": {"PHP/8.2.1"}}, "PHP", "8.2.1", ""},
		// the distro is named by the Server header, the PHP version comes from another one
		{map[string][]string{"server": {"Apache/2.4.38 (Debian)"}, "x-powered-by": {"PHP/7.3.31"}}, "PHP", "7.3.31", ""},
	} {
		d, ok := find(Match(db(fps), Page{Headers: c.headers}), c.tech)
		if !ok || d.Version != c.version || d.Distro != c.distro {
			t.Errorf("%v: %s = %q distro %q (found %v), want %q distro %q", c.headers, c.tech, d.Version, d.Distro, ok, c.version, c.distro)
		}
	}
	// Only a claim of the chosen version names its distro, and two claims naming two distros give the same answer on
	// every run (the fingerprint's header patterns are read in map order).
	acme := map[string]schema.Fingerprint{"Acme": {Headers: map[string]schema.StringList{
		"Server": {`acme/([\d.]+)\;version:\1`}, "X-Acme": {`acme/([\d.]+)\;version:\1`}, "X-Acme-Too": {`acme/([\d.]+)\;version:\1`}}}}
	for _, c := range []struct {
		headers       map[string][]string
		version, want string
	}{
		{map[string][]string{"server": {"acme/1.0 (Debian)"}, "x-acme": {"acme/1.0.2"}}, "1.0.2", ""},
		{map[string][]string{"server": {"acme/1.0.2 (Ubuntu)"}, "x-acme": {"acme/1.0.2 (Debian)"}, "x-acme-too": {"acme/1.0.2"}}, "1.0.2", "Debian"},
	} {
		for range 20 {
			d, ok := find(Match(db(acme), Page{Headers: c.headers}), "Acme")
			if !ok || d.Version != c.version || d.Distro != c.want {
				t.Fatalf("%v: Acme = %q distro %q, want %q distro %q", c.headers, d.Version, d.Distro, c.version, c.want)
			}
		}
	}

	d, _ := find(Match(db(fps), Page{Headers: map[string][]string{"server": {"nginx/1.18.0 (Ubuntu)"}}}), "Nginx")
	if b, _ := json.Marshal(d); !strings.Contains(string(b), `"distro":"Ubuntu"`) {
		t.Errorf("detection JSON %s does not name the distro", b)
	}
}

// Every OS token a distro's packagers put in a banner names that distro, in any case — the list is written out here,
// not read from the table, so a token dropped from the table fails; a rebuild of upstream releases that only mentions
// Debian is not a distro package build.
func TestDistroOfEveryToken(t *testing.T) {
	want := map[string]string{
		"Ubuntu": "Ubuntu", "Debian": "Debian", "Raspbian": "Raspbian", "CentOS": "CentOS", "CentOS Stream": "CentOS Stream",
		"Red Hat Enterprise Linux": "Red Hat Enterprise Linux", "Red Hat": "Red Hat", "Fedora": "Fedora", "Amazon": "Amazon Linux",
		"Amazon Linux": "Amazon Linux", "Rocky Linux": "Rocky Linux", "AlmaLinux": "AlmaLinux", "Linux/SUSE": "SUSE",
	}
	if len(want) != len(distroTokens) {
		t.Errorf("the table holds %d tokens, this test %d: add the new one here with the banner it comes from", len(distroTokens), len(want))
	}
	for token, name := range want {
		for _, v := range []string{"Apache/2.4.6 (" + token + ")", "Apache/2.4.6 (" + strings.ToUpper(token) + ") OpenSSL/1.0.2k-fips"} {
			if got := distroOf(v); got != name {
				t.Errorf("distroOf(%q) = %q, want %q", v, got, name)
			}
		}
	}
	for _, v := range []string{"PHP/8.2.12-1+0~20231026.31+debian11~1.gbpfb5f0a", "PHP/8.1.2+deb.sury.org", "Apache/2.4.57 (Win64)", "nginx/1.25.3 ()",
		"Apache/2.4.41 (Unix) ubuntu", "MyServer/1.0 (on ubuntu box)", "nginx/1.18.0 ubuntu", "nginx/1.18.0 +deb1",
	} { // a distro's revision is glued to the version, never a word after it
		if got := distroOf(v); got != "" {
			t.Errorf("distroOf(%q) = %q, want none", v, got)
		}
	}
}

// The claims a detection lists name their distro by the same rule as the detection, so a page gives the same claims
// on every run — and a header that only marks the tech, capturing no version, names no distro for another's version.
func TestVersionClaimsAreDeterministic(t *testing.T) {
	acme := map[string]schema.Fingerprint{"Acme": {Headers: map[string]schema.StringList{
		"Server": {`acme/([\d.]+)\;version:\1`}, "X-Acme": {`acme/([\d.]+)\;version:\1`}, "X-Acme-Too": {`acme/([\d.]+)\;version:\1`}}}}
	page := Page{Headers: map[string][]string{"server": {"acme/1.0.2 (Ubuntu)"}, "x-acme": {"acme/1.0.2 (Debian)"}, "x-acme-too": {"acme/2.0.1"}}}
	for range 200 {
		d, _ := find(Match(db(acme), page), "Acme")
		if !d.VersionConflict || len(d.VersionClaims) != 2 || d.VersionClaims[0].Version != "1.0.2" || d.VersionClaims[0].Distro != "Debian" {
			t.Fatalf("claims %+v, want 1.0.2 named Debian (the alphabetically first of its claims) on every run", d.VersionClaims)
		}
	}
	marker := map[string]schema.Fingerprint{"Apache": {Headers: map[string]schema.StringList{
		"Server": {`Apache`}, "X-Ver": {`apache/([\d.]+)\;version:\1`}}}}
	d, ok := find(Match(db(marker), Page{Headers: map[string][]string{"server": {"Apache (Debian)"}, "x-ver": {"apache/2.4.38"}}}), "Apache")
	if !ok || d.Version != "2.4.38" || d.Distro != "" {
		t.Errorf("version from X-Ver, Debian only in a Server header that captures none: %q distro %q, want 2.4.38 and none", d.Version, d.Distro)
	}
}
