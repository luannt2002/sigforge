package enrich

import (
	"reflect"
	"testing"
)

func TestParsePackageRef(t *testing.T) {
	cases := []struct {
		in   string
		want PkgRef
		bad  bool
	}{
		{"pkg:npm/lodash@4.17.20", PkgRef{"npm", "lodash", "4.17.20"}, false},
		{"pkg:npm/%40babel/core@7.0.0", PkgRef{"npm", "@babel/core", "7.0.0"}, false},
		{"pkg:npm/@babel/core@7.0.0", PkgRef{"npm", "@babel/core", "7.0.0"}, false},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", PkgRef{"maven", "org.apache.logging.log4j:log4j-core", "2.14.1"}, false},
		{"pkg:golang/github.com/gin-gonic/gin@v1.6.0", PkgRef{"golang", "github.com/gin-gonic/gin", "v1.6.0"}, false},
		{"pkg:pypi/django@3.2.0", PkgRef{"pypi", "django", "3.2.0"}, false},
		{"pkg:composer/laravel/framework@8.0.0", PkgRef{"composer", "laravel/framework", "8.0.0"}, false},
		{"pkg:gem/rails@6.0.0#lib", PkgRef{"gem", "rails", "6.0.0"}, false},
		{"pkg:cargo/serde", PkgRef{"cargo", "serde", ""}, false},
		{"pypi:requests@2.19.0", PkgRef{"pypi", "requests", "2.19.0"}, false},
		{"maven:org.apache.logging.log4j:log4j-core@2.14.1", PkgRef{"maven", "org.apache.logging.log4j:log4j-core", "2.14.1"}, false},
		{"npm:@babel/core", PkgRef{"npm", "@babel/core", ""}, false},
		{"lodash@4.17.20", PkgRef{}, true}, // no ecosystem
		{"pkg:npm/", PkgRef{}, true},
		{"pkg:/lodash@1.0.0", PkgRef{}, true},
		{"", PkgRef{}, true},
	}
	for _, c := range cases {
		got, err := ParsePackageRef(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("%q: want an error, got %+v", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q = %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
}

// "ecosystem:$NAME@$VER" with the name unset leaves no name: it is refused, as the purl form already is,
// not looked up as a package named "@1.0". A leading "@" followed by a "/" stays an npm scope.
func TestParsePackageRefRefusesAnEmptyName(t *testing.T) {
	for _, in := range []string{"npm:@1.0", "npm:@", "pypi:@2.19.0", "pkg:npm/@1.0"} {
		if got, err := ParsePackageRef(in); err == nil {
			t.Errorf("%q: want an error, got %+v", in, got)
		}
	}
	for in, want := range map[string]PkgRef{
		"npm:@angular/core@12.0.0": {"npm", "@angular/core", "12.0.0"},
		"npm:@angular/core":        {"npm", "@angular/core", ""},
		"npm:lodash@":              {"npm", "lodash", ""},
	} {
		if got, err := ParsePackageRef(in); err != nil || got != want {
			t.Errorf("%q = %+v, %v; want %+v", in, got, err, want)
		}
	}
}

// An SBOM from any tool yields every component's package (nested ones too), once each;
// components without a purl are counted, not silently dropped.
func TestParseCycloneDX(t *testing.T) {
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"name":"lodash","purl":"pkg:npm/lodash@4.17.20"},
	  {"name":"no-purl"},
	  {"name":"django","purl":"pkg:pypi/django@3.2.0","components":[{"purl":"pkg:pypi/sqlparse@0.4.1"}]},
	  {"purl":"pkg:npm/lodash@4.17.20"}]}`
	refs, skipped, err := ParseCycloneDX([]byte(bom))
	if err != nil {
		t.Fatal(err)
	}
	want := []PkgRef{{"npm", "lodash", "4.17.20"}, {"pypi", "django", "3.2.0"}, {"pypi", "sqlparse", "0.4.1"}}
	if !reflect.DeepEqual(refs, want) || skipped != 1 {
		t.Fatalf("got %+v (skipped %d), want %+v (skipped 1)", refs, skipped, want)
	}
	if _, _, err := ParseCycloneDX([]byte(`{"spdxVersion":"SPDX-2.3"}`)); err == nil {
		t.Fatal("a document that is not a CycloneDX SBOM must be refused")
	}
}

// OS packages: the purl's distro qualifier names the release the advisories are kept per, and
// the lookup uses the name OSV files them under — the source package (Debian, Ubuntu, Alpine,
// Rocky), the binary one for AlmaLinux — with the epoch put back into the version.
func TestParsePackageRefDistro(t *testing.T) {
	cases := []struct {
		in   string
		want PkgRef
	}{
		{"pkg:deb/debian/libc6@2.36-9%2Bdeb12u13?arch=amd64&distro=debian-12.13", PkgRef{"Debian:12", "libc6", "2.36-9+deb12u13"}},
		{"pkg:deb/debian/libc6@2.36-9+deb12u4?arch=amd64&upstream=glibc%402.36-9%2Bdeb12u4&distro=debian-12", PkgRef{"Debian:12", "glibc", "2.36-9+deb12u4"}},
		{"pkg:deb/debian/libc-bin@2.36-9?upstream=glibc@2.36-9+deb12u4&distro=debian-12", PkgRef{"Debian:12", "glibc", "2.36-9+deb12u4"}}, // a raw "+" is not a space
		{"pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.13&epoch=1", PkgRef{"Debian:12", "zlib1g", "1:1.2.13.dfsg-1"}},
		{"pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?distro=ubuntu-22.04", PkgRef{"Ubuntu:22.04:LTS", "libssl3", "3.0.2-0ubuntu1.10"}},
		{"pkg:deb/ubuntu/curl@8.2.1-1ubuntu3?distro=ubuntu-23.10", PkgRef{"Ubuntu:23.10", "curl", "8.2.1-1ubuntu3"}},
		{"pkg:apk/alpine/libssl1.1@1.1.1s-r0?arch=x86_64&distro=3.16.3", PkgRef{"Alpine:v3.16", "libssl1.1", "1.1.1s-r0"}},
		{"pkg:apk/alpine/libssl3@3.0.8-r0?upstream=openssl&distro=alpine-3.17.2", PkgRef{"Alpine:v3.17", "openssl", "3.0.8-r0"}},
		{"pkg:apk/wolfi/glibc@2.38-r1?distro=wolfi-20230201", PkgRef{"Wolfi", "glibc", "2.38-r1"}},
		{"pkg:rpm/rocky/openssl-libs@1.1.1k-7.el8_6?epoch=1&upstream=openssl-1.1.1k-7.el8_6.src.rpm&distro=rocky-8.6", PkgRef{"Rocky Linux:8", "openssl", "1:1.1.1k-7.el8_6"}},
		{"pkg:rpm/almalinux/openssl-libs@3.0.7-25.el9_3?epoch=1&upstream=openssl-3.0.7-25.el9_3.src.rpm&distro=almalinux-9.3", PkgRef{"AlmaLinux:9", "openssl-libs", "1:3.0.7-25.el9_3"}},
		{"pkg:deb/debian/openssl@3.0.11-1~deb12u2", PkgRef{"Debian", "openssl", "3.0.11-1~deb12u2"}},              // no release: the source says so
		{"pkg:rpm/redhat/openssl@1.1.1k-7.el8_6?distro=rhel-8.6", PkgRef{"Red Hat", "openssl", "1.1.1k-7.el8_6"}}, // known distro, release form not mapped
		{"pkg:deb/kali/tool@1.0", PkgRef{"deb", "tool", "1.0"}},                                                   // unknown distro stays its purl type
	}
	for _, c := range cases {
		got, err := ParsePackageRef(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q = %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
}

// A Trivy SBOM names each binary's source package in component properties, not in the purl;
// binaries of one source package collapse into one lookup.
func TestParseCycloneDXSourcePackage(t *testing.T) {
	bom := `{"bomFormat":"CycloneDX","components":[
	  {"purl":"pkg:deb/debian/libc6@2.36-9%2Bdeb12u13?arch=amd64&distro=debian-12.13","properties":[
	    {"name":"aquasecurity:trivy:SrcName","value":"glibc"},{"name":"aquasecurity:trivy:SrcVersion","value":"2.36"},
	    {"name":"aquasecurity:trivy:SrcRelease","value":"9+deb12u13"}]},
	  {"purl":"pkg:deb/debian/libc-bin@2.36-9%2Bdeb12u13?arch=amd64&distro=debian-12.13","properties":[
	    {"name":"aquasecurity:trivy:SrcName","value":"glibc"},{"name":"aquasecurity:trivy:SrcVersion","value":"2.36"},
	    {"name":"aquasecurity:trivy:SrcRelease","value":"9+deb12u13"}]},
	  {"purl":"pkg:deb/debian/libcap2@2.66-4%2Bdeb12u2%2Bb2?arch=amd64&distro=debian-12.13&epoch=1","properties":[
	    {"name":"aquasecurity:trivy:SrcEpoch","value":"1"},{"name":"aquasecurity:trivy:SrcName","value":"libcap2"},
	    {"name":"aquasecurity:trivy:SrcRelease","value":"4+deb12u2"},{"name":"aquasecurity:trivy:SrcVersion","value":"2.66"}]},
	  {"purl":"pkg:apk/alpine/ssl_client@1.35.0-r17?arch=x86_64&distro=3.16.3","properties":[
	    {"name":"aquasecurity:trivy:SrcName","value":"busybox"},{"name":"aquasecurity:trivy:SrcVersion","value":"1.35.0-r17"}]},
	  {"purl":"pkg:npm/lodash@4.17.20","properties":[{"name":"aquasecurity:trivy:SrcName","value":"ignored"}]}]}`
	refs, skipped, err := ParseCycloneDX([]byte(bom))
	if err != nil {
		t.Fatal(err)
	}
	want := []PkgRef{{"Debian:12", "glibc", "2.36-9+deb12u13"}, {"Debian:12", "libcap2", "1:2.66-4+deb12u2"},
		{"Alpine:v3.16", "busybox", "1.35.0-r17"}, {"npm", "lodash", "4.17.20"}}
	if !reflect.DeepEqual(refs, want) || skipped != 0 {
		t.Fatalf("got %+v (skipped %d), want %+v", refs, skipped, want)
	}
}
