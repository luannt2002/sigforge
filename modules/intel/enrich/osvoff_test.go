package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// A package's scope is its key in watch: a run with OSV off names it the way a run with OSV on does — every
// alias and release of an ecosystem OSV supports under the ecosystem's own name — so one run without the OSV
// URL neither drops the package's recorded leads nor makes them NEW the run after; an ecosystem OSV does not
// support keeps the name it was given.
func TestOSVOffScopesAPackageAsOSVOnDoes(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler()) // OSV on, its dump missing: the scope it answers with is enough
	defer srv.Close()
	on := osv.New(srv.URL, fetch.New()).Lookuper()
	want := map[string][]string{ // scope → package refs
		"ecosystem:npm":         {"npm:p@1.0", "yarn:p@1.0", "pnpm:p@1.0", "node:p@1.0", "javascript:p@1.0", "js:p@1.0", "pkg:npm/lodash@4.17.20"},
		"ecosystem:PyPI":        {"pypi:p@1.0", "pip:p@1.0", "python:p@1.0", "poetry:p@1.0", "PyPI:p@1.0", "pkg:pypi/requests@2.0"},
		"ecosystem:Go":          {"go:p@1.0", "gomod:p@1.0", "golang:p@1.0", "pkg:golang/github.com/gin-gonic/gin@v1.6.0"},
		"ecosystem:Packagist":   {"packagist:p@1.0", "composer:p@1.0", "php:p@1.0"},
		"ecosystem:Maven":       {"maven:p@1.0", "gradle:p@1.0", "java:p@1.0", "pkg:maven/org.apache/commons@1.0"},
		"ecosystem:RubyGems":    {"rubygems:p@1.0", "gem:p@1.0", "bundler:p@1.0", "ruby:p@1.0"},
		"ecosystem:crates.io":   {"crates.io:p@1.0", "crates:p@1.0", "cargo:p@1.0", "rust:p@1.0"},
		"ecosystem:NuGet":       {"nuget:p@1.0", "dotnet:p@1.0", "csharp:p@1.0", ".net:p@1.0"},
		"ecosystem:Hex":         {"hex:p@1.0"},
		"ecosystem:Pub":         {"pub:p@1.0"},
		"ecosystem:SwiftURL":    {"swift:p@1.0", "swifturl:p@1.0"},
		"ecosystem:CRAN":        {"cran:p@1.0"},
		"ecosystem:Hackage":     {"hackage:p@1.0"},
		"ecosystem:Debian":      {"debian:p@1.0", "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", "pkg:deb/debian/zlib@1.0-1"},
		"ecosystem:Ubuntu":      {"ubuntu:p@1.0", "pkg:deb/ubuntu/curl@7.0-1?distro=ubuntu-22.04"},
		"ecosystem:Alpine":      {"alpine:p@1.0", "pkg:apk/alpine/musl@1.2.4-r0?distro=3.18.4"},
		"ecosystem:Wolfi":       {"wolfi:p@1.0", "pkg:apk/wolfi/busybox@1.36-r0"},
		"ecosystem:Chainguard":  {"chainguard:p@1.0", "pkg:apk/chainguard/git@2.4-r0"},
		"ecosystem:Rocky Linux": {"rocky linux:p@1.0", "rocky:p@1.0", "pkg:rpm/rocky/bash@5.1-1?distro=rocky-9.2"},
		"ecosystem:AlmaLinux":   {"almalinux:p@1.0", "pkg:rpm/almalinux/glibc@2.34-1?distro=almalinux-9"},
		// outside OSV's ecosystems: the name as given
		"ecosystem:foo":     {"foo:p@1.0"},
		"ecosystem:deb":     {"pkg:deb/foo/x@1.0"},
		"ecosystem:Red Hat": {"pkg:rpm/redhat/openssl@3.0-1?distro=rhel-9"},
	}
	for scope, refs := range want {
		for _, ref := range refs {
			p, err := ParsePackageRef(ref)
			if err != nil {
				t.Fatal(err)
			}
			inp := EnrichInput{Packages: []PkgRef{p}}
			off := EnrichUnifiedExt(context.Background(), nil, nil, inp, Options{})
			if len(off) != 1 || off[0].Scope != scope || off[0].State != unified.StateNotChecked || off[0].Identity != p.Name || off[0].Version != p.Version {
				t.Errorf("%s with OSV off = %+v, want one not_checked result in %s", ref, off, scope)
			}
			if got := EnrichUnifiedExt(context.Background(), nil, nil, inp, Options{OSV: on}); len(got) != 1 || got[0].Scope != scope {
				t.Errorf("%s with OSV on = %+v, want its scope %s", ref, got, scope)
			}
		}
	}
}
