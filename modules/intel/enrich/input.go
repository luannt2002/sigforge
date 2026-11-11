package enrich

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ParsePackageRef reads one package reference for the OSV dispatch: a Package URL
// (pkg:type/namespace/name@version — the identifier every ecosystem shares) or the short
// form ecosystem:name@version. The ecosystem is passed through as written; the OSV source
// decides whether it supports it.
func ParsePackageRef(s string) (PkgRef, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "pkg:") {
		return parsePURL(s)
	}
	eco, rest, ok := strings.Cut(s, ":")
	if !ok || eco == "" || rest == "" {
		return PkgRef{}, fmt.Errorf("package %q: want a purl (pkg:npm/lodash@4.17.20) or ecosystem:name@version", s)
	}
	name, version := rest, ""
	if at := strings.LastIndex(rest, "@"); at > 0 || at == 0 && !strings.Contains(rest, "/") { // at 0 is an npm scope only with a "/"
		name, version = rest[:at], rest[at+1:]
	}
	if strings.TrimSpace(name) == "" {
		return PkgRef{}, fmt.Errorf("package %q: empty name", s)
	}
	return PkgRef{Ecosystem: eco, Name: name, Version: version}, nil
}

// parsePURL follows the purl spec: the subpath (#) is dropped, the version follows the last
// "@" of the final segment, every segment is percent-decoded, and the namespace joins the
// name the way each ecosystem's advisories name a package (maven group:artifact; path-style
// elsewhere, e.g. npm @scope/name, Go module paths). An OS package (deb/apk/rpm) is resolved
// by distroRef.
func parsePURL(s string) (PkgRef, error) { return parsePURLSource(s, "") }

// parsePURLSource is parsePURL with the OS package's source package given out of band
// ("name@version", as an SBOM property carries it); "" falls back to the upstream qualifier.
func parsePURLSource(s, source string) (PkgRef, error) {
	rest := strings.TrimPrefix(s, "pkg:")
	rest, _, _ = strings.Cut(rest, "#")
	rest, rawQ, _ := strings.Cut(rest, "?")
	q, err := purlQualifiers(rawQ)
	if err != nil {
		return PkgRef{}, fmt.Errorf("purl %q: %w", s, err)
	}
	version := ""
	if slash := strings.LastIndex(rest, "/"); slash >= 0 {
		if at := strings.LastIndex(rest[slash+1:], "@"); at >= 0 {
			version, rest = rest[slash+1+at+1:], rest[:slash+1+at]
		}
	}
	segs := strings.Split(rest, "/")
	for i, seg := range segs {
		d, err := url.PathUnescape(seg)
		if err != nil {
			return PkgRef{}, fmt.Errorf("purl %q: %w", s, err)
		}
		segs[i] = d
	}
	version, err = url.PathUnescape(version)
	if err != nil {
		return PkgRef{}, fmt.Errorf("purl %q: %w", s, err)
	}
	if len(segs) < 2 || segs[0] == "" || strings.TrimSpace(segs[len(segs)-1]) == "" {
		return PkgRef{}, fmt.Errorf("purl %q: want pkg:type/[namespace/]name[@version]", s)
	}
	typ, ns, name := strings.ToLower(segs[0]), strings.Join(segs[1:len(segs)-1], "/"), segs[len(segs)-1]
	if eco, ok := distroEcosystems[typ+"/"+strings.ToLower(ns)]; ok {
		return distroRef(eco, name, version, q, source), nil
	}
	if typ == "deb" || typ == "apk" || typ == "rpm" {
		return PkgRef{Ecosystem: typ, Name: name, Version: version}, nil // a distro OSV does not file
	}
	switch {
	case ns == "":
	case typ == "maven":
		name = ns + ":" + name
	default:
		name = ns + "/" + name
	}
	return PkgRef{Ecosystem: typ, Name: name, Version: version}, nil
}

// purlQualifiers decodes "k=v&k=v". Values are path-unescaped: url.ParseQuery would turn the
// "+" of a Debian version (9+deb12u4) into a space.
func purlQualifiers(raw string) (map[string]string, error) {
	q := map[string]string{}
	for _, kv := range strings.Split(raw, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if k == "" {
			continue
		}
		d, err := url.PathUnescape(v)
		if err != nil {
			return nil, err
		}
		q[strings.ToLower(k)] = d
	}
	return q, nil
}

// distroEcosystems maps an OS purl (type/namespace) to the OSV ecosystem filing its advisories
// (OSV's own purl mapping; "rocky" is the os-release ID that SBOM tools also write).
var distroEcosystems = map[string]string{
	"deb/debian": "Debian", "deb/ubuntu": "Ubuntu", "deb/echo": "Echo",
	"apk/alpine": "Alpine", "apk/wolfi": "Wolfi", "apk/chainguard": "Chainguard", "apk/minimos": "MinimOS",
	"rpm/rocky-linux": "Rocky Linux", "rpm/rocky": "Rocky Linux", "rpm/almalinux": "AlmaLinux",
	"rpm/redhat": "Red Hat", "rpm/suse": "SUSE", "rpm/opensuse": "openSUSE", "rpm/mageia": "Mageia",
	"rpm/openeuler": "openEuler", "rpm/azure-linux": "Azure Linux",
}

// binaryNamed distros file advisories under binary package names (checked on the AlmaLinux
// dump: glibc-devel, glibc-common, …); every other distro uses the source package name.
var binaryNamed = map[string]bool{"AlmaLinux": true, "Red Hat": true}

// distroRef names an OS package the way its distro's advisories do: ecosystem plus release,
// the source package where the distro files by source, and the epoch back in the version.
func distroRef(eco, name, version string, q map[string]string, source string) PkgRef {
	if source == "" {
		source = q["upstream"]
	}
	if src, srcVer := sourceRef(source); src != "" && !binaryNamed[eco] {
		name = src
		if srcVer != "" {
			version = srcVer
		}
	}
	if ep := q["epoch"]; ep != "" && ep != "0" && !strings.Contains(version, ":") {
		version = ep + ":" + version
	}
	if r := distroRelease(eco, q["distro"]); r != "" {
		eco += ":" + r
	}
	return PkgRef{Ecosystem: eco, Name: name, Version: version}
}

// sourceRef reads a source package reference: "name", "name@version", or an RPM SOURCERPM
// file name ("openssl-1.1.1k-7.el8_6.src.rpm" → openssl, 1.1.1k-7.el8_6).
func sourceRef(up string) (name, version string) {
	if base, ok := strings.CutSuffix(up, ".src.rpm"); ok {
		if r := strings.LastIndex(base, "-"); r > 0 {
			if v := strings.LastIndex(base[:r], "-"); v > 0 {
				return base[:v], base[v+1:]
			}
		}
	}
	name, version, _ = strings.Cut(up, "@")
	return name, version
}

var reTrailingVersion = regexp.MustCompile(`\d+(?:\.\d+)*$`)

// distroRelease turns a distro qualifier ("debian-12.13", "3.16.3", "ubuntu-22.04") into the
// release suffix OSV files that distro under; "" when absent or not mapped (the lookup then
// says the release is missing instead of guessing one).
func distroRelease(eco, distro string) string {
	parts := strings.Split(reTrailingVersion.FindString(distro), ".")
	switch {
	case parts[0] == "":
		return ""
	case eco == "Debian" || eco == "Rocky Linux" || eco == "AlmaLinux":
		return parts[0]
	case eco == "Alpine" && len(parts) > 1:
		return "v" + parts[0] + "." + parts[1]
	case eco == "Ubuntu" && len(parts) > 1:
		r := parts[0] + "." + parts[1]
		if yy, err := strconv.Atoi(parts[0]); err == nil && yy%2 == 0 && parts[1] == "04" {
			r += ":LTS" // Ubuntu LTS releases are the even-year April ones
		}
		return r
	}
	return ""
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	PURL       string         `json:"purl"`
	Properties []cdxProperty  `json:"properties"`
	Components []cdxComponent `json:"components"`
}

// trivySrc prefixes the properties in which a Trivy SBOM names a binary's source package.
const trivySrc = "aquasecurity:trivy:Src"

// source is the component's source package as "name@[epoch:]version[-release]", "" if not given.
func (c cdxComponent) source() string {
	p := map[string]string{}
	for _, x := range c.Properties {
		if k, ok := strings.CutPrefix(x.Name, trivySrc); ok {
			p[k] = x.Value
		}
	}
	if p["Name"] == "" {
		return ""
	}
	v := p["Version"]
	if p["Release"] != "" {
		v += "-" + p["Release"]
	}
	if p["Epoch"] != "" && p["Epoch"] != "0" {
		v = p["Epoch"] + ":" + v
	}
	return p["Name"] + "@" + v
}

// ParseCycloneDX reads a CycloneDX JSON SBOM — from any tool, any ecosystem — into the
// package refs of all its components, nested ones too, once each. A component without a
// purl, or with one that does not parse, is counted in skipped, never silently dropped.
func ParseCycloneDX(b []byte) (refs []PkgRef, skipped int, err error) {
	var bom struct {
		BOMFormat  string         `json:"bomFormat"`
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(b, &bom); err != nil {
		return nil, 0, fmt.Errorf("sbom: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, 0, errors.New(`sbom: not a CycloneDX JSON document (bomFormat is not "CycloneDX")`)
	}
	seen := map[PkgRef]bool{}
	var walk func([]cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			r, err := parsePURLSource(strings.TrimSpace(c.PURL), c.source())
			switch {
			case err != nil || !strings.HasPrefix(strings.TrimSpace(c.PURL), "pkg:"):
				skipped++
			case !seen[r]:
				seen[r] = true
				refs = append(refs, r)
			}
			walk(c.Components)
		}
	}
	walk(bom.Components)
	return refs, skipped, nil
}
