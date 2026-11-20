package matcher

import (
	"regexp"
	"strings"
)

// distroTokens maps the OS token a distro's packagers compile into a server banner ("Apache/2.4.38 (Debian)",
// "nginx/1.18.0 (Ubuntu)") to the distro's name. The token of a build that is not a distro package ("(Win64)",
// "(Unix)") is not listed, so it names none.
var distroTokens = map[string]string{
	"ubuntu": "Ubuntu", "debian": "Debian", "raspbian": "Raspbian",
	"centos": "CentOS", "centos stream": "CentOS Stream",
	"red hat enterprise linux": "Red Hat Enterprise Linux", "red hat": "Red Hat",
	"fedora": "Fedora", "amazon": "Amazon Linux", "amazon linux": "Amazon Linux",
	"rocky linux": "Rocky Linux", "almalinux": "AlmaLinux", "linux/suse": "SUSE",
}

var (
	reParenToken = regexp.MustCompile(`\(([^()]+)\)`)
	// The package revision a distro appends to the upstream version, always lower case: "7.4.3-4ubuntu2.19",
	// "7.3.31-1~deb10u1", "7.4.33+deb11u3". A rebuild of upstream releases for Debian ("+debian11", "+deb.sury.org")
	// is not one; the same rebuild for Ubuntu ("-1+ubuntu22.04.1+deb.sury.org+1") still reads as Ubuntu — the safe
	// direction: its hits become potentially_affected, never clean.
	reUbuntuRevision = regexp.MustCompile(`\d[^\s/()]*ubuntu`)
	reDebianRevision = regexp.MustCompile(`\d[^\s/()]*[~+]deb\d`)
)

// distroOf names the distro whose package build a field value says it is, or "".
func distroOf(value string) string {
	for _, m := range reParenToken.FindAllStringSubmatch(value, -1) {
		if name, ok := distroTokens[strings.ToLower(m[1])]; ok {
			return name
		}
	}
	switch {
	case reUbuntuRevision.MatchString(value):
		return "Ubuntu"
	case reDebianRevision.MatchString(value):
		return "Debian"
	}
	return ""
}

// claimDistro is the distro named by a claim of the chosen version — a claim of another version says nothing about
// it. Two claims naming two distros give the alphabetically first, so the same claims always give the same answer.
func claimDistro(claims []VersionClaim, version string) string {
	distro := ""
	for _, c := range claims {
		if c.Version == version && c.Distro != "" && (distro == "" || c.Distro < distro) {
			distro = c.Distro
		}
	}
	return distro
}
