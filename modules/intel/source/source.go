// Package source holds the operator-gated fetch+normalize adapters that widen the
// published DB with third-party fingerprint data. Each adapter is a Source: it
// knows its id and SPDX license, can Fetch its raw bytes from an operator-supplied
// URL, and can Normalize those bytes into sigforge's schema. Normalize is a PURE
// function (no network, no state), so it is fixture-tested offline.
//
// LICENSE POSTURE. sigforge never relicenses: every entry an adapter produces is
// tagged with the source's provenance + license + synced version. The fetched data
// is operator-generated, carries that source's own license, and is NEVER vendored
// into this repo. Every adapter is OFF by default — a Source does nothing, and
// building one errors, unless the operator supplies its URL (flag or env).
package source

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// Source is one third-party fingerprint origin.
type Source interface {
	Name() string                                                // provenance id, e.g. "webappanalyzer"
	License() string                                             // SPDX id of the source's own license
	Fetch(ctx context.Context) ([]byte, error)                   // pull raw bytes from the operator URL
	Normalize(raw []byte) (map[string]schema.Fingerprint, error) // pure: raw → schema entries
}

// New builds the adapter with id, bound to the operator-supplied url and client.
// It returns ok=false for an unknown id. An empty url is allowed here (so a caller
// can report "off"); Fetch is what refuses to run without one.
func New(id, srcURL string, client *fetch.Client) (Source, bool) {
	switch id {
	case "webappanalyzer":
		return &webappanalyzer{url: srcURL, client: client}, true
	case "nuclei":
		return &nuclei{url: srcURL, client: client}, true
	case "whatweb":
		return &whatweb{url: srcURL, client: client}, true
	}
	return nil, false
}

// EnvVar is the environment variable an operator may use instead of a flag value
// to supply a source's URL, e.g. SIGFORGE_SOURCE_WEBAPPANALYZER_URL.
func EnvVar(id string) string {
	return "SIGFORGE_SOURCE_" + strings.ToUpper(id) + "_URL"
}

// Stamp fills provenance (and license, when given) on every entry that lacks one,
// and sets the synced provenance_version on all of them. Called after Fetch so the
// version reflects what was actually pulled.
func Stamp(set map[string]schema.Fingerprint, provenance, license, version string) {
	for name, fp := range set {
		if fp.Provenance == "" {
			fp.Provenance = provenance
		}
		if fp.License == "" {
			fp.License = license
		}
		fp.ProvenanceVersion = version
		set[name] = fp
	}
}

var (
	shaRe = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	tagRe = regexp.MustCompile(`^v?\d+\.\d+(?:\.\d+)?$`)
)

// Version is the sync marker for a fetch: the pinned git SHA or release tag found
// in the URL path, else "unversioned@<RFC3339>". It never fabricates a SHA — an
// unpinned URL (a branch like main, or no ref) is honestly recorded as unversioned.
func Version(srcURL string, fetchedAt time.Time) string {
	if ref := pinnedRef(srcURL); ref != "" {
		return ref
	}
	return "unversioned@" + fetchedAt.UTC().Format(time.RFC3339)
}

func pinnedRef(srcURL string) string {
	u, err := url.Parse(srcURL)
	if err != nil {
		return ""
	}
	for _, seg := range strings.Split(u.Path, "/") {
		switch seg {
		case "", "refs", "tags", "heads":
			continue
		}
		if shaRe.MatchString(seg) || tagRe.MatchString(seg) {
			return seg
		}
	}
	return ""
}

// requireURL is the shared guard: an adapter with no operator URL does nothing.
func requireURL(name, u string) error {
	if strings.TrimSpace(u) == "" {
		return errors.New(name + ": no URL configured (supply --fetch " + name + "=<url> or " + EnvVar(name) + "); source is off by default")
	}
	return nil
}
