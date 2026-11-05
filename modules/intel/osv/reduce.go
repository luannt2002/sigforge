// reduce.go — the PURE reducer for an OSV bulk dump (no network).
//
// An OSV per-ecosystem all.zip holds hundreds of thousands of JSON advisories, each 2-20KB,
// totalling ~205MB for npm. Disk on the host is scarce, so the dump is never retained: each zip
// entry is streamed, reduced to exactly what a lockfile lookup needs (package, ecosystem, affected
// ranges, the OSV id + CVE alias, the upstream severity label), and the heavy parts (details,
// references, credits, git commit lists, database_specific extras) are dropped in the loop.
//
// CONTRACT: no panic. A corrupt entry or odd JSON is skipped — one junk file must not kill the
// whole index build. Every exported function here is pure and offline-testable.
package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"strings"
)

const (
	// maxEntryBytes caps the decompressed size of one JSON entry (blocks a zip bomb). The largest
	// real OSV record is ~1MB (a long version list); 8MB is generous yet still blocks a forged 4GB file.
	maxEntryBytes = 8 << 20
	// maxExactVersions caps the concrete-version list kept for an advisory that has NO range (npm
	// advisories often enumerate hundreds), so the in-RAM index does not balloon.
	maxExactVersions = 96
)

// affectedRange is one affected range distilled from the OSV event sequence.
// introduced empty/"0" means from the start; fixed is HALF-OPEN (version < fixed is affected);
// lastAffected is CLOSED (version <= lastAffected is affected).
type affectedRange struct {
	introduced   string
	fixed        string
	lastAffected string
}

// record is one reduced advisory row, keyed in the index by package name.
type record struct {
	pkg       string
	ecosystem string
	id        string // native OSV id (GHSA-/GO-/PYSEC-…)
	cve       string // CVE alias if any
	severity  string // upstream text label mapped to low|medium|high|critical, or "" if unscored
	ranges    []affectedRange
	versions  []string // concrete versions, only when the advisory carries no range
}

// rawRecord is the subset of the OSV schema actually read; every other field is dropped at decode.
type rawRecord struct {
	ID        string          `json:"id"`
	Aliases   []string        `json:"aliases"`
	Withdrawn json.RawMessage `json:"withdrawn"`
	DBSpec    rawDBSpecific   `json:"database_specific"`
	Affected  []rawAffected   `json:"affected"`
}

type rawDBSpecific struct {
	Severity string `json:"severity"` // GHSA text label: LOW|MODERATE|HIGH|CRITICAL
}

type rawAffected struct {
	Package  rawPackage    `json:"package"`
	Ranges   []rawRange    `json:"ranges"`
	Versions []string      `json:"versions"`
	DBSpec   rawDBSpecific `json:"database_specific"`
}

type rawPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type rawRange struct {
	Type   string     `json:"type"` // SEMVER | ECOSYSTEM | GIT
	Events []rawEvent `json:"events"`
}

type rawEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// reduceRecord turns one OSV advisory into 0..n index rows (one advisory can touch several
// packages). Returns nil when the advisory is withdrawn, has no id, or no package in eco.
func reduceRecord(raw *rawRecord, eco string) []record {
	if raw == nil || strings.TrimSpace(raw.ID) == "" {
		return nil
	}
	if isWithdrawn(raw.Withdrawn) {
		return nil // reporting a withdrawn advisory would be a pure false positive
	}
	cve := ""
	for _, a := range raw.Aliases {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(a)), "CVE-") {
			cve = strings.ToUpper(strings.TrimSpace(a))
			break
		}
	}
	base := mapSeverity(raw.DBSpec.Severity)

	out := make([]record, 0, len(raw.Affected))
	for i := range raw.Affected {
		af := &raw.Affected[i]
		name := strings.TrimSpace(af.Package.Name)
		if name == "" {
			continue
		}
		// A per-ecosystem dump still carries multi-ecosystem records (the same CVE for npm + PyPI),
		// so filter to keep the npm index free of PyPI packages.
		recEco := strings.TrimSpace(af.Package.Ecosystem)
		if eco != "" && recEco != "" && !sameEcosystem(recEco, eco) {
			continue
		}
		if recEco == "" {
			recEco = eco
		}
		sev := base
		if s := mapSeverity(af.DBSpec.Severity); s != "" {
			sev = s
		}
		r := record{
			pkg:       name,
			ecosystem: trimEcosystem(recEco),
			id:        strings.TrimSpace(raw.ID),
			cve:       cve,
			severity:  sev,
			ranges:    rangesFrom(af.Ranges),
		}
		if len(r.ranges) == 0 {
			// No range: the only thing left to match on is the concrete version list, capped.
			for _, v := range af.Versions {
				if v = strings.TrimSpace(v); v == "" {
					continue
				}
				r.versions = append(r.versions, v)
				if len(r.versions) >= maxExactVersions {
					break
				}
			}
			if len(r.versions) == 0 {
				continue // no range, no versions: nothing to match, keeping it only wastes RAM
			}
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// rangesFrom collapses the OSV event sequence into introduced→fixed/lastAffected pairs.
// GIT ranges are dropped: they are commit hashes, not comparable to a lockfile version.
func rangesFrom(rs []rawRange) []affectedRange {
	var out []affectedRange
	for _, r := range rs {
		if strings.EqualFold(strings.TrimSpace(r.Type), "GIT") {
			continue
		}
		cur := affectedRange{}
		open := false
		for _, ev := range r.Events {
			switch {
			case strings.TrimSpace(ev.Introduced) != "":
				if open {
					out = append(out, cur) // previous range had no fixed: open to infinity
				}
				cur = affectedRange{introduced: strings.TrimSpace(ev.Introduced)}
				open = true
			case strings.TrimSpace(ev.Fixed) != "":
				cur.fixed = strings.TrimSpace(ev.Fixed)
				out = append(out, cur)
				cur, open = affectedRange{}, false
			case strings.TrimSpace(ev.LastAffected) != "":
				cur.lastAffected = strings.TrimSpace(ev.LastAffected)
				out = append(out, cur)
				cur, open = affectedRange{}, false
			}
		}
		if open {
			out = append(out, cur)
		}
	}
	return out
}

// isWithdrawn reports whether the advisory carries a withdrawal timestamp (null/"" is still in effect).
func isWithdrawn(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != `""`
}

// mapSeverity maps an upstream text label to the internal scale; "" when unrecognized or empty, so
// an unscored advisory carries no severity rather than a fabricated one.
func mapSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return ""
}

// reduceZip streams the zip dump, calling emit for each reduced row. r/size is an io.ReaderAt so
// archive/zip can read the central directory without loading the whole dump into RAM (the caller
// passes the downloaded temp file, or a bytes.Reader in tests). emit returning an error stops early.
func reduceZip(ctx context.Context, r io.ReaderAt, size int64, eco string, emit func(*record) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil || size <= 0 {
		return errEmptyDump
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return err
	}
	for i, zf := range zr.File {
		if i%256 == 0 { // periodic cancel check; every iteration would cost more than it saves
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
		if zf == nil || zf.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(zf.Name), ".json") {
			continue
		}
		recs, err := readZipEntry(zf, eco)
		if err != nil {
			continue // a corrupt entry must not kill the whole index
		}
		for j := range recs {
			if err := emit(&recs[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

// readZipEntry opens and decodes one entry. Split out so defer Close runs each iteration rather than
// leaving every file descriptor open until the whole walk finishes.
func readZipEntry(zf *zip.File, eco string) ([]record, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var raw rawRecord
	if err := json.NewDecoder(io.LimitReader(rc, maxEntryBytes)).Decode(&raw); err != nil {
		return nil, err
	}
	return reduceRecord(&raw, eco), nil
}

// ---------------------------------------------------------------------------
// Version comparison — semver-ish, stdlib only. Tolerates 1.2.3, 1.2, v1.2.3,
// 1.2.3-beta.1, 4.17.21+build, 2.0.0.RELEASE, 1.2.3-1ubuntu2.
// ---------------------------------------------------------------------------

// CompareVersions returns -1 / 0 / 1. Per semver, a prerelease is SMALLER than the release with the
// same numbers (1.0.0-rc < 1.0.0).
//
// TRADEOFF: this is ONE semver-ish comparator used for every ecosystem. PyPI PEP440 (epochs, "1.0a1"
// vs "1.0.0") and OS-package orderings ("1ubuntu2", Debian epochs) can sort differently at edge
// cases, so a borderline advisory can be missed → recall may be LOW there. That is why the
// ecosystem whitelist (ecosystemNames) admits only language ecosystems, not OS distros.
func CompareVersions(a, b string) int {
	ac, apre := splitVersion(a)
	bc, bpre := splitVersion(b)
	n := len(ac)
	if len(bc) > n {
		n = len(bc)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(ac) {
			x = ac[i]
		}
		if i < len(bc) {
			y = bc[i]
		}
		if c := cmpSegment(x, y); c != 0 {
			return c
		}
	}
	return cmpPrerelease(apre, bpre)
}

// splitVersion strips a v prefix, cuts build metadata (+…), splits off the prerelease (-…), then
// splits the core on ".".
func splitVersion(s string) ([]string, string) {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre, v = v[i+1:], v[:i]
	}
	if v == "" {
		return nil, pre
	}
	return strings.Split(v, "."), pre
}

// cmpSegment compares one version segment: number vs number by value, text vs text lexically;
// a number sorts BELOW text (the semver prerelease rule).
func cmpSegment(a, b string) int {
	an, bn := isNum(a), isNum(b)
	switch {
	case an && bn:
		return cmpNum(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

func isNum(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cmpNum compares two numeric strings of any length (a build date like 20230101120000 overflows int64).
func cmpNum(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// cmpPrerelease compares prerelease identifiers; "" (the final release) is GREATER than any prerelease.
func cmpPrerelease(a, b string) int {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if c := cmpSegment(as[i], bs[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// VersionInRange reports whether version falls inside r. introduced empty/"0" means from the start;
// fixed is a HALF-OPEN bound (version < fixed); lastAffected is a CLOSED bound (version <= lastAffected).
func VersionInRange(version string, r affectedRange) bool {
	if in := strings.TrimSpace(r.introduced); in != "" && in != "0" {
		if CompareVersions(version, in) < 0 {
			return false
		}
	}
	if f := strings.TrimSpace(r.fixed); f != "" {
		return CompareVersions(version, f) < 0
	}
	if l := strings.TrimSpace(r.lastAffected); l != "" {
		return CompareVersions(version, l) <= 0
	}
	return true // introduced but never fixed: every version from there on is affected
}

// normVersionKey normalizes a version for matching the concrete-version list ("v1.2.3" == "1.2.3").
func normVersionKey(s string) string {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	return strings.ToLower(v)
}
