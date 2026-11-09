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
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/versioncmp"
)

const (
	// maxEntryBytes caps the decompressed size of one JSON entry (blocks a zip bomb). The largest
	// real OSV record is ~1MB (a long version list); 8MB is generous yet still blocks a forged 4GB file.
	maxEntryBytes = 8 << 20
	// maxExactVersions caps the concrete-version list kept for an advisory with no range a version
	// can be placed in — none, or commit (GIT) ranges only — so the in-RAM index does not balloon
	// (npm advisories often enumerate hundreds).
	maxExactVersions = 96
)

// OSV range types (schema). ECOSYSTEM/default compares under the package ecosystem's rules;
// SEMVER compares under semver regardless of ecosystem; GIT bounds are commit hashes, so a GIT
// range cannot position a version string and is kept only as an honest "indeterminate" marker.
const (
	rangeSemver = "SEMVER"
	rangeGit    = "GIT"
	rangeBroken = "UNREADABLE" // a range with no event that bounds a version: never "not in range"
)

// affectedRange is one affected range distilled from the OSV event sequence.
// introduced empty/"0" means from the start; fixed is HALF-OPEN (version < fixed is affected);
// lastAffected is CLOSED (version <= lastAffected is affected). typ is the OSV range type, which
// selects the comparison scheme; a GIT typ carries no comparable bounds.
type affectedRange struct {
	typ          string
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
	versions  []string // listed versions no range places (OSV: a listed version is affected)
	truncated bool     // versions holds only the first maxExactVersions of the advisory's list
	// vulnKeys is the normalized dedup set (own id + every alias) so one logical vuln reported
	// under several ids (OSV id + CVE/GHSA aliases) is folded to one lookup result, not counted twice.
	vulnKeys []string
}

// rawRecord is the subset of the OSV schema actually read; every other field is dropped at decode.
type rawRecord struct {
	ID        string          `json:"id"`
	Aliases   []string        `json:"aliases"`
	Withdrawn json.RawMessage `json:"withdrawn"`
	DBSpec    rawDBSpecific   `json:"database_specific"`
	Affected  []*rawAffected  `json:"affected"`
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
	// vulnKeys folds every id this advisory is known by (own id + aliases) so a cross-source
	// duplicate (same flaw as GHSA-… and GO-…/PYSEC-…) is deduped by alias set, not double-counted.
	vulnKeys := []string{strings.ToUpper(strings.TrimSpace(raw.ID))}
	cve := ""
	for _, a := range raw.Aliases {
		a = strings.ToUpper(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		vulnKeys = append(vulnKeys, a)
		if cve == "" && strings.HasPrefix(a, "CVE-") {
			cve = a
		}
	}
	base := mapSeverity(raw.DBSpec.Severity)

	out := make([]record, 0, len(raw.Affected))
	for i := range raw.Affected {
		af := raw.Affected[i]
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
			ecosystem: recEco, // keeps a distro release suffix ("Debian:12") for LookupIn
			id:        strings.TrimSpace(raw.ID),
			cve:       cve,
			severity:  sev,
			ranges:    rangesFrom(af.Ranges),
			vulnKeys:  vulnKeys,
		}
		// OSV counts a version affected when a range places it OR the versions list names it
		// (MAL- records list versions their range does not reach): keep the listed versions
		// no range places — all of them when only commit ranges exist — capped.
		for _, v := range af.Versions {
			if v = strings.TrimSpace(v); v == "" || placedByRange(v, &r) {
				continue
			}
			if len(r.versions) == maxExactVersions {
				r.truncated = true // a version past the cut is not known to be outside the list
				break
			}
			r.versions = append(r.versions, v)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// rangesFrom collapses each OSV range's event sequence into introduced→fixed/lastAffected pairs,
// stamping the range type so the matcher picks the right comparison scheme. A GIT range has commit
// hashes, not versions: it is kept as a single indeterminate marker (so the package stays indexed
// and the lookup is honestly UNKNOWN) rather than silently dropped into a false "no vuln".
func rangesFrom(rs []rawRange) []affectedRange {
	var out []affectedRange
	for _, r := range rs {
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		if typ == rangeGit {
			out = append(out, affectedRange{typ: rangeGit})
			continue
		}
		n := len(out)
		cur := affectedRange{typ: typ}
		open := false
		for _, ev := range r.Events {
			switch {
			case strings.TrimSpace(ev.Introduced) != "":
				if open {
					out = append(out, cur) // previous range had no fixed: open to infinity
				}
				cur = affectedRange{typ: typ, introduced: strings.TrimSpace(ev.Introduced)}
				open = true
			case strings.TrimSpace(ev.Fixed) != "":
				cur.fixed = strings.TrimSpace(ev.Fixed)
				out = append(out, cur)
				cur, open = affectedRange{typ: typ}, false
			case strings.TrimSpace(ev.LastAffected) != "":
				cur.lastAffected = strings.TrimSpace(ev.LastAffected)
				out = append(out, cur)
				cur, open = affectedRange{typ: typ}, false
			}
		}
		if open {
			out = append(out, cur)
		}
		if len(out) == n {
			out = append(out, affectedRange{typ: rangeBroken})
		}
	}
	return out
}

// placedByRange reports whether one of the record's ranges determinately holds version.
func placedByRange(version string, r *record) bool {
	for _, g := range r.ranges {
		if in, ok := versionInRange(version, g, r.ecosystem); in && ok {
			return true
		}
	}
	return false
}

// onlyCommitRanges reports whether no range can place a version (none, or GIT only).
func onlyCommitRanges(rs []affectedRange) bool {
	for _, r := range rs {
		if r.typ != rangeGit {
			return false
		}
	}
	return true
}

// repositoryLevel reports an affected entry made of commit ranges only (its versions list,
// if any, holds the repository's tags), which no package lookup reads.
func repositoryLevel(af *rawAffected) bool {
	for _, g := range af.Ranges {
		if !strings.EqualFold(strings.TrimSpace(g.Type), rangeGit) {
			return false
		}
	}
	return len(af.Ranges) > 0
}

// isWithdrawn reports whether the advisory carries a withdrawal timestamp (null is still in effect;
// readZipEntry has already refused any other non-timestamp value).
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
// skipped counts the JSON entries that could not be read (corrupt, or past maxEntryBytes).
func reduceZip(ctx context.Context, r io.ReaderAt, size int64, eco string, emit func(*record) error) (skipped int, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil || size <= 0 {
		return 0, errEmptyDump
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return 0, err
	}
	for i, zf := range zr.File {
		if i%256 == 0 { // periodic cancel check; every iteration would cost more than it saves
			select {
			case <-ctx.Done():
				return skipped, ctx.Err()
			default:
			}
		}
		if zf == nil || zf.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(zf.Name), ".json") {
			continue
		}
		recs, err := readZipEntry(zf, eco)
		if err != nil {
			skipped++ // a corrupt entry must not kill the whole index, but it is counted
			continue
		}
		for j := range recs {
			if err := emit(&recs[j]); err != nil {
				return skipped, err
			}
		}
	}
	return skipped, nil
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
	dec := json.NewDecoder(io.LimitReader(rc, maxEntryBytes))
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("osv: entry holds more than one JSON value")
	}
	if err := checkRecord(&raw); err != nil {
		return nil, err
	}
	return reduceRecord(&raw, eco), nil
}

// checkRecord rejects an entry the OSV schema does not allow — null, no id, a withdrawn
// that is not a timestamp, a null affected entry, or one that places versions without
// naming its package — so it is counted unreadable instead of read as "no advisory". An
// affected entry with commit ranges only and no package is repository-level.
func checkRecord(raw *rawRecord) error {
	if strings.TrimSpace(raw.ID) == "" {
		return errors.New("osv: entry has no id")
	}
	for _, af := range raw.Affected {
		if af == nil {
			return fmt.Errorf("osv: %s: an affected entry is null", raw.ID)
		}
		if strings.TrimSpace(af.Package.Name) == "" && !repositoryLevel(af) {
			return fmt.Errorf("osv: %s: an affected entry names no package and is not repository-level", raw.ID)
		}
	}
	if w := strings.TrimSpace(string(raw.Withdrawn)); w != "" && w != "null" {
		var at string
		if err := json.Unmarshal(raw.Withdrawn, &at); err != nil {
			return fmt.Errorf("osv: %s: withdrawn is not a timestamp: %s", raw.ID, w)
		}
		if _, err := time.Parse(time.RFC3339, at); err != nil {
			return fmt.Errorf("osv: %s: withdrawn: %w", raw.ID, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Version comparison — delegated to versioncmp so each ecosystem is sorted by its OWN
// rules (PEP 440 for PyPI, semver for npm/Go/crates.io, …). The internal matcher passes
// the record's ecosystem; the exported helpers below keep their old signatures for
// external callers and compare under the semver default.
// ---------------------------------------------------------------------------

// CompareVersions returns -1 / 0 / 1 under the semver default (no ecosystem). Kept for API
// compatibility; the ecosystem-aware matching path uses versioncmp.Compare directly. Since
// v0.4 input that is not semver ("2.0.0.RELEASE") compares as 0 rather than by v0.3.0's
// lenient reading: call versioncmp.Compare and check ok to tell "equal" from "not comparable".
func CompareVersions(a, b string) int {
	c, _ := versioncmp.Compare("", a, b)
	return c
}

// VersionInRange reports whether version falls inside r under the semver default. introduced
// empty/"0" means from the start; fixed is HALF-OPEN (version < fixed); lastAffected is CLOSED
// (version <= lastAffected). The internal matcher uses versionInRange with the record ecosystem.
func VersionInRange(version string, r affectedRange) bool {
	in, _ := versionInRange(version, r, "")
	return in
}

// versionInRange is the ecosystem-aware range test. ok=false means a bound could not be
// compared for this ecosystem, so membership is INDETERMINATE and the caller must keep the
// version unknown rather than treat it as out of range. The range type selects the scheme: a
// SEMVER range is ordered by semver whatever the ecosystem; a GIT range (commit hashes) is never
// comparable, so it returns indeterminate rather than guessing membership.
func versionInRange(version string, r affectedRange, eco string) (in, ok bool) {
	if r.typ == rangeGit || r.typ == rangeBroken {
		return false, false
	}
	if r.typ == rangeSemver {
		eco = ""
	}
	if lo := strings.TrimSpace(r.introduced); lo != "" && lo != "0" {
		if f := strings.TrimSpace(r.fixed); f != "" {
			if c, ok := versioncmp.Compare(eco, f, lo); !ok || c <= 0 {
				return false, false // fixed at or before introduced: the range places no version
			}
		}
		if l := strings.TrimSpace(r.lastAffected); l != "" {
			if c, ok := versioncmp.Compare(eco, l, lo); !ok || c < 0 {
				return false, false
			}
		}
		c, cok := versioncmp.Compare(eco, version, lo)
		if !cok {
			return false, false
		}
		if c < 0 {
			return false, true
		}
	}
	if f := strings.TrimSpace(r.fixed); f != "" {
		c, cok := versioncmp.Compare(eco, version, f)
		if !cok {
			return false, false
		}
		return c < 0, true
	}
	if l := strings.TrimSpace(r.lastAffected); l != "" {
		c, cok := versioncmp.Compare(eco, version, l)
		if !cok {
			return false, false
		}
		return c <= 0, true
	}
	return true, true // introduced but never fixed: every version from there on is affected
}

// normVersionKey normalizes a version for matching the concrete-version list ("v1.2.3" == "1.2.3").
func normVersionKey(s string) string {
	v := strings.TrimSpace(s)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	return strings.ToLower(v)
}
