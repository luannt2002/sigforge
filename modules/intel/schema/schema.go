// Package schema defines the on-disk fingerprint contract that sigforge publishes
// and that scanners read. The JSON form is Wappalyzer-compatible — the
// cats/headers/cookies/meta/html/scriptSrc/implies/dom fields and the inline
// `\;version:\1` / `\;confidence:N` pattern suffixes follow the de-facto standard,
// so any source normalizes into it and a consumer writes one loader. It is
// extended with per-entry provenance, license, confidence and alternate version
// regexes, and wrapped in a versioned envelope so a consumer can refuse a DB whose
// major schema version it does not understand.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/luannt2002/sigforge/framework/fsio"
)

// SchemaVersion is the version this build reads and writes. A DB is compatible
// when its major component equals this one (see Validate).
const SchemaVersion = "1.0.0"

// DB is the whole published fingerprint database: a versioned envelope around the
// set of fingerprints keyed by technology name.
type DB struct {
	SchemaVersion string                 `json:"schema_version"`
	GeneratedAt   string                 `json:"generated_at,omitempty"`
	Fingerprints  map[string]Fingerprint `json:"fingerprints"`
}

// Fingerprint is one technology's detection record. The first group of fields is
// the Wappalyzer-compatible pattern shape; the second group is sigforge's
// extension carrying the license posture and merge metadata of the entry.
type Fingerprint struct {
	Cats      []int                 `json:"cats,omitempty"`
	Headers   map[string]StringList `json:"headers,omitempty"`
	Cookies   map[string]StringList `json:"cookies,omitempty"`
	Meta      map[string]StringList `json:"meta,omitempty"`
	HTML      StringList            `json:"html,omitempty"`
	ScriptSrc StringList            `json:"scriptSrc,omitempty"`
	Implies   StringList            `json:"implies,omitempty"`
	Dom       json.RawMessage       `json:"dom,omitempty"` // carried through for consumers with a DOM; the reference matcher reads only what is observable without one (matcher_dom.go)

	Confidence        int      `json:"confidence,omitempty"`         // declared confidence (1..100) when a pattern carries no `\;confidence:N`; absent = 100
	Provenance        string   `json:"provenance,omitempty"`         // source id the entry came from, e.g. "baseline"
	ProvenanceVersion string   `json:"provenance_version,omitempty"` // the synced version of the source: a git SHA / release tag when the fetch URL pinned one, else "unversioned@<RFC3339>"
	License           string   `json:"license,omitempty"`            // SPDX id of the source's license, e.g. "Apache-2.0"
	VersionRegex      []string `json:"version_regex,omitempty"`      // alternate version-capturing patterns kept from lower-precedence sources during merge
	CPE               []string `json:"cpe,omitempty"`                // Common Platform Enumeration id(s) the source attests, e.g. "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*" — the bridge to CVE/NVD; populated only from a source's real cpe value, never fabricated

	// VersionRegexProv is the true provenance+license of each VersionRegex alternate,
	// aligned by index. The entry-level Provenance/License above describe the winning
	// source, but an alternate kept during merge may come from a lower-precedence
	// source under a different (e.g. GPL) license; recording it per pattern keeps a
	// consumer from serving that pattern under the winner's license. Absent or shorter
	// than VersionRegex ⇒ the unrecorded alternates share the entry's own license.
	VersionRegexProv []PatternProv `json:"version_regex_prov,omitempty"`

	// CPECandidate holds CPE id(s) that a lower-precedence entry of the SAME technology
	// name attested but this (winning) entry did not. The two entries may be different
	// editions/forks/distributions, so a borrowed CPE is NOT attested for this entry's
	// identity — it is an UNVERIFIED lead for a consumer to cross-verify (the identity
	// package resolves a verified CPE separately), never a CPE for direct CVE lookup.
	// Being here rather than in CPE is the "unverified, from another entry" flag; kept
	// rather than dropped so no CVE signal is lost silently.
	CPECandidate []string `json:"cpe_candidate,omitempty"`

	// CPECandidateProv is the true provenance+license of each CPECandidate, aligned by
	// index, since a borrowed CPE belongs to its lower-precedence source, not this
	// entry (mirrors VersionRegexProv — same license-posture guard).
	CPECandidateProv []PatternProv `json:"cpe_candidate_prov,omitempty"`
}

// CapturesVersion reports whether the entry can extract a version: a version_regex
// alternate, or any Wappalyzer pattern carrying the `\;version:` suffix. One definition
// shared by the refresh regression gate and the coverage report, so they cannot drift.
func (fp Fingerprint) CapturesVersion() bool {
	if len(fp.VersionRegex) > 0 {
		return true
	}
	for _, m := range []map[string]StringList{fp.Headers, fp.Cookies, fp.Meta} {
		for _, raws := range m {
			if hasVersionSuffix(raws) {
				return true
			}
		}
	}
	return hasVersionSuffix(fp.HTML) || hasVersionSuffix(fp.ScriptSrc)
}

// HasDetection reports whether the entry can detect its tech on its own: at least one
// channel the matcher evaluates (headers, cookies, meta, html, scriptSrc, and dom —
// evaluated passively by matcher_dom.go) is present. Implies, version_regex and the
// metadata fields never detect, so an entry without these channels is found only when
// another tech implies it. The refresh gate uses this one definition.
// shortcut: a present field counts even when none of its patterns can fire (html [""],
// a header name with no pattern, dom null/{}); upgrade if a normalized source emits such.
func (fp Fingerprint) HasDetection() bool {
	return len(fp.Headers) > 0 || len(fp.Cookies) > 0 || len(fp.Meta) > 0 ||
		len(fp.HTML) > 0 || len(fp.ScriptSrc) > 0 || len(fp.Dom) > 0
}

func hasVersionSuffix(raws []string) bool {
	for _, raw := range raws {
		if strings.Contains(raw, `\;version:`) {
			return true
		}
	}
	return false
}

// PatternProv carries the provenance and license of a single pattern, used by
// VersionRegexProv so a merged-in alternate is never mislabeled under the entry's
// license. The fields mirror the entry-level provenance trio.
type PatternProv struct {
	Provenance        string `json:"provenance,omitempty"`
	ProvenanceVersion string `json:"provenance_version,omitempty"`
	License           string `json:"license,omitempty"`
}

// StringList accepts a JSON string or an array of strings, because a Wappalyzer
// pattern field may be either. It always marshals back as an array.
type StringList []string

func (l *StringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*l = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

// LoadFile reads and validates a DB from a file (a merged output or any operator
// DB). A missing or unreadable path returns an error the caller may treat as "use
// the baseline only".
func LoadFile(path string) (*DB, error) {
	b, err := fsio.Read(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and validates a DB from its JSON bytes.
func Parse(b []byte) (*DB, error) {
	if len(b) == 0 {
		return nil, errors.New("schema: empty input")
	}
	var db DB
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, fmt.Errorf("schema: decode: %w", err)
	}
	if err := Validate(&db); err != nil {
		return nil, err
	}
	return &db, nil
}

// Validate checks the envelope and basic shape: a compatible schema version, a
// non-empty set with non-empty names, and that every regex pattern compiles — a
// malformed regex is rejected here, naming the rule, so the matcher never drops it
// silently at match time.
func Validate(db *DB) error {
	if db == nil {
		return errors.New("schema: nil DB")
	}
	ok, err := majorCompatible(db.SchemaVersion, SchemaVersion)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("schema: incompatible schema_version %q (this build reads %q)", db.SchemaVersion, SchemaVersion)
	}
	if len(db.Fingerprints) == 0 {
		return errors.New("schema: no fingerprints")
	}
	for name, fp := range db.Fingerprints {
		if strings.TrimSpace(name) == "" {
			return errors.New("schema: fingerprint with empty name")
		}
		if err := validatePatterns(name, fp); err != nil {
			return err
		}
	}
	return nil
}

// validatePatterns compiles every regex a matcher would run for this entry, so a
// malformed pattern is caught here instead of being silently dropped at match time.
// An empty pattern is a presence signal, not a regex, and is skipped.
func validatePatterns(name string, fp Fingerprint) error {
	for key, raws := range fp.Headers {
		if err := checkPatterns(name, "headers["+key+"]", raws); err != nil {
			return err
		}
	}
	for key, raws := range fp.Cookies {
		if err := checkPatterns(name, "cookies["+key+"]", raws); err != nil {
			return err
		}
	}
	for key, raws := range fp.Meta {
		if err := checkPatterns(name, "meta["+key+"]", raws); err != nil {
			return err
		}
	}
	if err := checkPatterns(name, "html", fp.HTML); err != nil {
		return err
	}
	if err := checkPatterns(name, "scriptSrc", fp.ScriptSrc); err != nil {
		return err
	}
	if err := checkPatterns(name, "version_regex", fp.VersionRegex); err != nil {
		return err
	}
	if len(fp.Dom) > 0 {
		return validateDom(name, fp.Dom)
	}
	return nil
}

func checkPatterns(name, field string, raws []string) error {
	for _, raw := range raws {
		expr := patternExpr(raw)
		if strings.TrimSpace(expr) == "" {
			continue // presence signal, no regex to compile
		}
		if _, err := regexp.Compile("(?i)" + expr); err != nil {
			return fmt.Errorf("schema: fingerprint %q: invalid %s regex %q: %w", name, field, raw, err)
		}
	}
	return nil
}

// patternExpr is the regex part of a "regex\;version:..\;confidence:.." pattern.
func patternExpr(raw string) string {
	expr, _, _ := strings.Cut(raw, `\;`)
	return expr
}

// validateDom compiles the attribute and text regexes of a Wappalyzer `dom` object
// as the matcher does (an attribute pattern is anchored to `attr=`, see
// matcher_dom.go). The array and bare-string dom shapes carry only selectors, which
// are presence tokens, not regexes.
func validateDom(name string, raw json.RawMessage) error {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	for _, nraw := range obj {
		var node struct {
			Text       string            `json:"text"`
			Attributes map[string]string `json:"attributes"`
		}
		if json.Unmarshal(nraw, &node) != nil {
			continue // bare string/array value → presence selector, no regex
		}
		for attr, pat := range node.Attributes {
			expr := regexp.QuoteMeta(attr) + `\s*=\s*["']?` + patternExpr(pat)
			if _, err := regexp.Compile("(?i)" + expr); err != nil {
				return fmt.Errorf("schema: fingerprint %q: invalid dom attribute %q regex %q: %w", name, attr, pat, err)
			}
		}
		if expr := patternExpr(node.Text); strings.TrimSpace(expr) != "" {
			if _, err := regexp.Compile("(?i)" + expr); err != nil {
				return fmt.Errorf("schema: fingerprint %q: invalid dom text regex %q: %w", name, node.Text, err)
			}
		}
	}
	return nil
}

// JSON renders the DB as indented JSON suitable for an on-disk file.
func (db *DB) JSON() ([]byte, error) {
	return json.MarshalIndent(db, "", "  ")
}

// majorCompatible reports whether got shares want's major version. An empty or
// non-numeric major in got is treated as an error the caller surfaces.
func majorCompatible(got, want string) (bool, error) {
	gm, err := major(got)
	if err != nil {
		return false, fmt.Errorf("schema: bad schema_version %q: %w", got, err)
	}
	wm, _ := major(want)
	return gm == wm, nil
}

func major(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, errors.New("missing")
	}
	head, _, _ := strings.Cut(v, ".")
	return strconv.Atoi(head)
}
