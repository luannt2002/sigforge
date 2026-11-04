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
	Dom       json.RawMessage       `json:"dom,omitempty"` // carried through for consumers with a DOM; this repo's reference matcher does not evaluate it

	Confidence   int      `json:"confidence,omitempty"`    // declared confidence (1..100) when a pattern carries no `\;confidence:N`; absent = 100
	Provenance   string   `json:"provenance,omitempty"`    // source id the entry came from, e.g. "baseline"
	License      string   `json:"license,omitempty"`       // SPDX id of the source's license, e.g. "Apache-2.0"
	VersionRegex []string `json:"version_regex,omitempty"` // alternate version-capturing patterns kept from lower-precedence sources during merge
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

// Validate checks the envelope and basic shape: a compatible schema version and a
// non-empty set with non-empty names. It does not compile patterns — a malformed
// regex is the matcher's concern, which drops it rather than failing the DB.
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
	for name := range db.Fingerprints {
		if strings.TrimSpace(name) == "" {
			return errors.New("schema: fingerprint with empty name")
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
