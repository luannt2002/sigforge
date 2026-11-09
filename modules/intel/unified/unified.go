// Package unified is the single result shape every intelligence source in SigForge
// emits, so a consumer (ASIE, the enrich pipeline, any scanner) handles ONE contract
// instead of six per-provider types. It is additive: each provider keeps its own
// typed API; an adapter maps that output into a unified.Result.
//
// HONESTY IS THE CONTRACT. The State values force a consumer to tell apart
// "not looked up", "looked up, nothing applies", and "an advisory applies by version
// range" — none of which is a verified exploitable vulnerability (that judgment is
// ASIE's, against a real asset). unknown/stale/source-unavailable are never "clean".
package unified

import (
	"encoding/json"
	"fmt"
)

// State — the one dimension a consumer must never collapse. A lead that is
// AffectedByAdvisory is still only an advisory-range match on a (spoofable) version,
// not a proven hole.
type State int

const (
	StateNotChecked            State = iota // the source was off / not invoked (no env URL, disabled)
	StateSourceUnavailable                  // the source errored / was unreachable — NOT "clean"
	StateUnknownProduct                     // the source does not recognise this identity
	StateUnknownVersion                     // the version could not be determined or compared for this scope
	StatePotentiallyAffected                // an advisory exists for the product but the version can't be pinned
	StateAffectedByAdvisory                 // the version falls in an advisory range (a LEAD, never proof)
	StateNotAffectedByAdvisory              // the version resolved and no advisory matched (clean for THIS source only); not issued in this release — see Clean
)

func (s State) String() string {
	switch s {
	case StateNotChecked:
		return "not_checked"
	case StateSourceUnavailable:
		return "source_unavailable"
	case StateUnknownProduct:
		return "unknown_product"
	case StateUnknownVersion:
		return "unknown_version"
	case StatePotentiallyAffected:
		return "potentially_affected"
	case StateAffectedByAdvisory:
		return "affected_by_advisory"
	case StateNotAffectedByAdvisory:
		return "not_affected_by_advisory"
	}
	return "invalid"
}

// Applicable reports whether this result is an actionable lead a scanner should look at
// (potentially- or advisory-affected). Everything else is unknown/clean-for-source/off.
func (s State) Applicable() bool {
	return s == StatePotentiallyAffected || s == StateAffectedByAdvisory
}

// Evidence is what a source knows when nothing matched; Clean turns it into the named gap.
// Both holding is what a "not affected" answer would rest on — this release still issues none.
type Evidence struct {
	// FullData: the answer came from the source's complete data — a live, synced or queried
	// catalog — not an embedded sample, one page of a paged answer or a cut-off list.
	FullData bool
	// Positioned: the version was compared with every advisory the source has for the
	// identity (true when there are none).
	Positioned bool
}

// NoteNoClearance is why a lookup that matched nothing in a source's whole data is still a gap.
const NoteNoClearance = "no advisory in the source's data matched; this release issues no clearance: a source can be cut short or stop tracking a release without saying so"

// Clean is the one door to not_affected_by_advisory, and in this release it stays shut: real
// sources were found cut short (truncated epochs) or no longer tracking a release while their
// data read as whole, so a miss is reported as a gap with why, never as a clearance. The
// evidence still names the gap: not_checked when the data is incomplete, unknown_version when
// the version could not be compared with every advisory, not_checked with NoteNoClearance
// otherwise.
func Clean(ev Evidence) (State, string) {
	switch {
	case !ev.FullData:
		return StateNotChecked, "only part of the source's data was available (an embedded sample, a page or a cut-off list): what is absent from it was not checked"
	case !ev.Positioned:
		return StateUnknownVersion, "the version could not be compared with every advisory of the source"
	}
	return StateNotChecked, NoteNoClearance
}

// Answered reports whether the lookup reached a conclusion — affected, potentially affected,
// or not affected; every other state is a gap, never read as clean.
func (s State) Answered() bool { return s.Applicable() || s == StateNotAffectedByAdvisory }

// MarshalJSON writes the state as its readable name ("potentially_affected"), not an
// opaque integer — a consumer must never mistake one state for another.
func (s State) MarshalJSON() ([]byte, error) { return []byte(`"` + s.String() + `"`), nil }

// UnmarshalJSON reads a state by its name; an unknown name is an error, never a default state.
func (s *State) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	for st := StateNotChecked; st <= StateNotAffectedByAdvisory; st++ {
		if st.String() == name {
			*s = st
			return nil
		}
	}
	return fmt.Errorf("unified: unknown state %q", name)
}

// AdvisoryState is the ONE rule every advisory source uses to label a match, so no
// adapter decides it on its own: with the running version pinned, a match means that
// version falls in an advisory range (affected_by_advisory); without one, the advisories
// are only known for the product (potentially_affected) — never a claim about a version
// nobody detected.
func AdvisoryState(versionPinned bool) State {
	if versionPinned {
		return StateAffectedByAdvisory
	}
	return StatePotentiallyAffected
}

// NoteNoVersion is the shared Err note for a potentially_affected verdict that comes from
// a missing version, so every source explains it the same way.
const NoteNoVersion = "no version detected: advisories for the product, not pinned to the running version"

// Freshness — where the data behind this result came from, so a stale snapshot is never
// read as live truth.
type Freshness int

const (
	FreshnessUnknown  Freshness = iota
	FreshnessLive               // fetched from the configured live source this run
	FreshnessSnapshot           // from an embedded point-in-time snapshot (offline baseline)
	FreshnessStale              // a cache/snapshot known to be past its freshness window
)

func (f Freshness) String() string {
	switch f {
	case FreshnessLive:
		return "live"
	case FreshnessSnapshot:
		return "snapshot"
	case FreshnessStale:
		return "stale"
	}
	return "unknown"
}

// MarshalJSON writes the freshness as its readable name, so a stale snapshot is never
// serialized as an opaque integer a reader could overlook.
func (f Freshness) MarshalJSON() ([]byte, error) { return []byte(`"` + f.String() + `"`), nil }

// UnmarshalJSON reads a freshness by its name; an unknown name is an error.
func (f *Freshness) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	for fr := FreshnessUnknown; fr <= FreshnessStale; fr++ {
		if fr.String() == name {
			*f = fr
			return nil
		}
	}
	return fmt.Errorf("unified: unknown freshness %q", name)
}

// Lead — one advisory/CVE a source attributes to the identity+version. Score (CVSS,
// 0–10) and EPSS (exploitation probability, 0–1) are separate pointers: different
// scales must never share a field, and nil keeps "no score" distinct from a real 0.0.
type Lead struct {
	ID         string   `json:"id"`                        // the source's own id (GHSA/KEV/WPVDB/RetireID…)
	CVE        []string `json:"cve,omitempty"`             // mapped CVE ids, if any
	Title      string   `json:"title,omitempty"`           //
	Severity   string   `json:"severity,omitempty"`        // the source's severity LABEL, empty if unscored (never fabricated)
	CVSS       string   `json:"cvss,omitempty"`            // raw CVSS vector/score as the source gave it
	Score      *float64 `json:"score,omitempty"`           // nullable numeric CVSS base score — nil ≠ 0.0
	EPSS       *float64 `json:"epss,omitempty"`            // nullable EPSS probability — nil ≠ 0.0
	KnownExpl  bool     `json:"known_exploited,omitempty"` // in CISA KEV
	References []string `json:"references,omitempty"`
}

// Result — the unified intelligence result. Every field a consumer needs to decide
// "is this a lead, how sure, from where, how fresh" without knowing which provider ran.
type Result struct {
	State      State     `json:"state"`
	Scope      string    `json:"scope"`                 // "cpe" | "ecosystem:npm" | "wordpress:plugin" | "jslib" | "eol"
	Identity   string    `json:"identity,omitempty"`    // the CPE / package / slug this result is about
	Version    string    `json:"version,omitempty"`     // the (spoofable) version evaluated
	Leads      []Lead    `json:"leads,omitempty"`       // advisories when (potentially) affected
	Source     string    `json:"source,omitempty"`      // provider source id
	Freshness  Freshness `json:"freshness,omitempty"`   //
	ObservedAt string    `json:"observed_at,omitempty"` // when the evidence was observed (consumer-supplied)
	FetchedAt  string    `json:"fetched_at,omitempty"`  // when the feed data was fetched (RFC3339), if known
	SnapshotID string    `json:"snapshot_id,omitempty"` //
	// CPEState records HOW the CPE in Identity was resolved, kept apart from Err so a
	// resolution note is never mistaken for a lookup failure: "verified" (NVD dictionary),
	// "attested" (source fingerprint), "candidate" (borrowed, never queried) or "none".
	CPEState    string `json:"cpe_state,omitempty"`
	CPEEvidence string `json:"cpe_evidence,omitempty"` // what backed the state (e.g. "nvd-dict", "source")
	// Tech is the detected technology a page detection's result is about ("Nginx"): the lookup
	// identity (a CPE, an EOL product slug) does not say which detection it came from.
	Tech string `json:"tech,omitempty"`
	Err  string `json:"error,omitempty"` // non-fatal note (why source_unavailable/unknown)
}

// Unknown builds a not-looked-up / unavailable result for a scope+identity, so a
// provider adapter never returns a zero Result that a consumer could misread as clean.
func Unknown(scope, identity string, state State, err string) Result {
	return Result{State: state, Scope: scope, Identity: identity, Err: err}
}
