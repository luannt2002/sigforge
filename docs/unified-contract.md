# Unified Intelligence Contract

Package `modules/intel/unified` (added v0.4).

## 1. Why it exists

Before v0.4 each depth source (`cve`, `lifecycle`, `osv`, `jslib`, `wpcve`, `kev`)
spoke its own result type. A consumer — ASIE, a report, the `enrich` CLI — had to
know six shapes and six sets of "what does absence mean here". `unified.Result` is
the **one shape every source emits**, so a consumer handles ONE contract.

It is **additive**. Each provider keeps its own typed API; a thin `ToUnified` (or, for
`kev`, `MapSignal` / `EnrichUnified`) adapter maps that output into a `unified.Result`.
Nothing existing changed shape.

## 2. The honesty rule (the whole point)

`unified.State` is the one dimension a consumer must **never collapse**. A lead that is
`affected_by_advisory` is still only an advisory-range match on a (spoofable) version —
**not** a proven, exploitable hole. That verdict is ASIE's, against a real asset.

`unknown_*`, `source_unavailable` and `not_checked` are **never** "clean" and never
"safe". Collapsing any of them into "no finding" is the exact mistake the contract
forbids.

### The seven states

| `State` (constant) | JSON name | meaning |
|---|---|---|
| `StateNotChecked` | `not_checked` | the source was off / not invoked (no env URL, disabled) |
| `StateSourceUnavailable` | `source_unavailable` | the source errored or was unreachable — **not** "clean" |
| `StateUnknownProduct` | `unknown_product` | the source does not recognise this identity |
| `StateUnknownVersion` | `unknown_version` | the version could not be determined or compared for this scope |
| `StatePotentiallyAffected` | `potentially_affected` | an advisory exists for the product but the version can't be pinned |
| `StateAffectedByAdvisory` | `affected_by_advisory` | the version falls in an advisory range — a **LEAD**, never proof |
| `StateNotAffectedByAdvisory` | `not_affected_by_advisory` | the version resolved and no advisory matched — clean **for THIS source only**. **Not issued in v0.4** (see below) |

`State.Applicable()` is true for exactly the two actionable states
(`potentially_affected`, `affected_by_advisory`); everything else is
unknown / off (or clean-for-this-source, which v0.4 does not issue). `State.MarshalJSON` writes the readable name,
never an opaque integer — a consumer cannot mistake one state for another by
mis-reading a number.

### When each state is used (how the sources map)

Every adapter documents its own mapping; the pattern across all of them:

- **feed off** (no env URL) → `not_checked`. The source was never queried.
- **feed errored / unreachable** → `source_unavailable`.
- **identity not in the source** → `unknown_product` (e.g. OSV package absent, wpcve
  slug not listed).
- **version present but not comparable** → `unknown_version` (e.g. jslib detected a
  version that is not a version at all, lifecycle mapped the product but matched no
  cycle, a detection's patterns disagree on the version). An advisory whose bound cannot
  be compared with a readable version (jslib, osv) is `potentially_affected` with a note.
- **advisory matched, version pinned** → `affected_by_advisory` + one `Lead` per advisory.
- **advisory exists, version not pinnable** → `potentially_affected`.

Every product-version source (`cve`, `lifecycle`, `osv`, `jslib`, `wpcve`) picks between
those two through ONE function, `unified.AdvisoryState(versionPinned)`, and explains a
missing version with the shared `unified.NoteNoVersion` — no adapter decides it alone.
(`kev` is CVE-centric: its identity is the CVE, there is no product version to pin.) Two
cross-source contract tests in `modules/intel/accuracy/contract_test.go` hold the rules
for all sources at once: no version is never `affected_by_advisory`, and an empty result
is never `not_affected_by_advisory`.

### "Not affected" has one door — shut in v0.4

No source sets that state itself: `unified.Clean(Evidence)` is the only producer.
`TestOnlyCleanProducesNotAffected` (package `unified`) parses every non-test file and
fails if any other code names the state outside a comparison — assigns, returns, passes or
stores the constant — converts a value to `State`, or does arithmetic on a `State`
constant. It reads syntax, not types: a bare number typed as `State` would slip past it.

**In v0.4 the door stays shut: no source answers "not affected".** A source's data can
read as whole and still be wrong for a version, without saying so — found on real data
while preparing this release:

- the Rocky Linux dump carries RPM epochs cut to their last digit (bind `32:` stored as
  `2:`), so `bind 32:9.11.20-5.el8` matched nothing, while the AlmaLinux dump lists 18
  advisories for the same build;
- a distro release the source stopped tracking (Debian 10: newest record 2024-07-01)
  matches nothing published since, so any old package on it looked clear.

So `Clean` names the gap instead, from the evidence the source states — `FullData` (the
answer came from the source's complete data: a live, synced or queried catalog, not an
embedded sample, one page of a paged answer or a cut-off list) and `Positioned` (the
version was compared with every advisory the source has for the identity):

| evidence | answer |
|---|---|
| not `FullData` | `not_checked` — only part of the source's data was available |
| not `Positioned` | `unknown_version` — the version could not be compared with every advisory |
| both | `not_checked` with `unified.NoteNoClearance` — nothing matched in the whole data, which is not a clearance |

`TestCleanNeedsEvidence` covers every combination of the two (the whole truth table), so
with the AST test above no path to `not_affected_by_advisory` is left in the code (a bare
number typed as `State` aside — none exists; review keeps it that way).
`TestIncompleteDataIsNeverClean` and the dirty-data corpus (`TestDirtyDataIsNeverClean`,
`modules/intel/accuracy`) run each source on incomplete, malformed and ambiguous data; the
corpus's well-formed controls must reach the whole-data branch (`NoteNoClearance`), so the
readers below stay exercised. A clearance can return once a source states how far its
data reaches (the releases and dates it still tracks) and an answer can be cross-checked.

**Embedded samples answer positively only.** The small snapshots embedded for air-gapped
use (KEV, Retire.js, the CPE dictionary) are a handful of entries, not the catalogs: a
hit in one is a lead, a miss in one is `not_checked`, and the CPE sample never verifies an
identity (so it cannot displace a curated CPE).

**What each source needs before its data counts as whole** (the `FullData` evidence; in
v0.4 every "nothing matched" is `not_checked`, with `NoteNoClearance` when the data was whole):

| source | proof of `FullData` | "nothing matched" |
|---|---|---|
| `osv` | a whole dump: every entry read — a corrupt, oversized, null or id-less entry, one holding more than one JSON value, a `withdrawn` that is not a timestamp, a null affected entry, or one that names no package and is not repository-level (commit ranges only) leaves the dump unproven. A version is affected when a range places it or the versions list names it; an advisory with no range, a range with no bounding event, or an empty range (fixed at or before introduced) places no version, so it stays a lead | `not_checked` + `NoteNoClearance` when the version is pinned |
| `kev` | a catalog (live or synced) with as many rows as its own `count`, each row exactly one CVE id, none repeated | `not_checked` + `NoteNoClearance` (not in KEV) |
| `lifecycle` | the version's own cycle — the longest matching one (names trimmed, a `v` before a digit dropped) — states a verdict. `unknown_version` when one cycle is listed twice with opposite verdicts (a product listed twice in the bundle is read as one list), a release states neither `isEol` nor `eolFrom`, or a supported cycle has sub-cycles of its own or sits beside a row that cannot be read. A bundle release the feed marks ended stays ended whatever date it carries | `not_checked` + `NoteNoClearance` (supported cycle) |
| `cve` | none: a per-query, paged API | `not_checked` with the reason — never a clearance |
| `wpcve` | none: the feed carries no count | `not_checked` with the reason — never a clearance |
| `jslib` | none: the Retire.js repository carries no count | `not_checked` with the reason — never a clearance |

A body that is not the source's shape is a failed lookup (`source_unavailable`), never an
empty answer: an NVD answer must carry `totalResults`; a WordPress feed entry that is null
or has no `vulnerabilities` list is `unknown_product`.

`cve` treats "feed answered, no CVE" as `not_checked` (above), and CVEs found for
a query that carried no version as `potentially_affected` (they are the product's
advisories, none pinned to the running version); `lifecycle` treats
an EOL cycle as `affected_by_advisory` (end of support is a real risk) and a supported
cycle as `not_checked` with `NoteNoClearance`; `kev` is CVE-centric (`InKEV` → affected,
EPSS-only → potentially, neither → `not_checked` — with `NoteNoClearance` against a whole
catalog, with the partial-data reason when only the small embedded KEV sample is in use).

## 3. Freshness — a snapshot is never live truth

`Result.Freshness` travels with every result so a stale offline snapshot is never read
as a live lookup:

| `Freshness` | JSON name | meaning |
|---|---|---|
| `FreshnessUnknown` | `unknown` | no fetch happened (off / error / not-checked paths) |
| `FreshnessLive` | `live` | fetched from the configured live source this run |
| `FreshnessSnapshot` | `snapshot` | from an embedded point-in-time snapshot (offline baseline) |
| `FreshnessStale` | `stale` | a cache/snapshot known to be past its freshness window |

A source only claims `live` on the states that actually reached the feed; the off and
error paths leave freshness `unknown` rather than claiming a fetch. `jslib` reports
`snapshot` when it fell back to its embedded Retire.js snapshot and `live` only when
the operator's URL answered; `kev` reports `snapshot` when the live catalog was
unavailable and the embedded CISA KEV baseline was used.

## 4. `Lead.Score` and `Lead.EPSS` are `*float64` — nil ≠ 0.0, never mixed

A `Lead` is one advisory/CVE a source attributes to the identity. `Score` is the numeric
CVSS base score (0–10); `EPSS` is the exploitation probability (0–1) that the KEV/EPSS
prioritizer adds beside it. They are separate fields because they are different scales —
a consumer ranking by one must never get the other. Both are **pointers**: `nil` means
"the feed gave no metric", kept distinct from a real `0.0` (FIRST.org can legitimately
return an EPSS of `0.0`). Likewise `Severity` / `CVSS` are left empty rather than
fabricated when the source did not carry them.

> shortcut (documented in code): `cve.ToUnified` cannot distinguish a genuine CVSS
> `0.0` (severity NONE) from a missing metric — both parse to zero upstream — so it
> reports no score for a NONE-severity CVE. Upgrade to a presence flag in `cve.CVE` if
> a NONE-severity CVE ever needs its `0.0` preserved.

## 5. Result fields at a glance

`Result` carries everything a consumer needs to decide "is this a lead, how sure, from
where, how fresh" without knowing which provider ran: `State`, `Scope`
(`"cpe"` / `"ecosystem:npm"` / `"wordpress:plugin"` / `"jslib"` / `"eol"` / `"cve"`),
`Identity`, `Version`, `Leads`, `Source`, `Freshness`, `FetchedAt`, and the CPE
provenance pair `CPEState` / `CPEEvidence` — which records HOW the CPE was resolved
(`verified` from the NVD dictionary, `attested` from a source fingerprint, `candidate`
borrowed and never queried, or `none`) kept **apart from** `Err` so a resolution note
is never mistaken for a lookup failure. `unified.Unknown(scope, identity, state, err)`
builds a not-looked-up result, so an adapter never returns a zero `Result` a consumer
could misread as clean.
