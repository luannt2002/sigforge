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
  be compared with a readable version (jslib, osv, wpcve) is a lead with a `Note` saying
  so: with no advisory matched the result is `potentially_affected`; beside one that
  matched, it follows the matched leads inside `affected_by_advisory`. The typed results
  list such advisories in `Unplaced` whether or not another matched; `Vulns` keeps its meaning.
- **advisory matched, version pinned** → `affected_by_advisory` + one `Lead` per advisory.
- **advisory exists, version not pinnable** → `potentially_affected`.

Every product-version source (`cve`, `lifecycle`, `osv`, `jslib`, `wpcve`) picks between
those two through ONE function, `unified.AdvisoryState(versionPinned)`, and explains a
missing version with the shared `unified.NoteNoVersion`. One case sets `potentially_affected`
without it: a version OSV could not place against any advisory (jslib and wpcve route that
case through the function); `enrich` also downgrades a version conflict and a doubted
release lead after the source answered (`docs/enrich-pipeline.md`).
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

### Looked up, concluded, whole data

"Answered" once meant two things. Three questions now have a name each:

- **Looked up** — `Result.LookedUp()`: the source looked the identity up in its data and gave a
  state for it. `Result.Answered()` is the same function under its first name.
- **Concluded** — `State.Concluded()`: the lookup decided whether an advisory applies.
  `State.Answered()` is the same function under its first name.
- **Whole data** — `Result.FullData`: the answer came from the source's whole data, so a lead
  absent from it is not listed there. `false`, the default, proves nothing. Only `osv` sets it
  (`!Partial`: every entry of the dump was read); a source that cannot prove its data whole
  (`wpcve`, `jslib`, `cve` in the table above) never does.

| state | looked up | concluded | a lead absent from the answer is gone (`watch` GONE) |
|---|---|---|---|
| `not_checked` (off, unsupported, data cut short, nothing to ask with — a CPE the end-of-life bundle lists under two products included, though the bundle was read: `freshness` says so) | no | no | no: `UNCHECKED`, leads kept |
| `not_checked` + `NoteNoClearance` (a whole-data miss) | yes | no | with `FullData` |
| `source_unavailable` | no | no | no: `UNCHECKED`, leads kept |
| `unknown_product` | yes | no | with `FullData` (a package absent from a whole OSV dump) |
| `unknown_version` | yes | no | never: the version was not compared |
| `potentially_affected` / `affected_by_advisory` | yes | yes | with `FullData` |
| `not_affected_by_advisory` (not issued) | yes | yes | with `FullData` |

`TestLookedUpAndConcluded` holds the first two columns and that the first names keep their
meaning; `TestLeadsByIdentitySplitsWhatAnAnswerCanRuleOut` (`cmd/sigforge`) holds the last one.
`coverage.Results` counts looked up (`looked_up`) apart from concluded (`answered`), and `enrich`'s
table output (not `--json`) ends with `looked up X/N · concluded Y/N` when it has a result — with none
it prints `no detections` only (`TestEnrichTallyCountsLookedUpApartFromConcluded`,
`TestEnrichFailsWithNothingToLookUp`). In `watch`, a lead recorded before that an
answer without whole data, or for a version not compared, leaves out is kept and named
`UNCHECKED` with why, never `GONE`, while a new lead in that answer is still `NEW`. No WordPress or
JavaScript answer sets `FullData`, so their leads are never `GONE`.

### Reason codes

`Result.Reason` is `Err` as a code, so a consumer tells the gaps apart without parsing a sentence (`Err` stays the
sentence for people). It is set on every result that is not a conclusion, on every `potentially_affected`, and on an
`affected_by_advisory` drawn from part of the source's data; a plain match carries none. A consumer must read a code it
does not know as "not concluded", never as clean. Every source's paths are held to their code in
`TestEveryUnconcludedResultNamesAReason` (`modules/intel/accuracy`); this table is held to the code list by
`TestReasonCodesDocumented`.

| reason | set when | what a consumer can do |
|---|---|---|
| `source_off` | the source is not configured (no env URL, no provider wired): it was not asked | configure the source |
| `unsupported` | the source does not cover this kind of identity (an OSV ecosystem it lacks, a WordPress kind other than plugin, theme or core) | nothing in this source |
| `no_identity` | there is nothing to ask the source with: no CPE for a detection, no slug, a distro package without its release, a tech the end-of-life source has no product name for and no CPE to ask the bundle with, a CPE the end-of-life bundle lists under more than one product | give the identity (an attested CPE, a purl with `?distro=`) |
| `source_error` | the source failed (network, HTTP status, 429 hold-off) or answered with what is not its data | retry later; a stale stored copy, when one exists, answers with `freshness: stale` instead |
| `sample_only` | only the small sample embedded in the binary was read (Retire.js, CISA KEV): the source is not configured, or it failed with no stored copy to fall back on | configure the source; when it is configured, `error` says why it failed |
| `partial_answer` | part of the answer was read: one page of a paged feed, a cut-off list, a dump with entries it could not read | treat what is absent as not checked |
| `not_provably_complete` | nothing matched, in data the source cannot prove whole (the CVE API, a WordPress feed, the Retire.js repository) | no clearance: verify the component another way |
| `no_clearance` | nothing matched in the source's whole data — still not a clearance (see above) | no clearance: verify the component another way |
| `not_in_source` | the source does not list this identity | try a source that tracks it |
| `no_version` | no version was given: the product's advisories, none pinned | establish the running version |
| `version_unreadable` | a version was given that the source's version order cannot read; it is kept in `version`, never treated as missing | establish a version in the ecosystem's own form |
| `version_unplaced` | the version could not be placed for certain against the source's bounds (an advisory bound it cannot compare, no release cycle matching it, a release older than every version a package's advisories name) | read each lead's `note`; confirm the release |
| `version_conflict` | the page's version claims disagree, so the version asked may not be the running one (a hit becomes `potentially_affected`) | establish which claim is right |
| `distro_build` | the version was read from a distro's package build (`distro` names it): the package may carry a fix backported into the upstream number, or the distro may still support a release upstream ended, so a CVE or end-of-life hit becomes `potentially_affected` (`distro_build` replaces any other reason of the hit, `partial_answer` included — the "partial" note stays in `error` — except `version_conflict`, which is kept, with the distro added to its note) | check the distro's own advisory for the package, or give the package as a purl with its release (an OSV distro package is compared with the distro's advisories) |

The CVE source compares versions on its side (sigforge writes the version into the CPE it asks with), so it never
reports `version_unreadable`. `kev`'s own results — CVE-centric, used inside `enrich` to rank leads — are the one
`potentially_affected` without a reason: an EPSS probability exists, which is not a version question.

An advisory OSV marks withdrawn is left out of the index, never kept as a lead: a withdrawn advisory no longer says
anything about the package, and listing it beside live ones would be a claim nobody makes.

### What else a result says about its evidence

- **`kev`** — what the leads' `known_exploited` flag was checked against: `catalog` (the CISA KEV catalog, live,
  synced or stale), `sample` (the few entries embedded in the binary: absent from them is *not* "not exploited"), or
  absent (KEV not consulted). `known_exploited: false` means "not listed" only with `kev: catalog`; the `enrich` text
  prints `kev=-` otherwise. Set only on results with a lead naming a CVE.
- **`version_from`** — where `version` came from: a page field (`header`, `cookie`, `meta`, `html`, `scriptSrc`,
  `dom`, or `pattern` for a version pattern run over the page) — the site's own claim, spoofable — or `inventory`
  for a version the operator gave (`--package`, `--sbom`, `--wp-*`, `--jslib`). The matcher records it as
  `Detection.VersionFrom`.
- **`detection_confidence`** — the fingerprint's confidence (0–100) that the page runs the tech. It says how sure the
  *detection* is, not how likely an advisory is to apply or be exploitable; absent for identities not detected on a page.
- **`distro`** — the distro whose package build `version` was read from, when the banner says so: the OS token a
  packager compiles into it (`Apache/2.4.38 (Debian)`, `nginx/1.18.0 (Ubuntu)`) or the package revision appended to
  the upstream version (`PHP/7.4.3-4ubuntu2.19`, `PHP/7.3.31-1~deb10u1`). Read from header, cookie and meta values only
  — a banner in a page's HTML (an error page footer) is not read. The matcher records it as `Detection.Distro`.
- **CVE answers compare the upstream release.** A `cpe` or `eol` result compares the version a page names with the
  upstream project's releases. A distro build can carry a fix without changing that version (a backport): when the
  banner names the distro, a hit is `potentially_affected` (`distro_build`) with its leads kept; when it does not, the
  hit stays a lead to confirm against the package's own patch level. Only an OSV distro package
  (`ecosystem:Debian:12`, given as a purl with its release) is compared with the distro's own advisories.

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
error paths leave freshness `unknown` rather than claiming a fetch. An answer that the
source does not list the product (`not_in_source`) was read from the source, so it
carries the freshness and `fetched_at` of the copy it was read from, like any other answer. So does an end-of-life
`not_checked` (`no_identity`) for a CPE the bundle lists under more than one product: the bundle was read, and named
no one product (`TestEOLByCPEThatNamesNoOneProduct`). `jslib` reports
`snapshot` when it fell back to its embedded Retire.js snapshot and `live` only when
the operator's URL answered; `kev` reports `snapshot` when the live catalog was
unavailable and the embedded CISA KEV baseline was used.

Each source's labels on each path, and the test that holds them:

| source | off | failed | answered now | stored copy within `SIGFORGE_CACHE_MAX_AGE` | stored copy after the source failed |
|---|---|---|---|---|---|
| `cve` (per-query API) | unknown — `TestUnansweredResultsClaimNoFreshness` | unknown — same | live — `TestToUnifiedFetchedAt` | never: asked every lookup — `TestQueryFeedsAreNeverServedFromTheStore` | never: `source_unavailable` — same |
| `wpcve` (per-query feed) | unknown — `TestUnansweredResultsClaimNoFreshness` | unknown — same | live — same | never: asked every lookup — `TestQueryFeedsAreNeverServedFromTheStore` | never: `source_unavailable` — same |
| `lifecycle` bundle | unknown — `TestUnansweredResultsClaimNoFreshness` | unknown — same | live — `TestRunReplacesTheStoredBundleWithAGoodOne` | snapshot — `TestBundleFromSyncedStoreIsSnapshot` | stale — `TestBundleStaleCopyWhenSourceFails` |
| `lifecycle` bundle, product not listed (`not_in_source`, by name or by CPE) | not asked — as the row above | not answered — as the row above | live — `TestBundleMissCarriesItsFreshness` | snapshot — same | stale, why in `error` — same; also from a stored copy written without a fetch time (no `fetched_at`) — `TestBundleMissWithoutAStoredTime` |
| `osv` dump | unknown — `TestUnansweredResultsClaimNoFreshness` | unknown — same | live — `TestRunReplacesTheStoredDumpWithAGoodOne` | snapshot — `TestLookuperUsesStoredDump` | stale — same, `TestRunKeepsTheStoredDumpOverJunk` |
| `jslib` repository | snapshot (embedded sample) — `TestToUnifiedFreshnessSnapshot` | snapshot (sample) — `TestRunRechecksAStoredRepositoryServedUnchecked` | live — `TestToUnifiedFreshnessLive` | snapshot — `TestRepoFromSyncedStoreIsNotLive` | stale — `TestRepoStaleCopyWhenSourceFails` |
| `kev` catalog | snapshot (embedded sample) — `TestEnrichUnifiedSnapshotFreshness` | snapshot (sample) — `TestRunRechecksAStoredCatalogServedUnchecked` | live — `TestEnrichUnifiedLiveFreshnessAndFetchedAt` | snapshot — `TestKEVFromSyncedStoreIsSnapshot` | stale — `TestKEVStaleCopyWhenSourceFails` |

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
`Identity`, `Version`, `Leads`, `Source`, `Freshness`, `FetchedAt`, `FullData` (the answer
came from the source's whole data; `false` proves nothing), and the CPE
provenance pair `CPEState` / `CPEEvidence` — which records HOW the CPE was resolved
(`verified` from the NVD dictionary, `attested` from a source fingerprint, `candidate`
borrowed and never queried, or `none`) kept **apart from** `Err` so a resolution note
is never mistaken for a lookup failure. `unified.Unknown(scope, identity, state, err)`
builds a not-looked-up result, so an adapter never returns a zero `Result` a consumer
could misread as clean. `Reason`, `KEV`, `VersionFrom` and `DetectionConfidence` are described under "Reason codes" and
"What else a result says about its evidence" above.

## 6. Reading the JSON, and how it changes

`sigforge enrich --json` prints a JSON array of these results. Fixtures of what it prints for the cases a consumer must
tell apart — nothing to look up, a source off, a source failing, an identity the source does not list, a version it
cannot read, a match, a whole-data miss, a stale stored copy, KEV read from the embedded sample — are in
`cmd/sigforge/testdata/contract/`, each with the command, its exit code and its output, held by `TestContractFixtures`.
The six looked-up-or-not cases each carry their own (`state`, `reason`) pair.

How the shape changes: fields are added, never removed or renamed, and a field's meaning is not reused for another;
`state` and `freshness` names are fixed (a Go consumer gets an error decoding a name it does not know). A consumer must
read an unknown `state` or `reason` as not concluded, and an absent field as "not said" — never as false, zero or clean.
A change of meaning is listed under "Changed meaning" in `CHANGELOG.md`.
