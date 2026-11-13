# Enrich pipeline (breadth → depth → `[]unified.Result`)

Package `modules/intel/enrich`, functions `EnrichUnified` / `EnrichUnifiedExt`
(added v0.4). The older `Enrich` → `[]EnrichedDetection` flavour is unchanged and
documented in `docs/enrich.md`; this page covers the unified pipeline.

## 1. What it produces

One call turns a page into the **unified** result shape every consumer reads
(`docs/unified-contract.md`):

```
EnrichUnified(ctx, dets, db, opt)            → []unified.Result
EnrichUnifiedExt(ctx, dets, db, inp, opt)    → []unified.Result
```

For each `matcher.Detection`, `EnrichUnified` emits one `"cpe"`-scoped CVE result per
queried CPE plus one `"eol"`-scoped result. `EnrichUnifiedExt` is `EnrichUnified` plus
the operator/ASIE-supplied identities that do **not** come from the page.

## 2. End-to-end flow

```
stdin JSON Page ─▶ matcher.Match(db, page) ─▶ []Detection
                                                 │
                                   for each detection:
                                                 │
        resolveCPEs ──▶ IdentityResolver verified CPE?  ── yes ─▶ cpe_state=verified (nvd-dict)
                         │ no
                         └─▶ schema.Fingerprint.CPE (attested) ─▶ cpe_state=attested (source)
                         └─▶ none                                ─▶ unknown_product
                                                 │
                        cveResults: opt.CVE.Lookup(cpe, version) ─▶ cve.ToUnified
                                                 │  + prioritize(KEV/EPSS) per lead
                                                 │  + applyVersionConflict (downgrade)
                        eolResult:  opt.EOL.EOLStatus(tech, version) ─▶ lifecycle.ToUnified
                        platformResults: a release version (Drupal 7.59, Magento 2.4.6, Jetty 9.4.51.v…)
                                    ─▶ opt.OSVRelease per core package (platformPackages; releaseLine keeps a
                                       version out of a package that holds another release line; for a
                                       version older than all the package names (Packagist, Maven, NuGet),
                                       the release lookup still reports, marked OutsideListed, what an
                                       advisory listing the package's releases reaches only from the
                                       start; an advisory listing no versions keeps OSV's rule; one it
                                       cannot place is handled as in a package lookup. keepDoubtsApart
                                       reports both kinds of noted lead as potentially affected, apart
                                       from an affected result's other leads, each reason named once)
                        each result of the detection ─▶ applyExcludedBy (note only)
                                    ─▶ dropRepeated (an OSV lead an earlier result named at least as firmly is
                                                   not reported twice; a noted lead counts as potentially affected)
                                                 ▼
                                        []unified.Result

EnrichUnifiedExt also, from EnrichInput (NOT page-derived):
   Packages ─▶ dispatchOSV ─▶ opt.OSV(eco, name, ver)  ─▶ osv.ToUnified
   WPSlugs  ─▶ dispatchWP  ─▶ opt.WP(slug, ver, kind)   ─▶ wpcve.ToUnified (core: wpcve.CoreToUnified)
   JSLibs   ─▶ dispatchJS  ─▶ opt.JS(name, ver)         ─▶ jslib.ToUnified
```

## 3. Input

- `dets []matcher.Detection` + the `*schema.DB` they came from (for CPE, categories,
  provenance).
- `inp enrich.EnrichInput` (Ext only): `Packages []PkgRef` (ecosystem+name+version for
  OSV), `WPSlugs []WPRef` (slug+version+kind for wpcve), `JSLibs []LibRef`
  (name+version for jslib). These are operator/ASIE-supplied out-of-band — they are not
  derived from the page, because an attacker controls the page.
- `opt enrich.Options`: the depth providers, every one **injected** and nil-able.

## 4. Pure composition, every feed operator-gated

`enrich` holds **no network**. Each depth source is injected through `Options`, so a
caller wires the real operator-gated adapters and a test wires fakes:

| `Options` field | provider | nil (off) ⇒ |
|---|---|---|
| `CVE` | `cve.Adapter` (`CVEProvider`) | one `not_checked` cpe result |
| `EOL` | `lifecycle.Adapter` (`EOLProvider`) | one `not_checked` eol result |
| `KEV` | `kev.Adapter` (`KEVProvider`) | leads pass through unranked, never dropped |
| `IdentityResolver` | `identity.Resolver.ResolveCPE` | falls back to the source-attested CPE |
| `OSV` / `WP` / `JS` | the OSV/wpcve/jslib lookups | the dispatched identity yields `not_checked` |
| `OSVRelease` | OSV for a detected platform's release (`osv.Adapter.Lookupers`) | the platform is not looked up as its packages |

The CLI (`sigforge enrich`) wires these from env URLs only (`cve.EnvVar`,
`lifecycle.EnvVar`, `kev.EnvKEVURL` / `kev.EnvEPSSURL`, `identity.EnvCPEDictURL`). With
**no env set, every feed is off**, the output is honest `not_checked`, and no network
request is made to any target — safe to run against nothing.

## 5. Honesty carried through the pipeline

- **A nil / off provider is `not_checked`, never a fabricated "clean".** Absence from
  one source is absence from one source.
- **CPE safety:** only a dictionary-**verified** identity (when the
  `IdentityResolver` confirms one) or the source-**attested** fingerprint CPE is fed to
  a CVE lookup. An unverified borrowed `schema.CPECandidate` is **never** used — querying
  CVEs under a CPE borrowed from a different edition/fork would contaminate identity.
  How the CPE was resolved rides on `CPEState` / `CPEEvidence`, kept apart from `Err`.
- **Version conflict downgrades.** When `Detection.VersionConflict` is set the version
  can't be pinned, so `applyVersionConflict` — on the CVE, EOL and JS-library results of
  the detection — turns an `affected_by_advisory` HIT into `potentially_affected`, a
  `not_affected_by_advisory` answer (none in v0.4) into `unknown_version` (only one
  claimed version was asked), and records the conflicting claims in a note. (The matcher sets
  the flag when captured versions genuinely disagree, e.g. "9.5" vs "10"; it still picks
  one deterministically via `resolveVersion`, but the consumer is told it is uncertain.)
- **Excluded-by is a note, never a downgrade.** When `Detection.ExcludedBy` is set,
  `applyExcludedBy` adds `excluded by: <techs>` to each result of the detection; state and
  leads are untouched.
- **No version, no "affected".** A detection with no version is queried at the product
  level, so the feed lists every advisory the product ever had; `cve.ToUnified` reports
  that as `potentially_affected` with a "no version detected" note, never
  `affected_by_advisory`.
- **A truncated page says so.** The CVE API pages its answers; when `totalResults`
  exceeds what came back, the result carries a "partial: N of M CVEs" note instead of
  passing one page off as the complete list.
- **KEV/EPSS prioritizes, never filters.** `prioritize` upgrades each CVE lead with the
  KEV membership flag and the EPSS probability in `Lead.EPSS` (keyed by upper-cased CVE
  id) — beside the CVSS `Score`, never over it; with KEV off or no leads, results pass
  through unchanged. No lead is ever dropped for lacking a signal.
- **Every match is a LEAD.** A detected version is spoofable; a CVE/EOL/advisory match
  is a lead to corroborate against a real asset, not proof of exploitability.

## 6. CLI

```
sigforge enrich [--db FILE] [--json] < page.json
```

Reads a JSON `matcher.Page` from stdin, matches it, runs `EnrichUnifiedExt` with the
identities the inventory flags give and the env-gated feeds, and prints the `[]unified.Result` as a table (state, source,
freshness, per-lead KEV/EPSS signal and why the source doubts a lead, and any
note — CPE provenance, version conflict, excluded by, why a source was not
checked) or as JSON with `--json`.
