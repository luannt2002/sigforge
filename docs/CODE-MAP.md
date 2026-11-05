# Code map

One line per package: path → what it owns → the API a consumer calls (if any).
`framework/` is pure infrastructure and never imports `modules/`; `modules/intel/`
is the domain. Per-feature specs live beside this file (`docs/<package>.md`).

## framework/ — infrastructure (knows nothing about fingerprints)

| path | owns | consumer API |
|---|---|---|
| `framework/fsio` | file read + crash-safe atomic write | `Read`, `WriteAtomic` |
| `framework/fetch` | bounded, honest HTTP GET (no hardcoded URL; size + status + timeout guards) | `New`, `(*Client).Get` |
| `framework/define` | shared constant (`ServiceName`) | `ServiceName` — currently unused anywhere (see audit note) |

## modules/intel/ — the domain

| path | owns | consumer API |
|---|---|---|
| `modules/intel/schema` | the versioned on-disk contract + loader/validator; the Wappalyzer-compatible fingerprint shape plus sigforge's provenance/license/cpe extension | `DB`, `Fingerprint`, `StringList`, `Parse`, `Validate`, `LoadFile`, `(*DB).JSON` |
| `modules/intel/baseline` | the embedded (`go:embed`) curated-facts fingerprint set (58 techs) | `DB`, `Bytes` |
| `modules/intel/matcher` | apply a fingerprint set to a page's raw HTTP → detections; passive `dom` rule evaluation in `matcher_dom.go` | `Match`, `Page`, `Detection` |
| `modules/intel/merge` | combine baseline + trust-ranked sources into one set (baseline wins; losing version/cpe signals preserved) | `Merge`, `Source` |
| `modules/intel/source` | operator-gated fetch+normalize adapters (webappanalyzer/nuclei/whatweb) + sync manifest; data never vendored | `New`, `Source`, `EnvVar`, `Version`, `Stamp`, `Manifest`, `LoadManifest` |
| `modules/intel/diff` | pure set-difference between two DBs (added/removed/changed) | `Diff`, `Result` |
| `modules/intel/lifecycle` | version → end-of-life LEAD via an endoflife.date-shaped feed; honest tri-state (`StateUnknown`/`Supported`/`EOL`) | `New`, `(*Adapter).EOLStatus`, `Classify`, `ParseCycles`, `Status`, `State`, `ProductFor` |
| `modules/intel/cve` | CPE+version → known-CVE LEADs via an NVD-CVE-API-shaped feed; honest tri-state (`StateUnknown`/`NoKnownCVE`/`HasCVE`) | `New`, `(*Adapter).Lookup`, `Parse`, `Result`, `CVE`, `State` |
| `modules/intel/enrich` | pure composition of breadth (matcher) + depth (cve/lifecycle, injected as providers; nil = off = UNKNOWN) | `Enrich`, `EnrichedDetection`, `Options`, `CVEProvider`, `EOLProvider` |
| `modules/intel/accuracy` | correctness harness: precision/recall math + golden/oracle/adversarial test suite (offline fixtures) | `Score`, `(*Score).Add`, `Precision`, `Recall` |

## cmd/

| path | owns |
|---|---|
| `cmd/sigforge` | the operator CLI over the data files: `baseline`, `merge` (`--source`/`--fetch`/`--manifest`), `validate`, `diff`, `eol`, `cve`. Feeds are off unless the operator supplies a URL; nothing third-party is persisted or committed. |

## Honesty invariant (spans the domain)

Absence is never "safe": `cve.StateUnknown` (not checked) ≠ `cve.StateNoKnownCVE`
(checked, nothing listed — still not a guarantee); likewise `lifecycle.StateUnknown`
≠ `StateSupported`. A detected version is a spoofable LEAD, not proof. CPE/CVSS/EOL
values are taken verbatim from the operator's feed, never fabricated.
