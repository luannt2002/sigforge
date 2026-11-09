# Architecture

sigforge is a file-based data platform, not a service. Logic lives in code; data
lives in JSON files. The code is layered the same way as the scanner that consumes
it (ASIE): a `framework/` of fingerprint-agnostic infrastructure, a `modules/`
domain, and a `cmd/` entry point.

## Layers

```
cmd/sigforge ─────────────┐  the CLI (see cli.md): baseline | merge | refresh | sync | validate | verify |
                          │  rollback | diff | eol | cve | inspect | match | enrich | coverage
modules/intel/            │  the domain
 breadth — which technologies a page runs
  baseline  ──────────────┤    embedded curated-facts set  (go:embed data/baseline.json)
  schema    ──────────────┤    the versioned on-disk contract + loader
  matcher   ──────────────┤    apply a set to a page → detections
  source    ──────────────┤    operator-gated fetch adapters (webappanalyzer / nuclei / whatweb)
  merge, refresh, diff ───┤    baseline + sources → one set; regression-gated re-sync; what changed
  coverage  ──────────────┤    how much of a set can reach a CVE lookup / capture a version
 depth — what is known about a detection or a package
  unified   ──────────────┤    the one result shape: 7 honest states; unified.Clean is the only door
                          │    to "not affected" (see unified-contract.md)
  identity  ──────────────┤    tech → dictionary-verified CPE
  cve, lifecycle ─────────┤    CVE leads by CPE · end-of-life by product or CPE
  osv, versioncmp ────────┤    ecosystem and OS-distro advisories from stored dumps · per-ecosystem ordering
  wpcve, jslib ───────────┤    WordPress plugin/theme · client-side JS library advisories
  kev, takeoverfp ────────┤    KEV/EPSS on CVE leads · dangling-subdomain fingerprints
  enrich, feedset ────────┘    detections + packages/SBOM/purl → unified results · the env wiring the
                          │    CLI and an importing scanner share
framework/                │  infrastructure, knows nothing about fingerprints
  define                  │    shared constants (service name)
  fsio                    │    file read + atomic write
  fetch                   │    the one outbound client: store revalidated with ETag, max age,
                          │    stale-if-error, 429 hold-off, streamed dump downloads
```

Every package and its exported surface: [`CODE-MAP.md`](CODE-MAP.md).

**Dependency rule:** `framework/` never imports `modules/`. The domain may use the
framework; the framework may not use the domain. The CLI wires them together.

## Data flow

```
        (operator-gated adapters, OFF by default — modules/intel/source)
  source A ──fetch──▶ normalize ──▶ A.norm.json ┐   (webappanalyzer / nuclei / whatweb,
  source B ──fetch──▶ normalize ──▶ B.norm.json ┤    URL via flag/env; writes SYNC-MANIFEST.json)
                                                 │   sigforge merge
  baseline.json (embedded, curated facts) ──────▶├──────────────────▶ merged.json
                                                 │   (dedupe by tech id,
                                                 │    baseline > higher-trust source,
                                                 │    keep alternate version regexes,
                                                 │    carry provenance + license)
                                                 ┘
                                                        │
                        scanner (ASIE): baseline.DB() ──┤── schema.LoadFile(merged.json)
                                                        ▼
                                              matcher.Match(db, page) ──▶ detections (leads)
```

Depth (sources off until the operator sets their `SIGFORGE_SOURCE_*_URL`; with
`SIGFORGE_CACHE_DIR` each catalog and OSV dump is kept in a local store and read with
no request while younger than `SIGFORGE_CACHE_MAX_AGE` — see `snapshot-governance.md`):

```
  detections (tech, version, CPE) ┐
  packages · SBOM · purl ─────────┼─▶ enrich ─▶ cve · lifecycle · osv · wpcve · jslib
  WordPress plugins · JS libs ────┘                         │
                                                            ▼
                     []unified.Result (7 states, freshness, leads) ◀── kev/EPSS on CVE leads
                                                            │
                     consumer (ASIE): affected → lead · unpinned → info lead ·
                     unanswered → named coverage gap · never "clean" on absence
```

The pipeline in detail: [`enrich-pipeline.md`](enrich-pipeline.md).

## Why these boundaries

- **schema is the contract.** It is versioned (`schema_version`) so a consumer can
  refuse a DB whose major version it does not understand, and Wappalyzer-compatible
  so any source normalizes into it and a consumer writes one loader.
- **matcher is pure.** Same inputs, same outputs, no network, no shared state — so
  it is exhaustively table-testable and safe to embed in any scanner.
- **merge is pure and honest about licensing.** It never relicenses: each entry
  carries the provenance and license of the source it came from, and the operator
  chooses which sources to include.
- **fetch adapters are operator-gated and data-only.** Each adapter (`source`) is
  off until the operator supplies its URL (flag/env), and only DATA crosses the
  wire — never executable logic, which is exactly the supply-chain risk scanners
  detect. Normalize is pure and fixture-tested; the fetched data carries its
  source's license, is tagged per entry (provenance/license/version), and is never
  vendored here. `framework/fetch` is the bounded, honest HTTP client they share.

See the per-feature specs: `matcher.md`, `merge.md`, `baseline.md`, `cli.md`,
`source.md`, `cve.md`, `lifecycle.md`, `enrich.md`, `diff.md`, `accuracy.md`, and the
contracts `unified-contract.md`, `enrich-pipeline.md`, `snapshot-governance.md`.
