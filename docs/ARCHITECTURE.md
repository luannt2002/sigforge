# Architecture

sigforge is a file-based data platform, not a service. Logic lives in code; data
lives in JSON files. The code is layered the same way as the scanner that consumes
it (ASIE): a `framework/` of fingerprint-agnostic infrastructure, a `modules/`
domain, and a `cmd/` entry point.

## Layers

```
cmd/sigforge ─────────────┐  the CLI: baseline | merge | validate
                          │
modules/intel/            │  the domain (fingerprint knowledge)
  baseline  ──────────────┤    embedded curated-facts set  (go:embed data/baseline.json)
  schema    ──────────────┤    the versioned on-disk contract + loader
  matcher   ──────────────┤    apply a set to a page → detections
  merge     ──────────────┘    baseline + sources → one set, precedence + provenance
                          │
framework/                │  infrastructure, knows nothing about fingerprints
  define                  │    shared constants (service name)
  fsio                    │    file read + atomic write
```

**Dependency rule:** `framework/` never imports `modules/`. The domain may use the
framework; the framework may not use the domain. The CLI wires them together.

## Data flow

```
                 (later phase: operator-run adapters, off by default)
  source A ──fetch──▶ normalize ──▶ A.norm.json ┐
  source B ──fetch──▶ normalize ──▶ B.norm.json ┤
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

## Why these boundaries

- **schema is the contract.** It is versioned (`schema_version`) so a consumer can
  refuse a DB whose major version it does not understand, and Wappalyzer-compatible
  so any source normalizes into it and a consumer writes one loader.
- **matcher is pure.** Same inputs, same outputs, no network, no shared state — so
  it is exhaustively table-testable and safe to embed in any scanner.
- **merge is pure and honest about licensing.** It never relicenses: each entry
  carries the provenance and license of the source it came from, and the operator
  chooses which sources to include.
- **fetch adapters are deliberately out of scope for now.** Pulling executable
  logic over the wire is exactly the supply-chain risk scanners detect; sigforge
  moves only data, and that data is normalized to a local file by an
  operator-gated adapter before `merge` ever sees it.

See the per-feature specs: `matcher.md`, `merge.md`, `baseline.md`, `cli.md`.
