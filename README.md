# sigforge

A **file-based** security-intelligence data platform. It gathers, normalizes and
merges technology-fingerprint data into one versioned JSON database that scanners
(such as ASIE) consume to map a live site — "runs nginx 1.18 / WordPress 6.5 /
jQuery 1.12" — onto CVE / EOL knowledge.

sigforge owns the *data* concern so each scanner ships only a thin loader plus its
own clean baseline. The scanner stays permissively licensed; the license-laden
third-party sources are fetched by the operator at runtime and tagged, never
vendored into this repo.

## File-based, no database server

sigforge is **not** a service. There is no Postgres, SQLite or daemon. It is:

- a versioned JSON **schema** (`modules/intel/schema`) — the contract;
- **data files** — a curated baseline (`modules/intel/baseline/data/baseline.json`,
  embedded in the binary) plus any operator-supplied normalized source files, plus
  one **merged output file**;
- a small **CLI** (`cmd/sigforge`) that validates and merges those files.

The "database" a consumer reads is just that merged JSON file. Periodic sync =
re-run the CLI (e.g. from cron) to regenerate it. Benefits: portable,
git-diffable per pattern, offline, zero infrastructure.

## How a consumer (scanner) uses it

Everything works offline from the embedded baseline; an external DB only widens
breadth.

```go
import (
    "github.com/luannt2002/sigforge/modules/intel/baseline"
    "github.com/luannt2002/sigforge/modules/intel/matcher"
    "github.com/luannt2002/sigforge/modules/intel/schema"
)

db, _ := baseline.DB() // embedded curated set — always available, no config

// Optional: widen with an operator-supplied merged DB from an env path.
if path := os.Getenv("SCANNER_TECHFP_DB"); path != "" {
    if ext, err := schema.LoadFile(path); err == nil {
        db = ext // or merge it over the baseline with modules/intel/merge
    }
}

dets := matcher.Match(db, matcher.Page{
    Headers:    resp.Header,          // map[string][]string
    Cookies:    resp.Cookies,         // "name=value" strings
    HTML:       body,
    ScriptSrcs: scriptSrcs,
})
for _, d := range dets {
    // d.Tech, d.Version, d.Confidence, d.Categories, d.Provenance, d.License
}
```

A detection is a **lead, not proof**: a version from a `Server:` banner or a meta
generator is attacker-controllable and can be spoofed. Treat `Confidence` and
`Version` as hints to corroborate.

### Consuming the DB from another matcher

The on-disk JSON is Wappalyzer-compatible (`cats` / `headers` / `cookies` /
`meta` / `html` / `scriptSrc` / `implies` / `dom` with the inline
`\;version:\1` / `\;confidence:N` suffixes), wrapped in an envelope:

```json
{ "schema_version": "1.0.0", "generated_at": "…", "fingerprints": { "Nginx": { … } } }
```

A matcher that already understands the bare Wappalyzer map (e.g. ASIE's `techfp`)
consumes a sigforge DB by reading the `.fingerprints` object and ignoring the
extended per-entry fields (`provenance`, `license`, `confidence`,
`version_regex`) it does not need — unknown fields are simply skipped.

## Running the CLI

```
sigforge baseline                              # emit the embedded curated baseline to stdout
sigforge merge --out merged.json \             # baseline + normalized sources → one DB
    --source nuclei=nuclei.norm.json \
    --source whatweb=whatweb.norm.json
sigforge validate merged.json                  # check schema version + shape
```

In `merge`, the baseline always wins a tech-id conflict; among `--source` files an
earlier flag outranks a later one. A losing entry's version-capturing patterns are
kept as alternates (`version_regex`) so no version signal is lost, and every entry
carries the `provenance` and `license` of the source it came from.

A `--source` is a **local, already-normalized** DB file in this schema. Remote
fetch/normalize adapters (enthec/webappanalyzer, nuclei, WhatWeb, …) are a later
phase: they are operator-configured, off by default, and must write a normalized
file the operator then passes to `merge` — fetched third-party data is never
vendored into this repo.

## License policy

- sigforge's **own code** is **Apache-2.0** (see `LICENSE`).
- sigforge's **own baseline** (`baseline.json`) is authored from **public facts**
  — a `Server:` header, a cookie name, a path are facts, not copyrightable — and
  is likewise permissive (tagged `license: "Apache-2.0"` per entry).
- **Third-party fingerprint data is never relicensed and never vendored here.** It
  is fetched at the operator's command, under that source's own license, and each
  entry in a merged DB carries its `provenance` + `license`. The operator who
  selects which sources to include **owns the license posture of the output** they
  generate and distribute.

## Layout

```
framework/   infrastructure that knows nothing about fingerprints
  define/      shared constants (service name)
  fsio/        file read + atomic write
modules/     the domain
  intel/
    schema/     the versioned on-disk contract + loader (Parse/Validate/LoadFile)
    matcher/    apply a fingerprint set to a page → detections
    merge/      baseline + sources → one deduped, precedence-ordered set
    baseline/   the embedded curated-facts fingerprint set
cmd/sigforge/  the CLI
docs/          architecture + per-feature specs
```

`framework/` never imports `modules/`.
