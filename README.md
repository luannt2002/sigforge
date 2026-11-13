# sigforge

A **file-based** security-intelligence data platform. It gathers, normalizes and
merges technology-fingerprint data into one versioned JSON database that scanners
(such as ASIE) consume to map a live site — "runs nginx 1.18 / WordPress 6.5 /
jQuery 1.12" — onto CVE / EOL knowledge.

sigforge owns the *data* concern so each scanner ships only a thin loader plus its
own clean baseline. The scanner stays permissively licensed; the license-laden
third-party sources are fetched by the operator at runtime and tagged, never
vendored into this repo.

## What sigforge does

Run the blocks in order from the repository root, after `go install ./cmd/sigforge`, in a shell
with no `SIGFORGE_*` variable set. Nothing leaves the machine. The output is real, cut where it
shows `…`.

**Recognise the technology on a page.** `match` reads a page (headers, cookies, HTML, script
URLs) as JSON on stdin and applies the fingerprint baseline embedded in the binary:

```
$ PAGE='{"headers":{"Server":["nginx/1.18.0"],"X-Powered-By":["PHP/7.2.34"]},"scriptSrcs":["/js/jquery-3.4.0.min.js"]}'
$ echo "$PAGE" | sigforge match
Nginx 1.18.0  (confidence 100, baseline/Apache-2.0)
PHP 7.2.34  (confidence 100, baseline/Apache-2.0)
jQuery 3.4.0  (confidence 100, baseline/Apache-2.0)
```

**Attach CVE / end-of-life / KEV intel, and say what was not checked.** `enrich` looks up every
detection. A feed whose URL is not set is off and answers `not_checked`, never "clean" (the CVE
and end-of-life lines below). Retire.js, CISA KEV and the CPE dictionary fall back instead to a
small sample embedded in the binary: the one lead here comes from the Retire.js sample, and `kev=`
from the KEV sample:

```
$ echo "$PAGE" | sigforge enrich
[cpe] cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:* 1.18.0 → not_checked  source=cve
[eol] nginx 1.18.0 → not_checked  source=lifecycle
…
[jslib] jQuery 3.4.0 → affected_by_advisory  source=jslib freshness=snapshot
    lead CVE-2020-11022   medium   cvss=- epss=- kev=false
looked up 1/7 · concluded 1/7 · not concluded 6 (not_checked 6, …) — not concluded is not clean
```

**Report advisories that are new since the last run.** `sync` keeps a local copy of each
configured catalog (end-of-life bundle, KEV, Retire.js, CPE dictionary) and of each OSV dump named
with `--osv`; `watch` re-checks an inventory against the sources, using what `sync` stored. Here a
stand-in Retire.js feed is served on localhost (any static file server will do):

```
$ D=$(mktemp -d) && mkdir "$D/feed"
$ echo '{"jquery":{"vulnerabilities":[{"below":"3.4.0","identifiers":{"CVE":["CVE-2019-11358"]}}]}}' > "$D/feed/jsrepository.json"
$ python3 -m http.server -b localhost -d "$D/feed" 8765 >/dev/null 2>&1 & sleep 1
$ export SIGFORGE_CACHE_DIR="$D/store" SIGFORGE_SOURCE_RETIREJS_URL=http://localhost:8765/jsrepository.json
$ sigforge sync
…
  Retire.js repository   ok — 92 bytes in the store
…
$ sigforge watch --state "$D/watch.json" --jslib jquery@3.3.1
first run: 1 lead(s) on 1 identit(ies) recorded; later runs name what changes
$ cp modules/intel/jslib/data/retirejs-snapshot.json "$D/feed/jsrepository.json"   # the feed adds CVE-2020-11022
$ sigforge sync
…
  Retire.js repository   ok — 1655 bytes in the store
…
$ sigforge watch --state "$D/watch.json" --jslib jquery@3.3.1 --fail-on-new   # exits 1 on a NEW lead
NEW   jslib jquery@3.3.1  CVE-2020-11022
sigforge: watch: 1 new lead(s)
```

**Keep a local store.** `sources` reports what the last `sync` left per source. With
`SIGFORGE_CACHE_MAX_AGE`, a catalog or OSV dump synced less than that long ago is read from the
store with no request, so the lookup below works with the feed gone; an older copy is asked for
again and, if the feed fails, used and labelled `stale`. Per-query feeds (CVE, EPSS, per-product
end-of-life, WordPress) are asked on every lookup:

```
$ sigforge sources
…
  Retire.js repository   ok — synced 2026-11-12T12:09:34Z
…
$ kill $!   # stop the feed
$ SIGFORGE_CACHE_MAX_AGE=1h sigforge enrich --jslib jquery@3.3.1 < /dev/null
requests: localhost:8765=0 sent (1 served from the local store)
[jslib] jquery 3.3.1 → affected_by_advisory  source=jslib freshness=snapshot
    lead CVE-2019-11358   medium   cvss=- epss=- kev=false
    lead CVE-2020-11022   medium   cvss=- epss=- kev=false
…
```

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
`meta` / `html` / `scriptSrc` / `implies` / `requires` / `requiresCategory` / `excludes` / `dom` with the inline
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
    --source local=local.norm.json \           # a local, already-normalized file
    --fetch webappanalyzer=<url>               # OR fetch a third-party source at your command
sigforge validate merged.json                  # check schema version + shape
sigforge diff old.json new.json                # report techs a re-sync added/removed/changed
sigforge eol PHP 7.2.34                         # version → end-of-life status (feed off by default)
sigforge cve <cpe> <version>                    # CPE+version → known CVE leads (feed off by default)
sigforge inspect Nginx                          # data-only facts for one tech (no match, no network)
sigforge match < page.json                      # match a JSON Page from stdin → detections
sigforge enrich [--json] < page.json            # match → full unified CVE/EOL/KEV intel (feeds off by default); JS libraries the page reveals → Retire.js
sigforge enrich --sbom bom.json --package pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 \
               --wp-plugin contact-form-7@5.0 --jslib jquery@3.4.0 < /dev/null   # any ecosystem (purl / CycloneDX SBOM), WordPress, JS — OSV dump loaded once per ecosystem
sigforge enrich --sbom image.cdx.json < /dev/null  # container SBOM (Trivy/Syft): OS packages by distro release (Debian, Ubuntu, Alpine, Rocky, Alma, …)
sigforge verify merged.json                     # prove a merged DB against its sidecar + schema + manifest
sigforge rollback merged.json                   # restore the one prior snapshot from <DB>.prev*
sigforge refresh --out merged.json --fetch webappanalyzer  # re-sync; publish only if nothing regresses (else keep current, exit 1)
sigforge coverage [--db merged.json] [--json]   # how much of a DB can reach a CVE lookup / extract a version; names detection-only entries
sigforge sync                                   # refresh every configured catalog into SIGFORGE_CACHE_DIR; with SIGFORGE_CACHE_MAX_AGE later runs use it with no request (labelled snapshot)
sigforge sync --osv Debian --osv npm            # also keep those OSV dumps in the store, reduced once into an index file each scan reads (Ubuntu: 807MB dump → 19MB index)
sigforge sources --max-age 26h                  # what the last sync left per source: ok / FAILED (why) / never synced / off — exit 1 when one in use is failing, never synced or stale, or when none is in use (schedule it: docs/cli.md §3.2)
sigforge watch --state watch.json --sbom inventory.cdx.json --fail-on-new   # after each sync: NEW / GONE advisories for the inventory since the last run (GONE only from a source's whole data), UNCHECKED when a source did not answer or cannot rule a lead out, REMOVED when an identity with leads left the inventory (exit 1 on NEW, when no source answered at all, or when there is nothing to look up)
```

`diff`, `eol` and `cve` are the depth layer: `diff` is pure; `eol` and `cve` query
an operator-supplied feed (`SIGFORGE_SOURCE_ENDOFLIFE_URL` / `SIGFORGE_SOURCE_CVE_URL`)
and are **off by default** — unset, they report `unknown`, never "safe".

In `merge`, the baseline always wins a tech-id conflict; among `--source`/`--fetch`
inputs an earlier flag outranks a later one. A losing entry's version-capturing
patterns are kept as alternates (`version_regex`) so no version signal is lost, and
every entry carries the `provenance` and `license` of the source it came from.

A `--source` is a **local, already-normalized** DB file in this schema. A `--fetch`
runs an **operator-gated adapter** that pulls and normalizes a third-party source at
your command:

| id | format | license | env var (alternative to `=url`) |
|---|---|---|---|
| `webappanalyzer` | Wappalyzer-schema JSON | GPL-3.0 | `SIGFORGE_SOURCE_WEBAPPANALYZER_URL` |
| `nuclei` | tech-detect templates (YAML) | MIT | `SIGFORGE_SOURCE_NUCLEI_URL` |
| `whatweb` | plugins (Ruby) | GPL-2.0-or-later | `SIGFORGE_SOURCE_WHATWEB_URL` |

Every adapter is **off by default** — it does nothing, and errors, unless you supply
its URL. No source URL or vendor is hardcoded. Each fetch stamps the source's synced
version onto its entries and records it in `SYNC-MANIFEST.json` (one row per source:
url, version, fetched-at, count, license) — the marker a future re-sync diffs
against. Fetched third-party data is never vendored into this repo; the merged DB
and the manifest are operator-generated and gitignored. See `docs/source.md` for the
per-format mapping limits (`nuclei`/`whatweb` are best-effort).

## Unified intelligence

Every lookup source (CVE, end-of-life, OSV, WordPress, JS library) emits **one result
shape** — `modules/intel/unified.Result` — so a
consumer (ASIE, a report, the `enrich` CLI) handles ONE contract instead of six
per-provider types. It is fully **additive**: each provider keeps its own typed API;
a thin `ToUnified` adapter maps that output into a `unified.Result`.

**Honesty is the contract.** `unified.State` has **seven** values that a consumer
must never collapse:

| state | meaning |
|---|---|
| `not_checked` | the source was off / not invoked (no env URL), or nothing matched (the reason says which: part of the data, or `NoteNoClearance` for the whole) — **not** "clean" |
| `source_unavailable` | the source errored or was unreachable — **not** "clean" |
| `unknown_product` | the source does not recognise this identity |
| `unknown_version` | the version could not be determined or compared |
| `potentially_affected` | an advisory exists but the version can't be pinned (a LEAD) |
| `affected_by_advisory` | the version falls in an advisory range (a LEAD, never proof) |
| `not_affected_by_advisory` | the version resolved, no advisory matched — clean **for this source only**. **sigforge issues none**: a real source's data can read as whole and still be wrong (cut RPM epochs, a release no longer tracked), so "nothing matched" is `not_checked` with the reason |

`unknown*` / `source_unavailable` / `not_checked` are **never** "safe". An
`affected_by_advisory` result is an advisory-range match on a (spoofable) version — a
**lead** ASIE cross-verifies against a real asset, not a proven exploit. A
`Result.Freshness` (`live` / `snapshot` / `stale`) travels with every result so a
stale snapshot is never read as live truth, and each `Lead` carries `Score` (CVSS) and
`EPSS` as separate `*float64` fields that stay `nil` when the feed gave no metric (a
missing score is never the real `0.0`, and the two scales never share a field). See
`docs/unified-contract.md`.

### The enrich pipeline

`sigforge enrich` (and `enrich.EnrichUnified` / `EnrichUnifiedExt`) runs the full
breadth→depth pipeline over a page: `matcher.Match` → identity-verified CPE →
CVE / EOL / KEV-EPSS lookups → `[]unified.Result`. `EnrichUnifiedExt` also dispatches
operator-supplied identities that do not come from the page — ecosystem packages to
OSV, WordPress slugs to wpcve, JS libraries to jslib. Every feed is **injected and
operator-gated**: with no env URL set, every feed is off and the output is honest
`not_checked`, with no network touched — an embedded sample may still report a hit, never
a "not affected". See `docs/enrich-pipeline.md`.

### Snapshot governance

A merged DB is a point-in-time snapshot. `merge` now writes a **governance manifest**
(`<DB>.manifest.json`) beside the SHA-256 sidecar: which build produced the snapshot,
over which sources (with license posture), when, and the content hash it must still
match. `verify` refuses a DB whose manifest records an incompatible schema/engine
**major** version or whose hash does not describe the bytes on disk. `merge` also
archives the prior snapshot to `<DB>.prev*`, so `rollback` restores it in one step
(a single generation — not a versioned history). See `docs/snapshot-governance.md`.

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
  fetch/       the one outbound client (no hardcoded URL): store with ETag, max age, stale-if-error, 429 hold-off
modules/     the domain
  intel/
    schema/     the versioned on-disk contract + loader (Parse/Validate/LoadFile)
    matcher/    apply a fingerprint set to a page → detections (incl. passive dom rules)
    merge/      baseline + sources → one deduped, precedence-ordered set
    baseline/   the embedded curated-facts fingerprint set (58 public-fact techs)
    source/     operator-gated fetch+normalize adapters + sync manifest
    diff/       set-difference between two DBs (what a re-sync moved)
    refresh/    regression gate before a re-synced DB replaces the live one
    coverage/   counts what a DB or a run could not answer instead of hiding it
    lifecycle/  version → end-of-life LEAD via an operator-supplied endoflife feed
    cve/        CPE+version → known-CVE LEADs via an operator-supplied NVD-shaped feed
    osv/        ecosystem+package → advisory LEADs via an operator-supplied OSV dump
    jslib/      JS library+version → Retire.js LEADs (embedded snapshot or live feed)
    wpcve/      WordPress plugin/theme slug+version, or core version → advisory LEADs
    kev/        CVE → exploitation signal (CISA KEV membership + FIRST.org EPSS)
    takeoverfp/ dangling-subdomain fingerprints (operator data upgrading an embedded CC-BY-4.0 snapshot)
    identity/   tech → dictionary-VERIFIED CPE (NVD CPE dictionary); candidate ≠ verified
    unified/    the one result shape every source emits (7 honest states + freshness)
    versioncmp/ compare two versions under an ecosystem's rules (PEP 440, SemVer, dpkg, rpm, apk, Maven, Composer, …)
    enrich/     compose breadth (matcher) + depth (all sources) into []unified.Result
    feedset/    one run's sources from the SIGFORGE_* environment — shared by the CLI and importing scanners
    accuracy/   precision/recall + oracle + adversarial harness (correctness proof)
cmd/sigforge/  the CLI
docs/          architecture + per-feature specs
```

`framework/` never imports `modules/`.
