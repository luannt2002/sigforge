# Feature: CLI

Command `cmd/sigforge`.

## 1. User story

As an operator, I want a small command to emit the baseline, merge it with my
normalized sources into one DB, and validate a DB file — so I can regenerate my
scanner's database from cron without any server or infrastructure.

## 2. Pre-condition

- The sigforge binary is built.
- For `merge`, each `--source` points at a local normalized DB file in this schema.

## 3. Acceptance criteria

- `sigforge baseline` writes the embedded curated baseline JSON to stdout.
- `sigforge merge --out F [--source name=path ...]` writes a merged DB to `F`
  (baseline + sources), stamped with `schema_version` and a UTC `generated_at`.
- Earlier `--source` flags outrank later ones; the baseline outranks all sources.
- `sigforge validate FILE` prints `ok: schema <v>, <n> fingerprints` and exits 0
  on a valid, compatible DB; it exits non-zero with a message otherwise.
- `--out` is required for `merge`; a bad `--source` spelling or an unreadable
  source file is a clear error.
- `merge --fetch name[=url]` pulls a third-party source adapter at the operator's
  command: `webappanalyzer` (GPL-3.0), `nuclei` (MIT), `whatweb` (GPL-2.0-or-later).
  The URL comes from the flag or the source's env var (`SIGFORGE_SOURCE_<NAME>_URL`)
  — never hardcoded, and a source with no URL is off and errors. Each fetch stamps
  its synced version onto the entries and records a row (source, url, version,
  fetched_at, entry_count, license) in the `--manifest` file (default
  `SYNC-MANIFEST.json`), the marker a future re-sync diffs against.
- No source URL or vendor is hardcoded. A remote fetch happens only on an explicit
  `--fetch`. Fetched third-party data is operator-generated, carries its source's
  license, and is never vendored into this repo (the merged DB and manifest are
  gitignored).

## 4. Definition of Done

- `baseline`, `merge`, `validate` subcommands implemented; unknown command and
  `--help` give usage and the right exit code.
- The merged file is written atomically (temp + rename) so a crash never leaves a
  half-written DB.
- Verified end-to-end: `baseline | validate`, and `merge` of a demo source shows
  the new tech added with its provenance/license and the baseline entry's
  precedence preserved with the source's version regex kept as an alternate.

## 5. Description

The CLI is the only place the layers are wired: it reads the embedded baseline
(`baseline`), loads each normalized source (`schema.LoadFile`), merges
(`merge.Merge`) with trust assigned by flag order, wraps the result in a
`schema.DB` envelope, and writes it atomically (`fsio.WriteAtomic`). A `--source`
is a local normalized file; a `--fetch` runs an operator-gated adapter
(`modules/intel/source`) that pulls its URL via `framework/fetch`, normalizes to
the same schema, stamps provenance/license/version and updates the sync manifest.
Only DATA crosses the wire — no executable logic is pulled or run — keeping the
supply-chain boundary sigforge itself exists to protect.

### 5.1 Diagram

```
sigforge baseline ─▶ baseline.Bytes() ─▶ stdout

sigforge merge --out F --source a=p1 --source b=p2
   baseline.DB() ┐
   LoadFile(p1)  ┤ trust: a > b (flag order)
   LoadFile(p2)  ┘
        └▶ merge.Merge(base, a, b) ─▶ schema.DB{version, generated_at, fingerprints}
               └▶ fsio.WriteAtomic(F)

sigforge validate F ─▶ schema.LoadFile(F) ─▶ "ok: schema v, n fingerprints" | error(exit 1)
```
