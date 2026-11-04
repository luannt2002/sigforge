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
- No source URL or vendor is hardcoded. No remote fetch happens. No third-party
  data is vendored.

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
`schema.DB` envelope, and writes it atomically (`fsio.WriteAtomic`). Remote
fetch/normalize adapters are a later phase: for now a source is a local file an
operator-gated adapter produced, keeping the data-only, no-executable-logic
boundary.

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
