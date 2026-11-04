# Feature: Merge

Package `modules/intel/merge`.

## 1. User story

As an operator, I want to combine sigforge's curated baseline with the normalized
sources I have chosen into one database, so that my scanner reads a single file —
with each pattern tagged by where it came from and under what license.

## 2. Pre-condition

- The baseline fingerprint set is in hand.
- Zero or more normalized source sets are available, each with a name and a trust
  rank.

## 3. Acceptance criteria

- The result is a new set; the inputs are not mutated.
- On a tech-id conflict the baseline entry wins whole; its own patterns are
  untouched.
- Among sources, a higher `Trust` wins a conflict; ties resolve to the order given.
- A losing entry's version-capturing patterns are preserved as alternates in the
  winner's `version_regex` (de-duplicated), so no version signal is dropped.
- A tech present only in a source is added, stamped with that source's provenance.
- Every entry carries a `provenance` (baseline entries → "baseline"; source
  entries → the source name) and the license it came with.

## 4. Definition of Done

- `merge.Merge(baseline, ...Source) map[string]schema.Fingerprint` implemented,
  pure.
- Tests cover: baseline-wins-and-keeps-alternate-version, new-tech-stamped,
  source-precedence-by-trust, inputs-not-mutated. All green.

## 5. Description

`Merge` copies the baseline first, stamping provenance "baseline" where absent. It
then applies sources in descending `Trust` (stable for ties). For a tech already
present (the higher-precedence winner), it collects the incoming entry's
version-bearing patterns — any field pattern containing `\;version:` plus its
existing alternates — and appends them, de-duplicated and sorted, to the winner's
`version_regex`. A tech not yet present is added and stamped. sigforge never
relicenses: the per-entry `provenance` + `license` is the record the operator uses
to understand the license posture of the output they distribute.

### 5.1 Diagram

```
baseline ─▶ copy, stamp provenance="baseline"  ──────────────┐
                                                             ▼
sources (sorted by Trust desc, stable) ──▶ for each entry:   out[name]
   ├─ name already in out (winner)  ─▶ append its version patterns to winner.version_regex
   └─ name new                      ─▶ add, stamp provenance=source.Name, license=source's
                                                             │
                                                             ▼
                                   merged set (deduped, precedence-ordered, provenance+license per entry)
```
