# Feature: Schema (the on-disk fingerprint contract)

Package `modules/intel/schema`.

## 1. User story

As a scanner (and as every other sigforge package) I want ONE versioned contract
for what a fingerprint database looks like on disk, so that any source normalizes
into it, a consumer writes a single loader, and a build can refuse a database whose
major schema version it does not understand — instead of silently misreading it.

## 2. Pre-condition

- A DB is JSON: a versioned envelope `{schema_version, generated_at?, fingerprints}`
  around a map of technology-name → fingerprint.
- The fingerprint shape is Wappalyzer-compatible (`cats`/`headers`/`cookies`/`meta`/
  `html`/`scriptSrc`/`implies`/`requires`/`requiresCategory`/`excludes`/`dom` with
  inline `\;version:\1` / `\;confidence:N` pattern suffixes), extended with sigforge's
  per-entry provenance/license/confidence/
  version_regex/cpe metadata.

## 3. Acceptance criteria

- `Parse(bytes)` / `LoadFile(path)` decode and `Validate` a DB; a missing file or
  empty input is an error the caller may treat as "baseline only".
- `Validate` accepts a DB only when its schema_version shares this build's MAJOR
  (`SchemaVersion = 1.0.0`), the fingerprint set is non-empty, and no name is blank.
  It also compiles every regex pattern (headers, cookies, meta, html, scriptSrc,
  version_regex, dom attribute and text) and fails naming the entry and field of a
  malformed one; a dom attribute pattern is compiled behind its `attr=` prefix, so one
  that compiles only there (`?abc`) passes and the matcher drops it.
- `StringList` unmarshals a Wappalyzer field that is either a bare string or an array
  of strings, and always marshals back as an array.
- `(*DB).JSON()` renders indented JSON suitable for an on-disk file.
- The `cpe` field is populated only from a source's real value — never fabricated —
  so it stays a trustworthy bridge to CVE/NVD.

## 4. Definition of Done

- Schema types, `Parse`/`Validate`/`LoadFile`/`JSON`, major-version gate and the
  `StringList` string-or-array codec implemented and unit-tested.
- Consumer-facing shapes (`DB`, `Fingerprint`, `StringList`) are stable; any change
  to them is ADDITIVE so the ASIE consumer does not break.

## 5. Description

The schema is the seam between every producer (baseline, merge, the source adapters)
and every consumer (matcher, diff, a downstream scanner). Keeping it Wappalyzer-shaped
means an external dataset in that shape normalizes with little translation and a
matcher that already reads the bare Wappalyzer map can read a sigforge DB by taking
`.fingerprints` and ignoring the extended fields it does not need. The envelope's
major version is the compatibility gate: a consumer refuses a `2.x` DB rather than
guessing at fields that moved. `Validate` checks the shape and that every regex
compiles: a bad pattern fails the DB naming its entry and field, instead of degrading
one detection unseen — except a dom attribute pattern that compiles only behind its
`attr=` prefix (see §3 above), which passes and the matcher drops.

### 5.1 Diagram

```
bytes / file ──▶ Parse / LoadFile ──▶ Validate (major-version gate, non-empty, named, regexes compile)
                                          │
                                          ▼
                                   *schema.DB ──▶ matcher.Match / merge.Merge / diff.Diff
                                          │
                                   (*DB).JSON() ──▶ on-disk merged DB
```
