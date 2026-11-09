# Snapshot governance (manifest, verify, rollback)

Package `modules/intel/merge` (`manifest.go`) + the `verify` / `rollback` commands in
`cmd/sigforge` (added v0.4).

## 1. The problem

A merged DB is a **point-in-time snapshot**, not a live feed: it was produced by one
sigforge build, over a specific set of sources with their own licenses, at one moment.
A consumer that trusts the raw bytes has no way to tell whether the file drifted, was
tampered with, or was produced by an incompatible build whose merge semantics it would
misread. Governance makes the snapshot **describe itself** so `verify` can refuse a bad
one instead of silently trusting it.

## 2. What `merge` writes

Alongside the merged DB (`db.json`), `merge` writes two sidecar files and archives the
prior generation:

- **`db.json.sha256`** — the content checksum, for drift/tamper detection.
- **`db.json.manifest.json`** — the governance manifest (below).
- **`db.json.prev*`** — the DB + its sidecar + manifest that were at `--out` before this
  merge overwrote them, so `rollback` can restore one step.

### Manifest fields (`merge.Manifest`)

| field | meaning |
|---|---|
| `schema_version` | the on-disk shape version (`schema.SchemaVersion`) |
| `engine_version` | the sigforge build that produced (and can read) the snapshot (`merge.EngineVersion`) |
| `generated_at` | when the snapshot was built |
| `content_sha256` | the hash the bytes must still match |
| `fingerprint_count` | number of fingerprints in the DB |
| `sources` | one row per distinct `(id, provenance_version, license)` present |
| `freshness` | always `snapshot` — a merged DB is a snapshot by construction |

`collectSources` walks every entry's provenance **and** the per-pattern provenances the
merge preserved (`VersionRegexProv` / `CPECandidateProv`), so a GPL pattern pooled under
an Apache winner is reported under its **own** license. The manifest must not under-state
the license posture the merge took care to keep — the operator owns the license posture
of the output they distribute, and the manifest is what they read to know it. Rows are
de-duplicated by `(id, version, license)` and sorted for a reproducible manifest.

## 3. `verify` — refuse, don't trust

```
sigforge verify db.json
```

1. **Integrity:** the DB must still hash to the SHA-256 in `db.json.sha256`. A missing
   sidecar is reported as "no checksum", never treated as OK; any mismatch is
   TAMPER/DRIFT and exits non-zero.
2. **Schema:** the DB must parse clean through `schema.Parse` (full validation, regex
   compilation included), so a checksum-valid DB carrying a broken regex is caught as
   drift here rather than silently dropped at match time.
3. **Compatibility (`Manifest.Compatible`):** the manifest's `schema_version` **and**
   `engine_version` must share the same **MAJOR** as the running build. A differing major
   is `INCOMPATIBLE` and refused — a major bump may change the shape or merge semantics
   this build would misread. (Major-match mirrors the rule `schema.Validate` already
   applies to `schema_version`.)
4. **Description:** the manifest's `content_sha256`, when present, must describe this DB,
   or it is a `MISMATCH`.

A **missing** manifest is a WARNING, not a pass: integrity is still checked, but the DB
is explicitly not a trusted snapshot.

> Honest limit (stated in the command's own output): SHA-256 here detects accidental
> drift and naive tampering only. It is **not** authenticity — an attacker who rewrites
> both the DB and its sidecar passes. Real signing (a key the operator trusts, e.g.
> TUF / Sigstore) is out of scope.

## 4. `rollback` — one honest step back

```
sigforge rollback db.json
```

Restores the one previous snapshot archived at `db.json.prev*` by the last overwriting
merge. It **refuses a blind rollback**: the archived DB must still match its own `.prev`
checksum sidecar and parse clean through schema validation; a corrupt or missing archive
is never restored. On success it restores the DB, its sidecar and (when archived) its
manifest — each write is atomic on its own, though the three are not jointly
transactional.

> Honest limit (stated in the code): this is a **single-step, file-based** rollback (one
> `.prev` generation), not a versioned history. The next merge overwrites `.prev`, and
> rolling back twice is a no-op. If an operator needs deeper history, they keep their own
> versioned copies — sigforge does not pretend to.
