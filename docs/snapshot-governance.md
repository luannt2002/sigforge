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

## 5. One publish at a time

`merge`, `refresh` and `rollback` take the publish lock of the DB before writing: a lock the operating system holds on
`<out>.lock` for the run — `flock` on Linux, macOS and the BSDs, `LockFileEx` on Windows. A second run of any of them on
the same DB while it is held exits 1 naming the file and the holder — its PID as the system reports it on Linux,
"another run" elsewhere — and writes nothing: two publishes used to interleave, leaving the DB of one with the sidecar
and manifest of the other, which `verify` then refused until the next publish. `refresh` holds the lock from reading
the live DB to publishing, so its gate compares the candidate with the DB it replaces.

The system lets the lock go when the run ends, however it ends — done, failed, interrupted, killed, or stopped by a
broken pipe (`sigforge refresh … | head -1`) — so a run that died never blocks the next one and nothing is removed by
hand. `<out>.lock` stays on disk after a run; the file alone is not a lock. It is a lock target only: sigforge never
writes it, never removes it (removing it while held would let another run lock a new file of the same name), and sets
its mode — 0644, whatever the umask, so every user who may publish the DB can lock it read-only — only when the run
created it. On Linux, macOS and the BSDs a symbolic link or anything but a plain file at `<out>.lock` is refused,
never followed; on Windows and other systems a link there is followed, and nothing is written through it. A lock file
another user made that this one cannot read is reported by path: make it readable, or remove it while no publish
runs.

A run killed while it writes may leave a `.sigforge-*.tmp` file beside the DB, which nothing reads, and the DB may be
newer than its sidecar: run `verify` before trusting it. The lock is tested on Linux; on Windows it is built, not
tested — there the system lets a dead run's lock go "as soon as system resources allow", so a run started right after
may be refused once. On a system with neither `flock` nor `LockFileEx` publishes are not serialized.

The lock does not make the three files one write: a reader that runs `verify` while a publish is writing can see the new
DB beside the previous sidecar and is refused — run it again once the publish is done. A reader that loads only the DB
always gets a whole file.

## 6. A directory another user can write

A DB published into a directory another user can write is only as trustworthy as that user: they can replace the DB,
its sidecar and its manifest at any time, and `verify` cannot tell their consistent set from yours. Keep the
directory — and the store `SIGFORGE_CACHE_DIR` names — writable by the user who publishes only.

What sigforge does guarantee, even run as root in such a directory, is that write access to the directory never
becomes access to any other file. Every write opens the directory once and works inside it: the temporary file is
created there (never an existing name), its mode is set on the open file, the rename is refused if that file was
swapped meanwhile, and the write fails if what lands at the path is not the file it wrote — a swap in the very instant
of the rename is reported, never silent. The archive of the previous DB (`<out>.prev*`) never reads through a link:
a link is archived as the same link, unread, and a plain file is read through the file opened. The publish lock never
follows a link (§5). The OSV store writes its changed records inside its own directory, never through a link out of
it. Those were three ways a link or a swapped temporary file made a root run change the mode of, copy out, or write
into a file of the other user's choosing (all present in v0.5.0).
