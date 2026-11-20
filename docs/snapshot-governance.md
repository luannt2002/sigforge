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
transactional. Each is restored as the archive kept it: a link as the same link (a DB, sidecar
and manifest published as links into a `releases/` directory come back as those links), a plain
file as its bytes. Anything else in place of an archived file — a FIFO, a directory — is refused,
and all three are read and checked before any is written, so a refused rollback changes nothing. A refusal over
an archived link names the link and quotes nothing read through it — no digest, no word of its target.

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
created it. On Linux, macOS and the BSDs a symbolic link or anything but a plain file at `<out>.lock` is refused, never
followed; on Windows a link there is followed, and nothing is written through it; on a system with neither `flock` nor
`LockFileEx` (Solaris, illumos, AIX, Plan 9), where no lock is taken, the file there is opened as every file sigforge
reads back is (§6) — a link refused, never followed, a FIFO never waited on — through the same code the tests run on
Linux (that system itself is not in the tests). A lock file another user made that this one cannot read is reported by
path: make it readable, or remove it while no publish runs.

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

What sigforge does guarantee, even run as root in such a directory, is that write access to the directory never becomes
access to any other file. Every write — a published DB, a stored copy, a downloaded dump, an index cut from it — opens
the directory once and works inside it: the temporary file is created there (never an existing name), its mode is set on
the open file, the rename is refused if that file was swapped meanwhile, and the write fails if what lands at the path
is not the file it wrote, removing what landed — a swap in the very instant of the rename is reported, never silent, and
never left at the path; a write works in the directory it opened even once that directory's path names another. The
archive of the previous DB (`<out>.prev*`) never reads through a link: a link is archived as the same link, unread, and
a plain file is read through the file opened. The publish lock never follows a link (§5). The OSV store writes its
changed records inside its own directory, never through a link out of it.

Every file sigforge wrote and reads back is opened without following a link and only as a plain file: the store's
copies, indexes, overlay and dictionary, `sync`'s status (`sync-status.json`), `watch`'s state and the sync manifest.
A link, a FIFO or a directory there is no entry for the store and the status, and an error for the others — never
read, never waited on. `rollback` restores what the archive kept (§4): a link is restored as the same link, never
copied out — its target is read only to check the DB against its checksum, without waiting on it — so no file
`rollback` writes ever holds what a link someone put among the archived files points to. What the operator names is
read as they name it, through a link and from a pipe, as before: `--db`, a merge source, `--sbom`, and the DB `verify`
checks with its sidecar and manifest (`verify` writes nothing). `sync` reads the store back before it calls a source
ok: a copy the store did not keep — a write refused, a file swapped under it — fails the source.

Those were the ways a link or a swapped temporary file made a root run change the mode of, copy out, or write into a
file of the other user's choosing (all present in v0.5.0). A test holds the module to them, deny by default. What it
type-checks covers what can be built: every Go file a build of the module compiles for Linux, Windows, macOS or Plan 9
is type-checked whole, and each of these fails it outright — a Go file none of those builds takes (another
architecture's or system's, a cgo file: the test builds with cgo off), outside what the go tool leaves out of `./...`
(`testdata`, a directory whose name starts with `.` or `_`, a nested module — a directory holding its own `go.mod`
file); a file the go tool compiles or links that is not Go (assembly, C, a `.syso` object), for any system or
architecture, anywhere in the module; a `//go:` directive other than `build`, `embed` and `generate` (`go:linkname`,
`go:cgo_import_dynamic`, …), a `//line` directive, and a `godebug` line in `go.mod`; a package of another module under
the module's path that a build of it imports. Outside `framework/fsio` (and, for the network, `framework/fetch`):
importing a standard package that is not on a short list of pure ones, or calling a file system or network function or
method that is not on a short list of safe ones (metadata, an open file, an `os.Root` working inside its directory),
fails the test unless a comment on its line names it and says why. Every use of an interface's method — a call, a method
value or expression, through a type parameter's constraint or an embedded field — is checked against every type the
module holds a value of: it fails the test outright when one of them has a judged method of that name whose signature
matches (aliases resolved, a type parameter matching any type, any other kind that holds a type parameter matching as
well) — `WriteFile` on an interface an `*os.Root` could answer, `Do` on one an `*http.Client` could. It is the call that
is checked, so the path the value took to the interface does not matter. A type only its owner holds (a network
connection inside `framework/fetch`) is the owner's: what it hands out through an interface is its API, reviewed with
it. A value that carries a judged method is also held to the uses that keep its type where it flows into code the test
does not read (the standard library), and taking a judged function as a value fails the test outright. What the test
cannot decide — whether an allowed call is given a path inside a directory another user can write — the comment states,
and review and the behaviour tests hold; so is a change to the test itself, and an `unsafe` import, which needs a
comment naming it.
