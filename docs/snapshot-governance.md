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

`merge`, `refresh` and `rollback` take the publish lock of the DB before they write it, its sidecar or its manifest: a
lock the operating system holds on `<out>.lock` for the run — `flock` on Linux, macOS and the BSDs, `LockFileEx` on
Windows. A second run of any of them on the same DB while it is held exits 1 naming the file and the holder — its PID
as the system reports it on Linux, "another run" elsewhere — and writes no DB, sidecar or manifest (what a `--fetch`
downloaded may already be in the store `SIGFORGE_CACHE_DIR` names): two publishes used to interleave, leaving the DB of
one with the sidecar and manifest of the other, which `verify` then refused until the next publish. `refresh` holds the
lock from reading the live DB to publishing, so its gate compares the candidate with the DB it replaces.

The system lets the lock go when the run ends, however it ends — done, failed, interrupted, killed, or stopped by a
broken pipe (`sigforge refresh … | head -1`) — so a run that died never blocks the next one and nothing is removed
by hand. `<out>.lock` stays on disk after a run; the file alone is not a lock. It is a lock target only: sigforge never
writes it, never removes it (removing it while held would let another run lock a new file of the same name), and sets
its mode — on a Unix system 0644, whatever the umask, so every user who may publish the DB can lock it read-only; on
Windows the mode only sets or clears the read-only attribute (`go doc os.Chmod`) — only when the run created it. On
Linux, macOS and the BSDs a symbolic link or anything but a plain file at `<out>.lock` is refused, never followed; on
Windows a link there is followed, and nothing is written through it; on a system with neither `flock` nor `LockFileEx`,
where no lock is taken, the file there is opened as every file sigforge reads back is on that system (the table in §6),
through the same code the tests run on Linux (those systems themselves are not in the tests). A lock file another user
made that this one cannot read is reported by path: make it readable, or remove it while no publish runs.

A run killed while it writes may leave a `.sigforge-*.tmp` file beside the DB, which nothing reads, and the DB may be
newer than its sidecar: run `verify` before trusting it. The lock is tested on Linux, on a local file system (not on a
network one such as NFS); on Windows it is built, not tested, and a run started right after one that died may be refused
once, the dead run's lock not yet let go (`cmd/sigforge/lock_windows.go`). On a system with neither `flock` nor
`LockFileEx` publishes are not serialized.

The lock does not make the three files one write: a reader that runs `verify` while a publish is writing can see the new
DB beside the previous sidecar and is refused — run it again once the publish is done. A reader that loads only the DB
always gets a whole file.

## 6. A directory another user can write

A DB published into a directory another user can write is only as trustworthy as that user: they can replace the DB,
its sidecar and its manifest at any time, and `verify` cannot tell their consistent set from yours. Keep the
directory — and the store `SIGFORGE_CACHE_DIR` names — writable by the user who publishes only.

What sigforge does guarantee, even run as root in such a directory, is that write access to the directory never becomes
access to any other file — on Linux, Android, macOS, the BSDs, Solaris, illumos, AIX and Windows (what differs among
them: the table below), save what the end of this section names. On Plan 9, js/wasm and wasip1 it is not guaranteed: on
Plan 9 and js Go's `os.Root` holds a directory by its name, not a descriptor (`go doc os.Root`), and none of the three
is tested. Every write — a published DB, a stored copy, a downloaded dump, an index cut from it — opens the
directory once and works inside it: the temporary file is created there (never an existing name), its mode is set on the
open file, the rename is refused if that file was swapped meanwhile, and the write fails if what lands at the path is
not the file it wrote, removing what landed — a swap in the very instant of the rename is reported, never silent, and
never left at the path (but for the plain file the end of this section names); a write works in the directory it opened
even once that directory's path names another. The archive of the previous DB (`<out>.prev*`) keeps a link it finds
there as the same link, unread, and reads a plain file through the file opened — never waiting on it, with one name,
as the table below has it — refused if that is not the file it looked at (what can be swapped in between the look and
the open: after the table below). The publish lock follows a link on Windows, where nothing is written through it (§5),
and one swapped in at the open on Plan 9, js/wasm and wasip1, as after the table below. The OSV store writes its changed
records inside its own directory, never through a link out of it.

These files sigforge wrote and reads back are read only as the plain file it looked at: the store's copies, indexes,
overlay and dictionary, `sync`'s status (`sync-status.json`), `watch`'s state and the sync manifest. A link, a FIFO or a
directory there is no entry for the store and the status, and an error for the others; a file with another name (a hard
link, where the system counts a file's names: the table below) is refused when it is opened — a downloaded dump or
dictionary is handed out by the store first, then refused at that open. None is read or waited on (what can be swapped
in between the look and the open: after the table below). `rollback` restores what the archive kept (§4): a link is
restored as the same link, never copied out — its target is read only to check the DB against its checksum, without
waiting on it where `fsio` has `O_NONBLOCK` (the table below) — so no file `rollback` writes ever holds what a link
someone put among the archived files points to. What the operator names is read as they name it, through a link and from
a pipe, as before: `--db`, a merge source, `--sbom`, the DB `verify` checks with its sidecar and manifest (`verify`
writes nothing). The live DB `refresh` reads at `--out` is read through a link too, but only as a plain file (the end of
this section). `sync` reads the store back before it calls a source ok: a copy the store did not keep — a write
refused, a file swapped under it — fails the source.

What the system itself enforces differs. The build tags of the files named below decide the row a build takes:

| System | Publish lock (§5) | Holder named in a refusal | `fsio` has `O_NOFOLLOW`, `O_NONBLOCK` and a file's count of names |
|---|---|---|---|
| Linux, Android | `flock` | its PID | yes |
| macOS, FreeBSD, NetBSD, OpenBSD, DragonFly BSD | `flock` | "another run" | yes |
| Windows | `LockFileEx`; a link at `<out>.lock` is followed, nothing is written through it | "another run" | no |
| Solaris, illumos, AIX | none: publishes are not serialized | — | yes |
| Plan 9, js/wasm, wasip1 | none: publishes are not serialized | — | no |

Lock: `cmd/sigforge/lock_flock.go`, `lock_windows.go`, `lock_other.go`; holder: `cmd/sigforge/holder_linux.go`; flags
and count: `framework/fsio/openflags_unix.go`, `openflags_other.go`, `links_unix.go`, `links_other.go`. A file read back
is looked at (`Lstat`), opened without waiting where `fsio` has `O_NONBLOCK`, checked once open to be a plain file —
with one name where the system counts them (`fsio.OpenPlainIn`, `fsio.OpenOwn`) — and checked to carry the number of
the file looked at (`SameFile`). A link swapped in between the look and the open is refused at the open where `fsio` has
`O_NOFOLLOW` and the file is opened by its path (`fsio.OpenOwn`, `fsio.ReadOwn`); it is followed on a system without the
flag, and on every system for a file read inside a directory opened once — the OSV overlay, the DB, sidecar and
manifest being archived, a plain file `rollback` restores — where `os.Root` follows a link that stays inside the
directory; what it leads to is then read only if it carries that number. Where the open has no `O_NONBLOCK` — a system
without the flag that has FIFOs — a FIFO swapped in makes it wait for a writer. The tests run on Linux only.

What these checks do not cover. `SameFile` compares numbers, and a removed file's number can go to the next file made
(ext4 gives it at once): a plain file another user makes at a name after removing the file looked at there, or the
temporary file a write closed, can carry its number and pass — it is read, archived or left at the name as theirs, no
more than they could do by writing there before the look or after the write; a FIFO, a directory or a link made so is
still refused. `refresh` reads the live DB at `--out` as the operator names it, through a link, once it holds the
publish lock: it refuses what is no plain file there (a FIFO, a device) without waiting where `fsio` has `O_NONBLOCK`,
but a link there, symbolic or hard, to another file is read, and the techs that file lists can be named in the gate's
report, and what a refused parse quotes of it in the error. Where the system gives no count of a file's names (Windows,
Plan 9, js/wasm, wasip1), a hard link put where sigforge reads a file back, to another file, is read as that file: on
such a system that lets a user hard-link a file they cannot read, `merge` and `refresh` can archive it into
`<out>.prev*`, and `sync`, `watch` and `merge --fetch` can write what they read of it back into their status, state or
sync manifest, each mode 0644.

Those were the ways a link or a swapped temporary file made a root run change the mode of, copy out, or write into a
file of the other user's choosing (all present in v0.5.0). A test holds the module to them, deny by default. What it
type-checks covers what can be built: every Go file a build of the module compiles for Linux, Windows, macOS or Plan 9
is type-checked whole, and each of these fails it outright — a Go file none of those builds takes (another
architecture's or system's, a cgo file: the test builds with cgo off), outside what the go tool leaves out of `./...`
(`testdata`, a directory whose name starts with `.` or `_`, a nested module — a directory holding its own `go.mod`
file); a file the go tool compiles or links that is not Go (assembly, C, a `.syso` object), for any system or
architecture, anywhere under the module's directory (the walk follows no symbolic link and skips every directory named
`.git`); a `//go:` directive other than `build`, `embed` and `generate` (`go:linkname`, `go:cgo_import_dynamic`, …), a
`//line` directive, and a `godebug` line in `go.mod`; a package of another module whose directory is under the module's
directory and that a build of it imports. Outside `framework/fsio` (and, for the network, `framework/fetch`): importing
a standard package that is not on a short list of pure ones, or calling a file system or network function or method that
is not on a short list of safe ones (metadata, an open file, an `os.Root` working inside its directory), fails the test
unless a comment on its line, or the comment block just above it, names it and says why. Every use of an interface's
method — a call, a method value or expression, through a type parameter's constraint or an embedded field — is
checked against every type the module holds a value of: it fails the test outright when one of them has a judged method
of that name whose signature matches (aliases resolved, a type parameter matching any type, any other kind that holds a
type parameter matching as well) — `WriteFile` on an interface an `*os.Root` could answer, `Do` on one an
`*http.Client` could. It is the call that is checked, so the path the value took to the interface does not matter. A
type only its owner holds (a network connection inside `framework/fetch`) is the owner's: what it hands out through an
interface is its API, reviewed with it. A value that carries a judged method is also held to the uses that keep its type
where it flows into code the test does not read (the standard library), and taking a judged function as a value fails
the test outright. What the test cannot decide — whether an allowed call is given a path inside a directory another
user can write — the comment states, and review and the behaviour tests hold; so is a change to the test itself, and
an `unsafe` import, which needs a comment naming it.
