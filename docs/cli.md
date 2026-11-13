# Feature: CLI

Command `cmd/sigforge`.

## 1. User story

As an operator, I want a small command to emit the baseline, merge it with my
normalized sources into one DB, and validate a DB file — so I can regenerate my
scanner's database from cron without any server or infrastructure — and to look up
the intel behind a detection (CVE, end-of-life, OSV, KEV) the same way a scanner
importing sigforge does.

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

### 3.1 The other subcommands

`sigforge --help` prints the full usage; in short:

| command | what it does |
|---|---|
| `refresh --out DB …` | `merge` behind a regression gate: re-syncs only if no entry is lost beyond `--allow-removed N` and no kept tech loses its verified CPE, version-capturing signal or every detection channel (`--allow-removed` never relaxes these), else keeps the current DB and exits non-zero |
| `sync [--osv ECOSYSTEM …]` | refreshes every configured catalog (KEV, endoflife bundle, CPE dictionary, Retire.js) and the named OSV dumps into `SIGFORGE_CACHE_DIR`, cutting each dump's index once; with `SIGFORGE_CACHE_MAX_AGE` later runs read the store with no request. `sync` puts a new copy in the store only once the parser a run reads it with accepts it and finds an entry in it — a dump, once its index is cut from it and holds an advisory; an answer that fails this (an HTML page in place of the data, JSON of another shape holding no entry, an empty body, a broken zip or one holding no advisory, a transfer broken off) fails that source, in `sources` too, and `sync` leaves the stored copy as it was |
| `sources [--max-age D]` | each source the last `sync` left (it keeps `sync-status.json` in the store): ok · FAILED with why · never synced · off; exits 1 when a source in use is failing, never synced or older than `D`, and when no source is in use (every one off: nothing was checked), naming each variable not set — an OSV dump is in use once `sync --osv` has tried it, a failed try included, and while `SIGFORGE_SOURCE_OSV_URL` is set |
| `watch --state FILE [--fail-on-new] [--package REF …] [--sbom FILE] [--wp-plugin …] [--jslib …]` | re-checks an inventory against the sources as they are now and names what changed since its last run: `NEW` (a new advisory for something in use — and, once after upgrading from a release that did not report it, an advisory the version cannot be placed against beside one it matched) and `GONE` (one an answer from the source's whole data — an OSV dump read whole — no longer lists); `UNCHECKED` when a source did not answer, or when its answer cannot rule out a recorded lead it leaves out (data it cannot prove whole — WordPress, JavaScript, an OSV dump with an unreadable entry — or a version it could not compare): the lead is kept, not reported gone; an identity with leads that is no longer in the inventory is `REMOVED` (its leads leave the state; listed again, they are `NEW`); an identity's first answer is recorded, not new — on the first run, after a run nothing answered, or for a package added later; a run after the first names one with leads `FIRST` (the first run prints one line counting what it recorded); a run no source answered for anything exits 1 and leaves an existing state file as it was — the embedded Retire.js sample is not a source: a run only it answered for (`SIGFORGE_SOURCE_RETIREJS_URL` unset, or neither the repository nor the store giving a usable copy) is such a run, records nothing the sample said and names the sample in its error; `--fail-on-new` exits 1 on a NEW lead. A distro package is keyed by its release (`ecosystem:Debian:12 openssl@3.0.11-1`); a state written before that holds one release-less key (`ecosystem:Debian openssl@3.0.11-1`), whose leads — and that it was answered before, so nothing is `FIRST` — go to each release key of a run that the state does not hold yet, and the old key leaves the state: with two releases, each takes every lead and names `GONE` once what its release does not list (from a whole answer only). A run with nothing to look up (no inventory flag, an empty `--sbom` value, an SBOM without a component carrying a usable purl) names no change, exits 1 and leaves the state file as it was. It reads the store `sync` keeps (a stored source up to a day old when `SIGFORGE_CACHE_MAX_AGE` is unset); without `SIGFORGE_CACHE_DIR` every run downloads each OSV dump whole |
| `verify FILE` / `rollback FILE` | checks a DB against its `.sha256` sidecar, schema and manifest / restores the prior valid snapshot |
| `diff OLD NEW` | what a re-sync added, removed or changed |
| `eol [--explain] TECH VERSION` · `cve [--explain] CPE VERSION` | one end-of-life / CVE lookup, with the reasoning on `--explain` |
| `inspect [--db FILE] TECH` · `match [--db FILE] [--explain]` | one fingerprint entry / match a JSON page from stdin |
| `enrich [--db FILE] [--json] [--package REF …] [--sbom FILE] [--wp-plugin slug@ver …] [--wp-theme slug@ver …] [--jslib name@ver …]` | match a page (stdin) and look up every detection and given identity (purl or `ecosystem:name@version`, CycloneDX SBOM, WordPress plugin/theme, JS library) → unified results ([`enrich-pipeline.md`](enrich-pipeline.md), [`unified-contract.md`](unified-contract.md)); with no page (stdin empty or blank) and no inventory flag (an empty `--sbom` value is none) there is nothing to look up: it exits 1 and prints no result, `--json` too. A page that matches nothing (`{}`) is still a page: `no detections` / `[]`, exit 0 |
| `coverage [--db FILE] [--json]` | how much of a DB can reach a CVE lookup or extract a version |

Every intel source is off until its `SIGFORGE_SOURCE_*_URL` is set (see
`.env.example`); an off source answers `not_checked`, never "clean".
A repeatable flag given a value that names nothing — empty, blank, or a version with no name
(`--jslib @3.1.0`), as an unset variable leaves it — is refused with the flag's name before
anything is looked up or written.

### 3.2 Keeping the sources current

Nothing runs by itself: schedule `sync` and watch `sources`. A source that did not change
answers 304 (one small request); the OSV bucket marks its files `max-age=3600`, KEV's GitHub
mirror `max-age=300`, so an hourly sync is the natural pace. With systemd (user units):

```ini
# ~/.config/systemd/user/sigforge-sync.service
[Service]
Type=oneshot
EnvironmentFile=%h/.config/sigforge/env        # SIGFORGE_CACHE_DIR, SIGFORGE_SOURCE_*_URL (SIGFORGE_CACHE_MAX_AGE optional)
ExecStart=%h/bin/sigforge sync --osv npm --osv PyPI --osv Debian
ExecStartPost=%h/bin/sigforge sources --max-age 26h
ExecStartPost=%h/bin/sigforge watch --state %h/.local/state/sigforge/watch.json --sbom %h/inventory.cdx.json --fail-on-new

# ~/.config/systemd/user/sigforge-sync.timer
[Timer]
OnCalendar=hourly
RandomizedDelaySec=10m
Persistent=true
[Install]
WantedBy=timers.target
```

`systemctl --user enable --now sigforge-sync.timer`; a failing or stale source fails the unit,
so `systemctl --user status sigforge-sync` (or any monitor reading the exit code) shows it — and so
does a new advisory for the inventory: `watch` re-checks it after each sync (an hourly OSV sync
brings in what changed within the hour), reading the store sync just filled with no request, and
fails on a NEW lead. This is how a new CVE reaches the assets it touches without a rescan.
An OSV dump already in the store is not downloaded again each hour (OSV rebuilds its dumps all
the time, so asking for one again would almost always mean its whole size): `sync` reads the head
of `<ecosystem>/modified_id.csv` down to the last record it fetched and fetches each changed
record on its own into an overlay beside the dump (measured 09/11/2026: npm 3 records in the last
hour, 13 in a day, against a 220 MB dump). Runs read the dump's index with the overlay on top. The
dump is taken whole again after a day, or when more than 500 records changed.

Without systemd, a cron line does the same: `17 * * * * . ~/.config/sigforge/env && sigforge
sync --osv npm --osv PyPI --osv Debian && sigforge sources --max-age 26h && sigforge watch --state
~/.local/state/sigforge/watch.json --sbom ~/inventory.cdx.json --fail-on-new`. Scans then set `SIGFORGE_CACHE_MAX_AGE` (e.g. `2h`) to
read the synced store with no request.

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
