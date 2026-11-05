# Feature: DB diff (what a re-sync changed)

Package `modules/intel/diff` + CLI `sigforge diff`.

## 1. User story

As an operator, after I re-run `merge --fetch` I want to see exactly which
technologies the new DB added, removed or changed versus the previous DB — so a
third-party source update is a reviewed delta, not a silent swap I have to trust.

## 2. Pre-condition

- Two DB files on disk that `schema.LoadFile` accepts (a merged output, the
  baseline, or any operator DB). The previous DB is whatever the operator kept
  before re-syncing; the `SYNC-MANIFEST.json` records which source versions
  produced it.

## 3. Acceptance criteria

- `Diff(old, new *schema.DB) Result` returns three stable-sorted name lists:
  `Added` (in new, not old), `Removed` (in old, not new), `Changed` (in both, but
  the fingerprint differs — markers, provenance/version, license or confidence).
- A nil DB is treated as the empty set, so diffing against a missing previous DB
  reports everything as added.
- `Result.Empty()` is true iff the two fingerprint sets are identical; in
  particular `Diff(A, A)` is empty.
- `sigforge diff OLD.json NEW.json` prints a one-line count summary plus the three
  lists, and always exits 0 — it is a report, not a gate.
- Pure and in-domain: no network, no third-party data, no state.

## 4. Definition of Done

- `modules/intel/diff` implemented and wired into `sigforge diff`.
- Table-tested with fixtures (added / removed / changed-by-version /
  changed-by-marker / identical / nil-old / mixed-sorted) and a `Diff(A, A)`
  identity test.
- `go test ./...` green; the consumer API (`baseline.DB`, `matcher.Match`,
  `schema.LoadFile`, `schema.DB`, `merge.Merge`) unchanged.

## 5. Description

`Diff` is a set comparison over the two DBs' `Fingerprints` maps. A technology is
`Changed` when it exists in both DBs but its `schema.Fingerprint` is not
`reflect.DeepEqual` — which captures *any* field difference: a marker edit, a
bumped `provenance_version` from a re-sync, a license change, or a confidence
change. This is deliberately a superset of "markers differ": the diff never
under-reports a change.

Lists are sorted so identical inputs always print identically (stable for a
review diff). The CLI summary reads e.g.:

```
diff old.json → new.json: +1 added, -1 removed, ~1 changed
  added    NewTech
  removed  Caddy
  changed  Nginx
```

### 5.1 Why `reflect.DeepEqual`

The alternative — hand-comparing selected fields — would silently miss a field
added to `schema.Fingerprint` later. `DeepEqual` over the whole struct stays
correct as the schema grows, at the cost of flagging cosmetic-only changes
(there are none in a stable schema). Honest over clever.

### 5.2 Limits

The diff reports *that* a technology changed, not *which field*. Field-level
reporting was not built — the operator opens the two entries when a name shows up
in `changed`, which is rare per re-sync. Upgrade the `Result` to carry per-field
reasons only if a review workflow needs it.
