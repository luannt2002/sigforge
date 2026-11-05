# Feature: Source adapters (fetch + normalize)

Package `modules/intel/source` + client `framework/fetch`.

## 1. User story

As an operator, I want to widen the published DB with third-party fingerprint data
that is too license-laden to vendor — from a source I choose, at a moment I choose —
so my scanner gets broader coverage while sigforge's own repo stays permissive and
free of third-party data.

## 2. Pre-condition

- The operator supplies a source URL (via `--fetch name=url` or the source's env
  var `SIGFORGE_SOURCE_<NAME>_URL`). Without it, the source is OFF and errors.
- The URL points at that source's own data; sigforge hardcodes no URL or vendor.

## 3. Acceptance criteria

- A `Source` has `Name()`, `License()`, `Fetch(ctx)` and a PURE `Normalize(raw)`.
- Three adapters exist, each off by default, each tagging every produced entry with
  its `provenance`, `license` and the synced `provenance_version`:
  | id | format | license | env var |
  |---|---|---|---|
  | `webappanalyzer` | Wappalyzer-schema JSON | `GPL-3.0` | `SIGFORGE_SOURCE_WEBAPPANALYZER_URL` |
  | `nuclei` | tech-detect YAML templates | `MIT` | `SIGFORGE_SOURCE_NUCLEI_URL` |
  | `whatweb` | plugins (Ruby) | `GPL-2.0-or-later` | `SIGFORGE_SOURCE_WHATWEB_URL` |
- `framework/fetch` is bounded (timeout + size ceiling) and honest (non-2xx and
  over-limit are errors, not silent truncation); it hardcodes no URL.
- Each fetch records a sync marker in `SYNC-MANIFEST.json`: one row per source =
  `{source, url, version, fetched_at, entry_count, license}`. The `version` is a
  git SHA / release tag when the URL pins one, else `unversioned@<RFC3339>` — never
  a fabricated SHA.
- `Normalize` is fixture-tested with no network; `fetch` is tested over httptest
  loopback only.

## 4. Definition of Done

- All three adapters + the fetch client + the manifest implemented and wired into
  `sigforge merge --fetch name[=url] [--manifest FILE]`.
- The merged DB and `SYNC-MANIFEST.json` are gitignored (operator-generated); no
  fetched third-party data is committed.
- `go test ./...` green; the consumer API (`baseline.DB`, `matcher.Match`,
  `schema.LoadFile`, `schema.DB`, `merge.Merge`) is unchanged.

## 5. Description

Each adapter fetches its raw bytes and normalizes them into `schema.Fingerprint`
entries. Because the schema is Wappalyzer-compatible, `webappanalyzer` is a near
direct decode; `nuclei` and `whatweb` are BEST-EFFORT extractions from formats that
do not map cleanly, so a detection stays a LEAD (the matcher already assumes this).

### 5.1 Mapping limits (honest)

- **webappanalyzer** — accepts a bare `{Tech:{...}}` map or the wrapped
  `{technologies:{...}, categories:{...}}`; a single malformed entry is dropped, not
  fatal. Highest fidelity (same schema).
- **nuclei** — only `word`/`regex` matchers on `part: header`/`part: body` are
  mapped (header `Name: value` → header pattern; else HTML substring/regex). NOT
  mapped: `status`/`dsl`/`binary`/`favicon` matchers, extractors,
  `matchers-condition: and`, `negative: true`, multi-request flow. Dropping AND/
  negative logic means an entry is an OR-set of markers and may over-match.
- **whatweb** — `:text` → HTML substring, `:regexp` → HTML regex, `:version` →
  HTML regex that also captures a version. NOT mapped: `:md5`, `:ghdb`, `:account`,
  `:filepath`, `:url`, `:tagpattern`, and `:search => "headers[...]"` routing (every
  marker is flattened to a body scan). A Ruby regex RE2 rejects is dropped at match
  time.

### 5.2 Sync marker

`SYNC-MANIFEST.json` mirrors ASIE's UPSTREAM-SYNC idea: it records which version of
each source the operator last pulled, so a future re-sync diffs against it. Rows are
upserted by source id (one per source) and sorted for a stable diff. The marker is
DATA only and honest: a source exposing no pinned ref is recorded as
`unversioned@<fetched_at>`, never a faked SHA.
