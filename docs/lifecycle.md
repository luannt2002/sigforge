# Feature: Lifecycle / EOL (version → end-of-life)

Package `modules/intel/lifecycle` + CLI `sigforge eol`.

## 1. User story

As an operator, once a scan detects a technology *and a version* I want to know
whether that version is still maintained or past its vendor end-of-life — so a
detection like "PHP 7.2" becomes an actionable risk lead ("PHP 7.2 reached EOL on
2020-11-30") instead of a bare fact.

## 2. Pre-condition

- The operator supplies the feed's base URL via env `SIGFORGE_SOURCE_ENDOFLIFE_URL`
  (e.g. `https://endoflife.date/api`, one request per product), or the one-document
  bundle via `SIGFORGE_SOURCE_ENDOFLIFE_BUNDLE_URL` (the v1 `products/full` list:
  every product in one request, and a technology without a name mapping is found by
  its CPE). The bundle takes precedence. Without either the feed is OFF and
  `sigforge eol` errors for a tracked product. No URL is hardcoded anywhere in the code.
- A detected version string. It is whatever a scanner reported and is **spoofable**
  (a forged `Server` header), so every verdict is a LEAD, not proof.

## 3. Acceptance criteria

- A `tech → endoflife.date product` map authored from PUBLIC FACTS (currently 23
  baseline techs: Nginx, Apache, Apache Tomcat, PHP, Python, Node.js, Ruby, Django,
  Rails, Laravel, Symfony, WordPress, Drupal, Joomla, Magento, TYPO3, Vue, Angular,
  Bootstrap, jQuery, Next.js, Nuxt, ASP.NET Core). A tech endoflife.date does not
  track (CDNs, SaaS) is deliberately absent.
- `Adapter.EOLStatus(ctx, tech, version) → Status{Product, Version, Cycle, EOLDate,
  IsEOL}` where `IsEOL` is the tri-state `State`:
  - **StateUnknown** — unmapped product, unmatched cycle, feed off, or a verdict the
    data does not settle (see 5). *Never "supported" on absence.*
  - **StateSupported** — the version's own cycle has `eol` `false` or a future date,
    and that cycle vouches for its other versions (see 5).
  - **StateEOL** — the version's own cycle has `eol` `true` or a date in the past.
- Unknown product / unmatched cycle return `StateUnknown` with a nil error (a
  legitimate "we don't track this"); feed-off and fetch/decode failures return
  `StateUnknown` with an error the operator must see.
- `Classify(cycles, version, now)` is PURE (no network) and fixture-tested; the
  feed URL is operator-supplied, off by default.
- `sigforge eol TECH VERSION` prints the status; unset env errors with a hint.
- `ToUnified` maps a status onto the unified contract: EOL → `affected_by_advisory`
  (a lead), supported → `not_checked` with `unified.NoteNoClearance` (v0.4 issues no
  clearance; see `docs/unified-contract.md`), every
  unknown → `unknown_product` / `unknown_version` (see `docs/unified-contract.md`).

## 4. Definition of Done

- `modules/intel/lifecycle` implemented and wired into `sigforge eol`.
- Unit tests use fixtures only (no internet); adapter wiring is tested over an
  `httptest` loopback, matching how the repo's fetch adapters are tested.
- No feed data is committed: `eol` prints to stdout; with `SIGFORGE_CACHE_DIR` set the
  fetched bundle is kept in the operator's local store (labelled snapshot/stale), which
  is gitignored.
- `go test ./...` green; consumer API unchanged.

## 5. Description

endoflife.date serves one JSON array of release cycles per product at
`<base>/<product>.json`: `[{cycle, eol (date|bool), latest, ...}]`. `EOLStatus`
maps the tech to a product, fetches that product's cycles via the operator feed,
and hands them to `Classify`.

`Classify` finds the cycle a version belongs to — a version belongs to cycle `C`
when it equals `C` or begins with `C.` (endoflife cycles are version prefixes, so
`7.2` owns `7.2.34`; a cycle name is trimmed and a `v` before a digit dropped) — and,
of the cycles it belongs to, takes the **longest**: a feed lists a coarse line
(`2`) beside its own sub-lines (`2.346`), so Jenkins 2.346.1 is judged by `2.346`,
not by `2`. It then judges that cycle's `eol`:

- bool `false` → supported · bool `true` → eol
- date past `now` → eol · future/today date → supported
- missing / uninterpretable → unknown

and keeps the verdict unknown when the data does not settle it:

- one cycle listed twice with opposite verdicts;
- a **supported** cycle that has sub-lines of its own (a supported coarse line whose
  sub-lines end on their own — Jenkins `2`, log4j `2` — does not vouch for its other
  versions), or that sits beside a row that cannot be read (null, nameless). An ended
  cycle with sub-lines still ends the versions its sub-lines do not cover (.NET
  Framework `4.6` ended, `4.6.2` supported → 4.6.1 is eol).

The bundle's releases become the same cycles: `eolFrom` (a date) decides, unless it
would reopen a release whose `isEol` is `true` (then eol stays `true`); a release
stating neither `isEol` nor `eolFrom` is unknown; a product listed twice is read as
one list, so a release the two lists disagree on is unknown.

### 5.1 Honesty (the controlled part)

The detected version is spoofable, so the verdict is a LEAD tied to a claim, never
a fact — stated in the package doc and surfaced as "unknown" wherever the feed,
product or cycle does not actually say otherwise. Absence is never upgraded to
"supported".

### 5.2 License

endoflife.date's data and code are **MIT**-licensed
(`github.com/endoflife-date/endoflife.date`, tagged `License = "MIT"` on the
adapter). Only the `cycle`/`eol`/`latest` fields are consumed; the product prose
(Wikipedia-derived, CC BY-SA) is not read. Fetched responses are operator-generated
and never vendored into this repo — same posture as the fetch sources.

### 5.3 Real-API verification (one-off, not in `go test`)

Verified live against `https://endoflife.date/api` on 2026-11-04:

| tech | version | product | cycle | eol | status |
|---|---|---|---|---|---|
| PHP | 7.2.34 | php | 7.2 | 2020-11-30 | **eol** |
| PHP | 8.3.1 | php | 8.3 | 2027-12-31 | supported |
| Nginx | 1.29.0 | nginx | 1.29 | 2026-05-13 | **eol** |
| WordPress | 6.7 | wordpress | 6.7 | false | supported |
| Apache | 2.2.0 | apache-http-server | 2.2 | 2017-07-11 | **eol** |
| ASP.NET Core | 3.1 | dotnet | 3.1 | 2022-12-13 | **eol** |
| Cloudflare | 1.0 | — | — | — | unknown (untracked) |

### 5.4 Limits

- Cycle matching is prefix-based; a release whose name is not a version prefix
  (`4.9-lts`) does not match and honestly reports `unknown` — 316 of the 6,939
  releases in the live bundle (checked 06/11/2026). A version that prefix-matches a
  neighbouring cycle instead (mulesoft 4.9.16 matches `4.9`, not `4.9-lts`) can carry
  that cycle's verdict: an eol lead may be wrong; a false "supported" was not seen —
  each release's latest version classified against its product's whole list in the
  live bundle gave 0 false "supported".
- ASP.NET Core maps to `dotnet` (ASP.NET Core ships in and shares the .NET support
  lifecycle); a pre-.NET-5 ASP.NET Core version outside the `dotnet` cycles reports
  `unknown` rather than guessing.
