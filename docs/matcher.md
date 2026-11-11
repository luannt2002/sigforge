# Feature: Matcher

Package `modules/intel/matcher`.

## 1. User story

As a scanner, I want to apply a fingerprint set to one HTTP response — its
headers, cookies, HTML, meta tags and script srcs — and get back the technologies
(with versions and confidence) it points to, so that I can drive CVE/EOL lookups.

## 2. Pre-condition

- A validated `*schema.DB` is in hand (from `baseline.DB()` or `schema.LoadFile`).
- The page's raw HTTP data is available: header map, cookie strings, body HTML,
  script srcs. No browser/DOM is required.

## 3. Acceptance criteria

- A technology whose header/cookie/meta/html/scriptSrc pattern matches is returned,
  subject to the `requires` / `requiresCategory` gate below.
- A captured version (`\;version:\1`) is populated when the matching pattern
  provides one.
- Confidence is the sum of matched patterns' confidences, each defaulting to the
  pattern's `\;confidence:N`, else the entry's declared confidence, else 100,
  capped at 100.
- `implies` relations are expanded (WordPress ⇒ PHP), and an implied technology is
  never more confident than the one that implied it.
- `requires` / `requiresCategory` gate a technology's own pattern match: it counts only
  once one of its required techs, or a tech in one of its required categories, is
  resolved (detected or implied) — any one of them suffices, as in Wappalyzer. The match
  never resolves its own requirement; once another resolved tech implies the technology,
  though, the techs it implies and its own categories do meet the gate. A gated
  technology that another resolved tech implies is returned even when its requirement is
  not resolved, as an implied detection: no evidence or version from its held-back match.
- `excludes` never removes a detection: the excluded tech stays, labeled `excludedBy`
  with the resolved techs (detected or implied) that exclude it.
- A tech present only through other techs — implied by them, or admitted by a
  `requires` / `requiresCategory` gate they meet — carries all their labels, over any
  number of steps, unless one of those techs is unlabeled and present on its own or
  through unlabeled techs. A tech with its own ungated match never inherits a label, and a
  tech never labels itself: an edition that requires and excludes its base stays unlabeled.
- A script-src pattern must not fire on its letters embedded mid-filename in a
  hashed bundle (token-boundary guard).
- A blank/irrelevant page yields zero detections (no false positives).
- `version_regex` alternates refine the version of an already-detected tech but can
  never, alone, create a detection.
- Output is sorted by confidence descending, then by name. The function is pure.

## 4. Definition of Done

- `matcher.Match(db, page) []Detection` implemented, pure, no network.
- Table tests cover: header version capture + provenance passthrough, implies,
  script-src boundary guard (positive and negative), cookie presence, blank-page
  no-FP, version_regex refine-only, confidence suffix. All green.

## 5. Description

`Match` lowercases header names, parses cookies into a name→values map, and
extracts `<meta>` tags from the HTML. For each fingerprint it runs the entry's
patterns against the matching evidence, accumulating confidence and the longest
captured version. Patterns are split on the `\;` suffix syntax into
(regex, version-template, confidence); a regex RE2 rejects is dropped rather than
failing the set. After per-entry matching it admits the `requires`-gated entries whose
requirement is resolved (expanding `implies` with a depth bound each round), labels
`excludes` (`excludedBy`, never a removal), then emits sorted `Detection`s carrying each
entry's `provenance` and `license` so the operator knows the license posture of every lead.

Honesty: a detection is a LEAD. Banner/meta versions are attacker-controllable.
The schema's `dom` rules are evaluated passively (see `matcher_dom.go`): with no
real DOM, a selector's distinguishing token and its attribute/text patterns are
tested as substrings/regexes over the raw HTML (e.g. `ng-version` → Angular+version,
`#vite-legacy-polyfill` → Vite). This is an approximation, not a DOM query, so a
rule depending on element structure or JS runtime `properties` can be missed; a
browser-backed consumer can still read `Fingerprint.Dom` itself.

### 5.1 Diagram

```
page ─┬─ headers ──▶ lower(name)→values ─┐
      ├─ cookies ──▶ name→values ────────┤
      ├─ html ─────▶ meta name→content ──┼─▶ for each fingerprint:
      └─ scriptSrcs ──────────────────────┘     match patterns → (conf += , version = longest)
                                                       │
                                                 resolve requires + expand implies (depth-bounded) · label excludes
                                                       │
                                                 refine version from version_regex (if detected, missing)
                                                       ▼
                                   []Detection{Tech,Version,Confidence,Categories,Provenance,License}
                                        sorted by confidence desc, then name
```
