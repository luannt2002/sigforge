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

- A technology whose header/cookie/meta/html/scriptSrc pattern matches is returned.
- A captured version (`\;version:\1`) is populated when the matching pattern
  provides one.
- Confidence is the sum of matched patterns' confidences, each defaulting to the
  pattern's `\;confidence:N`, else the entry's declared confidence, else 100,
  capped at 100.
- `implies` relations are expanded (WordPress ⇒ PHP), and an implied technology is
  never more confident than the one that implied it.
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
failing the set. After per-entry matching it expands `implies` with a depth bound,
then emits sorted `Detection`s carrying each entry's `provenance` and `license` so
the operator knows the license posture of every lead.

Honesty: a detection is a LEAD. Banner/meta versions are attacker-controllable.
The schema's `dom` rules are carried through for browser-backed consumers but are
not evaluated here (raw-HTTP layer).

### 5.1 Diagram

```
page ─┬─ headers ──▶ lower(name)→values ─┐
      ├─ cookies ──▶ name→values ────────┤
      ├─ html ─────▶ meta name→content ──┼─▶ for each fingerprint:
      └─ scriptSrcs ──────────────────────┘     match patterns → (conf += , version = longest)
                                                       │
                                                 expand implies (depth-bounded)
                                                       │
                                                 refine version from version_regex (if detected, missing)
                                                       ▼
                                   []Detection{Tech,Version,Confidence,Categories,Provenance,License}
                                        sorted by confidence desc, then name
```
