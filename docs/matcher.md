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
- A blank page yields zero detections (no false positives), and so does every
  hard-negative page of the accuracy corpus on the baseline set.
- A `dom` rule is read from the page's start tags, never from prose, comments or the
  text inside `<script>`/`<style>`: every test of a selector compound must hold on
  one start tag, and an attribute pattern runs on that attribute's value.
- Two limits are deliberate: relations between compounds (descendant, child,
  sibling) are not checked, and a `text` pattern is not evaluated.
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
The schema's `dom` rules are evaluated passively (see `matcher_dom.go`) against the
page's start tags, with no real DOM. A start tag is its name and attributes,
valueless ones included; a `>` inside a quoted value does not end it; comments and
the text inside `<script>` and `<style>` are not tags. That text runs to its own end
tag — the name in any case, then whitespace, `/` or `>`, so `</scripts>` is still
text — or to the end of the page. A selector splits into
comma-separated branches and each branch into compounds
(`div#id.cls[attr op "value" i]`, op one of `= ~= |= ^= $= *=`). A compound matches
a start tag when all its tests hold on that one tag: tag and attribute names ignore
case; ids, classes and values do not, except a value test that carries ` i`. A
branch with a pseudo-class other than a structural one (`:first-child`, `:nth-*`, …)
or a pseudo-element — `:not()`, `:has()`, … — never fires.

- An attribute pattern is a regex (unanchored, case-insensitive, as in Wappalyzer)
  over that attribute's value on a tag the branch's last compound matches, and needs
  every other compound to match a tag too (`<app-root ng-version="16.2.0">` →
  Angular 16.2.0). The same text in prose, in an XML prolog or on another tag is
  not that attribute.
- `exists`, a list or string selector (with its `\;confidence:N`), an empty attribute
  pattern and a node with no pattern are presence tests. A branch needs at least
  one literal: an attribute value of four or more characters (CSS escapes removed),
  an id/class of six or more characters or with `-`/`_`, or a tag/attribute name
  with `-`/`_` — the attribute an empty pattern names counts. All its literals must
  be in the raw HTML, a cheap filter before tags are read, and each compound must
  match a start tag; an empty pattern's attribute must sit on the last compound's
  tag (`#vite-legacy-polyfill` → Vite). A plain tag or attribute name (`script`,
  `content`) is never a literal, so a branch naming nothing else never fires.
- JS runtime `properties` are ignored: a node carrying only them is a presence test
  of its selector.

Two limits are deliberate. Relations between compounds are not checked — raw HTML is
not parsed into a tree, so `h2 + p` only means "an h2 and a p are on the page" and
can fire where a browser would not. A `text` pattern needs the element's own text, so
it is not evaluated and a rule built on it is missed. A browser-backed consumer can
still read `Fingerprint.Dom` itself.

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
