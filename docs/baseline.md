# Feature: Baseline

Package `modules/intel/baseline`, data in `data/baseline.json`.

## 1. User story

As a scanner, I want a curated fingerprint set compiled into my binary, so that I
detect the security-relevant stack offline, with zero configuration and zero
license risk, even when no external DB is present.

## 2. Pre-condition

- `data/baseline.json` is a valid DB in the current schema version.
- It is embedded via `go:embed` at build time.

## 3. Acceptance criteria

- `baseline.DB()` returns the parsed, validated set; `baseline.Bytes()` returns the
  raw JSON verbatim (for the CLI to emit).
- Every entry is authored from a public, observable fact (a `Server` header, a
  cookie name, a URL path, a meta generator, a script src) — nothing copied from a
  third-party dataset.
- Every entry carries `provenance: "baseline"` and `license: "Apache-2.0"`.
- Coverage spans the CVE/EOL-driving stack: web servers, languages, CMS, common JS
  libraries, and CDN/WAF.
- Patterns are anti-false-positive: tight enough not to over-match.

## 4. Definition of Done

- 26 technologies authored (see below), embedded and loading.
- Tests confirm the set loads, contains the expected key techs, every entry is
  stamped, and an end-to-end `Match` against a realistic page detects the stack.

## 5. Description

The baseline is the always-available source of truth. Because a `Server:` header
or a path is a fact rather than a copyrightable expression, the set ships in an
Apache-2.0 repo without relicensing anyone's data. An operator widens breadth at
runtime by merging a licensed external DB over it; on conflict the baseline wins,
because it is curated and anti-FP while the external entry is not trusted to weaken
it.

Technologies (26): **web servers** — Nginx, Apache, Microsoft IIS, LiteSpeed,
OpenResty; **languages/runtimes** — PHP, Microsoft ASP.NET, Python, Node.js,
Express, Ruby, Phusion Passenger; **CMS/e-commerce** — WordPress, Drupal, Joomla,
Magento, Laravel, Ghost; **JS libraries** — jQuery, React, Vue.js, Angular,
Bootstrap; **CDN/WAF** — Cloudflare, Akamai, Fastly.

Version regexes are included where the version is publicly observable (e.g.
`Server: nginx/1.18.0`, `<meta name=generator content="WordPress 6.5">`). Node.js
and Ruby carry no direct raw-HTTP signature and are reached via `implies` from
Express/Ghost and Phusion Passenger respectively.

### 5.1 Diagram

```
data/baseline.json ──go:embed──▶ baseline.Bytes()  ──▶ CLI `baseline`
                                      │
                                 schema.Parse + Validate
                                      │
                                 baseline.DB() ──▶ matcher.Match / merge.Merge(base, …)
```
