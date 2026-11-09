# Feature: CVE lookup (CPE + version → known CVEs)

Package `modules/intel/cve` + CLI `sigforge cve`.

## 1. User story

As an operator, once a scan detects a technology *with a CPE and a version* I want
the known CVEs the vulnerability feed attests for that exact CPE at that version — so
a detection like "nginx 1.18.0 (cpe f5:nginx)" becomes an actionable risk lead
("CVE-2021-23017, CVSS 7.7 HIGH") instead of a bare fact.

## 2. Pre-condition

- The operator supplies the CVE API base URL via env `SIGFORGE_SOURCE_CVE_URL`
  (e.g. `https://services.nvd.nist.gov/rest/json/cves/2.0`). Without it the feed is
  OFF and `sigforge cve` errors. No URL is hardcoded anywhere in the code.
- A CPE the SOURCE attested (carried on `schema.Fingerprint.CPE`, populated only from
  a source's real `cpe` value) and a detected version. The version is whatever a
  scanner reported and is **spoofable** (a forged `Server` banner), so every returned
  CVE is a LEAD, not proof.

## 3. Acceptance criteria

- `Adapter.Lookup(ctx, cpe, version) → Result{CPE, Version, State, CVEs}` where
  `CVEs` is `[]CVE{ID, CVSS float64, Severity, Source}` and `State` is the tri-state:
  - **StateUnknown** — feed off, or no CPE to query. *Not checked — never "no CVEs".*
  - **StateNoKnownCVE** — the feed WAS queried and listed nothing for this
    CPE+version. *A LEAD-negative, NOT a safety guarantee.*
  - **StateHasCVE** — the feed returned one or more CVE leads.
- An empty CPE returns `StateUnknown` with a nil error (a legitimate "no CPE to
  bridge"); a feed that is off and fetch/decode failures return `StateUnknown` with
  an error the operator must see. A bare "0 CVEs" is **never** emitted as "safe".
- The query uses the CPE **exactly as stored** (its vendor:product, e.g. `f5:nginx`)
  with only the version component filled in — never a guessed `vendor:product`.
- CVSS and Severity are taken verbatim from the feed, never fabricated.
- `Parse(raw)` is PURE (no network) and fixture-tested against a recorded NVD CVE API
  2.0 sample; the feed URL is operator-supplied, off by default. A body without
  `totalResults` is not an NVD CVE API answer (`{}`, `null`, an error object): it is a
  failed lookup, never an empty one. When `totalResults` exceeds the CVEs returned,
  the result says "partial: N of M" (one page of a paged feed).
- `ToUnified` maps a result onto the unified contract: CVEs → `affected_by_advisory`
  leads (`potentially_affected` without a version); **no CVE → `not_checked` with
  the reason** — a paged per-query API cannot prove a miss complete, so it is never a
  clearance (see `docs/unified-contract.md`).
- `sigforge cve CPE VERSION` prints the leads (or the honest not-checked / no-known
  line); unset env errors with a hint.

## 4. Definition of Done

- `modules/intel/cve` implemented and wired into `sigforge cve`.
- Unit tests use fixtures only (no internet); adapter wiring is tested over an
  `httptest` loopback, matching how the repo's fetch adapters are tested.
- No feed data is committed: `cve` prints to stdout; with `SIGFORGE_CACHE_DIR` set each
  query's response is kept in the operator's local store (gitignored, never pruned —
  a known limit), and `.gitignore` excludes `.cache/` and `*.merged.json`.
- `go test ./...` green; consumer API (`baseline.DB`, `matcher.Match`,
  `schema.LoadFile`, `merge.Merge`) unchanged — this feature is purely additive.

## 5. Description

The NVD CVE API 2.0 answers a CPE query at `<base>?virtualMatchString=<cpe>`, where
NVD matches the CPE (version and all) against each CVE's configured version ranges
and returns `{vulnerabilities:[{cve:{id, metrics:{…}}}]}`. `Lookup` fills the detected
version into the stored CPE's version field (`withVersion`), queries the feed, and
hands the body to `Parse`.

`Parse` reads only each CVE's `id` and CVSS metrics. For each CVE it takes the
highest-precedence metric present — v4.0 → v3.1 → v3.0 → v2.0 — and reads
`cvssData.baseScore` for CVSS and the severity from `cvssData.baseSeverity` (v3/v4) or
the metric-level `baseSeverity` (v2). A CVE with no CVSS metric is still reported,
with a zero CVSS and empty severity, rather than dropped.

### 5.1 Honesty (the controlled part)

The detected version is spoofable and a CPE tracks only the vendor:product the source
attested, so the verdict is a LEAD tied to a claim, never a fact. Absence is never
upgraded to "safe": `StateUnknown` (zero value) means *not checked*; `StateNoKnownCVE`
means *the feed listed nothing, which is still not a guarantee* — CPE mapping, NVD
coverage and the version claim are all fallible — and on the unified contract it is
`not_checked`, never `not_affected_by_advisory`. The CLI spells this out on every
line it prints.

### 5.2 Why NVD-by-CPE, not OSV

OSV is keyed by package ecosystem + package name (npm, PyPI, Go modules, …), not by
CPE. It cannot answer "what CVEs apply to this web-tech CPE". NVD's CPE applicability
is the right source for the CPE ids sigforge's fingerprints carry. Only the URL and
endpoint are operator config — the code hardcodes no vendor or URL; it only knows the
NVD CVE API 2.0 response shape it was designed for.

### 5.3 Real-API verification (one-off, not in `go test`)

Verified live against `https://services.nvd.nist.gov/rest/json/cves/2.0` on
2026-11-04, via the `sigforge cve` binary:

| cpe (vendor:product) | version | state | CVEs seen |
|---|---|---|---|
| `cpe:2.3:a:f5:nginx` | 1.18.0 | **has-cve** | CVE-2021-23017 (7.7 HIGH), CVE-2021-3618 (7.4 HIGH), CVE-2022-41741 (7.0 HIGH), CVE-2022-41742 (7.1 HIGH), CVE-2023-44487 (7.5 HIGH), CVE-2025-23419 (5.3 MEDIUM) |
| `cpe:2.3:a:f5:nginx` | 1.27.4 | **no-known-cve** | (none — patched; honestly not reported as "safe") |

CVE-2021-23017 (the nginx resolver off-by-one) appears with its real CVSS 3.1 base
score **7.7 HIGH** exactly as the task predicted; CVSS/Severity/Source are the feed's
own values, unmodified.

### 5.4 NVD rate limit / API key

The public NVD API rate-limits anonymous callers (~5 requests per 30 seconds; ~50
with a free API key). NVD takes the key in an `apiKey` request header, which the
bounded `framework/fetch` client does not inject, so an operator who needs the higher
limit should point `SIGFORGE_SOURCE_CVE_URL` at a gateway/proxy that adds the header
(or a mirror that carries the key) — adding header support to `fetch` is a future
step if a direct-key path is wanted. A single lookup stays well within the anonymous
limit; a batch sweep is what would trip it.

### 5.5 Limits

- `virtualMatchString` matching is only as good as the CPE: a stored CPE whose
  vendor:product does not match the feed's NVD mapping returns nothing (honestly
  `no-known-cve`, never a false negative dressed as "safe").
- Only the single highest-precedence CVSS metric per CVE is surfaced; the full vector
  string, references and configuration ranges are intentionally not read.
