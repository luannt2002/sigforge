# Feature: Accuracy harness (prove the value is CORRECT)

Package `modules/intel/accuracy`.

## 1. User story

As an operator I do not just want sigforge to emit detections and enrichments — I
want evidence they are **correct**: that detection does not invent technologies
(precision) or miss the ones that are there (recall), that the CVE/EOL parsers read
the real authoritative shapes, and that known mimics do not fool it. The harness
measures this on recorded fixtures, so a regression breaks a test instead of
silently mis-scoring a scan.

## 2. Pre-condition

- The embedded `baseline` DB (for the golden set and adversarial negatives).
- Recorded, OFFLINE fixtures only: golden HTTP responses with known-true techs, a
  minimal NVD CVE excerpt, a minimal endoflife.date php excerpt. No internet in
  `go test` — the one network-shaped path (`cve.Lookup`) runs over an `httptest`
  loopback serving the recorded fixture, as the `cve`/`lifecycle` tests already do.

## 3. Acceptance criteria — the MEASURED numbers

Run `go test ./modules/intel/accuracy/... -v` to see them printed.

- **Golden set** (4 recorded cases: nginx+WordPress+jQuery, a clean minimal site,
  the Apache-Coyote negative, a PHP site). Scored with `matcher.Match` against the
  known-true techs (implied techs included):

  | metric | measured | gate |
  |---|---|---|
  | precision | **1.000** (TP=42, FP=0) | **must be 1.0** — a false positive is a correctness bug |
  | recall | **1.000** (FN=0) | **must be ≥ 0.90** (documented floor `recallFloor`) |

  Measured over **24 positive fixtures + 6 hard-negatives**, reported **per technology**
  with an explicit coverage line (currently **29 / 58 baseline techs have a fixture**;
  the 29-tech gap is printed, not hidden). The 1.000 figures mean the matcher recognises
  its own baseline signatures with no cross-firing — they are NOT an estimate of accuracy
  on live web traffic; read them together with the coverage line.

  Precision is held hard at 1.0; recall has a floor so a future fixture that exposes
  a legitimately hard-to-detect tech does not falsely fail the gate.

- **Oracle pairs** (recorded authoritative JSON, parser locked to the real shape):
  - `cve.Lookup(cpe:…:f5:nginx, 1.18.0)` over the recorded NVD fixture →
    `StateHasCVE`, one lead **CVE-2021-23017, CVSS 7.7, HIGH**.
  - `lifecycle.Classify(php feed, "7.2.34")` → cycle **7.2**, eol **2020-11-30**,
    **StateEOL**.

- **Adversarial negatives** — the 6 hard-negative cases all assert NO false detection:
  - Apache-Coyote banner → **not** detected as Apache HTTP Server (Tomcat is fine).
  - `ng-version` in body text, not an attribute → **not** Angular.
  - `/static/xjquery.js` substring mimic → **not** jQuery.
  - a clean site, an SPA shell with a hashed bundle, and `Powered by nginx` in a footer
    (banner outside the `Server` header) → **nothing** fired.

- **Corroboration** — one tech attested by two source fixtures → enriched
  `Provenance` count **≥ 2**.

## 4. Definition of Done

- `modules/intel/accuracy` implemented: `Score` (precision/recall math, unit-tested)
  plus the harness test suite. All assertions green; numbers printed.
- Everything offline; only MINIMAL recorded oracle excerpts committed (one 1-CVE NVD
  sample, one 1-cycle endoflife sample) — tiny factual excerpts for testing.
- Consumer API unchanged; the harness only reads existing exported shapes.

## 5. Description

`Score.Add(detected, truth)` folds one run into a TP/FP/FN tally (de-duping detected
names); `Precision` and `Recall` are the usual ratios, with an empty-vs-empty run
scoring 1.0 (a clean site correctly yields nothing). The golden test aggregates all
cases into one micro-averaged score. The oracle test exercises the full `cve.Lookup`
path (loopback) and the pure `lifecycle.Classify`, so the parsers stay pinned to the
shapes NVD and endoflife.date actually emit.

### 5.1 Why recorded, not live

Live feeds drift and need the network; a unit suite must be deterministic and
offline. The fixtures are the contract. Drift in the live feed shape is caught by the
periodic spot-check below, not by `go test`.

### 5.2 LIVE spot-check (periodic, NOT in `go test`)

Run this by hand every so often (and after an NVD/endoflife schema announcement) to
catch drift the offline fixtures cannot — this is how the real Apache-Coyote
over-match was first caught. It needs the network and the operator feeds set.

```sh
# 1. CVE oracle — expect CVE-2021-23017 (CVSS 7.7 HIGH) among the leads.
export SIGFORGE_SOURCE_CVE_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
go run ./cmd/sigforge cve 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*' 1.18.0

# 2. EOL oracle — expect product=php cycle=7.2 eol=2020-11-30 status=eol.
export SIGFORGE_SOURCE_ENDOFLIFE_URL=https://endoflife.date/api
go run ./cmd/sigforge eol PHP 7.2.34

# 3. EOL negative control — a current cycle must report supported, never unknown-by-accident.
go run ./cmd/sigforge eol PHP 8.3.1
```

If a live result no longer matches the oracle value, the authoritative shape changed:
update the recorded fixture in `accuracy_test.go` (and the `cve`/`lifecycle` parsers
if the field moved) so the offline gate reflects reality again.

### 5.3 Limit

The golden set is small and hand-built, so recall==1.0 reflects these cases, not the
whole web. It is a regression floor and a correctness proof for the shapes sigforge
claims to handle, not a population estimate. Grow the golden set as new baseline
techs are added.
