# Feature: Enrich (compose breadth + depth into one result)

> This is the original `Enrich` → `[]EnrichedDetection` flavour (CVE + EOL per detection), unchanged.
> The v0.4 pipeline that answers every source on the honest unified contract — packages, SBOMs, purls,
> WordPress, JS libraries, OSV, KEV/EPSS — is `EnrichUnified`: see [`enrich-pipeline.md`](enrich-pipeline.md).

Package `modules/intel/enrich`.

## 1. User story

As an operator, once a scan has a list of breadth detections (matcher) I want each
one joined with its depth intel — the CVE leads for its CPE and the end-of-life
status of its version — in a single `EnrichedDetection`, so I read one enriched
result per technology instead of cross-referencing three tools by hand.

## 2. Pre-condition

- A `[]matcher.Detection` (breadth) and the `*schema.DB` they came from (for CPE,
  categories and provenance).
- Optionally the depth providers, both **operator-gated and nil-able**: a
  `*cve.Adapter` and a `*lifecycle.Adapter` (or any value satisfying
  `enrich.CVEProvider` / `enrich.EOLProvider`). A nil provider means that depth
  layer is OFF. The providers are **injected**, so the composition is pure and tests
  wire fakes — no network lives in `enrich`.

## 3. Acceptance criteria

- `Enrich(ctx, dets, db, opt) → []EnrichedDetection` where

  ```go
  type EnrichedDetection struct {
      Tech       string
      Version    string
      Confidence int
      Provenance []string          // DISTINCT sources that attested the tech; len is the corroboration
      Categories []int
      CPE        []string          // from the DB entry
      CVEs       []cve.CVE         // attached only when the CVE provider is set
      EOL        lifecycle.Status  // attached only when the EOL provider is set
  }
  ```

- For each detection: CPE / categories / provenance come from the DB entry; if the
  CVE provider is set, `cve.Lookup(cpe, version)` is called per CPE and its leads are
  attached; if the EOL provider is set, `lifecycle.EOLStatus(tech, version)` is
  attached. **Corroboration** = the count of distinct provenance sources for that
  tech (detections of the same tech from different sources collapse into one result
  whose `Provenance` records each).
- **Honesty.** A nil/off provider leaves its field UNKNOWN — `CVEs` stays `nil`
  (which is "no leads attached", never "no CVE = safe") and `EOL.IsEOL` stays
  `lifecycle.StateUnknown` (never "supported"). A provider that errors (feed off,
  fetch failure) leaves the field UNKNOWN too, rather than failing the whole run.
- Pure composition: no network in the package; the depth lookups are injected.

## 4. Definition of Done

- `modules/intel/enrich` implemented; fixture test proves: providers set → both CVE
  and EOL attached; providers nil → both UNKNOWN; two provenances for one tech →
  corroboration ≥ 2.
- Consumer API of `matcher` / `schema` / `cve` / `lifecycle` unchanged — `enrich` is
  additive and only consumes their existing exported shapes.
- `go test ./...` green.

## 5. Description

`Enrich` groups the incoming detections by tech (so the same tech attested by
several sources becomes one result), takes the max confidence and the longest
version seen, and collects the distinct provenance strings as the corroboration
signal. It then reads CPE and categories from the DB entry and, only for the
providers that are set, calls into the depth layers.

### 5.1 Why injection

The real depth adapters (`*cve.Adapter`, `*lifecycle.Adapter`) hit operator-supplied
feeds over the network. `enrich` depends on the two small interfaces instead, so the
composition is deterministic and testable with fakes, and the operator's feed gating
(off by default, no hardcoded URL) is unchanged — a nil provider is simply "off".

### 5.2 Honesty limit

`EnrichedDetection.CVEs` is a flat `[]cve.CVE`; it cannot distinguish "feed off /
not checked" from "feed checked, nothing found" — both appear as `nil`. That
tri-state lives in `cve.Result.State` at the layer below; the flattening here is
deliberate (the struct the consumer asked for), and `nil` is never rendered as
"safe". When the distinction matters, call `cve.Lookup` directly and read `State`.
`EOL` keeps its own tri-state (`lifecycle.Status.IsEOL`), so absence there stays
honest at the enrich layer.
