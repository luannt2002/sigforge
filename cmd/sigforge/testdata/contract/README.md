# Contract fixtures

What `sigforge enrich --json` prints for the cases a consumer must tell apart. Each `N-*.json` holds the command's
arguments, the names of the variables it set (never their values), its exit code, its error when it failed, and the
results it printed (`[]unified.Result`, see `docs/unified-contract.md`). A consumer can mirror them to check its own
reading of the contract.

| fixture | case | what it shows |
|---|---|---|
| `1-nothing-to-look-up` | no page, no inventory flag | exit 1, no result — never an empty list read as quiet |
| `2-source-off` | OSV not configured | `not_checked` / `source_off` |
| `3-source-error` | OSV answers 500 | `source_unavailable` / `source_error` |
| `4-not-in-source` | a package the dump does not list | `unknown_product` / `not_in_source` |
| `5-version-unreadable` | a version npm's order cannot read | `potentially_affected` / `version_unreadable`, the version kept, the product's advisory as a lead |
| `6-advisory-match` | a version inside an advisory range | `affected_by_advisory`, no reason — still a lead, never proof |
| `7-no-clearance` | the whole dump read, nothing matched | `not_checked` / `no_clearance` — never "not affected" |
| `8-stale-stored-copy` | the source fails, a stored copy answers | the stored answer with `freshness: stale` and why in `error` |
| `9-kev-from-sample` | KEV not configured | `kev: sample` — `known_exploited` absent means "not in the sample", not "not exploited" |
| `10-version-conflict` | the page claims two versions (`conflict-db.json`) | a CVE hit downgraded to `potentially_affected` / `version_conflict`, the lead kept |
| `11-distro-build` | the banner shows a distro's package build (`Apache/2.4.6 (CentOS)`) | a CVE hit downgraded to `potentially_affected` / `distro_build`, the lead kept, `distro: CentOS` |
| `12-edge-layer` | a CDN in front (`CF-RAY`, `Server: cloudflare`) and `X-Powered-By: PHP/7.4.3` | Cloudflare's results carry `layer: edge`; PHP's keep their state and say the header may be the edge's — no `layer`, never `origin` |

Cases 2–7 each carry their own (`state`, `reason`) pair. The sources are local stand-ins started by the test; their
address is written `http://source.test`, and `fetched_at` is written `2000-01-01T00:00:00Z` (the real value is when the
data that answered was fetched — by this run for a live answer, earlier for the stored copy of case 8). `TestContractFixtures` regenerates the output and compares it with these files; `TestContractFixturesRoundTrip`
checks that each one reads back into `unified.Result` and writes out byte for byte, and that none is clean or unconcluded
without a reason. After a deliberate change of output, review it and rewrite the files with
`go test ./cmd/sigforge -run TestContractFixtures -args -update-contract`.
