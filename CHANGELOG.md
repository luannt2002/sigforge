# Changelog

## v0.5.0

v0.5.0 adds monitoring of an inventory between syncs (`watch`, `sources`), new lookups (WordPress core, CVE by ID,
detected platforms in OSV, JavaScript libraries from a script) and keeps a good stored copy when a source answers
with junk. No exported declaration of v0.4.0 was removed or given another type (`merge.EngineVersion` holds "0.5.0");
the changes in meaning we know of are listed under "Consumer API".

### New
- `sigforge watch --state FILE` re-checks an inventory (`--package`, `--sbom`, `--wp-plugin`, `--wp-theme`, `--jslib`)
  and prints what changed since its last run: `NEW`, `GONE`, `UNCHECKED`, `REMOVED` and `FIRST`. A lead is `GONE` only
  when the source answered from data it can prove whole; otherwise it is kept. `--fail-on-new` exits 1 on a `NEW` lead.
- `sigforge sources [--max-age D]` prints, per source, what the last `sync` left: ok, FAILED with the reason, never
  synced, or off. `sync` now records this in `sync-status.json` in the store.
- `enrich` looks a detected platform (Drupal, Magento, Next.js, Apache Tomcat, …) that has a release version up in OSV
  under the platform's own packages, beside its CPE.
- WordPress core: `wpcve.Provider.LookupCore` and `wpcve.CoreToUnified`; `feedset` looks an `enrich.WPRef` of kind
  `core` up there, scoped `wordpress:core`.
- CVE lookup by ID (`cve.Adapter.LookupID`); CVE records carry their weaknesses (CWE) and publication date.
- KEV leads carry CISA's remediation due date and required action (`due_date`, `required_action`).
- OSV leads carry the CVSS v3 base score computed from the record's vector. `sync --osv` keeps a stored dump current
  by fetching only the records changed since the last sync; it takes the dump whole again after a day, or when more
  than 500 records changed.
- `jslib.Adapter.Identify` names a JavaScript library and its version from a script's URL, file name or content, using
  the Retire.js repository's own extractors.
- `takeoverfp.MatchNXDomain` matches a CNAME the caller has seen resolve to NXDOMAIN against providers whose takeover
  is triggered by NXDOMAIN, without looking at a response body.
- The webappanalyzer source keeps `requires`, `requiresCategory` and `excludes`. A tech with `requires` or
  `requiresCategory` counts its own match only once a tech it requires (or one in a required category) is resolved. A
  tech that a resolved tech excludes is kept and labeled `excludedBy`, which `match` and `enrich` print.
- The passive `dom` rules match only start tags the page really has: comments and the text inside `<script>` and
  `<style>` are skipped.
- The CPE dictionary is read as it streams to disk, so one larger than the in-memory body limit is still used; a
  truncated one is not used.

### Changed behaviour
- A command that would check nothing fails (exit 1) instead of reporting a quiet run. `enrich` with no page on stdin
  and no inventory flag prints no result and exits 1 (it printed `no detections` and exited 0). The new commands
  follow the same rule: `sources` exits 1 when every source is off, naming the variables not set; `watch` exits 1 when
  it has nothing to look up or no source answered, leaving an existing state file as it was. The Retire.js sample
  embedded in the binary does not, on its own, count as a source answering.
- A repeatable flag (`--package`, `--wp-plugin`, `--wp-theme`, `--jslib`, `sync --osv`) whose value names nothing
  (empty, blank, or a version with no name such as `@3.1.0`, as an unset variable leaves it) is refused before anything
  is looked up. A `--package` whose name is only whitespace is refused too.
- `sync`, and every run that asks a source again, keep the stored copy when the source answers with something the
  parser refuses or that lists no entry (an HTML page, an empty body, a broken zip). `sync` reports that source FAILED;
  a run uses the stored copy, flagged stale, with the reason. When a source answers 304, the stored copy is checked
  again: one the parser refuses is an error (`stored copy unusable`) and loses its validators, so the next request
  downloads a whole copy.
- OSV: a range's `limit` event bounds the range, as OSV defines it; it was read as an open-ended range.
- `refresh` also refuses a candidate DB in which a kept tech lost every detection pattern of its own.
- Error messages: a malformed purl is reported as `package "…"` (it was `purl "…"`); a failing `refresh --fetch`
  reports `refresh:` (it was `merge:`).
- The `enrich` text output ends with `looked up N/T · concluded N/T · not concluded N (…)` (it was
  `answered N/T · unanswered N (…)`): a source that looked a package up but concluded nothing is counted apart.
- With the WordPress feed off, kind `core` is scoped `wordpress:core` (it was `wordpress:plugin`). A WordPress kind
  other than plugin, theme or core is not looked up (`not_checked`); it was looked up as a plugin.
- With OSV off, a package carries the scope OSV gives it when on (`ecosystem:PyPI` for `pypi`), so its `watch` key does
  not change when the OSV variable is missing for one run.
- Baseline: Tomcat's version is read from its default error page (the `Apache-Coyote` header names the connector, not
  the release); a Jetty version keeps its build suffix (`9.4.51.v20230217`); a script whose name only contains
  `bootstrap` (`angular-ui-bootstrap`) is not Bootstrap.

### Consumer API
Added:
- `unified`: `Lead.Note`, `Lead.CWE`, `Lead.Published`, `Lead.DueDate`, `Lead.RequiredAction`, `Result.FullData`,
  `Result.LookedUp` (and `Result.Answered`), `State.Concluded`, `CWEIDs`.
- `osv`: `Scope`, `Adapter.Lookupers`, `Result.Unplaced`, `Result.BelowListed`, and on `Vuln`: `Score`, `Scored`,
  `Vector`, `CWE`, `Published`, `OutsideListed`.
- `wpcve`: `ScopeFor`, `CoreResult`, `Provider.LookupCore`, `CoreToUnified`, `PluginResult.Unplaced`.
- `jslib`: `Result.Unplaced`, `Result.Err`, `Adapter.Identify`, `Found`.
- `fetch`: `Client.GetChecked`, `Client.GetMetaChecked`, `Client.DownloadChecked`, `Client.Stored`, `Client.Confirm`.
- `lifecycle.Status.Err`, `enrich.Options.OSVRelease`, `matcher.Detection.ExcludedBy`, `schema.Fingerprint.Requires`,
  `RequiresCategory`, `Excludes` and `HasDetection`, `cve.Adapter.LookupID` and new `cve.CVE` / `cve.Result` fields,
  `identity.ReadDict`, `takeoverfp.MatchNXDomain` and `FP.NXDomain`, `DueDate`, `RequiredAction` and `CWE` on
  `kev.KEVEntry` and `kev.Signal`, `kev.CatalogStatus.Skipped` and `Warn`, `refresh.ReasonLostDetection`,
  `coverage.ResultsReport.LookedUp`.

Changed meaning:
- An advisory the version cannot be placed against is no longer hidden by one that matched. In an
  `affected_by_advisory` result from `osv.ToUnified`, `wpcve.ToUnified` / `CoreToUnified` or `jslib.ToUnified` it
  follows the matched leads as a lead with `Note` set; when no advisory could be placed, every lead of the
  `potentially_affected` result carries the note. On a detected platform's release, `enrich` moves such leads into a
  `potentially_affected` result of their own. A consumer that turns leads into findings or severities must read
  `Lead.Note`: a noted lead may not apply. The `enrich` text output prints the note under its lead.
- The typed results keep `Vulns` as before and list every advisory the version could not be placed against in
  `Unplaced`.
- `osv.ToUnified`, `osv.Unavailable` and the OSV lookups scope a result with `osv.Scope`: OSV's own ecosystem name
  with the distro release kept (`ecosystem:Debian:12`, it was `ecosystem:Debian`), whether the source answers, fails
  or is off.
- `jslib.ToUnified` and `lifecycle.ToUnified` add to `Err` why the source failed when the embedded sample or a stale
  stored copy is in use.
- `versioncmp.Compare`: PyPI compares local version labels (`1.0+cu118` is above `1.0`, `2.0.0+local.1` below
  `2.0.0+local.2`; they compared equal) and cannot compare a malformed one (`1.0+`), which it compared before. Maven
  folds a hyphen group holding only a release qualifier (`ga`, `final`, `release`) into the next one (`1-ga-1`,
  `1-final-1` and `1-release-1` equal `1-1`; they were lower). Packagist reads `~`, a space and a
  repeated or trailing dot as a separator (`1.0~1`, `1.0 1` and `1.0..1` equal `1.0.1`, `1.0.` equals `1.0`).
- `lifecycle`: a product name in the endoflife bundle, and the tech given to `ProductFor`, match without regard to case
  (`nginx` is Nginx); a bundle's product name, a cycle and a version drop invisible format characters (zero-width
  space, BOM), and a cycle or version reads a leading `V` and a decimal comma (`V8,2` is `8.2`).
- `identity`: `Resolver.ResolveCPE` no longer verifies a CPE from a dictionary read only in part (one page of a paged
  feed); it answers unknown, as with the embedded sample.
- `kev`: the live catalog is read row by row. A row's field of the wrong type costs that field; it made the whole
  catalog unusable before. A row without a well-formed CVE id is skipped and counted (`CatalogStatus.Skipped`, `Warn`).

### Upgrading
The engine version is 0.5.0: a DB built with this release names it in its manifest, and `verify` still accepts a DB
built with 0.4.0. `watch` and `sources` are new in this release. A `watch` state file written by a build of `main`
before v0.5.0 is read as it is, with two one-time effects:
- An advisory the old rule hid beside a matched one (JavaScript libraries, WordPress, OSV) is printed `NEW` once (with
  `--fail-on-new` that run fails) and recorded; later runs print nothing for it.
- A distro package's key now holds its release (`ecosystem:Debian:12 openssl@3.0.11-1`). An old key without the
  release hands its leads to each release key of the run that the state does not hold yet, and leaves the state. When
  one old key covers two or more releases, each release key may print `GONE` once for a lead its own release does not
  list.

### Known limitations
- `matcher.Match` compiles the DB's patterns on every call.
- The passive `dom` matcher still reads tags inside `<textarea>` and `<title>`, so a tag written in such text can fire
  a rule. A comment closed by `<!-->` or by `--!>` runs on to the next `-->`, so tags in between are missed.
- `schema.Validate` accepts a `dom` attribute pattern that compiles only behind its `attr=` prefix (such as `?abc`);
  the matcher drops it.
- `enrich --sbom FILE` with no page and no component carrying a usable purl prints `no detections` and exits 0, where
  `watch` exits 1.
- A stored copy refused on a 304 keeps its old fetch time, so a run with `SIGFORGE_CACHE_MAX_AGE` may read it without
  asking the source (and fall back as for any unusable copy) until that age has passed.
- When the embedded Retire.js sample answers beside a configured source, `watch` records its leads; a later run that
  reads the real repository can print `NEW` for advisories the sample does not carry.
- `watch` prints `UNCHECKED … (the source did not answer: its leads are kept as they were)` on a first run too, when
  no lead was recorded yet.
- A first `watch` run that only the embedded Retire.js sample answered prints that it recorded 0 leads, exits 1 and
  writes a state file holding none.
- The store replaces a file and its metadata one after the other, not together; a `sync` stopped while it moves a
  new OSV dump's index into place can leave an unused `*.idx.gz` file in the store.
- A passive `dom` rule's `text` pattern is not evaluated, so a tech whose only `dom` rule needs one is not detected
  through `dom`.
- In `enrich` results, OSV leads of the same severity follow the order of the dump's entries (`watch` sorts them).
- A chain of `implies` five or more levels deep can miss its last level on some runs; the bundled data is at most
  three levels deep.
- `schema.Validate` and the `refresh` gate accept a pattern that can never match (an empty `html` or `scriptSrc`
  pattern, a header without a pattern); `refresh` can count more techs changed than `sigforge diff` reports for the
  same two DBs; and the gate does not notice a tech detected only through `implies` losing the last tech that
  implies it.
