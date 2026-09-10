# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Contextual pattern evidence in CLI/JSON and review-export reasons: hit counts,
  nonblank distinct-sample counts, unweighted ratios and rejection reasons.
- Adapted date regression tests from PR #25 by **1cbyc** and **insisong**,
  including calendar-preserving scan-and-mask coverage.

- Import/export historical decisions using CSV, XLSX (optional `excel` extra),
  or a strict Markdown table. Records preserve analyst `user_id`, reviewer,
  review dates, masking strategy, type baseline and expiry. Atomic imports
  reject conflicting rows; revisions and explicit approved replacements
  preserve prior decisions for audit. `scan --output` creates a review file.

### Changed

- Pattern selection no longer uses `ratio * weight`; `Pattern.weight` is a
  deprecated, ignored compatibility field. Default thresholds are 90% and 20
  nonblank sampled values. Name/type conflicts and ambiguous candidates are
  held for review. Bare numeric identifiers, names, cities, ZIPs and cards
  require appropriate context. See `docs/detection.md` for migration details.
- Date detection and `fake_date` share explicit calendar parsing with MDY/DMY
  configuration. `fake_date` seed-map entries use a new, date-order-specific
  scope to avoid reusing invalid outputs from the old parser.

- Only approved, applicable imported history is reused. Automatic results and
  legacy rows are pending suggestions, not approvals. Imported pending,
  expired, type-changed or unavailable-strategy records require review.
  Explicitly reviewed strategies cannot silently fall back to another method.
  Existing history rows are retained without altering the legacy table.

### Fixed

- Masking now uses constrained phone/SSN generators and brand/length/Luhn-valid
  card replacements, with column-aware first/last-name defaults. Strict date,
  phone, SSN and card strategies reject invalid nonempty input; the engine
  rejects unchanged replacements. Review exports include the resolved strategy.
  See `docs/strategies.md` for seed-map migration and batch-failure behavior.

- Reject impossible calendar dates, invalid IPv4 octets and excluded US SSN
  number groups; restrict phone detection to supported NANP formats. Unknown
  cities no longer fall back to names. City reference updates invalidate the
  cached lookup through its content key.

- **Earlier date/city/address fix (#26), now refined above.** The `phone`
  pattern matched date-shaped values (`1994-03-15` is digits and hyphens,
  longer than seven characters) and outweighed `date`, so date columns were
  masked with `format_random` and stopped being valid calendar dates. The
  `full_name` pattern matched two-word city names, so city columns were
  replaced with person names. Street addresses matched nothing and were left
  unmasked as `UNKNOWN`. `phone` now rejects dates and bounds its digit count,
  and new dictionary-backed `city` and `address` patterns take those columns.
  [#24]

## [0.1.1] - 2026-08-24

Safety release: a top-to-bottom review of the failure modes that matter most
in a masking tool — "it said dry-run but wrote", "it said masked but didn't",
"it said verified but skipped". Upgrading before any real use is strongly
recommended.

### Security

   - **`dbmask mask` without `--apply` could write to the database** while
     printing "DRY-RUN (no changes written)" when the config set
     `masking.dry_run: false`. The CLI flag is now the single source of
     truth. Tracked as
     [GHSA-2jwm-hcfc-72xm](https://github.com/sealandseacat/dbmask/security/advisories/GHSA-2jwm-hcfc-72xm).
    
### Fixed

- **Masking no longer proceeds on an incomplete scan.** Columns whose
  analysis raised were silently left unmasked while the command exited 0.
  Masking now fails closed (`ScanIncompleteError` / exit 2) unless
  `--allow-partial` is passed explicitly; `dbmask scan` exits 3 when it could
  not analyze every column. [#6]
- **"Could not tell" is no longer recorded as "not sensitive".**
  Inconclusive columns (no pattern match, LLM off — e.g. empty tables) were
  stored as safe with confidence 0.5 and reused from history forever. They
  are now `UNKNOWN`: never persisted, never masked, and surfaced by both
  `scan` ("Needs review") and `mask` (explicit warning listing each one). [#7]
- **Sensitive primary-key columns are no longer silently skipped.** The
  engine planned them, the preview showed them masked — but the UPDATE never
  touched them. They are now excluded up front and reported loudly
  (`TableMaskResult.skipped_columns`, CLI "NOT MASKED — primary-key column"). [#8]
- **Dry runs no longer write to the seed map.** Previews had a persistent
  side effect (recording original→masked pairs). Dry runs are now read-only;
  determinism keeps the preview identical to what `--apply` later writes. [#9]
- **`llm.api_style` is now actually configurable.** `LocalProvider` supported
  OpenAI-style local servers (LM Studio, vLLM) but the config field did not
  exist and the factory never passed it. [#12]
- **Validation reports no longer leak sensitive values.** FAIL details carry
  shape-redacted samples plus row keys instead of the original values. [#11]

### Changed

- **The masking-completeness check is now primary-key aligned.** Rows are
  matched key-by-key and the sensitive column compared value-by-value, which
  catches a row whose email survived unmasked while its name changed — the
  case the old whole-row heuristic reported as fine. The heuristic remains
  only for keyless tables, and its clean result is now a WARNING ("cannot
  verify per-row without a primary key"), not a PASS. Tables present on only
  one side are also surfaced as warnings.
- **`fake_email` now lands on the reserved, undeliverable `example.invalid`
  domain.** The previous behavior (original domain preserved — often enough
  to identify a small organization) is available explicitly as
  `fake_email_keep_domain`.
- **Masked values stay valid for their data type.** New default strategies:
  `uuid` → `fake_uuid` (a real v4 UUID), `ip_address` → `fake_ip` (valid
  octets), `credit_card` → `fake_credit_card` (Luhn-valid),
  `date`/`date_of_birth` → `fake_date` (deterministic ±30–730-day shift,
  always a real calendar date). `format_random`/`shuffle` now preserve the
  Python type of ints, floats, Decimals, dates, datetimes, UUIDs and
  booleans instead of returning strings. [#10]
- **Mask previews redact original values by default** (shape-only, e.g.
  `***-**`); pass `--show-values` to display them. Keeps PII out of
  terminals, scrollback and CI logs.
- **`mask` warns when running with the publicly-known default seed**, and
  `scan`/`mask` warn before sampled values are sent to an external LLM
  provider.

### Added

- `dbmask validate --strict` (and `ValidationReport.passed_strict`):
  warnings and skipped checks fail the gate; the non-strict summary line now
  names its caveats instead of printing a bare "PASSED".
- `validation.pk_row_limit` — row budget for the PK-aligned check, with
  partial coverage stated in the report.
- `llm.send_values: false` — metadata-only mode: the model judges from the
  column name alone; no data values leave the machine.
- `--allow-partial` (mask) and `--show-values` (mask) flags.
- Strategies: `fake_uuid`, `fake_ip`, `fake_credit_card`, `fake_date`,
  `fake_email_keep_domain`.
- 75 new regression tests (121 total), most driving the real CLI against
  real config files and throwaway SQLite databases.

### Upgrade notes

- **History stores written by 0.1.0** may contain columns recorded as
  `not_sensitive` merely because detection was inconclusive at the time.
  Delete `dbmask_history.db` (or the affected rows) to have them re-evaluated
  as UNKNOWN.
- **Mappings for new values change** for the email/uuid/ip/credit-card/date
  rules (they now produce valid-format output). Pairs already recorded in a
  seed map are preserved and keep winning; only values masked for the first
  time are affected.
- Scripts that relied on `dbmask mask` writing without `--apply` (via
  `dry_run: false` in YAML) must now pass `--apply`.

## [0.1.0] - 2026-08-20

First public release.

### Changed
- **Repositioned the README** from test-data masking to what the engine
  actually is: discovering, masking and validating sensitive data in any
  database, for every environment production data flows to. Added use-cases
  and roadmap sections (data-governance integration first among them).
  Prompted by [#1](https://github.com/sealandseacat/dbmask/issues/1) —
  thanks @dbwhizard.
- **Renamed the package from `datamask` to `dbmask`.** The name `datamask`
  is already taken on PyPI by an existing project in the same space, so the
  package needed a new, non-colliding name before its first release.
  Everything follows the new name: the import (`import dbmask`), the CLI
  (`dbmask scan ...`), the config file names (`config/dbmask.config.yaml`),
  the seed-salt environment variable (`DBMASK_SEED_SALT`), the default store
  files (`dbmask_history.db`, `dbmask_seedmap.db`) and their table names.
- Masking applies in key-ordered pages (keyset pagination) instead of writing
  into a live streaming read; reads and writes no longer overlap.

### Fixed
- **Masking tables larger than one batch no longer fails with
  `database is locked` on SQLite**
  ([#2](https://github.com/sealandseacat/dbmask/issues/2)).
  The engine used to stream-read the table
  while writing batches back on a second connection; the in-flight read held
  a SHARED lock that blocked every write commit. Applies now read one page,
  write it back, then read the next.
- **Bundled dictionaries crashed on Python 3.9** (`TypeError` from
  `importlib.resources.files()` anchored on a namespace package;
  [#3](https://github.com/sealandseacat/dbmask/issues/3)). Resource
  loading is now anchored on a regular package and works on all supported
  Pythons (3.9–3.14). Loader breakage now also fails loudly instead of
  silently degrading every fake name to the same fallback value.

### Added
- Keyset pagination API for connectors (`Connector.iter_pages`), with a
  portable expanded row-value comparison for composite primary keys.
- `py.typed` marker: type checkers now use the package's inline annotations.
- CI: tests on Python 3.9–3.14 (Ubuntu) and Windows, plus sdist/wheel build
  validation with `twine check --strict` on every push and pull request.
- `CONTRIBUTING.md`, `SECURITY.md`, and this changelog.

[Unreleased]: https://github.com/sealandseacat/dbmask/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/sealandseacat/dbmask/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sealandseacat/dbmask/releases/tag/v0.1.0
[#6]: https://github.com/sealandseacat/dbmask/issues/6
[#7]: https://github.com/sealandseacat/dbmask/issues/7
[#8]: https://github.com/sealandseacat/dbmask/issues/8
[#9]: https://github.com/sealandseacat/dbmask/issues/9
[#10]: https://github.com/sealandseacat/dbmask/issues/10
[#11]: https://github.com/sealandseacat/dbmask/issues/11
[#12]: https://github.com/sealandseacat/dbmask/issues/12
[GHSA-2jwm-hcfc-72xm]: https://github.com/sealandseacat/dbmask/security/advisories/GHSA-2jwm-hcfc-72xm
[#24]: https://github.com/sealandseacat/dbmask/issues/24
