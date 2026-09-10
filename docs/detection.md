# Pattern detection

Pattern analysis checks actual sampled values together with column-name and
declared database-type context. It produces a suggested type, evidence and
review reasons. It does not establish that a phone, SSN, card or email belongs
to a real person, is assigned, is deliverable or is usable.

## Match ratios and decisions

```yaml
detection:
  sample_size: 100
  pattern_min_ratio: 0.9
  pattern_min_samples: 20
  date_order: MDY
```

The ratio is **matching nonblank sample values / all nonblank sample values**.
NULL, empty strings and whitespace-only values are excluded. Nonblank invalid
values stay in the denominator. Only outer whitespace is stripped globally;
leading zeros and separators remain available to each format check.

The SQL connector uses `SELECT DISTINCT ... LIMIT`, so this is a proportion
of **sampled distinct values**, not of all rows, a random representative sample,
or a probability that the classification is correct. For example, 99 identical
valid email rows plus one invalid row produce two distinct samples and a 50%
email match ratio. The matcher itself evaluates the supplied sequence without
deduplicating it. Changing the database sampling strategy is a separate task.

A suggestion requires at least 20 nonblank samples by default, a ratio >=90%,
applicable context and exactly one eligible candidate. These are configurable
starting points, not empirically calibrated guarantees. Tiny test/demo datasets
can explicitly set `pattern_min_samples: 1`. A limited city vocabulary may
therefore remain UNKNOWN even if every distinct value in a small sample matches.

No weight is multiplied into the ratio. `Pattern.weight` is retained as an
ignored compatibility argument; custom `Pattern.min_ratio` values can impose a
stricter threshold than the matcher's configured floor. Ties remain inconclusive.

## Supported checks

| Type | Value check | Context / limits |
|---|---|---|
| `phone` | NANP NXX-NXX-XXXX, N=2-9; optional `1`/`+1`, supported spaces/dots/hyphens/parentheses, `ext`, `ext.`, `x` or `#` plus 1-6 extension digits | Bare digits require phone context. Seven-digit local numbers, other country codes and malformed grouping remain inconclusive. NANP includes US/Canada and other participating regions; this does not verify geographic assignment. |
| `ssn` | Nine digits or 3-2-4 hyphen groups; excludes 000/666/900-999 area, 00 group, 0000 serial | Bare digits require SSN context; partial, masked and invalid SSNs need review. US SSN only, not Canadian SIN. |
| `date` | Real calendar parsing, leap years and valid time ranges | DATE/DATETIME/TIMESTAMP metadata supplies context. Compact YYYYMMDD needs date context; no two-digit-year or epoch guessing. |
| `email` | Common address syntax including `+tag`, multi-label domains and common TLDs | No delivery/network check. Quoted local parts, internationalized special syntax and embedded text are outside this conservative recognizer. |
| `credit_card` | Brand prefix + supported length + Luhn | Requires card context. Visa 13/16/19; Mastercard 16, prefixes 51-55 or 2221-2720; Amex 15, 34/37; Discover subset 16/19, 6011/644-649/65. Other brands/ranges require review. |
| `zip_code` | Five digits or ZIP+4 with the 5-4 hyphen | Requires ZIP/postal context. Bare nine digits remain ambiguous. Format only; no postal assignment lookup. US ZIP only, not Canadian postal codes. |
| `city` | Membership in the existing small `us_cities` dictionary | Requires city/town context; unknown cities remain reviewable. No enlarged reference dataset is bundled in this change. |
| `full_name` | One to six words with letters and supported name punctuation | Requires personal-name context such as `full_name`, `first_name`, `last_name`; Unicode letters supported. Generic `name`/`product_name` is intentionally ambiguous. Format is not proof of a person's identity. |
| `ip_address` | Valid IPv4 octets, using `ipaddress.IPv4Address` | Rejects 999.999.999.999 and ambiguous leading-zero octets. IPv6 is outside this catalogue. |
| `uuid`, `url`, `address` | Existing UUID, common URL and US street shapes | Subject to the same sample/context checks. |

Names are tokenized across snake_case and camelCase. `email_address` is email
context; `hotel` is not `tel`, and `candidate` is not `date`. Austin can support
city in a `city` column or a person name in `first_name`. An unlisted city in a
`city` column cannot fall through to `full_name`. The generic person-name rule
is still `full_name`; choose `fake_first_name` / `fake_last_name` through the
existing reviewed strategy or per-column strategy settings when appropriate.

The city dictionary still doubles as the fake-city pool. A future reference-data
change should separate them and handle provenance, aliases and postal mappings.
Runtime `register_dictionary("us_cities", ...)` changes are respected immediately.

## Dates and masking

Supported date layouts are YYYY-M-D, YYYY/M/D, YYYYMMDD, M/D/YYYY and M-D-YYYY.
With explicit `date_order: DMY`, the last two mean D/M/YYYY and D-M-YYYY instead.
Dot-separated D.M.YYYY is explicitly day-first. Single-digit months/days are
supported. An optional space or `T` time suffix accepts H:MM, optional seconds,
1-6 fractional second digits and `Z` or an offset such as `+05:30`.

`03/04/2026` means March 4 under the US default MDY and April 3 under DMY. Choose
the order that your dataset uses; mixed MDY/DMY columns need manual handling.
Detection and `fake_date` share this parser and preserve separators, date-field
widths and time suffixes. Shifts stay within the calendar for recognized textual
dates, including year-boundary extremes.

`fake_date` now scopes seed-map entries as `fake_date:calendar-v2:MDY` (or DMY).
Old entries remain stored but are not reused: an old parser could have stored
digit-randomized output for a newly supported format. Date mappings may therefore
change once on upgrade. Do not mix old and new date mappings across related
copies. Direct `MaskingEngine` callers can supply `date_order="DMY"`; Runner
passes it from detection configuration.

A 90% matching column can still contain malformed remaining values. `fake_date`
rejects unparseable nonempty text, as do the strict phone/SSN/card strategies.
Neither the sample threshold nor the parser guarantees every database row is
valid. Review mismatches before applying masking; see [strategies](strategies.md).

## Reports and review

CLI example:

```text
[SENSITIVE] main.contacts.email -> email (pattern, match=96.00%)
  ... email: 96/100 (96.00%) ...
```

`scan --json` additionally exposes `pattern_candidates` (hits, total, ratio,
threshold, eligibility and reasons), `pattern_sample_count` and
`pattern_sample_basis: "distinct_values"`. No raw samples are included in these
new evidence fields. `scan --output review.csv` / `.xlsx` retains the summary
in the existing review `reason` field, so the history file schema stays compatible.
Ratios are rounded for display only; the exact float determines threshold checks.

Manual overrides and approved applicable history keep their precedence. An
imported pending decision remains held. Strong name/type/value conflicts and
multiple eligible patterns return UNKNOWN for a person, even with the LLM on.
Other inconclusive evidence may use the optional LLM; its confidence stays
separate and pattern evidence remains attached. Passing evidence into the LLM
prompt and free-text fragment extraction are deferred.

New pattern/LLM decisions are pending suggestions. As before, conclusive fresh
suggestions can drive the current `mask` run; this change does not add a universal
approval gate. UNKNOWN columns remain unmasked and do not stop masking of other
columns. Review the scan before applying a masking plan.

In particular, a `notes` column with one embedded email out of 100 is outside
whole-value classification. Failure to reach 90% never proves that a column is
safe; free-text extraction belongs in the next stage of the agreed plan.

## Python API

```python
from dbmask.detection.patterns import PatternMatcher

matcher = PatternMatcher(min_ratio=0.9, min_samples=20, date_order="MDY")
result = matcher.analyze(values, column="phone_number", data_type="VARCHAR(40)")
print(result.summary())
match = result.match  # None when evidence is inconclusive
```

`match(values, column=..., data_type=...)` remains a convenience wrapper.
Existing callers must supply context for ambiguous types and account for the
new minimum sample size; `.confidence` on a pattern result equals `.ratio`.

## Attribution and format references

The scenarios in `tests/test_date_detection.py` come from
[PR #25](https://github.com/sealandseacat/dbmask/pull/25), commit
`933a769b7f928594cb197a06b7ce453626581c34`, authored by **1cbyc** with
**insisong** as co-author. This change adapts only the small-sample matcher
configuration and the explicit phone context, plus an attribution header.
Their nine test cases are retained, including scan-and-mask calendar validation.
This carries their tests forward; it does not claim that PR #25 itself was merged
or that its authors endorsed the new production rules.

Rule references: [NANPA numbering format](https://www.nanpa.com/about),
[SSA SSN randomization](https://www.ssa.gov/employer/randomization.html),
[SSA SSN randomization FAQ](https://www.ssa.gov/employer/randomizationfaqs.html),
and [Braintree card type definitions](https://github.com/braintree/credit-card-type/blob/main/src/lib/card-types.ts).
