# Historical decisions

Historical decisions identify a column by the exact tuple
`database`, `schema`, `table`, `column`. `database` is the connector's logical
name (`database.name` in config), not its URL. Names are case-sensitive and
preserved as written, including embedded dots. There is no wildcard or
same-column-name fallback. For SQLite the usual schema is `main`; an empty
schema is accepted only when that is the actual connector schema.

## Install and configure

CSV and Markdown need no additional dependency. For XLSX:

```bash
pip install "dbmask[excel]"
```

For a source checkout use `python -m pip install -e ".[dev]"` (includes XLSX).

```yaml
database:
  url: sqlite:///demo.db
  name: demo
history:
  enabled: true
  url: sqlite:///demo_history.db
detection:
  use_history: true
  user_id: analyst-001
```

History commands connect only to the configured history store. They do not
connect to or mask the source database. A scan subsequently verifies the
declared type against source metadata before reusing an approved record.

## File schema

Use one current row per exact column. The first 13 headers below are required
(some values may be blank). The last three headers are optional on first
import and included in all exports. Header order may vary; spelling may not.

| Field | Meaning |
|---|---|
| `database` | Required logical database name |
| `schema` | Exact schema, including an intentionally empty schema |
| `table` | Required table name |
| `column` | Required column name |
| `decision` | `mask`, `keep`, or `review` |
| `detected_type` | Optional type label such as `email` or `free_text` |
| `masking_strategy` | Executable strategy ID such as `blank` or `fake_email`; empty for `keep` |
| `review_status` | `pending`, `approved`, or `superseded` |
| `user_id` | Required analyst ID, stored separately from the reviewer |
| `reviewed_by` | Required for `approved` |
| `reviewed_at` | Required ISO date/timestamp for `approved` |
| `reason` | Explanation of the decision |
| `analysis_date` | Required ISO date/timestamp of analysis |
| `data_type` | Reviewed declared SQL type, including length/precision where relevant |
| `expires_at` | Optional ISO expiry timestamp; blank means no scheduled expiry |
| `revision` | Exported revision, initially `0`; do not edit it |

Use ISO dates (`2026-09-08`) or timestamps (`2026-09-08T14:00:00Z`). Timestamps
without a zone and native Excel dates are interpreted as UTC. Analyst IDs,
names, decisions and strategies must be text cells. This preserves IDs such
as `00123`. Format these columns as Text before entering data in Excel.

`approved` requires `mask` or `keep`, `reviewed_by`, and `reviewed_at`.
Missing required author/review fields, invalid dates, invalid status values,
and `keep` with a masking strategy reject the complete batch. An expired
approval, missing type baseline, or unknown/missing masking strategy for
`mask` is imported as `pending` with an explanation. The import summary lists
these downgrades, so success does not imply every input approval was accepted.

`data_type` must match the database-declared type after case and whitespace
normalization. Types are not loosely aliased: `VARCHAR(100)` changing to
`VARCHAR(200)` requires review. Start with `scan --output` to capture the
actual type rather than guessing. Custom connectors may implement
`column_type`; unavailable metadata prevents approved reuse.

## File formats

- **CSV:** UTF-8, optional BOM, comma delimiter and standard quoting. Use
  Excel's UTF-8 CSV export. Use XLSX for formula-looking literal text (CSV
  cannot encode a cell's text type; the exporter rejects unsafe prefixes).
- **XLSX:** worksheet `history`, one header row and data rows. Select a
  different sheet with `--sheet`. Formulas are rejected, not evaluated.
  Old `.xls` files must be saved as `.xlsx` first.
- **Markdown:** exactly one pipe-delimited table, with a header and separator
  row. No surrounding prose, fenced code, or natural-language instructions.
  Escape embedded pipes as `\|`; `<br>` represents a newline. Use XLSX/CSV for
  literal backslashes, literal `<br>` or edge whitespace that cannot round-trip.

The repository includes [a CSV example](../config/history.example.csv) and
[a Markdown example](../config/history.example.md) containing synthetic data.
Remove or replace the example rows before importing your own decisions.

## Review and import

Create a worksheet of the current scan, including unknown/empty columns:

```bash
dbmask scan --config dbmask.yaml --output review.xlsx
```

Automatic rows are suggestions (`pending`). Review the decision and method,
fill `reviewed_by` and `reviewed_at`, and change `review_status` to `approved`
only after actual review. Keep the analyst `user_id` and `analysis_date`.
For a notes column you can approve `decision=mask`, `detected_type=free_text`,
`masking_strategy=blank`. `keep` means a reviewed choice to leave the column
unchanged, not a claim that the column can never be sensitive.

Preview the import, then import the same reviewed file:

```bash
dbmask history-import --config dbmask.yaml --file review.xlsx --dry-run
dbmask history-import --config dbmask.yaml --file review.xlsx
dbmask history --config dbmask.yaml --json
dbmask scan --config dbmask.yaml
dbmask mask --config dbmask.yaml
```

The import is atomic: if any row is malformed, conflicting or stale, no
decision rows from that batch are committed. A dry run changes no decision
records, although opening a new store can create its empty tables. It does
not check live source schema. Scan verifies live types afterward.

The final `mask` command above is a preview. Actual source changes still
require the existing `--apply` flag. This feature governs historical reuse;
it does not add a universal approval gate to the existing masking command.
Fresh pattern/LLM classifications can still drive the current run's masking.
To hold a column for human review, import its pending record. Such imported
pending (or superseded) records produce `UNKNOWN` and are not masked or
silently replaced by an automatic fallback. Unknown columns continue to be
reported by the existing CLI; they do not by themselves abort the whole run.

Approved history is reused even if current samples are all empty. A record
that expires, changes declared type, or loses its registered strategy becomes
pending, preserving its earlier approval in the revision audit. Update the
type baseline/method after review and re-import to approve it again.

Explicitly reviewed `masking_strategy` wins over broad `column_strategies`,
`rule_strategies`, and the catch-all default. A fresh detection override still
wins before history. Setting `use_history: false` explicitly bypasses all
history, including imported review holds.

## Corrections, conflicts and audit

Identical rows/imports are idempotent. Different rows for the same column in
one file are rejected regardless of row order (even if one is superseded).
Keep older versions in the audit, not as multiple current rows in an import.

To change an existing approval, first export the latest current records:

```bash
dbmask history-export --config dbmask.yaml --output current.xlsx
```

Review and edit the intended rows, preserving their exported `revision`.
Then preview and apply an explicitly authorized replacement:

```bash
dbmask history-import --config dbmask.yaml --file current.xlsx --replace-approved --dry-run
dbmask history-import --config dbmask.yaml --file current.xlsx --replace-approved
dbmask history --config dbmask.yaml --audit
```

`--replace-approved` allows changes to existing approvals, including sending
them back to pending. It does not bypass duplicate-row conflicts, field
validation or revision checks. A changed stale file is rejected; export again
and reconcile the differences. Review the entire batch before using this flag.
Each accepted change gets a new revision and a retained audit snapshot.
Export will not overwrite an existing file: use a new output filename.

Analyst and reviewer IDs are recorded as supplied. This is audit metadata,
not identity authentication or a KPI calculation system. Machine analysis
runs are retained in `dbmask_history_suggestions`; exported current views show
the latest suggestion per column, with imported decisions taking precedence.

## Existing history stores

The legacy `dbmask_decisions` table is retained untouched. Its old automatic
classifications are no longer reused as approval. Export exposes them as
pending evidence with their original analysis date, where available. No
analyst/reviewer ID is invented. New scans can generate updated suggestions.

Before using an existing history store with the new version, back it up.
Export, review, fill missing analyst/reviewer/type information, and import
approved decisions. New tables hold reviewed current records, their revisions,
and machine suggestions. No destructive schema rewrite is required.

The import payload format works with the existing SQLAlchemy store interface.
This change is tested locally with SQLite. Dataedo synchronization and
cloud-database-specific deployment testing are outside this change.
