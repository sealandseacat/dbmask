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

The repository includes [a CSV example](https://github.com/sealandseacat/dbmask/blob/main/config/history.example.csv) and
[a Markdown example](https://github.com/sealandseacat/dbmask/blob/main/config/history.example.md) containing synthetic data.
Remove or replace the example rows before importing your own decisions.

## Write decisions back to the original file

Use this mode when your CSV, XLSX or Markdown file should remain the source
of truth. It is opt-in; without `source_file`, the SQL workflow below remains
unchanged. No SQL history database is created or synchronized in file mode.
Existing SQL stores remain available if you switch back, but contain only
their own records; export/import explicitly if migrating decisions between modes.

```yaml
database:
  url: sqlite:///demo.db
  name: database-A             # unique, stable name; part of every record key
history:
  enabled: true
  source_file: history/master.xlsx
  sheet: history              # source worksheet; can be a custom name
  # url is unused while source_file is configured
detection:
  use_history: true
  user_id: analyst-001
```

`source_file` is resolved relative to the YAML config file. Supply an existing
file in the schema above; a header-only file is valid for an empty master.
The CLI `--file`/`--output` paths are relative to the working directory.
Each scan reads the master afresh. It reuses applicable approved records by
exact database/schema/table/column, then uses patterns and optional LLM for
columns without history. Imported pending/superseded rows still hold review.
Explicit detection overrides still have first priority.

1. Validate and load the original file (this command does not rewrite it):

   ```bash
   dbmask history-import --config dbmask.yaml --file history/master.xlsx
   ```

   File mode uses the configured source `sheet`. `history-import` accepts that
   original file only; subsequent reviews use `history-writeback`.

2. Scan and export a separate review worksheet:

   ```bash
   dbmask scan --config dbmask.yaml --output review.xlsx
   ```

   This creates `review.xlsx` and `review.xlsx.dbmask.json`. Keep them together.
   The companion identifies the original source, its content hash, the exported
   locations, revisions and analysis metadata. Do not edit it. The worksheet
   contains no raw database samples; pattern evidence remains in `reason`.
   Set `detection.user_id` before export. Scan does not write suggestions into
   the master; in file mode they survive through this review export.

3. Review the worksheet's `history` sheet. Set `decision=mask` with a registered
   `masking_strategy`, or `decision=keep` with an empty strategy. Edit the reason,
   type label and expiry if needed. Mark only reviewed rows `approved`.
   `reviewed_by` and `reviewed_at` are filled by the next command for changed
   approvals. Keep the exported database/schema/table/column, `revision`,
   `user_id`, `analysis_date` and `data_type` unchanged. To refresh a type
   baseline, scan again; a type-changed historical row is exported as pending
   with today's declared type and analyst. Close Excel before continuing.

4. Preview, then save the reviewed changes to the original file:

   ```bash
   dbmask history-writeback --config dbmask.yaml --file review.xlsx --reviewed-by siyuan
   dbmask history-writeback --config dbmask.yaml --file review.xlsx --reviewed-by siyuan --apply
   dbmask history --config dbmask.yaml --json
   dbmask scan --config dbmask.yaml
   ```

   `--sheet` on writeback selects the review sheet, default `history`; the source
   sheet comes from config. Both files can independently be CSV, XLSX or MD.
   The preview lists old/new decisions, strategies and scopes. The applying
   command stamps its reviewer/time, increments changed revisions and reports
   the backup filename. No `--apply` means no writes or backup creation.

Only approved rows are merged. Pending/superseded or omitted review rows do
not delete, revoke or replace an existing approval. Unchanged approvals keep
their reviewer, date and revision. To revise an approval, change its decision,
strategy or rationale and approve it; `history-export --output current.xlsx`
can prepare a review without connecting to the data database. Use `scan` when
you need current column types or fresh pattern/LLM suggestions.

The whole review is validated before writing. Duplicate rows, altered scope
or analysis fields, stale revisions, unavailable strategies and expired new
approvals reject the batch. If the original file changed since export, export
again and reconcile the changes; a second apply of an already-used review
also needs a fresh export. Never bypass the companion/hash check to force an
old decision onto newer history. Reviewer names and the companion are audit
metadata and conflict detection, not authentication or cryptographic approval.

Writeback merges exact keys, so a mask decision in database A cannot overwrite
a keep decision in database B. Unrelated records stay present. It takes an
exclusive `.dbmask.lock`, validates a staged file by reading it back, saves an
exact pre-write `.bak` snapshot, and atomically replaces the original. An I/O
failure before replacement leaves the source unchanged. Close spreadsheet
editors and do not edit the master during writeback: the lock serializes
other dbmask writers, not external editors. After a process crash, remove a
leftover lock only after confirming no writer is still running.

CSV/MD output may normalize serialization while preserving record contents.
XLSX updates the named worksheet and retains other sheets and ordinary cell
formatting/comments/formulas outside the history sheet. It is not a byte-for-byte
Excel editor: advanced workbook features unsupported by openpyxl may change;
use a plain history workbook and keep the backup. Formula cells in the history
sheet remain disallowed. File-mode audit is the master revisions plus backups;
`history --audit` remains SQL-only. Restore by copying a backup over the master
with its original extension while dbmask is stopped, then export fresh reviews.

This workflow persists decisions, not the underlying database values. Actual
masking is still a separate `dbmask mask` preview followed by `--apply` on a
disposable database copy. The masking command retains its existing behavior:
new pattern/LLM suggestions can drive a run, so complete review first; unknown
and held columns are reported and remain unmasked.

### Database-scoped YAML overrides

For overrides that must apply to only one database, use explicit fields:

```yaml
sensitive:
  - database: database-A
    schema: main
    table: accounts
    column: account_number
    rule: account_number
    masking_strategy: redact
    note: Human decision for database A
not_sensitive:
  - database: database-B
    schema: main
    table: accounts
    column: account_number
    note: Human decision for database B
```

All four fields are literal and case-sensitive, including embedded dots; an
empty schema is allowed when it matches the connector. This form takes priority
over legacy `match` entries. Do not combine it with `match`/`name` aliases.
Legacy shorthand/globs remain supported and can apply across databases.
Overrides appear as pending suggestions in the scan review; explicitly approve
and write them back to persist them. Once saved, those exact historical decisions
can be reused after removing the temporary override file. `redact` here is a
text masking example, not encryption; choose a type-compatible strategy.

## SQL history: review and import

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

## SQL history: corrections, conflicts and audit

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
