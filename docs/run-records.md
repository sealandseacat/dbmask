# Confirmed plans and run records

A run record links the scan, the actual masking writes and their validation.
The confirmed plan fixes the column classifications and the effective masking
strategy for each sensitive column. Validation uses that same list, including
columns such as sensitive primary keys that masking could not update. It does
not reclassify the already-masked target or narrow the list through a later
`validation.columns` setting.

## Prepare the configuration

Keep an untouched source database and a separate target copy. Configure both
`source_database` and `database` **before** creating the plan. Plan approval
does not create a database copy or grant permission to write to a source.

For a configuration at `config/dbmask.config.yaml`, add:

```yaml
audit:
  directory: ../.dbmask/runs

validation:
  check_row_counts: true
  check_schema_elements: true
  check_masking_completeness: true
  pk_row_limit: null
```

Merge these settings into the existing YAML blocks. `pk_row_limit: null`
compares all rows and uses memory proportional to each selected column and
its keys; choose the budget before confirming the plan. A bounded comparison
reports partial coverage and cannot pass `--strict`.

`Config.load()` resolves `audit.directory` relative to the configuration
file, including its default `.dbmask/runs`. Thus the default for a file in
`config/` is `config/.dbmask/runs`; the example above selects `.dbmask/runs`
at the repository root. Run files must be direct children of the selected
audit directory, and all operations on one target must retain that directory.

## Scan, confirm, preview, apply and validate

Run the following commands from the repository root:

```bash
dbmask plan --config config/dbmask.config.yaml --run-file .dbmask/runs/trial-001.json
```

Inspect the JSON file's `plan.scope` and `plan.decisions`: verify the selected
tables, column classifications, review metadata and resolved strategies. If
a column is unknown, history review is pending, or the scan has an error,
resolve it through the existing overrides/history workflow and create a new
plan with a new filename. Do not edit the frozen JSON plan.

Confirmation requires a decision for every inventoried column. Whole-table
`skip_table_patterns` leave missing decisions and prevent confirmation;
remove those skips and review the table's classifications explicitly.

After inspecting the plan, confirm it and preview the result:

```bash
dbmask approve --run-file .dbmask/runs/trial-001.json --reviewed-by "Siyuan Feng"
dbmask mask --config config/dbmask.config.yaml --run-file .dbmask/runs/trial-001.json
```

Plan confirmation records who accepted the entire plan and its digest. It
does not rewrite per-column history approvals; pattern and override decisions
may still carry their original `pending` metadata. Previewing modifies no
target data and keeps its progress separate from committed apply progress.

Apply the confirmed plan, then validate against the untouched source:

```bash
dbmask mask --config config/dbmask.config.yaml --run-file .dbmask/runs/trial-001.json --apply
dbmask validate --config config/dbmask.config.yaml --run-file .dbmask/runs/trial-001.json --strict
```

Keep the same configuration for all phases. A changed target/source identity,
masking policy, validation policy, tool version or reflected table/column
inventory requires a new plan. Frozen validation ignores later detector or
history changes; it uses the confirmed classifications. A run without a
completed apply, or with a required validation check disabled, cannot pass.
Warnings and skipped checks fail `--strict`, including partial comparisons
and the keyless-table heuristic.

## Read the record

| Field | Evidence retained |
| --- | --- |
| `run_id`, `tool_version`, `created_at` | Run identity and creation version/time |
| `plan.target`, `plan.source` | Endpoint fingerprints and logical labels |
| `plan.scope` | Schema/table/column inventory, types, keys and writable metadata |
| `plan.decisions` | Classifications, review metadata and resolved strategies |
| `plan_sha256`, `approval` | Frozen-plan integrity digest and person confirming it |
| `execution.tables` | Scanned/written row counts, committed batches, skipped columns and in-flight state |
| `previews`, `execution_history` | Preview attempts and preceding apply attempts |
| `validations` | Coverage, check outcomes, failures and redacted row references |

The JSON excludes raw row values, previews, decision explanations, connection
URLs/credentials, masking seeds and API keys. Database/table/column names and
reviewer identifiers remain metadata in the record. The digest detects plan
edits; it is not a digital signature or an externally trusted approval.

## Partial writes and repeat protection

Before every batch update, the record saves an `in_flight` marker. After the
target transaction returns, it records the committed batch and row count.
An error preserves earlier confirmed commits and its exception type, without
copying database exception text or query parameters into the record.

Target commits and audit-file writes are separate operations. A crash or an
audit-write failure can therefore leave `in_flight: true` even when the batch
committed. Treat that state as uncertain. Inspect the run and restore a fresh
untouched target copy before retrying; this feature is not automatic resume
or a rollback of previously committed batches.

The local guard refuses another apply whose sensitive-column scope overlaps
a tracked completed, partial or uncertain write to the same target. It also
holds an exclusive local target lock while applying. A stale lock requires
operator inspection before removal. After verifying that a target was restored,
an explicit `--remask-reason "..."` override can authorize another apply and
records that reason; it does not recover a partly masked copy.

Protection depends on retaining the audit records in the same directory. It
does not discover writes made elsewhere, recognize every host/connection
alias, coordinate separate machines, or survive deletion of the evidence.
Direct calls to `MaskingEngine` are outside Runner's run-record workflow.

## Existing commands and API callers

Standalone CLI `scan` saves a draft record automatically; `--run-file` chooses
its filename. Existing `mask` commands and `Runner.mask()` callers also save
automatic records and receive local repeat protection. Those automatic plans
remain visibly unreviewed. Use `plan` → `approve` → `mask --run-file` →
`validate --run-file` for the linked, confirmed workflow.

Legacy `validate` without `--run-file` retains its source-based discovery
behavior and saves a separate, unreviewed record labelled
`original_source_scan_unreviewed`. It is not evidence that it checked an
earlier confirmed plan.

## PostgreSQL contract artifacts

The generated PostgreSQL contract workflow keeps its shared frozen plan at
`run-records/confirmed.json` inside the retained evidence directory. Scanning,
previewing, applying and the positive/negative/final validation stages reuse
that file, and a repeated-apply control verifies refusal without changing the
target snapshot. The fixture confirms the plan automatically only after its
exact expected classifications have been asserted. This automated test
confirmation is separate from a person reviewing and confirming a real
database's plan. The bounded-coverage control uses its own validation policy
and a separate unreviewed record.
