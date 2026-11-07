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
| `execution.tables[*].resumed_from_rows` | Rows already committed at the start of a PostgreSQL resume |
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
committed. For applies started without a database checkpoint, inspect that
state and restore an untouched target copy before reapplying.

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

## Resume a PostgreSQL apply

Use an approved plan for a disposable, stable PostgreSQL target. Set
`database.schemas` explicitly (for example, `[public]`) before planning and
keep `dbmask_internal` outside that list. The masking role needs access to
create and write `dbmask_internal.mask_runs_v1` on the target. An administrator
can pre-create the dedicated schema and grant the role `USAGE` and `CREATE`
there. Use a direct PostgreSQL connection or a pooler in session mode.

Keep the same target copy, configuration, seed map, audit directory and
approved run file for the entire operation. Keep the target exclusive to
this run, including between attempts, with stable primary keys and rows.
Resuming checks table row counts and the frozen schema. Changes that preserve
row counts can still invalidate the ordered prefix. Plan to verify the whole
target against the untouched source before using it.

```bash
# First apply on the clean target copy
dbmask mask --config config/dbmask.config.yaml --run-file .dbmask/runs/trial-001.json --apply --resumable

# After a disconnect, once the connection is back
dbmask mask --config config/dbmask.config.yaml --run-file .dbmask/runs/trial-001.json --apply --resume

dbmask validate --config config/dbmask.config.yaml --run-file .dbmask/runs/trial-001.json --strict
```

Each batch's updates and the checkpoint commit together in PostgreSQL. A
rolled-back batch is processed on resume. A committed batch is skipped even
when the local JSON still shows it as in flight. The first read of a partial
table starts after the committed primary-key-ordered prefix and later pages
use keyset pagination. Completed tables are skipped. The target journal
stores only plan identity, table names and row/batch counts.

The database lock serializes resumable applies in the target database. Keep
using the same local audit directory so the existing repeat guard also sees
other tracked applies. If a process was force-terminated, inspect the stale
audit lock and verify that its process has exited before removing that lock.
Preserve the run file and PostgreSQL journal. For a previously interrupted
apply to resume, the matching journal entry must exist in the original target.

On a resumed run, `resumed_from_rows` and `resumed_from_batches` show the
starting point per table. `rows_written` and `committed_batches` are cumulative
totals. The preceding attempt stays in `execution_history`. After apply reaches
`execution.status: applied`, use `validations[-1].passed_strict` to check the
result of the separate strict validation.

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
that file. It terminates a PostgreSQL connection before and after a batch
commit, verifies the resume points and checks that committed rows keep their
original PostgreSQL tuple versions across retries. A repeated-apply control
also verifies refusal. The fixture confirms the plan automatically only after its
exact expected classifications have been asserted. This automated test
confirmation is separate from a person reviewing and confirming a real
database's plan. The bounded-coverage control uses its own validation policy
and a separate unreviewed record.
