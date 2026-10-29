# PostgreSQL: generated data and independent checks

The PostgreSQL contract creates matching synthetic source and target databases,
runs the public scan → preview → apply → strict-validation CLI, and independently
checks the observed database contents. Every run starts from new databases.
No production data, external LLM or downloaded dataset is needed.

The existing [three-row Ota workflow](https://github.com/sealandseacat/dbmask/actions/runs/40892527475)
passed on main commit `c9f1674`. That is bounded smoke evidence, not a large-table
capacity claim. The separate workflow described here adds repeatable larger
tests; claim a scale as verified only after retaining its successful run report.

## Run in GitHub Actions

The **PostgreSQL contract (16 / py3.12)** job runs on pull requests and pushes to
main. It generates **10,001 customers and 10,001 orders** and runs the integration
test with mapping persistence disabled. Failures are not ignored. The ordinary
SQLite test matrix and the advisory Ota workflow remain separate.

For a newly added workflow, first open a pull request: its automatic 10,001-row
job is the initial verification. Merge only after reviewing its actual result.
The manual dispatch entry becomes available after the workflow reaches the
default branch.

To measure a larger scale after that, open **Actions → PostgreSQL contract → Run workflow**.
Select the desired branch, rows per table (`10001`, `100001` or `200001`), and
whether to persist mappings (`on` or `off`). Manual runs default to `on`, matching
the application's default. For example, `100001` means 200,002 database rows
across the two tables, not 100,001 rows in total. Compare timings only when the
environment, schema and mapping mode match.

Download the `dbmask-postgres-contract-…` artifact even when a run fails. Read
`run/report.json` and the stage logs to distinguish a contract failure from setup or
connection failure. A passing run must contain the expected checks and full
coverage; a missing service, missing driver, empty test selection or skipped
integration test is not an acceptable result in the dedicated job.

A red job makes the workflow fail, but preventing merges also requires a
repository rule that marks **PostgreSQL contract (16 / py3.12)** as required.
This patch does not change repository rules or add a release-publishing gate.

## What the fixture tests

Both databases contain the same deterministic, synthetic records:

- `customers`: integer primary key, unique non-sensitive customer reference,
  name, email, phone, date of birth, status and credit limit.
- `orders`: a composite primary key, a real foreign key to customers, contact
  email, quantity and price, and an unselected generated total.
- Real UNIQUE and CHECK constraints and an index, with NULLs and repeated
  values deliberately placed in the fixture.

Every column has an explicit reviewed sensitivity decision. The test therefore
measures database reading, masking and validation rather than detection
precision or model quality. The LLM and history are disabled. Full validation
uses `validation.pk_row_limit: null`, avoiding the default 5,000-row budget.

Independent SQL checks require that the source stays unchanged, target keys and
non-sensitive fields stay unchanged, every eligible sensitive value changes,
NULLs retain the intended meaning, repeated emails map consistently, and orders
still join to customers. Metadata and actual constraint behavior are checked
separately from dbmask's own report.

After the positive run, separate negative controls temporarily:

1. Restore only the original email at row 5,001.
2. Restore only the original email at the last row.
3. Remove one order.
4. Replace an order key while preserving the row count.
5. Remove the real UNIQUE constraint.

Each control must cause the expected strict-validation refusal, including the
relevant check and location. A generic error does not count as discovering the
fault. Each mutation is restored before the next control; the runner verifies
that the positive target state has been restored.

## Local execution

Use an isolated, disposable PostgreSQL service. The runner deliberately requires
local URLs, its dedicated synthetic account and exact database names. It drops
and recreates those two databases; the explicit reset flag is mandatory. Never
point it at an existing business database or reuse production credentials.

From a fresh repository checkout, after installing `.[dev,postgres]`, start the
same fixed service image used in CI (Docker must already be running):

```bash
docker run --name dbmask-contract-pg \
  -e POSTGRES_USER=dbmask \
  -e POSTGRES_PASSWORD=dbmask-contract-only \
  -e POSTGRES_DB=postgres \
  -p 127.0.0.1:5432:5432 -d \
  postgres@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297
docker exec dbmask-contract-pg pg_isready -U dbmask -d postgres
```

Wait for `accepting connections`. If port 5432 is occupied, use Actions rather
than changing or deleting the existing server. Set the disposable connections
and run the script (bash syntax):

```bash
export DBMASK_CONTRACT_SOURCE_URL='postgresql+psycopg2://dbmask:dbmask-contract-only@localhost:5432/dbmask_contract_source'
export DBMASK_CONTRACT_TARGET_URL='postgresql+psycopg2://dbmask:dbmask-contract-only@localhost:5432/dbmask_contract_target'
python scripts/postgres_contract.py --rows 10001 --seed-map off \
  --output postgres-contract-evidence --allow-reset-disposable-databases
```

For PowerShell, use `$env:DBMASK_CONTRACT_SOURCE_URL = "…"` and the corresponding
target variable; put the Python command on one line. Change `--rows` to `100001`
or `200001` for the scale runs and record `--seed-map` in comparisons. A failed
apply can leave committed earlier batches; always restart through the runner,
which recreates the disposable pair, rather than applying again to the old
target. Stop the container when finished: `docker stop dbmask-contract-pg`.

## Evidence and limits

The report records the requested scale, observed row/check counts, source
commit and working-tree state, fixture/config identifiers, Python/driver/server
versions, mapping mode, stage durations, positive validation and expected versus
observed negative results. Python worker peak memory is process memory only:
it excludes the PostgreSQL server and is reported as unavailable where the
platform cannot measure it. It is not a database memory benchmark.

These tests use PostgreSQL 16.10, Python 3.12 and psycopg2 on Linux in CI. They
do not establish support for all PostgreSQL versions, all column types, every
schema, sensitive primary-key rewriting, cascading sensitive relationship-key
updates, trigger/grant preservation, other database engines, installed-wheel
behavior, or production workloads. The current implementation writes rows
individually and full validation retains keys and values for one sensitive
column at a time; capacity and acceptable duration must come from measured
runs, not the absence of an explicit row cap.
