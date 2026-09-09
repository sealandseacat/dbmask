# Configuration

Two YAML files that work as a pair:

- the **main config** — connection, detection, history, LLM, masking,
  validation. Copy
  [`config/dbmask.config.example.yaml`](https://github.com/sealandseacat/dbmask/blob/main/config/dbmask.config.example.yaml)
  and edit; every option is commented there too.
- the **field overrides file** — your manual sensitive/safe toggles,
  referenced from the main config via `detection.overrides_file`. Copy
  [`config/dbmask.fields.example.yaml`](https://github.com/sealandseacat/dbmask/blob/main/config/dbmask.fields.example.yaml).

Any string value can use `${ENV_VAR}` (or `${ENV_VAR:default}`) placeholders,
so credentials never live in the file:

```yaml
database:
  password: ${DB_PASSWORD}
```

## `database` — what to scan/mask

Either a full SQLAlchemy URL, or parts and dbmask builds it:

```yaml
database:
  url: "postgresql+psycopg2://user:${DB_PASSWORD}@staging-host:5432/mydb"
  # -- or --
  dialect: postgresql        # postgresql | mysql | mssql | oracle | sqlite | ...
  driver: psycopg2
  host: staging-host
  port: 5432
  username: myuser
  password: ${DB_PASSWORD}
  database: mydb
  name: mydb                 # logical name used in history/reports
  schemas: []                # empty = all visible schemas
  connect_args: {}           # passed to SQLAlchemy create_engine
```

!!! danger "Point this at a copy"
    `mask --apply` rewrites this database in place. It must be the staging /
    snapshot copy — never production.

## `source_database` — the original (for `validate`)

Same shape as `database`. Only used by `dbmask validate`, which compares the
masked database against this untouched original.

## `detection`

```yaml
detection:
  sample_size: 100              # distinct values sampled per column for patterns
  pattern_min_ratio: 0.9        # inclusive; raw match ratio, no weights
  pattern_min_samples: 20       # nonblank sampled values needed for a suggestion
  date_order: MDY               # MDY (US default) or explicitly DMY
  use_patterns: true
  use_history: true
  user_id: analyst-001          # analysis author, separate from reviewer
  overrides_file: config/dbmask.fields.yaml
  skip_column_patterns: []      # regex, case-insensitive: [".*_id$"]
  skip_table_patterns: []       # ["^tmp_", "_bkp$"]
```

Ratios and supported formats are described in [Pattern detection](detection.md).
Small synthetic demos may explicitly lower `pattern_min_samples`; the production
default is 20. A strong context conflict is held for a person even when the LLM
is enabled. Other inconclusive evidence may use the optional LLM fallback.

### Field overrides

The overrides file always wins over every automatic layer:

```yaml
sensitive:
  - match: "public.customers.email"   # exact schema.table.column
    rule: email
  - match: "ssn"                      # this column name anywhere
    rule: ssn
  - match: "pattern:*_password"       # glob on column names
    rule: redact
  - "date_of_birth"                   # shorthand: sensitive, rule auto-picked

not_sensitive:
  - match: "public.orders.order_number"
    note: "Looks like an ID but is safe"
```

Match precedence: `schema.table.column` → `table.column` → `column` →
`pattern:` globs.

## `history`

Automatic results are stored as pending suggestions and re-analyzed on later
runs. Only approved, applicable imported records are reused. Imported pending
or invalidated records hold a column for review instead of falling through to
automatic classification. See [Historical decisions](history.md) for the file
schema, review workflow, revisions and migration.

```yaml
history:
  enabled: true
  url: "sqlite:///dbmask_history.db"   # any SQLAlchemy URL
```

## `llm`

Optional fallback for columns the patterns cannot decide — see
[LLM detection](llm.md) for providers, local setups, and the privacy
controls (`send_values: false` metadata-only mode).

## `masking`

```yaml
masking:
  dry_run: true                     # library default; the CLI enforces --apply anyway
  seed: ${DBMASK_SEED}              # PRIVATE seed -> deterministic masking
  default_strategy: format_random
  column_strategies:                # after an explicit reviewed history strategy
    notes: blank
    public.users.bio: redact
  rule_strategies:                  # per detected rule
    email: fake_email
    credit_card: fake_credit_card
  seed_map:
    enabled: true
    url:                            # blank = sqlite:///dbmask_seedmap.db
    salt: ${DBMASK_SEED_SALT}       # keep the salt out of the store
    untracked_strategies: ["null", "blank", "redact"]
```

Strategy resolution order and the full catalogue:
[Masking strategies](strategies.md). Durable consistency:
[The seed map](seed-map.md).

## `validation`

```yaml
validation:
  enabled: true
  check_row_counts: true
  check_schema_elements: true
  check_masking_completeness: true
  pk_row_limit: 5000            # rows compared per column (PK-aligned mode)
  distinct_value_limit: 5000    # ┐
  max_common_values: 100        # │ fallback heuristic tuning
  max_rows_per_value: 50        # │ (keyless tables only)
  unmasked_evidence_threshold: 10  # ┘
  ignore_test_data: true        # skip 'test', 'n/a', single chars, ...
  columns: []                   # explicit list, or empty = from history/scan
    # - public.customers.email
```

What each check proves — and what it can't: [Validation](validation.md).

## CLI flags worth knowing

| Command | Flag | Effect |
|---|---|---|
| `mask` | `--apply` | actually write (otherwise always a dry run) |
| `mask` | `--allow-partial` | proceed despite scan errors (unscanned columns stay unmasked) |
| `mask` | `--show-values` | show original values in the preview instead of redacting |
| `scan`/`mask` | — | non-zero exit on scan errors (3 / 2) |
| `validate` | `--strict` | warnings and skipped checks also fail |
| `scan`/`validate`/`seeds` | `--json` | machine-readable output |
