# Mixed-format masking demo (issue #36)

From a source checkout with dbmask installed, run:

```bash
python examples/issue36_demo.py
```

Each run creates a fresh `issue36-demo-*` folder in the current directory and
prints the paths to `before.csv`, `after.csv` and `verification.json`. No Ollama,
API key, external database or spreadsheet editing is required. This focused
masking demo uses an explicit reviewed plan; it does not demonstrate LLM
accuracy or the historical-file review/writeback workflow.

The six synthetic rows include numeric and English-month dates, timestamps,
phones, full/spaced/partial SSNs, IPv4/IPv6 addresses, credit cards and known missing
markers. The script creates an untouched `original.db` and a separate
`masked.db`, checks that preview leaves the target unchanged, applies the plan,
runs strict post-masking validation, and independently checks every demo cell:

- Every useful sensitive value changes and stays nonempty and format-valid.
- Date layout/time suffixes remain intact and SSN last-four digits change.
- Only allowlisted markers become SQL NULL. Real NULLs and blanks remain missing.
- Row count, primary keys, account status and the original database remain intact.

`pattern_evidence.json` retains the actual tiny fixture's sample evidence. Some
columns are inconclusive at normal detection thresholds; `reviewed_fields.yaml`
records the explicit demo decisions. The script does not lower the production
threshold or claim all columns were automatically identified.
The pattern catalogue remains IPv4-only; this demo's reviewed IP plan exercises
the existing IPv6 masking support and checks IP validity independently.

The generated `config.yaml` shows the per-column policy:

```yaml
masking:
  null_placeholders:
    - schema: main
      table: customers
      column: date_of_birth
      values: ["NULL", "null", "N/A", "n/a", "-", "???", "unknown", "TBD"]
```

Each exact column needs its own entry. Markers match case-sensitively after
trimming surrounding whitespace. The list is a deliberate choice for this
fixture, not a global list of values that dbmask assumes safe. Columns must
allow NULL. Unknown nonempty invalid values still fail strict masking.

In CSV, both SQL NULL and an empty string display as an empty field; the
SQLite files and `verification.json` retain the distinction. UTF-8 BOM encoding
makes the CSV files convenient to open in Excel on Windows.

To choose the output directory explicitly:

```bash
python examples/issue36_demo.py --output issue36-output
```

That directory must not already exist. Reusing a completed output directory
fails without overwriting files. Re-run without `--output` for another fresh
demo. Real deployments still need a reviewed plan and a fresh test copy;
masking commits in batches and does not promise database-wide rollback.
