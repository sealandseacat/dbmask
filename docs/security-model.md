# Security model & limitations

dbmask reduces the blast radius of copying production data. Used correctly
it removes the obvious re-identification paths — but **masking is not
anonymization**, and this page is explicit about where the line is.

## What dbmask defends against

- **Casual exposure**: developers, analysts, demo audiences, vendors and
  LLM pipelines seeing real names, emails, identifiers, card numbers.
- **Data-breach amplification**: a leaked staging or analytics copy that
  would otherwise be as bad as leaking production.
- **Silent process failure**: the scan/mask/validate loop is built to fail
  closed and to make "this was not masked" impossible to miss — that is a
  security property as much as a UX one.

## What it does NOT defend against

### Determinism is attackable for guessable values

Masking is deterministic by design (that is what keeps joins working). The
consequence: anyone who knows `masking.seed` **and can guess a candidate
value** can recompute its mask and test for its presence. Mitigations:

- set a private `masking.seed` (the CLI warns on the public default);
- set the seed-map salt from the environment
  (`salt: ${DBMASK_SEED_SALT}`), so the store alone cannot be probed;
- treat the seed, the salt, the history DB and the seed-map DB as
  **operational secrets** — they reveal which columns are sensitive and how
  values map between environments, even though they contain no originals.

### Linkage and inference re-identification

Consistent fakes preserve the *structure* of the data — that is the point.
Structure itself can re-identify: a masked row that is still "the only
customer in ZIP 47374 with 41 orders" is findable regardless of the fake
name. If your threat model includes a motivated adversary joining against
outside data, you need aggregation/generalization/differential-privacy
techniques on top of (or instead of) masking. dbmask does not claim to
provide them.

### Free text

Column-level detection cannot see a phone number buried in a `notes` field
of otherwise harmless text. The safe treatments for free text are blunt:
`blank`, `null`, or `redact`, chosen explicitly per column
(`masking.column_strategies`).

### Primary-key columns

Key columns are never rewritten (row addressing and foreign keys depend on
them). dbmask refuses and **announces** this; if the key itself is sensitive
(emails as natural keys, national IDs), restructure before sharing, or
exclude those tables.

### Generated and identity-managed columns

Unselected generated fields can recompute from masked inputs; the engine does
not include them in UPDATE assignments. A selected generated or identity-managed
field aborts metadata preflight before target-table writes. Identity masking is
deliberately unsupported even for BY DEFAULT identities writable on some engines.
Reflection is not a complete permission/trigger check or a rollback mechanism.
See [column writability](strategies.md#generated-and-identity-managed-columns).

### Diagnostic output

Validation samples use random report-local references and source row positions
instead of raw primary-key values, and fully redact sample content. Caught
validation errors and provider-request errors suppress raw exception text.
Reports still expose operational metadata such as schema names, counts and
value lengths. Protect reports and inspect other runtime/database exceptions
before sharing logs; `--show-values` deliberately displays original data.

### Derived and residual signals

Aggregates, string lengths kept by format-preserving strategies, row order,
timestamps outside the masked columns, database logs, backups of the
pre-masked copy — all can leak. Masking one column list is not a data
governance program.

## Operational rules

1. **Mask a copy, never production.** `mask --apply` rewrites in place.
2. **Review every `UNKNOWN` column** before treating a copy as safe.
3. **Gate on `validate --strict`** in the pipeline that publishes the copy.
4. Keep seed/salt in a secret manager; keep history & seed-map databases
   with the same care as the masked data itself.
5. When using an external LLM provider, decide consciously:
   `llm.send_values: false`, a local model, or acceptance of that egress
   (dbmask warns either way — see [LLM detection](llm.md)).

## Reporting

Think you can defeat one of the guarantees above — recover an original from
a seed map, produce a "PASSED" validation over surviving data, make a
strategy echo its input? That is a vulnerability. Please report it privately:
[SECURITY.md](https://github.com/sealandseacat/dbmask/blob/main/SECURITY.md).
