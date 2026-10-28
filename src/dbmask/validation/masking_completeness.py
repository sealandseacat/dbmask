"""Masking-completeness validation (check #3).

Two modes, picked automatically per table:

**Primary-key aligned (preferred).** When source and target share a usable
primary key, rows are matched key-by-key and the sensitive column is compared
value-by-value: any row whose masked value is *identical* to its source value
is a genuine transformation failure. This catches the case the old heuristic
could not — a row where *this* column survived unmasked while some *other*
column changed. Coverage is bounded by ``pk_row_limit`` (in key order) and the
report states explicitly when it was partial. Partial comparisons are WARNINGs,
so strict mode cannot mistake an unchecked tail for verified data.

**Overlap heuristic (fallback, keyless tables).** Without a key there is no
way to say which target row corresponds to which source row, so the check
falls back to the older approach: find values common to both sides, then look
for entire rows that are identical across databases. A clean result here is
reported as a WARNING, not a PASS — "no identical whole rows" is evidence,
not proof, and the report must not claim more than it verified.

Why the heuristic exists at all: with dictionary masking a real value can be
replaced by *another* real value that also occurs in the data (the dictionary
contains both ``Tesla`` and ``Apple``; after masking ``Tesla -> Apple`` and
``Apple -> Tesla``). Column-level "are there common values?" checks scream
"unmasked!" at that, so the row-level comparison is needed to avoid false
alarms. All comparisons run in Python, keeping the check database-agnostic —
source and target can be different engines (e.g. Oracle -> PostgreSQL).

Privacy note: FAIL reports include fully redacted sample values, random report
references and positions in the inspected source key order. Primary-key values
never enter diagnostics; natural keys can themselves be sensitive. References
are local to the report and cannot be used to test guesses about source keys.
"""
from __future__ import annotations

import secrets
from typing import Optional

from dbmask.config import ValidationConfig
from dbmask.connectors.base import Connector
from dbmask.validation.result import Status, ValidationIssue
from dbmask.validation.testdata import is_test_data

# Column types we cannot (or should not) compare directly.
_NONCOMPARABLE_TYPES = ("LOB", "CLOB", "BLOB", "NCLOB", "LONG", "BYTEA", "IMAGE", "XML")


def _redact(value) -> Optional[str]:
    """Preserve length only; punctuation can itself be sensitive data."""
    if value is None:
        return None
    return "*" * len(str(value))


class MaskingCompletenessValidator:
    check_name = "masking_completeness"

    def __init__(self, config: ValidationConfig):
        self.config = config

    # -- entry point -----------------------------------------------------------
    def validate_column(
        self,
        source: Connector,
        target: Connector,
        schema: str,
        table: str,
        column: str,
    ) -> ValidationIssue:
        try:
            key = self._usable_key(source, target, schema, table)
            if key:
                return self._pk_aligned(source, target, schema, table, column, key)
            return self._overlap_heuristic(source, target, schema, table, column)
        except Exception as exc:  # noqa: BLE001
            return ValidationIssue(
                check=self.check_name,
                status=Status.ERROR,
                schema=schema, table=table, column=column,
                message=(
                    "Masking-completeness check failed; inspect database access and "
                    "schema. Exception text and query parameters are suppressed "
                    "because they may contain sensitive values."
                ),
                detail={"error_type": type(exc).__name__},
            )

    def _usable_key(
        self, source: Connector, target: Connector, schema: str, table: str
    ) -> Optional[list[str]]:
        """A primary key usable for row alignment: present and identical on
        both sides. (Key columns are never rewritten by the engine, so key
        values are stable across masking.)"""
        src_pk = source.primary_key_columns(schema, table)
        tgt_pk = target.primary_key_columns(schema, table)
        if src_pk and src_pk == tgt_pk:
            return list(src_pk)
        return None

    # -- preferred: primary-key aligned comparison -----------------------------
    def _collect(
        self, conn: Connector, schema: str, table: str,
        key: list[str], column: str, limit: Optional[int],
    ) -> tuple[dict, bool]:
        rows: dict[tuple, object] = {}
        for page in conn.iter_pages(
            schema, table, key_columns=key, columns=[column], batch_size=1000
        ):
            for r in page:
                # Read one row beyond the budget before claiming truncation.
                # A table with exactly `limit` rows has been checked in full.
                if limit is not None and len(rows) >= limit:
                    return rows, True
                rows[tuple(r[k] for k in key)] = r[column]
        return rows, False

    def _pk_aligned(
        self,
        source: Connector,
        target: Connector,
        schema: str,
        table: str,
        column: str,
        key: list[str],
    ) -> ValidationIssue:
        cfg = self.config
        src_rows, src_trunc = self._collect(source, schema, table, key, column, cfg.pk_row_limit)
        tgt_rows, tgt_trunc = self._collect(target, schema, table, key, column, cfg.pk_row_limit)
        partial = src_trunc or tgt_trunc
        source_only = len(src_rows.keys() - tgt_rows.keys())
        target_only = len(tgt_rows.keys() - src_rows.keys())

        compared = 0
        unmasked = 0
        samples: list[dict] = []
        for source_row_number, (row_key, src_val) in enumerate(src_rows.items(), start=1):
            if row_key not in tgt_rows:
                continue
            compared += 1
            if src_val is None:
                continue
            if cfg.ignore_test_data and is_test_data(src_val):
                continue
            if src_val == tgt_rows[row_key]:
                unmasked += 1
                if len(samples) < 5:
                    samples.append({
                        "row_ref": "row-" + secrets.token_hex(12),
                        "source_row_number": source_row_number,
                        "value": _redact(src_val),
                    })
                if unmasked >= cfg.unmasked_evidence_threshold:
                    break

        coverage = (
            f"partial — first {cfg.pk_row_limit:,} row(s) in key order"
            if partial else "all rows"
        )
        detail = {
            "mode": "pk_aligned",
            "key": key,
            "rows_compared": compared,
            "coverage": coverage,
            "source_rows_inspected": len(src_rows),
            "target_rows_inspected": len(tgt_rows),
            # Counts only: natural keys themselves may contain sensitive data.
            "source_only_keys": source_only,
            "target_only_keys": target_only,
        }

        if unmasked > 0:
            detail["unmasked_rows"] = unmasked
            detail["samples_redacted"] = samples
            return ValidationIssue(
                check=self.check_name,
                status=Status.FAIL,
                schema=schema, table=table, column=column,
                message=(
                    f"{unmasked} row(s) hold a value identical to the source "
                    f"(compared {compared} row(s) aligned on {'+'.join(key)}) — "
                    "these values bypassed masking."
                ),
                detail=detail,
            )

        if source_only or target_only:
            # A bounded prefix cannot establish that a key is absent from the
            # entire other database (different engine collations may order it
            # differently). Full comparisons can establish an actual mismatch.
            return ValidationIssue(
                check=self.check_name,
                status=Status.WARNING if partial else Status.FAIL,
                schema=schema, table=table, column=column,
                message=(
                    f"Primary-key sets differ in the inspected ranges: {source_only} "
                    f"source-only and {target_only} target-only key(s); "
                    f"{compared} row(s) could be aligned. "
                    + ("Coverage is partial; keys outside those ranges were not checked."
                       if partial else "Source and target rows do not match.")
                ),
                detail=detail,
            )

        if not compared:
            return ValidationIssue(
                check=self.check_name,
                status=Status.SKIPPED,
                schema=schema, table=table, column=column,
                message="Both tables are empty; no sensitive values were compared.",
                detail=detail,
            )

        if partial:
            return ValidationIssue(
                check=self.check_name,
                status=Status.WARNING,
                schema=schema, table=table, column=column,
                message=(
                    f"PK-aligned comparison of {compared} row(s): checked values "
                    f"differ from their source, but coverage is {coverage}. "
                    "Remaining rows were not verified; increase validation.pk_row_limit "
                    "or set it to null for a full comparison."
                ),
                detail=detail,
            )

        return ValidationIssue(
            check=self.check_name,
            status=Status.PASS,
            schema=schema, table=table, column=column,
            message=(
                f"PK-aligned comparison of {compared} row(s): every sensitive "
                "value differs from its source."
            ),
            detail=detail,
        )

    # -- fallback: overlap heuristic (no usable primary key) -------------------
    def _comparable_columns(self, source: Connector, target: Connector, schema: str, table: str) -> list[str]:
        """Columns present in BOTH source and target, excluding LOB-like types."""
        try:
            src_cols = source.schema_elements(schema, table)["columns"]
            tgt_cols = target.schema_elements(schema, table)["columns"]
        except Exception:  # noqa: BLE001 - fall back to a plain column list
            common = [c for c in source.list_columns(schema, table)
                      if c in set(target.list_columns(schema, table))]
            return common

        common = []
        for name, type_str in src_cols.items():
            if name not in tgt_cols:
                continue
            upper = str(type_str).upper()
            if any(t in upper for t in _NONCOMPARABLE_TYPES):
                continue
            common.append(name)
        return common

    def _overlap_heuristic(
        self,
        source: Connector,
        target: Connector,
        schema: str,
        table: str,
        column: str,
    ) -> ValidationIssue:
        cfg = self.config

        # 1) Common values (INTERSECT done in Python).
        src_vals = set(source.distinct_values(schema, table, column, cfg.distinct_value_limit))
        tgt_vals = set(target.distinct_values(schema, table, column, cfg.distinct_value_limit))
        common = {v for v in (src_vals & tgt_vals) if v is not None}

        # 2) Drop test-data noise.
        if cfg.ignore_test_data:
            common = {v for v in common if not is_test_data(v)}

        if not common:
            return ValidationIssue(
                check=self.check_name,
                status=Status.PASS,
                schema=schema, table=table, column=column,
                message=(
                    "heuristic (no usable primary key): no value occurs in "
                    "both source and target — nothing survived masking."
                ),
                detail={"mode": "overlap_heuristic"},
            )

        comparable = self._comparable_columns(source, target, schema, table)
        if len(comparable) < 2:
            return ValidationIssue(
                check=self.check_name,
                status=Status.WARNING,
                schema=schema, table=table, column=column,
                message=(
                    f"heuristic (no usable primary key): {len(common)} common "
                    "value(s), but the table has <2 comparable columns — "
                    "cannot run a reliable row-level check."
                ),
                detail={"mode": "overlap_heuristic", "common_values": len(common)},
            )

        # 3) + 4) Row-level comparison for each common value.
        unmasked_rows = 0
        samples: list = []
        checked = 0
        for value in list(common)[: cfg.max_common_values]:
            checked += 1
            src_rows = {
                tuple(r) for r in source.fetch_rows_where(
                    schema, table, comparable, column, value, cfg.max_rows_per_value
                )
            }
            if not src_rows:
                continue
            tgt_rows = {
                tuple(r) for r in target.fetch_rows_where(
                    schema, table, comparable, column, value, cfg.max_rows_per_value
                )
            }
            identical = src_rows & tgt_rows
            if identical:
                unmasked_rows += len(identical)
                if len(samples) < 5:
                    samples.append(_redact(value))
                if unmasked_rows >= cfg.unmasked_evidence_threshold:
                    break

        if unmasked_rows > 0:
            return ValidationIssue(
                check=self.check_name,
                status=Status.FAIL,
                schema=schema, table=table, column=column,
                message=(
                    f"{unmasked_rows}+ identical row(s) across source and "
                    "target — these rows bypassed masking (transformation failure)."
                ),
                detail={
                    "mode": "overlap_heuristic",
                    "unmasked_rows": unmasked_rows,
                    "samples_redacted": samples,
                    "common_values_checked": checked,
                    "comparable_columns": len(comparable),
                },
            )

        # Values coincide but no whole row is identical. With no key to align
        # on, that is *consistent with* correct masking (dictionary swaps) but
        # not proof of it — say so instead of over-claiming.
        return ValidationIssue(
            check=self.check_name,
            status=Status.WARNING,
            schema=schema, table=table, column=column,
            message=(
                f"heuristic (no usable primary key): {len(common)} value(s) "
                "appear on both sides but no identical whole row was found — "
                "consistent with dictionary swaps, yet per-row masking cannot "
                "be verified without a primary key."
            ),
            detail={
                "mode": "overlap_heuristic",
                "common_values": len(common),
                "common_values_checked": checked,
            },
        )
