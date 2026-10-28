"""Row-count validation (check #1).

The simplest, fastest sanity check: every table should have the **same number
of rows** in the source (original) and target (masked) databases. Masking only
*changes values*; it must never add or drop rows. A mismatch usually means the
ETL job failed partway, filtered rows, or duplicated them.
"""
from __future__ import annotations

from dbmask.connectors.base import Connector
from dbmask.validation.result import Status, ValidationIssue


class RowCountValidator:
    check_name = "row_count"

    def validate_table(
        self, source: Connector, target: Connector, schema: str, table: str
    ) -> ValidationIssue:
        try:
            src = source.row_count(schema, table)
            tgt = target.row_count(schema, table)
        except Exception as exc:  # noqa: BLE001
            return ValidationIssue(
                check=self.check_name,
                status=Status.ERROR,
                schema=schema,
                table=table,
                message=(
                    "Could not count rows; inspect database access and schema. "
                    "Exception text and query parameters are suppressed "
                    "because they may contain sensitive values."
                ),
                detail={"error_type": type(exc).__name__},
            )

        if src == tgt:
            return ValidationIssue(
                check=self.check_name,
                status=Status.PASS,
                schema=schema,
                table=table,
                message=f"Row counts match ({src:,}).",
                detail={"source": src, "target": tgt},
            )
        return ValidationIssue(
            check=self.check_name,
            status=Status.FAIL,
            schema=schema,
            table=table,
            message=f"Row count mismatch: source={src:,} target={tgt:,} (diff {tgt - src:+,}).",
            detail={"source": src, "target": tgt, "difference": tgt - src},
        )
