"""Schema-element validation (check #2).

Masking copies data, but the *structure* of the target should still match the
source: same columns/types, primary key, indexes, foreign keys, and unique/check
constraints. If the ETL or a manual copy dropped an index or a constraint, this
check catches it.

What is compared (portably, via SQLAlchemy):
  columns (name + type), primary key, indexes, foreign keys,
  unique constraints, check constraints.

Triggers and grants are **not** compared here because SQLAlchemy has no portable
way to read them. The framework leaves a clear slot for them — override
``Connector.schema_elements`` per dialect to include them, and they will be
compared automatically.
"""
from __future__ import annotations

from dbmask.connectors.base import Connector
from dbmask.validation.result import Status, ValidationIssue

# Friendly labels for each structural element we compare.
_ELEMENTS = {
    "columns": "columns/types",
    "primary_key": "primary key",
    "indexes": "indexes",
    "foreign_keys": "foreign keys",
    "unique_constraints": "unique constraints",
    "check_constraints": "check constraints",
}


class SchemaElementValidator:
    check_name = "schema_elements"

    def validate_table(
        self, source: Connector, target: Connector, schema: str, table: str
    ) -> list[ValidationIssue]:
        try:
            src = source.schema_elements(schema, table)
            tgt = target.schema_elements(schema, table)
        except Exception as exc:  # noqa: BLE001
            return [
                ValidationIssue(
                    check=self.check_name,
                    status=Status.ERROR,
                    schema=schema,
                    table=table,
                    message=(
                        "Could not read schema elements; inspect database access and schema. "
                        "Exception text and query parameters are suppressed "
                        "because they may contain sensitive values."
                    ),
                    detail={"error_type": type(exc).__name__},
                )
            ]

        issues: list[ValidationIssue] = []
        for key, label in _ELEMENTS.items():
            src_val = src.get(key)
            tgt_val = tgt.get(key)
            if src_val == tgt_val:
                issues.append(
                    ValidationIssue(
                        check=self.check_name,
                        status=Status.PASS,
                        schema=schema,
                        table=table,
                        message=f"{label} match.",
                        detail={"element": key},
                    )
                )
            else:
                issues.append(
                    ValidationIssue(
                        check=self.check_name,
                        status=Status.FAIL,
                        schema=schema,
                        table=table,
                        message=f"{label} differ between source and target.",
                        detail={"element": key, "source": src_val, "target": tgt_val},
                    )
                )
        return issues
