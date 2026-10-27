"""High-level orchestration used by the CLI and as a library entry point."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Optional

from dbmask.config import Config
from dbmask.connectors.base import Connector
from dbmask.connectors.sql import SQLConnector
from dbmask.detection.overrides import FieldOverrides
from dbmask.detection.pipeline import DetectionPipeline, TokenBudgetExceeded
from dbmask.detection.result import Decision
from dbmask.history.backend import HistoryBackend, history_backend
from dbmask.llm.factory import create_provider
from dbmask.masking.engine import MaskingEngine, TableMaskResult
from dbmask.validation.result import Status, ValidationIssue, ValidationReport
from dbmask.validation.validator import Validator


class ScanIncompleteError(RuntimeError):
    """Raised when masking would run on top of an incomplete scan.

    If any column failed to be analyzed, that column has no decision — and a
    column without a decision is silently left unmasked. For a tool whose job
    is to remove sensitive data, that must be an explicit choice, never a
    default, so masking fails closed unless the caller opts in.
    """


@dataclass
class ScanReport:
    decisions: list[Decision] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def sensitive(self) -> list[Decision]:
        return [d for d in self.decisions if d.is_sensitive]

    @property
    def unknown(self) -> list[Decision]:
        """Columns the pipeline could not classify — they will NOT be masked."""
        from dbmask.detection.result import Sensitivity

        return [d for d in self.decisions if d.sensitivity is Sensitivity.UNKNOWN]


class Runner:
    """Wires together connector, history, detection pipeline and masking."""

    def __init__(self, config: Config):
        self.config = config
        self.connector = SQLConnector(config.database)
        self.history: Optional[HistoryBackend] = (
            history_backend(config.history) if config.history.enabled else None
        )
        overrides = FieldOverrides.load(config.detection.overrides_file)
        llm = create_provider(config.llm)
        self.pipeline = DetectionPipeline(
            config=config,
            history=self.history,
            overrides=overrides,
            llm=llm,
        )
        self.masker = MaskingEngine(config.masking, date_order=config.detection.date_order)

    # -- lifecycle ------------------------------------------------------------
    def open(self) -> None:
        self.connector.connect()
        if self.history is not None:
            try:
                self.history.connect()
            except Exception:
                self.close()
                raise

    def close(self) -> None:
        self.connector.close()
        if self.history is not None:
            self.history.close()
        self.masker.close()

    def __enter__(self) -> Runner:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # -- operations -----------------------------------------------------------
    def scan(self) -> ScanReport:
        """Classify every column in the configured schemas."""
        return self._scan(self.connector, self.pipeline)

    def _scan(self, connector: Connector, pipeline: DetectionPipeline) -> ScanReport:
        """Use the same scope and error handling for target and source scans."""
        report = ScanReport()
        for schema in connector.list_schemas():
            for table in connector.list_tables(schema):
                if pipeline.should_skip_table(table):
                    continue
                for column in connector.list_columns(schema, table):
                    try:
                        decision = pipeline.analyze_column(
                            connector, schema, table, column
                        )
                        report.decisions.append(decision)
                    except TokenBudgetExceeded as exc:
                        report.errors.append(str(exc))
                        return report
                    except Exception as exc:  # keep going on per-column failures
                        report.errors.append(f"{schema}.{table}.{column}: {exc}")
        return report

    def mask(
        self,
        decisions: Optional[list[Decision]] = None,
        *,
        allow_partial: bool = False,
    ) -> list[TableMaskResult]:
        """Mask all sensitive columns. Runs a scan first if not given decisions.

        Fails closed: if the internal scan could not analyze every column,
        a :class:`ScanIncompleteError` is raised instead of silently masking
        only the columns that happened to scan cleanly. Pass
        ``allow_partial=True`` (CLI: ``--allow-partial``) to accept a partial
        scan explicitly.
        """
        if decisions is None:
            report = self.scan()
            if report.errors and not allow_partial:
                raise ScanIncompleteError(
                    f"{len(report.errors)} column(s) could not be analyzed; "
                    "unanalyzed columns would be silently left unmasked. "
                    "Errors:\n  - " + "\n  - ".join(report.errors)
                )
            decisions = report.decisions

        # Group sensitive decisions by (schema, table).
        grouped: dict[tuple[str, str], list[Decision]] = {}
        for d in decisions:
            if d.is_sensitive:
                grouped.setdefault((d.schema, d.table), []).append(d)

        results: list[TableMaskResult] = []
        for (schema, table), table_decisions in grouped.items():
            results.append(
                self.masker.mask_table(self.connector, schema, table, table_decisions)
            )
        return results

    # -- validation -----------------------------------------------------------
    def _sensitive_columns(self, scan: ScanReport) -> list[tuple[str, str, str]]:
        """Find sensitive columns to validate.

        An explicit list fixes the value-check scope. Otherwise use a scan of
        the original source (including applicable reviewed history), never a
        reclassification of data that has already been masked.
        """
        explicit = self.config.validation.columns
        if explicit:
            out: list[tuple[str, str, str]] = []
            for entry in explicit:
                parts = entry.split(".")
                if len(parts) != 3 or not all(parts):
                    raise ValueError("validation.columns entries must be schema.table.column")
                out.append((parts[0], parts[1], parts[2]))
            return out
        return [(d.schema, d.table, d.column) for d in scan.sensitive]

    def _classification_coverage(
        self, scan: ScanReport, sensitive: list[tuple[str, str, str]],
    ) -> list[ValidationIssue]:
        """Unresolved source columns cannot disappear behind a narrower list."""
        from dbmask.detection.result import Sensitivity

        issues: list[ValidationIssue] = []
        selected = set(sensitive)
        if scan.errors:
            issues.append(ValidationIssue(
                check="classification_coverage", status=Status.ERROR,
                message=(
                    f"Source classification was incomplete ({len(scan.errors)} error(s)); "
                    "scan the untouched source to investigate before sharing the copy."
                ),
            ))
        for d in scan.decisions:
            location = (d.schema, d.table, d.column)
            message = ""
            if d.sensitivity is Sensitivity.UNKNOWN:
                # Listing a column explicitly declares it sensitive for value
                # comparison, but never overrides a pending/invalid review.
                if location in selected and d.source != "history_pending":
                    continue
                message = (
                    "Source column has an unresolved classification or review; "
                    "classify it with an override or applicable approved history. "
                    "It cannot be treated as verified."
                )
            elif d.is_sensitive and location not in selected:
                message = (
                    "Sensitive source column is outside validation.columns and "
                    "was not checked; include it before treating the copy as verified."
                )
            if message:
                issues.append(ValidationIssue(
                    check="classification_coverage", status=Status.WARNING,
                    schema=d.schema, table=d.table, column=d.column, message=message,
                    detail={"classification_source": d.source},
                ))
        if not issues:
            issues.append(ValidationIssue(
                check="classification_coverage", status=Status.PASS,
                message=(
                    "Every source column in detection scope is classified or explicitly "
                    "selected for value comparison; no unresolved reviews remain."
                ),
                detail={"columns_analyzed": len(scan.decisions)},
            ))
        return issues

    def validate(self) -> ValidationReport:
        """Validate the masked (target) database against the source database.

        Requires ``source_database`` to be configured. Opens its own source
        connection for the duration of the call.
        """
        if not (self.config.source_database.url or self.config.source_database.dialect):
            raise ValueError(
                "validation requires 'source_database' to be configured "
                "(the original, pre-masking database)."
            )

        validator = Validator(self.config.validation)
        schemas = self.connector.list_schemas()
        # History belongs to the target's logical scope, even when the source
        # has a different connection name. Inspect only configured target schemas.
        source_config = replace(
            self.config.source_database, name=self.connector.name, schemas=schemas,
        )
        with SQLConnector(source_config) as source:
            sensitive = None
            coverage: list[ValidationIssue] = []
            if self.config.validation.check_masking_completeness:
                pipeline = DetectionPipeline(
                    config=self.config, history=self.history,
                    overrides=self.pipeline.overrides, patterns=self.pipeline.patterns,
                    llm=None, persist_suggestions=False,
                )
                scan = self._scan(source, pipeline)
                sensitive = self._sensitive_columns(scan)
                coverage = self._classification_coverage(scan, sensitive)
            report = validator.validate(
                source=source,
                target=self.connector,
                schemas=schemas,
                sensitive_columns=sensitive,
            )
        report.extend(coverage)
        return report
