"""High-level orchestration used by the CLI and as a library entry point."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from dbmask.config import Config
from dbmask.connectors.sql import SQLConnector
from dbmask.detection.overrides import FieldOverrides
from dbmask.detection.pipeline import DetectionPipeline, TokenBudgetExceeded
from dbmask.detection.result import Decision
from dbmask.history.backend import HistoryBackend, history_backend
from dbmask.llm.factory import create_provider
from dbmask.masking.engine import MaskingEngine, TableMaskResult
from dbmask.validation.result import ValidationReport
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
        report = ScanReport()
        for schema in self.connector.list_schemas():
            for table in self.connector.list_tables(schema):
                if self.pipeline.should_skip_table(table):
                    continue
                for column in self.connector.list_columns(schema, table):
                    try:
                        decision = self.pipeline.analyze_column(
                            self.connector, schema, table, column
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
    def _sensitive_columns(self) -> list[tuple[str, str, str]]:
        """Find sensitive columns to validate.

        Priority: explicit ``validation.columns`` -> the history store ->
        a fresh scan.
        """
        explicit = self.config.validation.columns
        if explicit:
            out: list[tuple[str, str, str]] = []
            for entry in explicit:
                parts = entry.split(".")
                if len(parts) == 3:
                    out.append((parts[0], parts[1], parts[2]))
            return out

        if self.history is not None:
            cols = [
                (d.schema, d.table, d.column)
                for d in self.history.all_decisions()
                if d.is_sensitive and d.database == self.connector.name
            ]
            if cols:
                return cols

        # Fall back to a fresh scan of the (masked) target database.
        return [(d.schema, d.table, d.column) for d in self.scan().sensitive]

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
        sensitive = (
            self._sensitive_columns()
            if self.config.validation.check_masking_completeness
            else None
        )
        schemas = self.connector.list_schemas()

        with SQLConnector(self.config.source_database) as source:
            return validator.validate(
                source=source,
                target=self.connector,
                schemas=schemas,
                sensitive_columns=sensitive,
            )
