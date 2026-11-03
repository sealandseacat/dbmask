"""High-level orchestration used by the CLI and as a library entry point."""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from dbmask.config import Config
from dbmask.connectors.base import Connector
from dbmask.connectors.sql import SQLConnector
from dbmask.detection.overrides import FieldOverrides
from dbmask.detection.pipeline import DetectionPipeline, TokenBudgetExceeded
from dbmask.detection.result import Decision, Sensitivity
from dbmask.history.backend import HistoryBackend, history_backend
from dbmask.llm.factory import create_provider
from dbmask.masking.engine import MaskingEngine, TableMaskResult
from dbmask.run_record import RunRecord, config_fingerprint, inventory, target_identity
from dbmask.validation.result import Status, ValidationIssue, ValidationReport
from dbmask.validation.validator import Validator

_LOGGER = logging.getLogger(__name__)


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
        self.last_run_file: Optional[str] = None
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

    # -- persisted plans ------------------------------------------------------
    def create_run(
        self, run_file: Optional[str] = None, scan: Optional[ScanReport] = None,
    ) -> RunRecord:
        """Freeze metadata and resolved strategies, never sample values.

        A plan is a draft until explicitly approved. Automatic legacy masks
        also get records, but are clearly labelled unreviewed.
        """
        if scan is None:
            scan = self.scan()
        scope = inventory(self.connector, self.connector.list_schemas())
        decisions = []
        for d in scan.decisions:
            decisions.append({
                "database": d.database, "schema": d.schema, "table": d.table,
                "column": d.column, "sensitivity": d.sensitivity.value,
                "rule": d.rule, "source": d.source,
                "confidence": d.confidence, "data_type": d.data_type,
                "review_status": d.review_status, "reviewed_by": d.reviewed_by,
                "reviewed_at": d.reviewed_at, "user_id": d.user_id,
                "masking_strategy": self.masker.resolve_strategy(d) if d.is_sensitive else None,
            })
        path = Path(run_file) if run_file else Path(self.config.audit.directory) / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f") + ".json"
        )
        source = None
        if self.config.source_database.url or self.config.source_database.dialect:
            source = target_identity(self.config.source_database)
        record = RunRecord.create(
            path, target=target_identity(self.config.database), source=source,
            config_digest=config_fingerprint(self.config), scope=scope,
            decisions=decisions, scan_error_count=len(scan.errors),
            validation=asdict(self.config.validation),
        )
        self.last_run_file = str(record.path)
        return record

    @staticmethod
    def _record_scan(record: RunRecord) -> ScanReport:
        decisions = [Decision(**item) for item in (
            {**d, "sensitivity": Sensitivity(d["sensitivity"])}
            for d in record.data["plan"]["decisions"]
        )]
        return ScanReport(
            decisions=decisions,
            errors=["Recorded scan error (details suppressed)"]
                   * record.data["plan"]["scan_error_count"],
        )

    def _check_run_scope(self, record: RunRecord) -> None:
        record.check_config(self.config)
        current = inventory(self.connector, self.connector.list_schemas())
        if current != record.data["plan"]["scope"]:
            raise ValueError("Target schema drift: create and review a new plan before proceeding")

    def mask(
        self,
        decisions: Optional[list[Decision]] = None,
        *,
        allow_partial: bool = False,
        run_file: Optional[str] = None,
        remask_reason: Optional[str] = None,
        scan_report: Optional[ScanReport] = None,
    ) -> list[TableMaskResult]:
        """Mask from a frozen plan, recording every committed page.

        Supplying ``run_file`` requires explicit plan approval. Legacy callers
        remain supported and get an automatic, unreviewed run record. The
        shared audit directory must be retained for repeat masking detection.
        """
        if self.config.source_database.url or self.config.source_database.dialect:
            if target_identity(self.config.source_database)["id"] == target_identity(
                self.config.database
            )["id"]:
                raise ValueError("Source and target must be separate databases before masking")
        if run_file is not None:
            if decisions is not None or scan_report is not None:
                raise ValueError("Use either run_file or decisions, not both")
            record = RunRecord.load(run_file)
            self.last_run_file = str(record.path)
            record.require_approved()
            self._check_run_scope(record)
            scan = self._record_scan(record)
        else:
            scan = scan_report if scan_report is not None else (
                self.scan() if decisions is None else ScanReport(decisions=decisions)
            )
            record = self.create_run(scan=scan)
        if scan.errors and not allow_partial:
            raise ScanIncompleteError(
                f"{len(scan.errors)} column(s) could not be analyzed; "
                "unanalyzed columns would be silently left unmasked. "
                "Errors:\n  - " + "\n  - ".join(scan.errors)
            )

        grouped: dict[tuple[str, str], list[Decision]] = {}
        for d in self._record_scan(record).sensitive:
            grouped.setdefault((d.schema, d.table), []).append(d)
        # Fix every effective strategy before touching the first table.
        dry_run = self.config.masking.dry_run
        guard = (record.operation_lock() if dry_run else record.apply_guard(
            self.config.audit.directory, reason=remask_reason,
        ))
        results: list[TableMaskResult] = []
        with guard:
            # All read/modify/write stages share the target lock. Refresh
            # after acquiring it so a stale object cannot erase another run's
            # committed progress.
            record.data = RunRecord.load(record.path).data
            if run_file is not None:
                record.require_approved()
                self._check_run_scope(record)
            previous_execution = record.data["execution"]
            execution: dict[str, Any] = {"status": "previewing" if dry_run else "applying", "tables": []}
            if dry_run:
                record.data.setdefault("previews", []).append(execution)
            else:
                record.data.setdefault("execution_history", []).append(previous_execution)
                if previous_execution.get("repeat_overrides"):
                    execution["repeat_overrides"] = previous_execution["repeat_overrides"]
                record.data["execution"] = execution
            record.save()  # persistence failure here must prevent all updates

            def progress(phase: str, result: TableMaskResult, batch_rows: int) -> None:
                tables = execution["tables"]
                item = next((t for t in tables if (
                    t["schema"], t["table"]
                ) == (result.schema, result.table)), None)
                if item is None:
                    item = {"schema": result.schema, "table": result.table,
                            "committed_batches": 0, "in_flight": False}
                    tables.append(item)
                item.update({
                    "rows_scanned": result.rows_scanned, "rows_written": result.rows_written,
                    "skipped_columns": [p.column for p in result.skipped_columns],
                    "batch_rows": batch_rows, "phase": phase,
                })
                if phase == "before_batch":
                    item["in_flight"] = True
                elif phase == "after_batch":
                    item["in_flight"] = False
                    item["committed_batches"] += 1
                record.save()

            try:
                execution["phase"] = "preflight"
                for (schema, table), table_decisions in grouped.items():
                    execution["active_table"] = {"schema": schema, "table": table,
                                                 "columns": [d.column for d in table_decisions]}
                    self.masker.preflight_table(self.connector, schema, table, table_decisions)
                execution["phase"] = "masking"
                for (schema, table), table_decisions in grouped.items():
                    execution["active_table"] = {"schema": schema, "table": table,
                                                 "columns": [d.column for d in table_decisions]}
                    results.append(self.masker.mask_table(
                        self.connector, schema, table, table_decisions, progress=progress,
                    ))
                execution["phase"] = "completed"
                execution["status"] = "previewed" if dry_run else "applied"
                execution["finished_at"] = datetime.now(timezone.utc).isoformat()
                # Preview progress is separate from apply progress, including
                # on disk: a failed preview cannot erase earlier commits.
                record.save()
            except BaseException as exc:
                execution["status"] = "failed"
                execution["error_type"] = type(exc).__name__
                execution["finished_at"] = datetime.now(timezone.utc).isoformat()
                # If audit storage itself failed, its last durable in_flight
                # marker must remain: do not claim a rollback across stores.
                try:
                    record.save()
                except OSError as audit_error:
                    # Failure recording is best effort. Preserve the original
                    # error without logging values from its chained traceback.
                    _LOGGER.warning(
                        "Could not save failed execution status (%s); "
                        "preserving the original error and last saved checkpoint.",
                        type(audit_error).__name__,
                    )
                raise
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

    def validate(self, run_file: Optional[str] = None) -> ValidationReport:
        """Validate the masked (target) database against the source database.

        Requires ``source_database`` to be configured. Opens its own source
        connection for the duration of the call.
        """
        if not (self.config.source_database.url or self.config.source_database.dialect):
            raise ValueError(
                "validation requires 'source_database' to be configured "
                "(the original, pre-masking database)."
            )

        if run_file is not None:
            return self._validate_run(run_file)

        validator = Validator(self.config.validation)
        schemas = self.connector.list_schemas()
        # History belongs to the target's logical scope, even when the source
        # has a different connection name. Inspect only configured target schemas.
        source_config = replace(
            self.config.source_database, name=self.connector.name, schemas=schemas,
        )
        with SQLConnector(source_config) as source:
            sensitive = None
            scan = ScanReport()
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
        record = self.create_run(scan=scan)
        record.data["validations"].append({
            "status": "passed" if report.passed_strict else "failed",
            "scope_origin": "original_source_scan_unreviewed",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "summary": report.summary(), "passed": report.passed,
            "passed_strict": report.passed_strict,
            "issues": [self._audit_issue(i) for i in report.issues],
        })
        record.save()
        return report

    def _validate_run(self, run_file: str) -> ValidationReport:
        """Compare the original against every frozen sensitive column."""
        record = RunRecord.load(run_file)
        self.last_run_file = str(record.path)
        with record.operation_lock():
            record.data = RunRecord.load(record.path).data
            return self._validate_record(record)

    def _validate_record(self, record: RunRecord) -> ValidationReport:
        attempt: dict[str, Any] = {"started_at": datetime.now(timezone.utc).isoformat(), "status": "running"}
        record.data["validations"].append(attempt)
        record.save()
        try:
            record.require_approved()
            self._check_run_scope(record)
            expected_source = record.data["plan"]["source"]
            actual_source = target_identity(self.config.source_database)
            if expected_source is None or expected_source["id"] != actual_source["id"]:
                raise ValueError("Source identity differs from the frozen plan; review a new plan")
            if actual_source["id"] == record.data["plan"]["target"]["id"]:
                raise ValueError("Source and target must be separate databases")
            scope = record.data["plan"]["scope"]
            schemas = sorted({item["schema"] for item in scope})
            scan = self._record_scan(record)
            sensitive = [(d.schema, d.table, d.column) for d in scan.sensitive]
            with SQLConnector(replace(self.config.source_database, schemas=schemas)) as source:
                if inventory(source, schemas) != scope:
                    raise ValueError("Source schema drift: original no longer matches the frozen scope")
                report = Validator(self.config.validation).validate(
                    source, self.connector, schemas=schemas, sensitive_columns=sensitive,
                )
            for issue in report.issues:
                if (issue.check == "masking_completeness" and issue.status is Status.PASS
                        and issue.detail.get("mode") == "overlap_heuristic"):
                    issue.status = Status.WARNING
                    issue.message += " Bounded overlap heuristics cannot verify every row."
            report.extend(self._classification_coverage(scan, sensitive))
            if record.data["execution"]["status"] != "applied":
                report.add(ValidationIssue(
                    check="run_execution", status=Status.ERROR,
                    message="This run has no completed apply; inspect execution progress before release.",
                ))
            for name in ("check_row_counts", "check_schema_elements", "check_masking_completeness"):
                if not getattr(self.config.validation, name):
                    report.add(ValidationIssue(
                        check="run_coverage", status=Status.ERROR,
                        message=f"Frozen workflow requires {name}; this check was disabled.",
                    ))
            attempt.update({
                "status": "passed" if report.passed_strict else "failed",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "summary": report.summary(), "passed": report.passed,
                "passed_strict": report.passed_strict,
                "sensitive_columns_expected": len(sensitive),
                "sensitive_columns_checked": sum(
                    i.check == "masking_completeness" and bool(i.column) for i in report.issues
                ),
                "issues": [self._audit_issue(i) for i in report.issues],
            })
            record.save()
            return report
        except BaseException as exc:
            attempt.update({"status": "error", "error_type": type(exc).__name__,
                            "finished_at": datetime.now(timezone.utc).isoformat()})
            try:
                record.save()
            except OSError:
                # Best-effort audit persistence: never hide the original failure
                # with a secondary filesystem/storage write error.
                pass
            raise

    @staticmethod
    def _audit_issue(issue: ValidationIssue) -> dict:
        # Schema diffs may include SQL CHECK literals. Keep check location,
        # outcome, counts, coverage and redacted row references only.
        allowed = {"mode", "key", "rows_compared", "coverage", "source_rows_inspected",
                   "target_rows_inspected", "source_only_keys", "target_only_keys",
                   "unmasked_rows", "samples_redacted", "error_type", "element",
                   "common_values", "common_values_checked", "comparable_columns",
                   "classification_source", "columns_analyzed", "difference"}
        item = issue.to_dict()
        item["detail"] = {k: v for k, v in issue.detail.items() if k in allowed
                          or (k in {"source", "target"} and isinstance(v, int))}
        return item
