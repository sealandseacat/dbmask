"""A configured CSV/XLSX/Markdown master, read without modifying its contents."""
from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Optional

from dbmask.detection.result import Decision
from dbmask.history.files import read_history_file
from dbmask.history.records import HistoryConflictError, HistoryRecord, HistoryValidationError


class FileHistoryStore:
    """Reuse exact reviewed scopes; keep this run's suggestions in memory only."""

    def __init__(self, path: str | Path, *, sheet: str = "history"):
        self.path = Path(path).resolve()
        self.sheet = sheet
        self.snapshot = b""
        self.digest = ""
        self.original: dict[str, HistoryRecord] = {}
        self.current: dict[str, HistoryRecord] = {}
        self.suggestions: dict[str, HistoryRecord] = {}

    def connect(self) -> None:
        self.snapshot = self.path.read_bytes()
        records = read_history_file(self.path, sheet=self.sheet)
        if self.path.read_bytes() != self.snapshot:
            raise HistoryConflictError("History source changed while reading; retry")
        self.original = {}
        self.current = {}
        self.suggestions = {}
        for record in records:
            if record.key in self.original:
                raise HistoryConflictError(f"Duplicate source rows for {record.location}")
            self.original[record.key] = record
            self.current[record.key] = record.validated()
        self.digest = hashlib.sha256(self.snapshot).hexdigest()

    def close(self) -> None:
        # The snapshot remains available for the review export after Runner closes.
        pass

    def get(
        self, database: str, schema: str, table: str, column: str,
        *, current_type: Optional[str] = None,
    ) -> Optional[Decision]:
        key = HistoryRecord(database, schema, table, column).key
        record = self.current.get(key)
        if record is None:
            return None
        checked = record.check_applicability(current_type=current_type, check_type=True)
        if checked.review_status != "approved":
            # Export today's declared type for re-review, retaining the old type
            # in the reason when it changed. Reading never rewrites the master.
            checked = replace(checked, data_type=current_type or "")
        self.current[key] = checked
        return checked.as_decision()

    def save(self, decision: Decision) -> None:
        record = HistoryRecord.from_decision(decision)
        self.suggestions[record.key] = record

    def records_for_review(self) -> list[HistoryRecord]:
        return sorted({**self.suggestions, **self.current}.values(),
                      key=lambda r: (r.database, r.schema, r.table, r.column))

    def all_decisions(self) -> list[Decision]:
        return [r.as_decision(suggestion=True) for r in self.records_for_review()]

    def audit_records(self) -> list[dict]:
        raise HistoryValidationError(
            "File history keeps revisions in the master and pre-write .bak snapshots; "
            "--audit is available for SQL history only"
        )

    def __enter__(self) -> FileHistoryStore:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
