"""Historical decision store.

Machine suggestions and reviewed decisions are stored separately. On later runs we *first*
consult approved history: only an applicable reviewed decision is reused
instead of re-asking patterns/LLM. This makes results reproducible and keeps
masking consistent (the same column always gets the same rule).

The store is itself just a database (SQLite by default, but any SQLAlchemy URL
works), so it is portable and easy to inspect/audit.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from dbmask.detection.result import Decision, Sensitivity
from dbmask.history.records import HistoryConflictError, HistoryRecord

_metadata = MetaData()

decisions_table = Table(
    "dbmask_decisions",
    _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("col_key", String(1024), nullable=False),
    Column("database", String(256)),
    Column("schema", String(256)),
    Column("table", String(256)),
    Column("column", String(256)),
    Column("sensitivity", String(32)),
    Column("rule", String(128), nullable=True),
    Column("source", String(32)),
    Column("confidence", Float),
    Column("detail", Text),
    Column("token_usage", Integer, default=0),
    Column("decided_at", DateTime),
    Column("updated_at", DateTime),
    UniqueConstraint("col_key", name="uq_dbmask_col_key"),
)

# New tables leave the legacy schema and its original evidence untouched.
reviewed_table = Table(
    "dbmask_reviewed_history", _metadata,
    Column("col_key", String(64), primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("payload", Text, nullable=False),
)
audit_table = Table(
    "dbmask_history_audit", _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("col_key", String(64), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("payload", Text, nullable=False),
    Column("recorded_at", DateTime, nullable=False),
)
suggestions_table = Table(
    "dbmask_history_suggestions", _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("col_key", String(64), nullable=False),
    Column("payload", Text, nullable=False),
)


class HistoryStore:
    """Transactional imports, exact scope, revisions, and reviewed-only reuse."""

    def __init__(self, url: str = "sqlite:///dbmask_history.db"):
        self.url = url
        self.engine: Optional[Engine] = None

    def connect(self) -> None:
        self.engine = create_engine(self.url)
        _metadata.create_all(self.engine)

    def close(self) -> None:
        if self.engine is not None:
            self.engine.dispose()
            self.engine = None

    def _require(self) -> Engine:
        if self.engine is None:
            raise RuntimeError("HistoryStore not connected. Call connect() first.")
        return self.engine

    def get(
        self, database: str, schema: str, table: str, column: str,
        *, current_type: Optional[str] = None,
    ) -> Optional[Decision]:
        key = HistoryRecord(database, schema, table, column).key
        with self._require().connect() as conn:
            payload = conn.execute(
                select(reviewed_table.c.payload).where(reviewed_table.c.col_key == key)
            ).scalar_one_or_none()
        if payload is None:
            # Legacy automatic results and new suggestions never authorize reuse.
            return None
        record = HistoryRecord(**json.loads(payload))
        checked = record.check_applicability(current_type=current_type, check_type=True)
        if checked != record:
            self.import_records([checked], replace_approved=True)
            checked = replace(checked, revision=record.revision + 1)
        return checked.as_decision()

    def import_records(
        self, records: list[HistoryRecord], *, replace_approved: bool = False,
        dry_run: bool = False,
    ) -> dict:
        # Validate the entire batch before writing; row order never decides a conflict.
        batch: dict[str, HistoryRecord] = {}
        warnings = []
        for raw in records:
            record = raw.validated()
            if record.review_status != raw.review_status:
                warnings.append(f"{record.location}: imported as pending: {record.reason}")
            if record.key in batch and batch[record.key] != record:
                raise HistoryConflictError(f"Conflicting rows for {record.location}")
            batch[record.key] = record
        result: dict[str, Any] = {"inserted": 0, "updated": 0, "unchanged": 0,
                  "approved": sum(r.review_status == "approved" for r in batch.values()),
                  "pending": sum(r.review_status == "pending" for r in batch.values()),
                  "superseded": sum(r.review_status == "superseded" for r in batch.values()),
                  "warnings": warnings, "dry_run": dry_run}
        try:
            with self._require().begin() as conn:
                for key, record in batch.items():
                    row = conn.execute(select(reviewed_table).where(
                        reviewed_table.c.col_key == key
                    )).mappings().first()
                    old = HistoryRecord(**json.loads(row["payload"])) if row else None
                    if old and replace(old, revision=0) == replace(record, revision=0):
                        result["unchanged"] += 1
                        continue
                    if record.revision != (old.revision if old else 0):
                        raise HistoryConflictError(
                            f"Stale revision for {record.location}; export current history and review again"
                        )
                    if old and old.review_status == "approved" and not replace_approved:
                        raise HistoryConflictError(
                            f"Existing approved decision for {record.location}; "
                            "use --replace-approved only after reviewing the change"
                        )
                    revision = (old.revision if old else 0) + 1
                    new = replace(record, revision=revision)
                    result["updated" if old else "inserted"] += 1
                    if dry_run:
                        continue
                    payload = json.dumps(new.to_dict(), ensure_ascii=False)
                    if old:
                        update = conn.execute(reviewed_table.update().where(
                            (reviewed_table.c.col_key == key)
                            & (reviewed_table.c.revision == old.revision)
                        ).values(revision=revision, payload=payload))
                        if update.rowcount != 1:
                            raise HistoryConflictError(f"Concurrent change for {record.location}")
                    else:
                        conn.execute(reviewed_table.insert().values(
                            col_key=key, revision=revision, payload=payload
                        ))
                    conn.execute(audit_table.insert().values(
                        col_key=key, revision=revision, payload=payload,
                        recorded_at=datetime.now(timezone.utc),
                    ))
        except IntegrityError as exc:
            raise HistoryConflictError("Concurrent history import; export and retry") from exc
        return result

    def save(self, decision: Decision) -> None:
        """Append analysis evidence as pending; never overwrite reviewed history."""
        if decision.sensitivity is Sensitivity.UNKNOWN:
            return
        record = HistoryRecord.from_decision(decision)
        with self._require().begin() as conn:
            conn.execute(suggestions_table.insert().values(
                col_key=record.key, payload=json.dumps(record.to_dict(), ensure_ascii=False)
            ))

    def records_for_review(self) -> list[HistoryRecord]:
        """Latest record per exact column, with imported decisions taking precedence.

        Legacy rows are exposed as pending for manual migration, not promoted.
        All analysis runs remain available in the suggestions table.
        """
        current: dict[str, HistoryRecord] = {}
        with self._require().connect() as conn:
            legacy = conn.execute(select(decisions_table)).mappings().all()
            for row in legacy:
                analysis_date = row["decided_at"] or datetime.now(timezone.utc)
                decision = Decision(
                    row["database"] or "", row["schema"] or "", row["table"] or "",
                    row["column"] or "", sensitivity=Sensitivity(row["sensitivity"]),
                    rule=row["rule"], detail=f"Legacy unreviewed ({row['source']}): {row['detail'] or ''}",
                    decided_at=analysis_date,
                )
                record = HistoryRecord.from_decision(decision)
                current[record.key] = record
            for payload in conn.execute(select(suggestions_table.c.payload).order_by(suggestions_table.c.id)).scalars():
                record = HistoryRecord(**json.loads(payload))
                current[record.key] = record
            for payload in conn.execute(select(reviewed_table.c.payload)).scalars():
                record = HistoryRecord(**json.loads(payload))
                current[record.key] = record
        return sorted(current.values(), key=lambda r: (r.database, r.schema, r.table, r.column))

    def all_decisions(self) -> list[Decision]:
        # Inspection/validation may use tentative classifications; get() alone
        # determines whether any decision is authoritative for the next scan.
        return [r.as_decision(suggestion=True) for r in self.records_for_review()]

    def audit_records(self) -> list[dict]:
        with self._require().connect() as conn:
            rows = conn.execute(select(audit_table).order_by(audit_table.c.id)).mappings().all()
        return [{"revision": r["revision"], "recorded_at": r["recorded_at"].isoformat(),
                 "record": json.loads(r["payload"])} for r in rows]

    def __enter__(self) -> HistoryStore:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
