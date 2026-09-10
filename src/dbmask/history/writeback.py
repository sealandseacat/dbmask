"""Explicit human review -> an atomic, backed-up merge into the original file."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from dbmask.history.file_store import FileHistoryStore
from dbmask.history.files import _excel, read_history_file, write_history_file
from dbmask.history.records import (
    HISTORY_FIELDS,
    HistoryConflictError,
    HistoryRecord,
    HistoryValidationError,
)

_IMMUTABLE = ("database", "schema", "table", "column", "revision", "user_id",
              "analysis_date", "data_type")


def manifest_path(review: str | Path) -> Path:
    return Path(str(review) + ".dbmask.json")


def export_review(
    store: FileHistoryStore, output: str | Path, records: list[HistoryRecord],
) -> None:
    """Keep source identity and scan metadata alongside the editable worksheet."""
    path = Path(output)
    sidecar = manifest_path(path)
    if path.resolve() == store.path or path.exists() or sidecar.exists():
        raise HistoryValidationError("Choose a new review filename; never overwrite the history source")
    if len({r.key for r in records}) != len(records):
        raise HistoryConflictError("Duplicate review identities")
    manifest = {
        "version": 1, "source_file": str(store.path), "sheet": store.sheet,
        "source_sha256": store.digest, "rows": [r.to_dict() for r in records],
    }
    write_history_file(path, records)
    try:
        with sidecar.open("x", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    except OSError:
        path.unlink(missing_ok=True)
        raise


def _load_baseline(store: FileHistoryStore, review: Path) -> dict[str, HistoryRecord]:
    sidecar = manifest_path(review)
    if not sidecar.exists():
        raise HistoryValidationError("Missing .dbmask.json review companion; export a fresh review")
    try:
        manifest = json.loads(sidecar.read_text(encoding="utf-8"))
        if (manifest["version"] != 1 or manifest["source_file"] != str(store.path)
                or manifest["sheet"] != store.sheet):
            raise HistoryConflictError("Review belongs to a different history source or format version")
        if manifest["source_sha256"] != store.digest:
            raise HistoryConflictError("History source changed since export; export and review again")
        rows = [HistoryRecord(**row) for row in manifest["rows"]]
        if len({r.key for r in rows}) != len(rows):
            raise HistoryConflictError("Duplicate identities in review companion")
        return {r.key: r for r in rows}
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HistoryValidationError("Invalid review companion; export a fresh review") from exc


def writeback(
    store: FileHistoryStore, review: str | Path, *, reviewed_by: str,
    apply: bool = False, sheet: str = "history",
) -> dict:
    """Preview by default; only explicitly approved rows can change the master."""
    if not reviewed_by.strip():
        raise HistoryValidationError("reviewed_by must not be blank")
    path = Path(review)
    if path.resolve() == store.path:
        raise HistoryValidationError("Review must be a separate exported worksheet")
    baseline = _load_baseline(store, path)
    rows = read_history_file(path, sheet=sheet)
    if len({r.key for r in rows}) != len(rows):
        raise HistoryConflictError("Duplicate review rows; nothing was written")
    updates: dict[str, HistoryRecord] = {}
    result: dict[str, Any] = {"dry_run": not apply, "inserted": 0, "updated": 0,
              "unchanged": 0, "skipped": 0, "changes": [], "backup": None}
    now = datetime.now(timezone.utc).isoformat()
    for row in rows:
        exported = baseline.get(row.key)
        if exported is None or any(getattr(row, f) != getattr(exported, f) for f in _IMMUTABLE):
            raise HistoryConflictError(
                f"Identity or analysis metadata changed for {row.location}; export and review again"
            )
        old = store.original.get(row.key)
        if row.revision != (old.revision if old else 0):
            raise HistoryConflictError(f"Stale revision for {row.location}")
        if row.review_status != "approved":
            row.validated()
            result["skipped"] += 1
            continue
        # A reviewer is supplied by the explicit command, not inferred from AI.
        checked = replace(row, reviewed_by=reviewed_by, reviewed_at=now).validated()
        if checked.review_status != "approved":
            raise HistoryValidationError(f"Cannot approve {row.location}: {checked.reason}")
        if old and replace(row, reviewed_by=old.reviewed_by, reviewed_at=old.reviewed_at) == old:
            result["unchanged"] += 1
            continue
        new = replace(checked, revision=(old.revision if old else 0) + 1)
        updates[new.key] = new
        result["updated" if old else "inserted"] += 1
        result["changes"].append({
            "database": new.database, "schema": new.schema, "table": new.table, "column": new.column,
            "before": old.to_dict() if old else None, "after": new.to_dict(),
        })
    if apply and updates:
        result["backup"] = str(_atomic_merge(store, updates))
    return result


def _update_xlsx(path: Path, store: FileHistoryStore, updates: dict[str, HistoryRecord]) -> None:
    """Edit only changed history rows, retaining the other workbook worksheets."""
    path.write_bytes(store.snapshot)
    book = _excel().load_workbook(path)
    try:
        ws = book[store.sheet]
        headers = [str(cell.value or "").strip() for cell in ws[1]]
        while headers and not headers[-1]:
            headers.pop()
        for field in HISTORY_FIELDS:
            if field not in headers:
                headers.append(field)
                ws.cell(1, len(headers), field)
        positions = {}
        for cells in ws.iter_rows(min_row=2):
            identity = [cells[headers.index(f)].value or "" for f in HISTORY_FIELDS[:4]]
            if any(identity):
                positions[HistoryRecord(identity[0], identity[1], identity[2], identity[3]).key] = cells[0].row
        for key, record in updates.items():
            row_number = positions.get(key, ws.max_row + 1)
            for field, value in record.to_dict().items():
                cell = ws.cell(row_number, headers.index(field) + 1)
                cell.value = value
                if isinstance(value, str):
                    cell.data_type = "s"
                    cell.number_format = "@"
        if ws.auto_filter.ref:
            ws.auto_filter.ref = ws.dimensions
        book.save(path)
    finally:
        book.close()


def _atomic_merge(store: FileHistoryStore, updates: dict[str, HistoryRecord]) -> Path:
    path = store.path
    lock = path.with_name(path.name + ".dbmask.lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise HistoryConflictError("History source is locked by another writeback") from exc
    os.close(descriptor)
    temporary = None
    try:
        if hashlib.sha256(path.read_bytes()).hexdigest() != store.digest:
            raise HistoryConflictError("History source changed before write; export and review again")
        merged = {**store.original, **updates}
        fd, filename = tempfile.mkstemp(prefix=".dbmask-", suffix=path.suffix, dir=path.parent)
        os.close(fd)
        temporary = Path(filename)
        if path.suffix.lower() == ".xlsx":
            _update_xlsx(temporary, store, updates)
        else:
            write_history_file(temporary, list(merged.values()), overwrite=True)
        actual = read_history_file(temporary, sheet=store.sheet)
        if len(actual) != len(merged) or {r.key: r for r in actual} != merged:
            raise HistoryValidationError("Staged history did not round-trip; original unchanged")
        with temporary.open("rb+") as handle:
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = path.with_name(f"{path.name}.{stamp}.{uuid4().hex[:8]}.bak")
        with backup.open("xb") as handle:
            handle.write(store.snapshot)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(backup, stat.S_IMODE(path.stat().st_mode))
        if hashlib.sha256(path.read_bytes()).hexdigest() != store.digest:
            raise HistoryConflictError("History source changed during staging; original not replaced")
        os.replace(temporary, path)
        return backup
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        lock.unlink(missing_ok=True)
