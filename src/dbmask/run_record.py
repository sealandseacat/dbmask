"""Versioned, metadata-only plans and local execution audit records.

The local guard is deliberately conservative: a stale lock or an interrupted
write requires inspection. It is not a distributed lock or a transaction shared
with the target database. Keep the audit directory with the target copy.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.engine import make_url

from dbmask import __version__
from dbmask.config import Config, DatabaseConfig
from dbmask.connectors.base import Connector
from dbmask.connectors.sql import build_url


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def target_identity(config: DatabaseConfig) -> dict[str, str]:
    """Identify a configured endpoint without serializing connection secrets.

    Passwords, users and connection query parameters are excluded. SQLite file
    paths are canonicalized and only enter the digest. Network aliases and
    routing hidden inside driver options cannot be identified as the same DB.
    """
    url = make_url(build_url(config))
    dialect = url.get_backend_name()
    if dialect == "sqlite":
        database = url.database or ":memory:"
        endpoint: dict[str, Any] = {
            "dialect": dialect,
            "database": database if database == ":memory:" else str(Path(database).expanduser().resolve()),
        }
    else:
        default_ports = {"postgresql": 5432, "mysql": 3306, "mssql": 1433, "oracle": 1521}
        endpoint = {
            "dialect": dialect, "host": (url.host or "").lower(),
            "port": url.port or default_ports.get(dialect), "database": url.database or "",
        }
    return {"id": _digest(endpoint), "dialect": dialect, "name": config.name or "database"}


def config_fingerprint(config: Config) -> str:
    """Bind execution and validation policy; only the digest is persisted."""
    masking = asdict(config.masking)
    masking.pop("dry_run", None)
    return _digest({
        "masking": masking,
        "date_order": config.detection.date_order,
        "validation": asdict(config.validation),
        "schemas": sorted(config.database.schemas),
    })


def inventory(connector: Connector, schemas: list[str]) -> list[dict[str, Any]]:
    """Capture every table and column in the selected schemas, deterministically."""
    return [
        {"schema": schema, "table": table,
         "columns": sorted(connector.list_columns(schema, table)),
         "primary_key": connector.primary_key_columns(schema, table),
         "column_types": {column: connector.column_type(schema, table, column)
                          for column in sorted(connector.list_columns(schema, table))},
         "non_writable": connector.non_writable_columns(schema, table)}
        for schema in sorted(set(schemas))
        for table in sorted(connector.list_tables(schema))
    ]


def _reject_constant(value: str) -> Any:
    raise ValueError(f"Invalid JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate keys in run record")
        result[key] = value
    return result


class RunRecord:
    """A frozen plan with mutable approval, execution and validation history."""

    def __init__(self, path: str | Path, data: dict[str, Any]):
        self.path = Path(path)
        self.data = data

    @classmethod
    def create(
        cls, path: str | Path, *, target: dict, source: Optional[dict],
        config_digest: str, scope: list[dict], decisions: list[dict], scan_error_count: int,
        validation: Optional[dict] = None,
    ) -> RunRecord:
        path = Path(path)
        if path.exists() or path.is_symlink():
            raise FileExistsError("Run record already exists; choose a new run file")
        plan = deepcopy({
            "target": target, "source": source, "config_digest": config_digest,
            "scope": scope, "decisions": decisions, "scan_error_count": scan_error_count,
            "validation": validation,
        })
        record = cls(path, {
            "schema_version": 1, "run_id": str(uuid.uuid4()),
            "tool_version": __version__, "created_at": _now(),
            "plan": plan, "plan_sha256": _digest(plan),
            "approval": {"status": "draft"},
            "execution": {"status": "planned", "tables": []}, "validations": [],
        })
        record._validate()
        # Reserve the filename before the atomic save; never replace an
        # unrelated run created concurrently between the existence check/save.
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            record.save()
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return record

    @classmethod
    def load(cls, path: str | Path) -> RunRecord:
        path = Path(path)
        with path.open("r", encoding="utf-8") as stream:
            data = json.load(stream, parse_constant=_reject_constant, object_pairs_hook=_unique_object)
        record = cls(path, data)
        record._validate()
        return record

    def _validate(self) -> None:
        data = self.data
        if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
            raise ValueError("Unsupported or invalid run-record schema_version")
        if not all(isinstance(data.get(key), str) and data[key]
                   for key in ("run_id", "tool_version", "created_at", "plan_sha256")):
            raise ValueError("Run record is missing required metadata")
        plan = data.get("plan")
        if not isinstance(plan, dict) or not all(
            key in plan for key in ("target", "source", "config_digest", "scope", "decisions", "scan_error_count")
        ):
            raise ValueError("Run record is missing its frozen plan")
        if _digest(plan) != data["plan_sha256"]:
            raise ValueError("Frozen run plan changed; create and approve a new plan")
        target = plan["target"]
        source = plan["source"]
        if not isinstance(target, dict) or not isinstance(target.get("id"), str) or not target["id"]:
            raise ValueError("Run record has no target identity")
        if source is not None and (not isinstance(source, dict) or not isinstance(source.get("id"), str)):
            raise ValueError("Run record has an invalid source identity")
        if not isinstance(plan["config_digest"], str) or not plan["config_digest"]:
            raise ValueError("Run record has no configuration fingerprint")
        if type(plan["scan_error_count"]) is not int or plan["scan_error_count"] < 0:
            raise ValueError("Invalid scan error count in run record")
        if not isinstance(plan["scope"], list) or not isinstance(plan["decisions"], list):
            raise ValueError("Run record scope and decisions must be lists")
        for table in plan["scope"]:
            if not isinstance(table, dict) or not all(isinstance(table.get(k), str) and table[k] for k in ("schema", "table")):
                raise ValueError("Invalid table in frozen scope")
            if not isinstance(table.get("columns"), list) or any(not isinstance(c, str) or not c for c in table["columns"]):
                raise ValueError("Invalid columns in frozen scope")
        seen = set()
        for decision in plan["decisions"]:
            if not isinstance(decision, dict) or not all(isinstance(decision.get(k), str) and decision[k] for k in ("schema", "table", "column")):
                raise ValueError("Invalid frozen column decision")
            key = (decision["schema"], decision["table"], decision["column"])
            if key in seen:
                raise ValueError("Duplicate column in frozen plan")
            seen.add(key)
            if decision.get("sensitivity") not in {"sensitive", "not_sensitive", "unknown"}:
                raise ValueError("Invalid sensitivity in frozen plan")
        if not isinstance(data.get("approval"), dict) or data["approval"].get("status") not in {"draft", "approved"}:
            raise ValueError("Invalid plan approval")
        execution = data.get("execution")
        if not isinstance(execution, dict) or not isinstance(execution.get("status"), str) or not isinstance(execution.get("tables"), list):
            raise ValueError("Invalid execution record")
        if not isinstance(data.get("validations"), list):
            raise ValueError("Invalid validation history")
        # Also reject non-finite numbers added anywhere outside the plan.
        _json(data)

    def save(self) -> None:
        """Atomically replace this JSON file, failing before writes on bad data."""
        self._validate()
        content = json.dumps(self.data, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)

    def approve(self, reviewed_by: str) -> None:
        self._validate()
        if not reviewed_by or not reviewed_by.strip():
            raise ValueError("A nonblank reviewer is required")
        target_id = self.data["plan"]["target"]["id"]
        with self.operation_lock():
            self.data = self.load(self.path).data
            if self.data["plan"]["target"]["id"] != target_id:
                raise ValueError("Run target changed while waiting for approval; reload the plan")
            plan = self.data["plan"]
            if plan["scan_error_count"]:
                raise ValueError("Cannot approve an incomplete scan; fix its errors and create a new plan")
            if any(d["sensitivity"] == "unknown" or d.get("source") == "history_pending"
                   for d in plan["decisions"]):
                raise ValueError("Cannot approve unresolved classifications or pending history reviews")
            expected = {(t["schema"], t["table"], column)
                        for t in plan["scope"] for column in t["columns"]}
            classified = {(d["schema"], d["table"], d["column"]) for d in plan["decisions"]}
            if not classified or classified != expected:
                raise ValueError("Cannot approve a plan with missing or out-of-scope column decisions")
            if self.data["execution"]["status"] not in {"planned", "previewed"}:
                raise ValueError("Cannot approve a run after execution has started")
            self.data["approval"] = {
                "status": "approved", "reviewed_by": reviewed_by.strip(),
                "approved_at": _now(), "plan_sha256": self.data["plan_sha256"],
            }
            self.save()

    def require_approved(self) -> None:
        self._validate()
        approval = self.data["approval"]
        if (approval.get("status") != "approved"
                or approval.get("plan_sha256") != self.data["plan_sha256"]
                or not isinstance(approval.get("reviewed_by"), str)
                or not approval["reviewed_by"].strip()
                or not approval.get("approved_at")):
            raise ValueError("Approve this frozen run plan before execution or validation")

    def check_config(self, config: Config) -> None:
        self._validate()
        if self.data["tool_version"] != __version__:
            raise ValueError("Run plan was created by another dbmask version; create a new plan")
        if target_identity(config.database)["id"] != self.data["plan"]["target"]["id"]:
            raise ValueError("Configured target does not match the frozen run plan")
        source = self.data["plan"]["source"]
        if source is not None:
            if not (config.source_database.url or config.source_database.dialect):
                raise ValueError("Frozen run plan requires its original source database")
            if target_identity(config.source_database)["id"] != source["id"]:
                raise ValueError("Configured source does not match the frozen run plan")
        if config_fingerprint(config) != self.data["plan"]["config_digest"]:
            raise ValueError("Masking or validation policy changed; create and approve a new plan")

    def _sensitive_scope(self) -> set[tuple[str, str, str]]:
        return {(d["schema"], d["table"], d["column"])
                for d in self.data["plan"]["decisions"] if d["sensitivity"] == "sensitive"}

    def _may_have_writes(self) -> bool:
        """Past committed or uncertain attempts remain relevant after retries."""
        attempts = [self.data["execution"], *self.data.get("execution_history", [])]
        for execution in attempts:
            if not isinstance(execution, dict):
                # Invalid historical progress must never enable an automatic
                # retry against a potentially modified target.
                return True
            status = execution.get("status")
            if status in {"applying", "applied"}:
                return True
            if status != "failed":
                continue
            if execution.get("in_flight"):
                return True
            # A failed attempt with no in-flight batch and no committed rows
            # is safe in isolation; it cannot erase a prior applied attempt.
            if execution.get("rows_written", 0) or execution.get("committed_batches", 0):
                return True
            if any(
                isinstance(table, dict) and (
                    table.get("rows_written", 0) or table.get("committed_batches", 0)
                    or table.get("in_flight")
                ) for table in execution.get("tables", [])
            ):
                return True
        return False

    @contextmanager
    def operation_lock(self, directory: Optional[str | Path] = None) -> Iterator[None]:
        """Exclude local writers to this target's records and database.

        Callers performing a read-modify-write operation must reload the record
        after entering this context, then hold the lock through their save.
        Stale locks are never removed automatically.
        """
        self._validate()
        directory = Path(directory) if directory is not None else self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        target_id = self.data["plan"]["target"]["id"]
        # A digest prevents identity data from becoming a filesystem path.
        lock = directory / ("." + _digest(target_id) + ".lock")
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ValueError("Target audit lock exists; another run or an interrupted run requires inspection") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"run_id": self.data["run_id"], "pid": os.getpid(), "created_at": _now()}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            yield
        finally:
            lock.unlink(missing_ok=True)

    @contextmanager
    def apply_guard(
        self, directory: str | Path, reason: Optional[str] = None, *, resume: bool = False,
    ) -> Iterator[None]:
        """Hold a local target lock and refuse tracked repeated masking.

        An explicit nonblank override reason records the caller's decision;
        it never bypasses the exclusive lock. All applied run files must be
        direct .json children of the common audit directory. Refreshing under
        the lock prevents stale objects from erasing a newer applied status.
        """
        self._validate()
        if reason is not None and not reason.strip():
            raise ValueError("A repeat override requires a nonblank reason")
        directory = Path(directory)
        if self.path.parent.resolve() != directory.resolve() or self.path.suffix != ".json":
            raise ValueError("Applied run files must be .json files directly inside audit.directory")
        target_id = self.data["plan"]["target"]["id"]
        with self.operation_lock(directory):
            self.data = self.load(self.path).data
            if self.data["plan"]["target"]["id"] != target_id:
                raise ValueError("Run target changed while waiting for execution; reload the plan")
            selected = self._sensitive_scope()
            for path in directory.glob("*.json"):
                prior = self if path.resolve() == self.path.resolve() else self.load(path)
                if (prior.data["plan"]["target"]["id"] == target_id
                        and selected & prior._sensitive_scope()
                        and prior._may_have_writes() and reason is None):
                    if prior is self and resume:
                        if self.data["execution"].get("resumable") is True:
                            # Runner must still verify this run's target-side checkpoint.
                            continue
                        raise ValueError("This run was not started with --resumable; it has no safe resume point")
                    raise ValueError(
                        "Tracked masking already affected this target and column scope; "
                        "restore an untouched copy or provide an explicit repeat override reason"
                    )
            if reason is not None:
                overrides = self.data.setdefault("repeat_overrides", [])
                overrides.append({"reason": reason.strip(), "recorded_at": _now()})
                self.save()
            yield
