"""Manual field overrides — the "toggle which fields are sensitive" feature.

A YAML file lets a human force a column to be treated as sensitive (with a
specific rule) or explicitly mark it as safe, overriding every automatic
layer. Overrides are matched in priority order:

  1. exact database/schema/table/column fields (case-preserving)
  2. exact ``schema.table.column`` (legacy, any database)
  3. ``table.column``
  4. ``column`` (applies everywhere with that column name)
  5. glob column-name patterns

See ``config/dbmask.fields.example.yaml`` for the file format.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from dbmask.detection.result import Decision, Sensitivity
from dbmask.masking.rules import get_strategy


@dataclass
class OverrideEntry:
    sensitive: bool
    rule: Optional[str] = None
    note: str = ""
    masking_strategy: Optional[str] = None


class FieldOverrides:
    """Loads and applies user-defined sensitivity toggles."""

    def __init__(self) -> None:
        self.scoped: dict[tuple[str, str, str, str], OverrideEntry] = {}
        self.exact: dict[str, OverrideEntry] = {}
        self.table_column: dict[str, OverrideEntry] = {}
        self.column: dict[str, OverrideEntry] = {}
        self.patterns: list[tuple[str, OverrideEntry]] = []

    # -- loading --------------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str | Path]) -> FieldOverrides:
        obj = cls()
        if not path:
            return obj
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Overrides file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        obj._ingest(data)
        return obj

    def _ingest(self, data: dict) -> None:
        for raw in data.get("sensitive", []) or []:
            self._add(raw, sensitive=True)
        for raw in data.get("not_sensitive", []) or []:
            self._add(raw, sensitive=False)

    def _add(self, raw, *, sensitive: bool) -> None:
        if isinstance(raw, str):
            target, entry = raw, OverrideEntry(sensitive=sensitive)
        else:
            target = raw.get("match") or raw.get("column") or raw.get("name")
            entry = OverrideEntry(
                sensitive=sensitive,
                rule=raw.get("rule"),
                note=raw.get("note", ""),
                masking_strategy=raw.get("masking_strategy"),
            )
            if entry.masking_strategy is not None:
                if not sensitive:
                    raise ValueError("not_sensitive overrides must not specify masking_strategy")
                try:
                    get_strategy(entry.masking_strategy)
                except KeyError as exc:
                    raise ValueError(str(exc)) from exc
            if "database" in raw:
                fields = ("database", "schema", "table", "column")
                if any(not isinstance(raw.get(f), str) for f in fields) or any(
                    not raw[f].strip() for f in ("database", "table", "column")
                ):
                    raise ValueError("Scoped overrides require database/schema/table/column text fields")
                if "match" in raw or "name" in raw:
                    raise ValueError("Scoped overrides use exact fields, not match/name aliases")
                key = (raw["database"], raw["schema"], raw["table"], raw["column"])
                if key in self.scoped:
                    raise ValueError("Duplicate database-scoped override")
                self.scoped[key] = entry
                return
        if not target:
            return
        target = str(target).lower()
        if target.startswith("pattern:"):
            self.patterns.append((target[len("pattern:"):], entry))
        elif target.count(".") >= 2:
            self.exact[target] = entry
        elif target.count(".") == 1:
            self.table_column[target] = entry
        else:
            self.column[target] = entry

    # -- lookup ---------------------------------------------------------------
    def lookup(
        self, schema: str, table: str, column: str, *, database: Optional[str] = None,
    ) -> Optional[OverrideEntry]:
        if database is not None and (database, schema, table, column) in self.scoped:
            return self.scoped[(database, schema, table, column)]
        s, t, c = schema.lower(), table.lower(), column.lower()
        for key, store in (
            (f"{s}.{t}.{c}", self.exact),
            (f"{t}.{c}", self.table_column),
            (c, self.column),
        ):
            if key in store:
                return store[key]
        for pattern, entry in self.patterns:
            if fnmatch.fnmatch(c, pattern.lower()):
                return entry
        return None

    def decide(self, database: str, schema: str, table: str, column: str) -> Optional[Decision]:
        entry = self.lookup(schema, table, column, database=database)
        if entry is None:
            return None
        return Decision(
            database=database,
            schema=schema,
            table=table,
            column=column,
            sensitivity=Sensitivity.SENSITIVE if entry.sensitive else Sensitivity.NOT_SENSITIVE,
            rule=entry.rule if entry.sensitive else None,
            source="override",
            confidence=1.0,
            detail=entry.note or "Manual field override",
            masking_strategy=entry.masking_strategy if entry.sensitive else None,
        )
