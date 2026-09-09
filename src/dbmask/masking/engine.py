"""ETL / masking engine — applies strategies to real rows.

Given the detections from the pipeline and the masking config, the engine:
  * resolves each sensitive column to a concrete strategy,
  * masks rows (optionally in batches), preserving format/consistency,
  * either previews the changes (``dry_run``) or writes them back.

Non-sensitive columns are passed through untouched.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Optional

from dbmask.config import MaskingConfig
from dbmask.connectors.base import Connector
from dbmask.detection.result import Decision
from dbmask.masking.format import coerce_stored
from dbmask.masking.rules import (
    DEFAULT_RULE_STRATEGIES,
    STRATEGIES,
    MaskContext,
    get_strategy,
)
from dbmask.masking.seed_store import DEFAULT_SEED_MAP_URL, SeedStore


@dataclass
class ColumnPlan:
    """How a single column will be masked."""

    schema: str
    table: str
    column: str
    rule: Optional[str]
    strategy_name: str


@dataclass
class TableMaskResult:
    schema: str
    table: str
    rows_scanned: int = 0
    rows_written: int = 0
    columns: list[ColumnPlan] = field(default_factory=list)
    #: Sensitive columns that could NOT be masked and were left untouched
    #: (currently: primary-key columns — rewriting keys safely requires
    #: cascading updates across referencing tables, which is not supported).
    skipped_columns: list[ColumnPlan] = field(default_factory=list)
    preview: list[dict] = field(default_factory=list)


class MaskingEngine:
    def __init__(self, config: MaskingConfig, seed_store: Optional[SeedStore] = None):
        self.config = config
        # Normalize per-column overrides to lowercase keys for matching.
        self._column_strategies = {
            k.lower(): v for k, v in (config.column_strategies or {}).items()
        }
        # Seed map: durable (original -> masked) pair tracking. Supplying a store
        # explicitly hands its lifecycle to the caller; otherwise the engine
        # creates and closes its own.
        self._seed_store = seed_store
        self._owns_seed_store = seed_store is None
        self._untracked = {
            s.lower() for s in (config.seed_map.untracked_strategies or [])
        }

    # -- seed map -------------------------------------------------------------
    def seed_store(self) -> Optional[SeedStore]:
        """Return the connected seed store, or ``None`` when tracking is off.

        Connects lazily so the engine works standalone (e.g. in examples/tests)
        without callers having to remember an explicit open step.
        """
        if not self.config.seed_map.enabled:
            return None
        if self._seed_store is None:
            self._seed_store = SeedStore(
                url=self.config.seed_map.url or DEFAULT_SEED_MAP_URL,
                salt=self.config.seed_map.salt,
            )
        if self._seed_store.engine is None:
            self._seed_store.connect()
        return self._seed_store

    def close(self) -> None:
        """Release the seed store if this engine created it."""
        if self._seed_store is not None and self._owns_seed_store:
            self._seed_store.close()
            self._seed_store = None

    # -- planning -------------------------------------------------------------
    def resolve_strategy(self, decision: Decision) -> str:
        """Pick the strategy name for a sensitive column.

        An explicit ``decision.masking_strategy`` (from reviewed history) wins first.
        Otherwise, priority is (first match wins):
          1. ``column_strategies`` — an explicit per-column choice the user made
             (e.g. blank a long ``notes`` field). Matched as
             ``schema.table.column`` -> ``table.column`` -> ``column``.
          2. ``rule_strategies`` — the user's mapping for the detected rule
             (e.g. ``email`` -> ``fake_email``).
          3. Built-in default strategy for that rule.
          4. The rule name itself, if it happens to be a valid strategy
             (lets an override set ``rule: blank`` and have it just work).
          5. ``default_strategy`` — the catch-all.
        """
        # An explicitly reviewed strategy must not be remapped by defaults or
        # broad per-column settings. A fresh detection override still wins at
        # the pipeline layer. Unknown explicit strategies fail, never fall back.
        if decision.masking_strategy is not None:
            get_strategy(decision.masking_strategy)
            return decision.masking_strategy

        # 1) per-column user choice (most specific)
        for key in (
            f"{decision.schema}.{decision.table}.{decision.column}",
            f"{decision.table}.{decision.column}",
            decision.column,
        ):
            if key.lower() in self._column_strategies:
                return self._column_strategies[key.lower()]

        rule = (decision.rule or "").lower()
        # 2) user mapping for the detected rule
        if rule in self.config.rule_strategies:
            return self.config.rule_strategies[rule]
        # 3) built-in default for the detected rule
        if rule in DEFAULT_RULE_STRATEGIES:
            return DEFAULT_RULE_STRATEGIES[rule]
        # 4) the rule may itself name a strategy (e.g. "blank", "null")
        if rule in STRATEGIES:
            return rule
        # 5) catch-all
        return self.config.default_strategy

    def plan_table(self, decisions: Iterable[Decision]) -> list[ColumnPlan]:
        plans: list[ColumnPlan] = []
        for d in decisions:
            if not d.is_sensitive:
                continue
            plans.append(
                ColumnPlan(
                    schema=d.schema,
                    table=d.table,
                    column=d.column,
                    rule=d.rule,
                    strategy_name=self.resolve_strategy(d),
                )
            )
        return plans

    # -- value masking --------------------------------------------------------
    def mask_value(self, value, plan: ColumnPlan):
        """Mask one value, reusing its tracked pair when the seed map is on.

        Order of operations:
          1. Look the value up in the seed map. A hit means this value was
             masked before, so the recorded replacement is reused — that is what
             keeps "Tesla always becomes Apple" true across runs, even if the
             dictionaries or the seed have changed since.
          2. On a miss, compute the replacement with the strategy and record the
             new pair, which assigns it a seed token for future tracking.
        """
        strategy = get_strategy(plan.strategy_name)
        ctx = MaskContext(column=plan.column, rule=plan.rule, seed=self.config.seed)

        store = self.seed_store()
        if (
            store is None
            or value is None
            or plan.strategy_name.lower() in self._untracked
        ):
            return strategy(value, ctx)

        # Pairs are scoped per strategy, so the same value masks identically in
        # every column that uses that strategy (preserving joins across tables).
        scope = plan.strategy_name
        original = str(value)

        recorded = store.lookup(scope, original)
        if recorded is not None:
            # The store keeps text; give the replacement back the original's
            # Python type (int/float/Decimal/date/datetime/UUID) so typed
            # columns on strict engines accept the write.
            return coerce_stored(value, recorded)

        masked = strategy(value, ctx)
        if masked is None or masked == "":
            return masked  # nothing meaningful to track
        # A dry run must not have side effects: pairs are only recorded when
        # values are actually written. Previews still *read* existing pairs
        # (and strategies are deterministic), so the preview matches what a
        # later --apply will write.
        if not self.config.dry_run:
            store.record(scope, original, str(masked), plan.strategy_name)
        return masked

    def mask_row(self, row: dict, plans: list[ColumnPlan]) -> dict:
        masked = dict(row)
        for plan in plans:
            if plan.column in masked:
                masked[plan.column] = self.mask_value(masked[plan.column], plan)
        return masked

    # -- table-level ETL ------------------------------------------------------
    def mask_table(
        self,
        connector: Connector,
        schema: str,
        table: str,
        decisions: Iterable[Decision],
        key_columns: Optional[list[str]] = None,
        batch_size: int = 1000,
        preview_limit: int = 10,
    ) -> TableMaskResult:
        plans = self.plan_table(decisions)
        keys = key_columns or connector.primary_key_columns(schema, table)

        # A primary-key column cannot be rewritten in place: the connector
        # (correctly) refuses to change the very values it uses to address
        # rows, and rewriting keys would require cascading updates through
        # every referencing table. Previously such columns were silently
        # dropped from the UPDATE while the preview showed them as masked.
        # Now they are excluded up front and reported, so "this key column
        # still holds sensitive data" is impossible to miss.
        key_set = {k.lower() for k in keys}
        skipped = [p for p in plans if p.column.lower() in key_set]
        plans = [p for p in plans if p.column.lower() not in key_set]

        result = TableMaskResult(
            schema=schema, table=table, columns=plans, skipped_columns=skipped
        )
        if not plans:
            return result  # nothing maskable here

        def _process(row: dict) -> dict:
            result.rows_scanned += 1
            masked = self.mask_row(row, plans)
            if len(result.preview) < preview_limit:
                result.preview.append(
                    {
                        "before": {p.column: row.get(p.column) for p in plans},
                        "after": {p.column: masked.get(p.column) for p in plans},
                    }
                )
            return masked

        if self.config.dry_run:
            # Read-only: a single streaming pass is safe (and works on tables
            # without a primary key, since nothing is written back).
            for row in connector.iter_rows(schema, table, batch_size=batch_size):
                _process(row)
            return result

        # Apply mode: read one page, then write it back, then read the next.
        # Reads and writes never overlap — interleaving writes into a live
        # streaming read used to deadlock databases whose readers block
        # writers (on SQLite the run died with "database is locked" as soon
        # as a table exceeded one batch).
        for page in connector.iter_pages(
            schema, table, key_columns=keys, batch_size=batch_size
        ):
            batch = [_process(row) for row in page]
            result.rows_written += connector.update_rows(schema, table, keys, batch)

        return result
