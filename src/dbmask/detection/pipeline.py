"""The detection pipeline — orchestrates all layers in priority order.

For each column we try, in order:

  1. **Field overrides** (manual human toggle) — authoritative, always wins.
  2. **History** — reuse a prior decision so results stay consistent.
  3. **Pattern matching** — fast, free, deterministic value heuristics.
  4. **LLM** — only when everything above is inconclusive (and only if enabled).

Automatic results are stored as pending suggestions. Only reviewed imports
are reused on later runs. A token budget caps LLM spend.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from dbmask.config import Config
from dbmask.connectors.base import Connector
from dbmask.detection.overrides import FieldOverrides
from dbmask.detection.patterns import PatternAnalysis, PatternMatcher
from dbmask.detection.result import Decision, Sensitivity
from dbmask.history.store import HistoryStore
from dbmask.llm.base import LLMProvider


class TokenBudgetExceeded(Exception):
    """Raised when LLM usage would exceed the configured budget."""


@dataclass
class PipelineStats:
    total: int = 0
    by_source: dict[str, int] = None  # type: ignore[assignment]
    sensitive: int = 0
    unknown: int = 0
    tokens: int = 0

    def __post_init__(self):
        if self.by_source is None:
            self.by_source = {}

    def record(self, decision: Decision) -> None:
        self.total += 1
        self.by_source[decision.source] = self.by_source.get(decision.source, 0) + 1
        if decision.is_sensitive:
            self.sensitive += 1
        if decision.sensitivity is Sensitivity.UNKNOWN:
            self.unknown += 1
        self.tokens += decision.token_usage


class DetectionPipeline:
    def __init__(
        self,
        config: Config,
        history: Optional[HistoryStore] = None,
        overrides: Optional[FieldOverrides] = None,
        patterns: Optional[PatternMatcher] = None,
        llm: Optional[LLMProvider] = None,
    ):
        self.config = config
        self.history = history
        self.overrides = overrides or FieldOverrides()
        self.patterns = patterns or PatternMatcher(
            min_ratio=config.detection.pattern_min_ratio,
            min_samples=config.detection.pattern_min_samples,
            date_order=config.detection.date_order,
        )
        self.llm = llm
        self.stats = PipelineStats()
        self._skip_cols = [re.compile(p, re.IGNORECASE) for p in config.detection.skip_column_patterns]
        self._skip_tables = [re.compile(p, re.IGNORECASE) for p in config.detection.skip_table_patterns]

    # -- name-based skipping (fully optional, off by default) -----------------
    def should_skip_table(self, table: str) -> bool:
        return any(p.search(table) for p in self._skip_tables)

    def should_skip_column(self, column: str) -> bool:
        return any(p.search(column) for p in self._skip_cols)

    # -- main entry point -----------------------------------------------------
    def analyze_column(
        self, connector: Connector, schema: str, table: str, column: str
    ) -> Decision:
        db = connector.name
        type_reader = getattr(connector, "column_type", None)
        data_type = (type_reader(schema, table, column) if type_reader else None) or ""
        analysis: Optional[PatternAnalysis] = None

        def finish(decision: Decision) -> Decision:
            decision.data_type = data_type
            decision.user_id = self.config.detection.user_id
            if analysis is not None:
                decision.pattern_candidates = analysis.candidates
                decision.pattern_sample_count = analysis.total
                decision.pattern_sample_basis = "distinct_values"
                decision.detail = (
                    decision.detail + "; Distinct nonblank sample evidence: " + analysis.summary()
                )
            return self._finalize(decision)

        # 1) Manual override wins outright.
        if decision := self.overrides.decide(db, schema, table, column):
            return finish(decision)

        # 2) History (consistency / reproducibility).
        if self.config.detection.use_history and self.history is not None:
            prior = self.history.get(db, schema, table, column, current_type=data_type)
            if prior is not None:
                self.stats.record(prior)
                return prior  # already persisted; do not rewrite

        # Configurable name-based skip (e.g. *_ID, audit columns).
        if self.should_skip_column(column):
            return finish(
                Decision(db, schema, table, column, Sensitivity.NOT_SENSITIVE,
                         source="skip", confidence=1.0, detail="Skipped by column name pattern")
            )

        sample = connector.sample_values(schema, table, column, self.config.detection.sample_size)

        # 3) Pattern matching.
        if self.config.detection.use_patterns and sample:
            analysis = self.patterns.analyze(sample, column=column, data_type=data_type)
            match = analysis.match
            if match is not None:
                return finish(
                    Decision(db, schema, table, column, Sensitivity.SENSITIVE,
                             rule=match.name, source="pattern", confidence=match.confidence,
                             detail=f"Pattern suggestion '{match.name}'; requires review")
                )

            # Do not let an LLM silently settle a strong metadata/value conflict
            # or a collision between eligible patterns. Preserve it for a person.
            conflict = any(
                c.ratio >= c.threshold and any("conflicts" in r for r in c.reasons)
                for c in analysis.candidates
            ) or any(r.startswith(("Conflicting", "Multiple eligible")) for r in analysis.reasons)
            if conflict:
                return finish(Decision(
                    db, schema, table, column, Sensitivity.UNKNOWN,
                    source="pattern_conflict", detail="Conflicting evidence; human review required",
                ))

        # 4) LLM fallback.
        if self.llm is not None and sample:
            return finish(self._classify_with_llm(db, schema, table, column, sample))

        # Nothing conclusive. "We could not tell" is NOT the same as "not
        # sensitive": the column is reported as UNKNOWN so a human can review
        # it (overrides file) or the LLM fallback can be enabled. UNKNOWN is
        # never persisted to history — every run re-evaluates it, so a column
        # that was empty yesterday is not permanently stamped as safe.
        if sample:
            detail = ("Pattern evidence is inconclusive and the LLM fallback is disabled — "
                      "review manually (overrides file) or enable llm.enabled")
            source = "inconclusive"
        else:
            detail = "Column has no data to sample — nothing to analyze"
            source = "no_data"
        return finish(
            Decision(db, schema, table, column, Sensitivity.UNKNOWN,
                     source=source, confidence=0.0, detail=detail)
        )

    def _classify_with_llm(self, db, schema, table, column, sample) -> Decision:
        if self.stats.tokens >= self.config.llm.max_tokens_budget:
            raise TokenBudgetExceeded(
                f"Token budget {self.config.llm.max_tokens_budget} reached."
            )
        # Metadata-only mode: send the column name but no data values.
        if self.config.llm.send_values:
            trimmed = sample[: self.config.llm.sample_size]
        else:
            trimmed = []
        result = self.llm.classify(column, trimmed)  # type: ignore[union-attr]
        sensitivity = Sensitivity.SENSITIVE if result.sensitive else Sensitivity.NOT_SENSITIVE
        return Decision(
            database=db, schema=schema, table=table, column=column,
            sensitivity=sensitivity,
            rule=result.rule if result.sensitive else None,
            source="llm", confidence=result.confidence,
            detail="Classified by LLM", token_usage=result.token_usage,
        )

    def _finalize(self, decision: Decision) -> Decision:
        self.stats.record(decision)
        if (
            self.history is not None
            and decision.source not in ("history",)
            # UNKNOWN must not be remembered: persisting it would freeze
            # "could not tell" into a permanent decision.
            and decision.sensitivity is not Sensitivity.UNKNOWN
        ):
            self.history.save(decision)
        return decision
