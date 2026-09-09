"""Detection result types shared across the whole pipeline."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from dbmask.detection.patterns import PatternEvidence


class Sensitivity(str, Enum):
    """Whether a column is considered sensitive."""

    SENSITIVE = "sensitive"
    NOT_SENSITIVE = "not_sensitive"
    UNKNOWN = "unknown"


@dataclass
class Decision:
    """The outcome of analyzing a single column.

    Attributes
    ----------
    database, schema, table, column:
        Fully-qualified location of the analyzed column.
    sensitivity:
        Whether the column is sensitive.
    rule:
        The masking/scrambling rule to apply (e.g. ``"email"``, ``"full_name"``,
        ``"null"``). ``None`` when the column is not sensitive.
    source:
        Which layer made the decision: ``history``, ``override``, ``pattern``
        or ``llm``. Useful for auditing and debugging.
    confidence:
        Compatibility score in [0, 1]. For pattern results this is the raw
        sample match ratio, NOT a probability of correct classification.
        LLM confidence is reported separately when that layer decides.
    detail:
        Free-form human-readable explanation.
    token_usage:
        Tokens consumed if an LLM was used (0 otherwise).
    decided_at:
        UTC timestamp of the decision.
    """

    database: str
    schema: str
    table: str
    column: str
    sensitivity: Sensitivity = Sensitivity.UNKNOWN
    rule: Optional[str] = None
    source: str = "unknown"
    confidence: float = 0.0
    detail: str = ""
    token_usage: int = 0
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Review metadata is independent of the tentative sensitivity/type.
    user_id: str = ""
    review_status: str = "pending"
    reviewed_by: str = ""
    reviewed_at: str = ""
    masking_strategy: Optional[str] = None
    data_type: str = ""
    expires_at: str = ""
    # Pattern ratios are observed sample proportions, not probabilities.
    pattern_candidates: list[PatternEvidence] = field(default_factory=list)
    pattern_sample_count: int = 0
    pattern_sample_basis: str = ""

    @property
    def is_sensitive(self) -> bool:
        return self.sensitivity == Sensitivity.SENSITIVE

    @property
    def key(self) -> str:
        """Stable identity for this column across runs."""
        return f"{self.database}.{self.schema}.{self.table}.{self.column}".lower()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sensitivity"] = self.sensitivity.value
        d["decided_at"] = self.decided_at.isoformat()
        return d
