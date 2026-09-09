"""Portable, explicitly reviewed historical decisions (no executable expressions)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Optional

from dbmask.detection.result import Decision, Sensitivity
from dbmask.masking.rules import DEFAULT_RULE_STRATEGIES, STRATEGIES


class HistoryValidationError(ValueError):
    """The file or record is not a valid historical decision."""


class HistoryConflictError(HistoryValidationError):
    """Conflicting decisions or a stale revision; nothing is imported."""


def utc_time(value: str) -> datetime:
    """Accept ISO dates/timestamps; interpret timezone-less values as UTC."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HistoryValidationError(f"Expected an ISO date/time, got {value!r}") from exc
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)


def normalized_type(value: str) -> str:
    return "".join(value.upper().split())


@dataclass(frozen=True)
class HistoryRecord:
    database: str
    schema: str
    table: str
    column: str
    decision: str = "review"
    detected_type: str = ""
    masking_strategy: str = ""
    review_status: str = "pending"
    user_id: str = ""
    reviewed_by: str = ""
    reviewed_at: str = ""
    reason: str = ""
    analysis_date: str = ""
    data_type: str = ""
    expires_at: str = ""
    revision: int = 0

    @property
    def key(self) -> str:
        # Exact, case-preserving tuple: embedded dots cannot alias another scope.
        identity = json.dumps([self.database, self.schema, self.table, self.column])
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    @property
    def location(self) -> str:
        return repr((self.database, self.schema, self.table, self.column))

    def to_dict(self) -> dict:
        return asdict(self)

    def validated(self, now: Optional[datetime] = None) -> HistoryRecord:
        for field in ("database", "table", "column", "user_id", "analysis_date"):
            if not getattr(self, field).strip():
                raise HistoryValidationError(f"{self.location}: {field} is required")
        if self.decision not in {"mask", "keep", "review"}:
            raise HistoryValidationError(f"{self.location}: invalid decision {self.decision!r}")
        if self.review_status not in {"pending", "approved", "superseded"}:
            raise HistoryValidationError(f"{self.location}: invalid review_status")
        if self.revision < 0:
            raise HistoryValidationError("revision must be a nonnegative integer")
        if self.decision == "keep" and self.masking_strategy:
            raise HistoryValidationError(f"{self.location}: keep must not specify a strategy")
        for field in ("analysis_date", "reviewed_at", "expires_at"):
            value = getattr(self, field)
            if value:
                utc_time(value)
        if self.review_status == "approved":
            if self.decision == "review" or not self.reviewed_by.strip() or not self.reviewed_at:
                raise HistoryValidationError(
                    f"{self.location}: approved requires mask/keep, reviewed_by and reviewed_at"
                )
        return self.check_applicability(now=now)

    def check_applicability(
        self, *, now: Optional[datetime] = None, current_type: Optional[str] = None,
        check_type: bool = False,
    ) -> HistoryRecord:
        if self.review_status != "approved":
            return self
        problem = ""
        if self.expires_at and utc_time(self.expires_at) <= (now or datetime.now(timezone.utc)):
            problem = "Historical decision expired"
        elif not self.data_type:
            problem = "Historical decision has no reviewed data_type"
        elif check_type and not current_type:
            problem = "Current column type could not be verified"
        elif check_type and normalized_type(self.data_type) != normalized_type(current_type or ""):
            problem = f"Column type changed: {self.data_type} -> {current_type}"
        elif self.decision == "mask" and self.masking_strategy not in STRATEGIES:
            problem = f"Unknown or missing masking_strategy: {self.masking_strategy!r}"
        if problem:
            return replace(self, review_status="pending", reason=f"{problem}. {self.reason}".strip())
        return self

    def as_decision(self, *, suggestion: bool = False) -> Decision:
        sensitive = {"mask": Sensitivity.SENSITIVE, "keep": Sensitivity.NOT_SENSITIVE,
                     "review": Sensitivity.UNKNOWN}[self.decision]
        usable = self.review_status == "approved"
        return Decision(
            self.database, self.schema, self.table, self.column,
            sensitivity=sensitive if usable or suggestion else Sensitivity.UNKNOWN,
            rule=self.detected_type or None,
            source="history" if usable else "history_pending",
            confidence=1.0 if usable else 0.0,
            detail=self.reason or f"Historical decision is {self.review_status}; review required",
            decided_at=utc_time(self.analysis_date), user_id=self.user_id,
            review_status=self.review_status, reviewed_by=self.reviewed_by,
            reviewed_at=self.reviewed_at,
            masking_strategy=self.masking_strategy if usable and self.decision == "mask" else None,
            data_type=self.data_type, expires_at=self.expires_at,
        )

    @classmethod
    def from_decision(cls, decision: Decision) -> HistoryRecord:
        action = {Sensitivity.SENSITIVE: "mask", Sensitivity.NOT_SENSITIVE: "keep",
                  Sensitivity.UNKNOWN: "review"}[decision.sensitivity]
        rule = decision.rule or ""
        strategy = decision.masking_strategy or DEFAULT_RULE_STRATEGIES.get(rule, "")
        if not strategy and rule in STRATEGIES:
            strategy = rule
        return cls(
            decision.database, decision.schema, decision.table, decision.column,
            decision=action, detected_type=rule,
            masking_strategy=strategy if action == "mask" else "",
            review_status="pending", user_id=decision.user_id,
            reason=decision.detail, analysis_date=decision.decided_at.isoformat(),
            data_type=decision.data_type,
        )


HISTORY_FIELDS = tuple(HistoryRecord.__dataclass_fields__)
REQUIRED_HEADERS = HISTORY_FIELDS[:13]
