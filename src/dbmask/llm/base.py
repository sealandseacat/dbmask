"""Base classes and shared prompt for LLM-based detection.

Providers talk to standard endpoints directly: the official OpenAI API, any
OpenAI-compatible gateway, or a local server such as Ollama / LM Studio.
"""
from __future__ import annotations

import json
import math
import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Optional

SYSTEM_PROMPT = (
    "You are a data privacy analyst. You identify whether a sample of column "
    "values is sensitive (personally identifiable, confidential, or regulated) "
    "and, if so, what kind of data it is."
)

# The model must answer in a strict, parseable format.
USER_PROMPT_TEMPLATE = """\
Below is a random sample of distinct values taken from a single database column.

Decide whether this column contains sensitive data. Sensitive data includes (but
is not limited to): full names, personal/organization addresses, phone numbers,
email addresses, government IDs (e.g. SSN), financial/account numbers, credentials,
health information, dates of birth, and free-text that reveals such details.

Respond with a single line of JSON and nothing else:
{{"sensitive": true|false, "rule": "<short_snake_case_label>", "confidence": 0.0-1.0}}

Use "rule" to name the data type using a short snake_case label such as
"full_name", "email", "phone", "address", "ssn", "credit_card", "date_of_birth".
If not sensitive, set "rule" to null.

Column name: {column_name}
Sample values:
{sample}
"""


@dataclass
class LLMResult:
    # None means the response could not establish a classification. This must
    # never be interpreted as a negative/non-sensitive answer by the pipeline.
    sensitive: Optional[bool]
    rule: Optional[str]
    confidence: float
    token_usage: int = 0
    raw: str = ""
    error: str = ""

    def validation_error(self) -> Optional[str]:
        """Return a fixed, value-free error code, including for custom providers."""
        if self.error:
            known = {
                "invalid_json", "invalid_fields", "invalid_sensitive", "invalid_confidence",
                "invalid_rule", "invalid_token_usage", "unknown_classification",
            }
            return self.error if isinstance(self.error, str) and self.error in known else "invalid_response"
        if self.sensitive is None:
            return "unknown_classification"
        if type(self.sensitive) is not bool:
            return "invalid_sensitive"
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not 0 <= self.confidence <= 1
            or not math.isfinite(self.confidence)
        ):
            return "invalid_confidence"
        if self.sensitive:
            if (
                not isinstance(self.rule, str)
                or len(self.rule) > 128
                or re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", self.rule) is None
            ):
                return "invalid_rule"
        elif self.rule is not None:
            return "invalid_rule"
        if (
            isinstance(self.token_usage, bool)
            or not isinstance(self.token_usage, int)
            or self.token_usage < 0
        ):
            return "invalid_token_usage"
        return None


class LLMProviderError(RuntimeError):
    """A provider failed; its potentially sensitive exception is not reportable."""


class LLMProvider(ABC):
    """Common interface so the pipeline is provider-agnostic."""

    @abstractmethod
    def classify(self, column_name: str, sample: Sequence[str]) -> LLMResult:
        """Classify ``column_name`` from ``sample`` values and return an ``LLMResult``."""

    @staticmethod
    def build_prompt(column_name: str, sample: Sequence[str]) -> str:
        if sample:
            body = "\n".join(f"- {v}" for v in sample)
        else:
            # Metadata-only mode (llm.send_values: false): no data values are
            # disclosed to the provider — only the column name.
            body = ("(no values provided — the operator disabled sending "
                    "sample values; judge from the column name alone)")
        return USER_PROMPT_TEMPLATE.format(column_name=column_name, sample=body)

    @staticmethod
    def parse_response(text: str) -> LLMResult:
        """Accept one complete JSON result; malformed/uncertain answers are UNKNOWN.

        A single whole fenced JSON block is tolerated, but surrounding prose,
        duplicate fields and multiple answers are rejected rather than guessed.
        Raw provider text remains available here for private debugging only;
        it must not be copied into decisions, reports or history.
        """
        raw = text.strip() if isinstance(text, str) else ""

        def unknown(code: str) -> LLMResult:
            return LLMResult(None, None, 0.0, raw=raw, error=code)

        body = raw
        fence = re.fullmatch(r"```(?:json)?[ \t]*\r?\n(.*?)\r?\n```", body, re.DOTALL)
        if fence:
            body = fence[1].strip()

        def unique_fields(pairs):
            result = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError("duplicate_fields")
                result[name] = value
            return result

        try:
            data = json.loads(body, object_pairs_hook=unique_fields)
        except (ValueError, TypeError, RecursionError):
            return unknown("invalid_json")
        if not isinstance(data, dict) or set(data) != {"sensitive", "rule", "confidence"}:
            return unknown("invalid_fields")

        result = LLMResult(data["sensitive"], data["rule"], data["confidence"], raw=raw)
        error = result.validation_error()
        if error:
            return LLMResult(None, None, 0.0, raw=raw, error=error)
        return result
