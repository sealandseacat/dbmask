"""Pattern-based sensitive-data detection.

Instead of guessing from *column names only*, each :class:`Pattern` inspects a
sample of the actual values and reports how many of them match. A column is
flagged when a high enough fraction matches.

The classic example: values containing an ``@`` are very
likely email addresses. Patterns are data-driven, easy to read, and trivial to
extend — add your own by appending to ``DEFAULT_PATTERNS`` or passing custom
patterns to :class:`PatternMatcher`.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Optional


@dataclass
class Pattern:
    """A named heuristic that recognizes one kind of sensitive value.

    Attributes
    ----------
    name:
        Human-readable identifier, also used as the default masking *rule*
        (e.g. ``"email"`` -> the engine looks up a strategy for ``email``).
    test:
        Callable returning ``True`` if a single value looks like this kind.
    min_ratio:
        Fraction of sampled values that must match before the column is flagged.
    weight:
        Tie-breaker / confidence contribution when several patterns match.
    """

    name: str
    test: Callable[[str], bool]
    min_ratio: float = 0.6
    weight: float = 1.0


def _regex_test(pattern: str, flags: int = re.IGNORECASE) -> Callable[[str], bool]:
    compiled = re.compile(pattern, flags)
    return lambda value: bool(compiled.search(value or ""))


# --- Reusable building-block regexes ---------------------------------------
_EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
_URL = r"^(https?://|www\.)[^\s]+$"
_IPV4 = r"^(\d{1,3}\.){3}\d{1,3}$"
_PHONE = r"^\+?[\d\s().-]{7,}$"
_SSN_US = r"^\d{3}-?\d{2}-?\d{4}$"
_ZIP_US = r"^\d{5}(?:-\d{4})?$"
_UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_DATE = r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}([ T]\d{1,2}:\d{2}(:\d{2})?)?$"


_DATE_RE = re.compile(_DATE)
_PHONE_RE = re.compile(_PHONE)
_STREET = (
    r"^\d+[a-z]?\s+[\w'.\- ]+?\s+"
    r"(st|street|ave|avenue|rd|road|blvd|boulevard|ln|lane|dr|drive|ct|court|"
    r"way|pl|place|ter|terrace|cir|circle|pkwy|parkway|hwy|highway)\.?"
    r"(\s+(apt|ste|suite|unit|#)\s*[\w-]+)?$"
)


@lru_cache(maxsize=1)
def _known_cities() -> frozenset:
    """Lower-cased city names from the bundled ``us_cities`` dictionary.

    Imported lazily so this module does not depend on the masking package at
    import time. Extend the pool with
    ``dbmask.masking.dictionaries.register_dictionary("us_cities", [...])``
    and both detection and masking learn the new locales together.
    """
    from dbmask.masking.dictionaries import get_dictionary

    return frozenset(c.strip().lower() for c in get_dictionary("us_cities") if c.strip())


def _looks_like_city(value: str) -> bool:
    return (value or "").strip().lower() in _known_cities()


def _looks_like_phone(value: str) -> bool:
    """Phone-shaped, and specifically *not* a date.

    ``^\\+?[\\d\\s().-]{7,}$`` on its own also matches ``1994-03-15`` — a date
    is digits plus hyphens and longer than seven characters — so date columns
    were classified as phone numbers and masked with ``format_random``, which
    does not preserve a valid calendar date. Dates are excluded here, and the
    digit count is bounded to the E.164 range so long integers (amounts, row
    counters) stop matching too.
    """
    value = (value or "").strip()
    if not value or _DATE_RE.match(value):
        return False
    if "," in value or re.fullmatch(r"\d+\.\d+", value):
        return False  # 1,234,567.89 and 4500.00 are amounts, not phone numbers
    if not _PHONE_RE.match(value):
        return False
    digits = re.sub(r"\D", "", value)
    if not 7 <= len(digits) <= 15:
        return False
    # A bare run of digits with no separator, plus sign or parentheses is far
    # more often an amount or a counter than a phone number. Accept it only at
    # the lengths real phone numbers actually take.
    if not re.search(r"[\s().+-]", value):
        return len(digits) in (10, 11)
    return True


def _looks_like_full_name(value: str) -> bool:
    """Two-to-three capitalized words, letters/hyphens/apostrophes only.

    Known city names are excluded: ``New York`` and ``Salt Lake City`` are
    capitalized multi-word strings too, and city columns were being masked with
    person names.
    """
    value = (value or "").strip()
    if _looks_like_city(value):
        return False
    parts = value.split()
    if not (2 <= len(parts) <= 3):
        return False
    return all(re.fullmatch(r"[A-Z][a-zA-Z'’-]+\.?", p) for p in parts)


def _luhn_valid(value: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# --- The default catalogue --------------------------------------------------
DEFAULT_PATTERNS: list[Pattern] = [
    Pattern("email", _regex_test(_EMAIL), min_ratio=0.6),
    Pattern("url", _regex_test(_URL), min_ratio=0.6),
    Pattern("ip_address", _regex_test(_IPV4), min_ratio=0.7),
    Pattern("uuid", _regex_test(_UUID), min_ratio=0.8),
    Pattern("ssn", _regex_test(_SSN_US), min_ratio=0.6),
    Pattern("credit_card", _luhn_valid, min_ratio=0.6, weight=1.2),
    Pattern("zip_code", _regex_test(_ZIP_US), min_ratio=0.7),
    Pattern("phone", _looks_like_phone, min_ratio=0.7, weight=0.8),
    Pattern("address", _regex_test(_STREET), min_ratio=0.6, weight=0.95),
    # Dictionary-backed, so it outranks the shape-only full_name heuristic on
    # a genuine city column while never firing on a person-name column.
    Pattern("city", _looks_like_city, min_ratio=0.6, weight=1.0),
    Pattern("full_name", _looks_like_full_name, min_ratio=0.5, weight=0.9),
    Pattern("date", _regex_test(_DATE), min_ratio=0.8, weight=0.9),
]


@dataclass
class PatternMatch:
    name: str
    ratio: float
    confidence: float


class PatternMatcher:
    """Runs a catalogue of :class:`Pattern` objects over sampled values."""

    def __init__(self, patterns: Optional[Sequence[Pattern]] = None):
        self.patterns = list(patterns if patterns is not None else DEFAULT_PATTERNS)

    def match(self, values: Sequence[str]) -> Optional[PatternMatch]:
        """Return the best-matching pattern for ``values`` or ``None``.

        ``None`` means "patterns are inconclusive" — the caller may then fall
        back to history or an LLM.
        """
        clean = [v for v in (values or []) if v not in (None, "")]
        if not clean:
            return None

        best: Optional[PatternMatch] = None
        for pat in self.patterns:
            hits = sum(1 for v in clean if pat.test(v))
            ratio = hits / len(clean)
            if ratio >= pat.min_ratio:
                confidence = min(1.0, ratio * pat.weight)
                if best is None or confidence > best.confidence:
                    best = PatternMatch(pat.name, ratio, confidence)
        return best
