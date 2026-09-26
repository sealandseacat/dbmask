"""Format evidence plus column context, with no weighted winner selection."""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from ipaddress import IPv4Address
from typing import Callable, Optional

from dbmask.dates import parse_date
from dbmask.ssn import parse_ssn


@dataclass
class Pattern:
    """A named value check; ``min_ratio`` can make the global floor stricter.

    ``weight`` is accepted for source compatibility only and is ignored.
    Overlapping eligible patterns are inconclusive, regardless of their order.
    """

    name: str
    test: Callable[[str], bool]
    min_ratio: float = 0.9
    weight: float = 1.0

    def __post_init__(self) -> None:
        if not 0 < self.min_ratio <= 1:
            raise ValueError("Pattern min_ratio must be in (0, 1]")


def _regex_test(pattern: str, flags: int = re.IGNORECASE) -> Callable[[str], bool]:
    compiled = re.compile(pattern, flags)
    return lambda value: bool(compiled.fullmatch(value))


_EMAIL = r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+"
_URL = r"(?:https?://|www\.)[^\s]+"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ZIP_US = r"[0-9]{5}(?:-[0-9]{4})?"
_PHONE_RE = re.compile(
    r"(?:\+?1[ .-]?)?(?:\([2-9][0-9]{2}\)[ .-]?|[2-9][0-9]{2}[ .-]?)"
    r"[2-9][0-9]{2}[ .-]?[0-9]{4}(?:\s*(?:ext\.?|x|#)\s*[0-9]{1,6})?",
    re.IGNORECASE,
)
_STREET = (
    r"[0-9]+[a-z]?\s+[\w'.\- ]+?\s+"
    r"(st|street|ave|avenue|rd|road|blvd|boulevard|ln|lane|dr|drive|ct|court|"
    r"way|pl|place|ter|terrace|cir|circle|pkwy|parkway|hwy|highway)\.?"
    r"(\s+(apt|ste|suite|unit|#)\s*[\w-]+)?"
)


def _known_cities() -> frozenset:
    """Small bundled reference; membership alone cannot establish a city."""
    from dbmask.masking.dictionaries import get_dictionary

    return _city_set(tuple(get_dictionary("us_cities")))


@lru_cache(maxsize=4)
def _city_set(values: tuple[str, ...]) -> frozenset:
    return frozenset(c.strip().lower() for c in values if c.strip())


def _looks_like_city(value: str) -> bool:
    return value.lower() in _known_cities()


def _looks_like_phone(value: str) -> bool:
    return bool(_PHONE_RE.fullmatch(value))


def _looks_like_ssn(value: str) -> bool:
    return parse_ssn(value) is not None


def _looks_like_email(value: str) -> bool:
    if not re.fullmatch(_EMAIL, value, re.IGNORECASE):
        return False
    local, domain = value.rsplit("@", 1)
    return (
        len(local) <= 64 and len(value) <= 254
        and not local.startswith(".") and not local.endswith(".") and ".." not in local
        and all(len(label) <= 63 for label in domain.split("."))
    )


def _looks_like_ip(value: str) -> bool:
    try:
        IPv4Address(value)
        return True
    except ValueError:
        return False


def _looks_like_full_name(value: str) -> bool:
    """Name-like characters, only useful with an explicit personal-name column.

    No capitalization requirement or city exclusion: Austin can be a person's
    name. Unknown cities cannot become names without personal-name context.
    """
    parts = value.split()
    return 1 <= len(parts) <= 6 and all(
        any(c.isalpha() for c in part)
        and all(c.isalpha() or c in "'-’." for c in part)
        for part in parts
    )


def _luhn_valid(value: str) -> bool:
    if not re.fullmatch(r"[0-9]+(?:[ -][0-9]+)*", value):
        return False
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    for i, digit in enumerate(digits):
        if i % 2 == len(digits) % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


# Prefix ranges and supported lengths, deliberately a documented subset.
# Format facts: braintree/credit-card-type, src/lib/card-types.ts.
CARD_BRANDS = (
    ("visa", (13, 16, 19), ((4, 4, 1),)),
    ("mastercard", (16,), ((51, 55, 2), (2221, 2720, 4))),
    ("amex", (15,), ((34, 34, 2), (37, 37, 2))),
    ("discover", (16, 19), ((6011, 6011, 4), (644, 649, 3), (65, 65, 2))),
)


def _looks_like_card(value: str) -> bool:
    if not _luhn_valid(value):
        return False
    digits = value.replace(" ", "").replace("-", "")
    return any(
        len(digits) in lengths
        and any(low <= int(digits[:width]) <= high for low, high, width in ranges)
        for _, lengths, ranges in CARD_BRANDS
    )


DEFAULT_PATTERNS: list[Pattern] = [
    Pattern("email", _looks_like_email),
    Pattern("url", _regex_test(_URL)),
    Pattern("ip_address", _looks_like_ip),
    Pattern("uuid", _regex_test(_UUID)),
    Pattern("ssn", _looks_like_ssn),
    Pattern("credit_card", _looks_like_card),
    Pattern("zip_code", _regex_test(_ZIP_US)),
    Pattern("phone", _looks_like_phone),
    Pattern("address", _regex_test(_STREET)),
    Pattern("city", _looks_like_city),
    Pattern("full_name", _looks_like_full_name),
    Pattern("date", lambda value: parse_date(value) is not None),
]

# Token boundaries avoid matching "tel" in "hotel" or "date" in "candidate".
_NAME_HINTS = {
    "email": {"email", "e_mail"},
    "phone": {"phone", "telephone", "tel", "mobile", "cell", "fax"},
    "ssn": {"ssn", "social_security"},
    "date": {"date", "datetime", "timestamp", "dob", "birth_date", "birthdate", "birth", "happened_on"},
    "credit_card": {"credit_card", "card_number", "card_no", "card_num", "pan", "cc_number"},
    "zip_code": {"zip", "zipcode", "postal_code", "postcode"},
    "city": {"city", "town"},
    "full_name": {"full_name", "first_name", "last_name", "middle_name", "given_name", "surname", "family_name", "person_name", "customer_name"},
    "address": {"street", "address", "addr"},
    "ip_address": {"ip", "ipv4"},
    "url": {"url", "website", "uri"},
    "uuid": {"uuid", "guid"},
}


def column_hints(column: str) -> set[str]:
    split = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", column)
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", split)
    normalized = re.sub(r"[^a-z0-9]+", "_", split.lower()).strip("_")
    wrapped = "_" + normalized + "_"
    hints = {
        name for name, words in _NAME_HINTS.items()
        if any("_" + word + "_" in wrapped for word in words)
    }
    # email_address and ip_address are established compound names.
    if hints & {"email", "ip_address"}:
        hints.discard("address")
    return hints


@dataclass
class PatternMatch:
    name: str
    ratio: float
    confidence: float  # Compatibility alias for the unweighted ratio.
    hits: int = 0
    total: int = 0


@dataclass
class PatternEvidence:
    name: str
    hits: int
    total: int
    ratio: float
    threshold: float
    eligible: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class PatternAnalysis:
    match: Optional[PatternMatch]
    candidates: list[PatternEvidence]
    total: int
    reasons: list[str]

    def summary(self) -> str:
        evidence = "; ".join(
            f"{c.name}: {c.hits}/{c.total} ({c.ratio:.2%})"
            + (" [" + "; ".join(c.reasons) + "]" if c.reasons else "")
            for c in self.candidates
        )
        return "; ".join(part for part in [evidence, *self.reasons] if part)


class PatternMatcher:
    """Check formats, minimum evidence and context; never rank by weights."""

    def __init__(
        self, patterns: Optional[Sequence[Pattern]] = None, *,
        min_ratio: float = 0.9, min_samples: int = 20, date_order: str = "MDY",
    ):
        if not 0 < min_ratio <= 1:
            raise ValueError("min_ratio must be in (0, 1]")
        if isinstance(min_samples, bool) or not isinstance(min_samples, int) or min_samples < 1:
            raise ValueError("min_samples must be a positive integer")
        if date_order not in {"MDY", "DMY"}:
            raise ValueError("date_order must be MDY or DMY")
        self.min_ratio, self.min_samples, self.date_order = min_ratio, min_samples, date_order
        self.patterns = list(patterns) if patterns is not None else [
            Pattern(p.name, p.test, min_ratio=min_ratio) for p in DEFAULT_PATTERNS
        ]
        if patterns is None:
            self.patterns[-1].test = lambda v: parse_date(v, self.date_order) is not None

    def analyze(
        self, values: Sequence[str], column: str = "", data_type: str = "",
    ) -> PatternAnalysis:
        # Trim outer whitespace only; separators and leading zeros are evidence.
        clean = [str(v).strip() for v in values if v is not None and str(v).strip()]
        total = len(clean)
        hints = column_hints(column)
        if re.match(r"^(?:DATE|DATETIME\d*|TIMESTAMP|SMALLDATETIME)\b", data_type.upper()):
            hints.add("date")
        candidates: list[PatternEvidence] = []
        reasons: list[str] = []
        if total < self.min_samples:
            reasons.append(f"Insufficient nonblank samples: {total}; need {self.min_samples}")
        if len(hints) > 1:
            reasons.append("Conflicting column/type context: " + ", ".join(sorted(hints)))
        for pat in self.patterns:
            matching = [v for v in clean if pat.test(v)]
            hits = len(matching)
            if not hits and pat.name not in hints:
                continue
            ratio = hits / total if total else 0.0
            threshold = max(self.min_ratio, pat.min_ratio)
            blockers = []
            if ratio < threshold:
                blockers.append(f"Below {threshold:.0%} threshold")
            if hints and hints != {pat.name}:
                blockers.append("Column/type context conflicts with " + ", ".join(sorted(hints)))
            requires_context = pat.name in {"full_name", "city", "zip_code", "credit_card"}
            if pat.name in {"phone", "ssn", "date"} and any(v.isascii() and v.isdigit() for v in matching):
                requires_context = True
            if pat.name == "ssn" and any(re.search(r"[Xx*]", v) for v in matching):
                requires_context = True
            if requires_context and pat.name not in hints:
                blockers.append("Requires supporting column/type context")
            is_eligible = total >= self.min_samples and not blockers and len(hints) <= 1
            candidates.append(PatternEvidence(pat.name, hits, total, ratio, threshold, is_eligible, blockers))
        eligible = [c for c in candidates if c.eligible]
        match = None
        if len(eligible) == 1:
            c = eligible[0]
            match = PatternMatch(c.name, c.ratio, c.ratio, c.hits, c.total)
        elif len(eligible) > 1:
            reasons.append("Multiple eligible patterns; review required: " + ", ".join(c.name for c in eligible))
        elif total:
            reasons.append("No conclusive pattern; review required")
        return PatternAnalysis(match, candidates, total, reasons)

    def match(
        self, values: Sequence[str], column: str = "", data_type: str = "",
    ) -> Optional[PatternMatch]:
        """Convenience API; use ``analyze`` to retain inconclusive evidence."""
        return self.analyze(values, column, data_type).match
