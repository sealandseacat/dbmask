"""Explicit US SSN shapes shared by detection and masking; no assignment claim."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_FULL = re.compile(r"(?:[0-9]{9}|[0-9]{3}([- ])[0-9]{2}\1[0-9]{4})")
_PARTIAL = re.compile(r"(?P<mask>[Xx*])(?P=mask){2}(?P<sep>[- ]?)(?P=mask){2}(?P=sep)[0-9]{4}")


@dataclass(frozen=True)
class ParsedSSN:
    digits: str
    partial: bool = False


def parse_ssn(value: str) -> Optional[ParsedSSN]:
    """Accept full 3-2-4 / compact SSNs, or five hidden digits plus a serial.

    Spaces or hyphens must group consistently. Partial forms use one repeated
    X, x or * marker; fully hidden strings and invalid visible serials fail.
    Hidden groups cannot be validated or reconstructed.
    """
    if _PARTIAL.fullmatch(value):
        return ParsedSSN(value[-4:], partial=True) if value[-4:] != "0000" else None
    if not _FULL.fullmatch(value):
        return None
    digits = value.replace("-", "").replace(" ", "")
    if (
        1 <= int(digits[:3]) <= 899 and digits[:3] != "666"
        and digits[3:5] != "00" and digits[5:] != "0000"
    ):
        return ParsedSSN(digits)
    return None
