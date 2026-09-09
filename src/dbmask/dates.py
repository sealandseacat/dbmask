"""Shared, explicit calendar parsing for detection and date masking.

No guessing between month/day orders. MDY is the US-oriented default; DMY
must be selected explicitly. Year-first and compact YYYYMMDD are unambiguous.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Optional


@dataclass(frozen=True)
class ParsedDate:
    value: date
    order: str
    separator: str
    widths: tuple[int, ...]
    suffix: str = ""

    def render(self, value: date) -> str:
        parts = {"Y": value.year, "M": value.month, "D": value.day}
        return self.separator.join(
            str(parts[part]).zfill(width) for part, width in zip(self.order, self.widths)
        ) + self.suffix


def parse_date(value: str, date_order: str = "MDY") -> Optional[ParsedDate]:
    """Validate a supported date and optional ISO-like time/offset suffix.

    Supported: YYYY-M-D, YYYY/M/D, YYYYMMDD; M/D/YYYY or M-D-YYYY
    (D/M/YYYY or D-M-YYYY with DMY); D.M.YYYY. Preserve original date
    widths/separators and the time suffix when rendering a shifted date.
    """
    if date_order not in {"MDY", "DMY"}:
        raise ValueError("date_order must be MDY or DMY")
    match = re.fullmatch(
        r"([0-9./-]+)([ T][0-9]{1,2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?"
        r"(?:Z|[+-][0-9]{2}:[0-9]{2})?)?", value.strip()
    )
    if not match:
        return None
    text, suffix = match.group(1), match.group(2) or ""
    if re.fullmatch(r"[0-9]{8}", text):
        order, separator = "YMD", ""
        chunks = [text[:4], text[4:6], text[6:]]
    elif re.fullmatch(r"[0-9]{4}([/-])[0-9]{1,2}\1[0-9]{1,2}", text):
        order, separator = "YMD", text[4]
        chunks = text.split(separator)
    elif re.fullmatch(r"[0-9]{1,2}([/.-])[0-9]{1,2}\1[0-9]{4}", text):
        separator = next(c for c in text if c in "/.-")
        order = "DMY" if separator == "." else date_order
        chunks = text.split(separator)
    else:
        return None
    components = dict(zip(order, (int(c) for c in chunks)))
    try:
        day = date(components["Y"], components["M"], components["D"])
        if suffix:
            # Explicit shape validation above plus calendar/time range validation.
            time_text = suffix[1:].replace("Z", "+00:00")
            hour, rest = time_text.split(":", 1)
            # Python versions differ on accepting 24:00 as next-day midnight.
            # This parser promises an unchanged suffix, so require 00..23.
            if int(hour) > 23:
                return None
            datetime.fromisoformat(day.isoformat() + "T" + hour.zfill(2) + ":" + rest)
            offset = re.search(r"[+-]([0-9]{2}):([0-9]{2})$", time_text)
            if offset and (int(offset[1]) > 23 or int(offset[2]) > 59):
                return None
    except ValueError:
        return None
    return ParsedDate(day, order, separator, tuple(len(c) for c in chunks), suffix)
