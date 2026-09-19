"""Shared, explicit calendar parsing for detection and date masking.

No guessing between month/day orders. MDY is the US-oriented default; DMY
must be selected explicitly. Year-first and compact YYYYMMDD are unambiguous.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Optional

# Deliberately independent of the process locale (including on Windows).
_MONTHS = (
    "January", "February", "March", "April", "May", "June", "July", "August",
    "September", "October", "November", "December",
)
_MONTH_NUMBERS = {name.lower(): i for i, name in enumerate(_MONTHS, 1)}
_MONTH_NUMBERS.update({name[:3].lower(): i for i, name in enumerate(_MONTHS, 1)})


@dataclass(frozen=True)
class ParsedDate:
    value: date
    order: str
    separator: str
    widths: tuple[int, ...]
    suffix: str = ""
    month_token: str = ""
    delimiters: tuple[str, ...] = ()

    def render(self, value: date) -> str:
        parts = {"Y": value.year, "M": value.month, "D": value.day}
        rendered = [
            str(parts[part]).zfill(width) for part, width in zip(self.order, self.widths)
        ]
        if self.month_token:
            month = _MONTHS[value.month - 1]
            # May is both a full name and an abbreviation. Prefer a full name
            # in prose layouts, an abbreviation in D-Mon-YYYY.
            if len(self.month_token) == 3 and (
                self.month_token.lower() != "may" or self.delimiters == ("-", "-")
            ):
                month = month[:3]
            if self.month_token.isupper():
                month = month.upper()
            elif self.month_token.islower():
                month = month.lower()
            rendered[self.order.index("M")] = month
        separators = self.delimiters or (self.separator, self.separator)
        return rendered[0] + separators[0] + rendered[1] + separators[1] + rendered[2] + self.suffix


def _named_date(text: str) -> Optional[ParsedDate]:
    """English D-Mon-YYYY / D Month YYYY / Month D[, ] YYYY."""
    match = re.fullmatch(r"([0-9]{1,2})([- ])([A-Za-z]+)\2([0-9]{4})", text)
    if match:
        day, separator, month, year = match.groups()
        order, delimiters, widths = "DMY", (separator, separator), (len(day), 0, 4)
    else:
        match = re.fullmatch(r"([A-Za-z]+)( +)([0-9]{1,2})(,? +)([0-9]{4})", text)
        if not match:
            return None
        month, first, day, second, year = match.groups()
        order, delimiters, widths = "MDY", (first, second), (0, len(day), 4)
    number = _MONTH_NUMBERS.get(month.lower())
    if number is None or not (month.islower() or month.isupper() or month.istitle()):
        return None
    try:
        value = date(int(year), number, int(day))
    except ValueError:
        return None
    return ParsedDate(value, order, "", widths, month_token=month, delimiters=delimiters)


def parse_date(value: str, date_order: str = "MDY") -> Optional[ParsedDate]:
    """Validate a supported date and optional ISO-like time/offset suffix.

    Supported: YYYY-M-D, YYYY/M/D, YYYYMMDD; M/D/YYYY or M-D-YYYY
    (D/M/YYYY or D-M-YYYY with DMY); D.M.YYYY. Preserve original date
    widths/separators and the time suffix when rendering a shifted date.
    Also supports English D-Mon-YYYY, D Month YYYY and Month D[, ] YYYY.
    """
    if date_order not in {"MDY", "DMY"}:
        raise ValueError("date_order must be MDY or DMY")
    match = re.fullmatch(
        r"(.+?)([ T][0-9]{1,2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?"
        r"(?:Z|[+-][0-9]{2}:[0-9]{2})?)?", value.strip()
    )
    if not match:
        return None
    text, suffix = match.group(1), match.group(2) or ""
    named = _named_date(text)
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
    elif named is not None:
        order, separator = named.order, named.separator
        chunks = []
    else:
        return None
    components = dict(zip(order, (int(c) for c in chunks)))
    try:
        day = named.value if named is not None else date(components["Y"], components["M"], components["D"])
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
    if named is not None:
        return ParsedDate(day, order, separator, named.widths, suffix, named.month_token, named.delimiters)
    return ParsedDate(day, order, separator, tuple(len(c) for c in chunks), suffix)
