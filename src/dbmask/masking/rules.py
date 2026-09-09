"""Masking strategies (the "how to transform a value" catalogue).

Every strategy is a callable ``(value, context) -> masked_value``. They are
deterministic: a seeded RNG derived from the input guarantees the same source
value always maps to the same masked value, which keeps referential consistency
(e.g. the same customer name masks identically everywhere).

Built-in options:
  * fake-value replacement from dictionaries (names, cities, ...),
  * shuffle,
  * random characters (format-preserving),
  * null / blank,
  * plus redaction and a generic dictionary factory.
"""
from __future__ import annotations

import string
import uuid as uuid_mod
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Callable, Optional

from dbmask.dates import parse_date
from dbmask.masking import dictionaries as dicts
from dbmask.masking.format import (
    digits_only_random,
    format_preserving_random,
    luhn_check_digit,
    seeded_rng,
)


@dataclass
class MaskContext:
    """Information available to a strategy when masking a single value."""

    column: str
    rule: Optional[str]
    seed: Optional[str]
    date_order: str = "MDY"


Strategy = Callable[[str, MaskContext], object]

# ---------------------------------------------------------------------------
# Individual strategies
# ---------------------------------------------------------------------------

def strat_null(value, ctx: MaskContext):
    """Replace with SQL NULL."""
    return None


def strat_blank(value, ctx: MaskContext):
    """Replace with an empty string."""
    return ""


def strat_redact(value, ctx: MaskContext):
    """Keep length but hide content (e.g. ``****``), preserving separators."""
    if value is None:
        return None
    return "".join("*" if ch.isalnum() else ch for ch in str(value))


def _mask_numeric(value, rng) -> object:
    """Digit-randomize a numeric value, returning the same Python type.

    Only digits are replaced (``1e-05`` keeps its ``e``; signs and decimal
    points stay), so the result still parses. Integers keep their digit count
    by never gaining a leading zero.
    """
    s = str(value)
    out = list(digits_only_random(s, rng))
    if isinstance(value, int) and not isinstance(value, bool):
        digit_idx = [i for i, ch in enumerate(out) if ch.isdigit()]
        if len(digit_idx) > 1 and out[digit_idx[0]] == "0":
            out[digit_idx[0]] = rng.choice("123456789")
    masked = "".join(out)
    try:
        if isinstance(value, int):
            return int(masked)
        if isinstance(value, float):
            return float(masked)
        if isinstance(value, Decimal):
            return Decimal(masked)
    except (ValueError, InvalidOperation):
        return value  # nothing to randomize (e.g. inf/nan) — leave unchanged
    return masked


def _typed_dispatch(value, ctx: MaskContext):
    """Route typed (non-string) values to a strategy that keeps them valid.

    Returns ``None`` when the value is a plain string and the caller should
    proceed with its own text-based logic.
    """
    if isinstance(value, bool):
        return value  # a boolean carries one bit; there is nothing to hide in shape
    if isinstance(value, (datetime, date)):
        return strat_fake_date(value, ctx)
    if isinstance(value, uuid_mod.UUID):
        return strat_fake_uuid(value, ctx)
    if isinstance(value, (int, float, Decimal)):
        return _mask_numeric(value, seeded_rng(str(value), ctx.seed))
    return None


def strat_format_random(value, ctx: MaskContext):
    """Random characters, preserving length and digit/letter/separator layout.

    Typed values stay typed **and valid**: dates stay real dates, UUIDs stay
    UUIDs, ints stay ints — a masked ``DATE`` column must never receive a
    string like ``"8342-73-51"``.
    """
    if value is None:
        return None
    typed = _typed_dispatch(value, ctx)
    if typed is not None:
        return typed
    rng = seeded_rng(str(value), ctx.seed)
    return format_preserving_random(str(value), rng)


def strat_shuffle(value, ctx: MaskContext):
    """Deterministically shuffle the characters of the value in place.

    Letters/digits are permuted; separators keep their positions so the overall
    format is preserved. Typed values are routed to a type-preserving strategy
    instead (shuffling the digits of a date rarely yields a valid date).
    """
    if value is None:
        return None
    typed = _typed_dispatch(value, ctx)
    if typed is not None:
        return typed
    s = str(value)
    rng = seeded_rng(s, ctx.seed)
    movable_idx = [i for i, ch in enumerate(s) if ch.isalnum()]
    chars = [s[i] for i in movable_idx]
    rng.shuffle(chars)
    out = list(s)
    for idx, ch in zip(movable_idx, chars):
        out[idx] = ch
    return "".join(out)


def _pick(dictionary: str, value: str, ctx: MaskContext) -> Optional[str]:
    pool = dicts.get_dictionary(dictionary)
    if not pool:
        return None
    rng = seeded_rng(str(value), ctx.seed)
    return rng.choice(pool)


def strat_fake_first_name(value, ctx: MaskContext):
    if value is None:
        return None  # a missing value stays missing; masking never invents data
    pick = _pick("first_names", value, ctx)
    return pick if pick is not None else strat_format_random(value, ctx)


def strat_fake_last_name(value, ctx: MaskContext):
    if value is None:
        return None
    pick = _pick("last_names", value, ctx)
    return pick if pick is not None else strat_format_random(value, ctx)


def strat_fake_name(value, ctx: MaskContext):
    """Replace a full name with a consistent fake first + last name."""
    if value is None:
        return None
    first = _pick("first_names", value, ctx) or "Alex"
    last = _pick("last_names", str(value) + "_last", ctx) or "Doe"
    return f"{first} {last}"


def strat_fake_city(value, ctx: MaskContext):
    """Replace a US city with another US city."""
    if value is None:
        return None
    pick = _pick("us_cities", value, ctx)
    return pick if pick is not None else strat_format_random(value, ctx)


def _fake_email_local(s: str, ctx: MaskContext) -> str:
    rng = seeded_rng(s, ctx.seed)
    first = (_pick("first_names", s, ctx) or "user").lower()
    last = (_pick("last_names", s + "_l", ctx) or "anon").lower()
    return f"{first}.{last}{rng.randint(1, 999)}"


def strat_fake_email(value, ctx: MaskContext):
    """Consistent fake email on the reserved ``example.invalid`` domain.

    ``.invalid`` is reserved by RFC 2606/6761 and can never resolve, so a
    masked address can never be delivered to a real mailbox — and the (often
    identifying) original domain is not carried over. Use
    ``fake_email_keep_domain`` when analytics need the domain preserved.
    """
    if value is None:
        return None
    return f"{_fake_email_local(str(value), ctx)}@example.invalid"


def strat_fake_email_keep_domain(value, ctx: MaskContext):
    """Fake email that preserves the original domain.

    Useful when per-domain analytics matter. Trade-off: a rare/corporate
    domain can still identify a person or organization on its own.
    """
    if value is None:
        return None
    s = str(value)
    domain = s.split("@", 1)[1] if "@" in s else "example.invalid"
    return f"{_fake_email_local(s, ctx)}@{domain}"


def strat_fake_uuid(value, ctx: MaskContext):
    """Replace with a deterministic, **valid** version-4 UUID.

    ``format_random`` used to hand hex positions letters ``g``–``z``, which is
    not a UUID at all — it breaks parsers and typed ``UUID`` columns.
    """
    if value is None:
        return None
    s = str(value)
    rng = seeded_rng(s, ctx.seed)
    hexd = "".join(rng.choice("0123456789abcdef") for _ in range(32))
    # Stamp version (4) and variant (8/9/a/b) bits so the result is a real v4.
    hexd = hexd[:12] + "4" + hexd[13:16] + rng.choice("89ab") + hexd[17:]
    out = f"{hexd[:8]}-{hexd[8:12]}-{hexd[12:16]}-{hexd[16:20]}-{hexd[20:]}"
    if isinstance(value, uuid_mod.UUID):
        return uuid_mod.UUID(out)
    core = s.strip("{}")
    if core.isupper() and any(c.isalpha() for c in core):
        out = out.upper()
    if s.startswith("{") and s.endswith("}"):
        out = "{" + out + "}"
    return out


def strat_fake_ip(value, ctx: MaskContext):
    """Replace an IP address with a deterministic, **valid** one.

    IPv4 octets land in 1–254 (``format_random`` could produce ``999``);
    IPv6 keeps its grouping and case with random hex digits. Values that are
    not IP-shaped fall back to format-preserving randomization.
    """
    if value is None:
        return None
    s = str(value).strip()
    rng = seeded_rng(s, ctx.seed)
    if ":" in s:  # IPv6 — replace hex digits in place, keep :: structure
        out = []
        for ch in s:
            if ch in "0123456789abcdefABCDEF":
                c = rng.choice("0123456789abcdef")
                out.append(c.upper() if ch.isupper() else c)
            else:
                out.append(ch)
        return "".join(out)
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(str(rng.randint(1, 254)) for _ in parts)
    return strat_format_random(value, ctx)


def strat_fake_credit_card(value, ctx: MaskContext):
    """Randomize card digits but keep the number **Luhn-valid**.

    Separators/spacing are preserved. Test suites and UIs that checksum card
    fields keep working; ``format_random`` produced numbers that fail Luhn
    (and can also be told apart from real data by that failure).
    """
    if value is None:
        return None
    s = str(value)
    rng = seeded_rng(s, ctx.seed)
    digit_idx = [i for i, ch in enumerate(s) if ch.isdigit()]
    if len(digit_idx) < 2:
        return strat_format_random(value, ctx)
    out = list(s)
    for i in digit_idx:
        out[i] = rng.choice(string.digits)
    if out[digit_idx[0]] == "0":
        out[digit_idx[0]] = rng.choice("123456789")
    partial = "".join(out[i] for i in digit_idx[:-1])
    out[digit_idx[-1]] = str(luhn_check_digit(partial))
    return "".join(out)


def _date_shift(anchor: str, ctx: MaskContext) -> timedelta:
    rng = seeded_rng(anchor, ctx.seed)
    return timedelta(days=rng.randint(30, 730) * rng.choice((-1, 1)))


def strat_fake_date(value, ctx: MaskContext):
    """Shift a date/datetime by a deterministic ±30–730 days.

    The result is always a **real calendar date** in the same representation
    as the input (`date` stays `date`, ``2026-02-14`` stays ISO-formatted).
    ``format_random`` on a date produced impossible values like
    ``8342-73-51`` that typed columns reject outright. Unparseable strings
    fall back to format-preserving randomization.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value + _date_shift(value.isoformat(), ctx)
    if isinstance(value, date):
        return value + _date_shift(value.isoformat(), ctx)
    s = str(value)
    parsed = parse_date(s, ctx.date_order)
    if parsed is not None:
        delta = _date_shift(s, ctx)
        try:
            shifted = parsed.value + delta
        except OverflowError:
            shifted = parsed.value - delta
        return parsed.render(shifted)
    rng = seeded_rng(s, ctx.seed)
    return format_preserving_random(s, rng)


def make_dictionary_strategy(dictionary: str) -> Strategy:
    """Build a strategy that replaces values from an arbitrary named dictionary."""

    def _strategy(value, ctx: MaskContext):
        if value is None:
            return None
        pick = _pick(dictionary, value, ctx)
        return pick if pick is not None else strat_format_random(value, ctx)

    return _strategy


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
STRATEGIES: dict[str, Strategy] = {
    "null": strat_null,
    "blank": strat_blank,
    "redact": strat_redact,
    "format_random": strat_format_random,
    "shuffle": strat_shuffle,
    "fake_name": strat_fake_name,
    "fake_first_name": strat_fake_first_name,
    "fake_last_name": strat_fake_last_name,
    "fake_city": strat_fake_city,
    "fake_email": strat_fake_email,
    "fake_email_keep_domain": strat_fake_email_keep_domain,
    "fake_uuid": strat_fake_uuid,
    "fake_ip": strat_fake_ip,
    "fake_credit_card": strat_fake_credit_card,
    "fake_date": strat_fake_date,
}

# Sensible defaults mapping *detected rule* -> *strategy* when the user hasn't
# configured one. Anything not listed falls back to the engine's default.
DEFAULT_RULE_STRATEGIES: dict[str, str] = {
    "email": "fake_email",
    "full_name": "fake_name",
    "first_name": "fake_first_name",
    "last_name": "fake_last_name",
    "city": "fake_city",
    "phone": "format_random",
    "ssn": "format_random",
    "credit_card": "fake_credit_card",
    "zip_code": "format_random",
    "ip_address": "fake_ip",
    "uuid": "fake_uuid",
    "date": "fake_date",
    "address": "redact",
    "date_of_birth": "fake_date",
}


def get_strategy(name: str) -> Strategy:
    if name not in STRATEGIES:
        raise KeyError(
            f"Unknown masking strategy '{name}'. Available: {sorted(STRATEGIES)}"
        )
    return STRATEGIES[name]


def register_strategy(name: str, strategy: Strategy) -> None:
    """Register a custom strategy at runtime."""
    STRATEGIES[name] = strategy
