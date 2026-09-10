"""Regression tests: masked values must stay *valid* for their data type.

``format_random`` treated every value as free text: dates became impossible
calendar entries (``8342-73-51``), UUIDs picked up letters g–z, IPv4 octets
went to 999, credit-card numbers failed Luhn, and typed Python values
(int/float/date/UUID) came back as strings — which strict engines reject on
write and which makes masked data trivially distinguishable from real data.

New strategies (fake_uuid / fake_ip / fake_credit_card / fake_date) and a
typed dispatch inside format_random/shuffle keep every replacement valid,
deterministic, and of the same Python type as the original.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import date, datetime
from decimal import Decimal

import pytest

from dbmask.config import MaskingConfig, SeedMapConfig
from dbmask.detection.patterns import _luhn_valid
from dbmask.masking.engine import ColumnPlan, MaskingEngine
from dbmask.masking.format import coerce_stored, luhn_check_digit
from dbmask.masking.rules import MaskContext, MaskingValidationError, get_strategy

CTX = MaskContext(column="x", rule=None, seed="format-tests")


def _run(strategy: str, value):
    return get_strategy(strategy)(value, CTX)


# -- fake_uuid -----------------------------------------------------------------

def test_fake_uuid_is_a_valid_v4_uuid():
    out = _run("fake_uuid", "6fa459ea-ee8a-3ca4-894e-db77e160355e")
    parsed = uuid.UUID(out)
    assert parsed.version == 4
    assert out != "6fa459ea-ee8a-3ca4-894e-db77e160355e"


def test_fake_uuid_deterministic_and_distinct():
    a1 = _run("fake_uuid", "6fa459ea-ee8a-3ca4-894e-db77e160355e")
    a2 = _run("fake_uuid", "6fa459ea-ee8a-3ca4-894e-db77e160355e")
    b = _run("fake_uuid", "16fd2706-8baf-433b-82eb-8c7fada847da")
    assert a1 == a2
    assert a1 != b


def test_fake_uuid_preserves_uppercase_and_braces():
    upper = _run("fake_uuid", "6FA459EA-EE8A-3CA4-894E-DB77E160355E")
    assert upper == upper.upper()
    uuid.UUID(upper)
    braced = _run("fake_uuid", "{6fa459ea-ee8a-3ca4-894e-db77e160355e}")
    assert braced.startswith("{") and braced.endswith("}")
    uuid.UUID(braced)


def test_fake_uuid_object_in_object_out():
    original = uuid.uuid4()
    out = _run("fake_uuid", original)
    assert isinstance(out, uuid.UUID)
    assert out != original


# -- fake_ip -------------------------------------------------------------------

def test_fake_ipv4_is_valid():
    out = _run("fake_ip", "203.0.113.77")
    parsed = ipaddress.ip_address(out)
    assert parsed.version == 4
    assert out != "203.0.113.77"
    assert all(1 <= int(o) <= 254 for o in out.split("."))


def test_fake_ipv6_is_valid_and_keeps_grouping():
    src = "2001:db8:85a3::8a2e:370:7334"
    out = _run("fake_ip", src)
    assert ipaddress.ip_address(out).version == 6
    assert out.count(":") == src.count(":")


def test_fake_ip_deterministic():
    assert _run("fake_ip", "203.0.113.77") == _run("fake_ip", "203.0.113.77")


def test_fake_ip_non_ip_falls_back_to_shape():
    out = _run("fake_ip", "not-an-ip")
    assert len(out) == len("not-an-ip")


# -- fake_credit_card ----------------------------------------------------------

def test_fake_credit_card_is_luhn_valid():
    src = "4111111111111111"
    out = _run("fake_credit_card", src)
    assert out != src
    assert len(out) == len(src)
    assert out.isdigit()
    assert _luhn_valid(out)


def test_fake_credit_card_keeps_separators():
    src = "4111-1111-1111-1111"
    out = _run("fake_credit_card", src)
    assert [i for i, c in enumerate(out) if c == "-"] == [4, 9, 14]
    assert _luhn_valid(out)


def test_luhn_check_digit_helper():
    # 7992739871 + check digit 3 is the classic worked example.
    assert luhn_check_digit("7992739871") == 3


# -- fake_date -----------------------------------------------------------------

def test_fake_date_object_stays_a_real_date():
    src = date(1990, 4, 15)
    out = _run("fake_date", src)
    assert isinstance(out, date)
    assert out != src
    assert 30 <= abs((out - src).days) <= 730


def test_fake_datetime_object_stays_datetime():
    src = datetime(2024, 1, 15, 10, 30, 0)
    out = _run("fake_date", src)
    assert isinstance(out, datetime)
    assert out != src


def test_fake_date_string_keeps_format_and_is_real():
    out = _run("fake_date", "1990-04-15")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", out)
    datetime.strptime(out, "%Y-%m-%d")  # parses -> a real calendar date
    assert out != "1990-04-15"


def test_fake_date_us_format_preserved():
    out = _run("fake_date", "04/15/1990")
    datetime.strptime(out, "%m/%d/%Y")
    assert out != "04/15/1990"


def test_fake_date_deterministic():
    assert _run("fake_date", "1990-04-15") == _run("fake_date", "1990-04-15")


def test_fake_date_garbage_requires_review():
    with pytest.raises(MaskingValidationError, match="valid calendar date"):
        _run("fake_date", "not a date")


# -- typed dispatch through format_random / shuffle ----------------------------

def test_format_random_int_stays_int():
    out = _run("format_random", 123456)
    assert isinstance(out, int)
    assert len(str(out)) == 6  # no leading-zero shrinkage
    assert out != 123456


def test_format_random_negative_int_keeps_sign():
    out = _run("format_random", -9876)
    assert isinstance(out, int) and out < 0


def test_format_random_float_stays_float():
    out = _run("format_random", 123.45)
    assert isinstance(out, float)
    assert out != 123.45


def test_format_random_decimal_stays_decimal():
    out = _run("format_random", Decimal("199.99"))
    assert isinstance(out, Decimal)


def test_format_random_bool_passes_through():
    assert _run("format_random", True) is True
    assert _run("format_random", False) is False


def test_format_random_date_object_valid():
    out = _run("format_random", date(2024, 1, 15))
    assert isinstance(out, date)


def test_format_random_uuid_object_valid():
    out = _run("format_random", uuid.uuid4())
    assert isinstance(out, uuid.UUID)


def test_shuffle_int_stays_int():
    out = _run("shuffle", 987654)
    assert isinstance(out, int)


# -- fake_email domains --------------------------------------------------------

def test_fake_email_uses_reserved_domain():
    out = _run("fake_email", "jane.roe@bigcorp.com")
    assert out.endswith("@example.invalid")
    assert "jane" not in out.split("@")[0] or out.split("@")[0] != "jane.roe"


def test_fake_email_keep_domain_variant():
    out = _run("fake_email_keep_domain", "jane.roe@bigcorp.com")
    assert out.endswith("@bigcorp.com")
    assert not out.startswith("jane.roe@")


def test_fake_email_deterministic():
    assert _run("fake_email", "a@b.c") == _run("fake_email", "a@b.c")


# -- seed-map round trip for typed values --------------------------------------

def test_seed_map_reuse_restores_python_type(tmp_path):
    url = f"sqlite:///{tmp_path / 'seeds.db'}"
    plan = ColumnPlan(schema="s", table="t", column="dob",
                      rule="date_of_birth", strategy_name="fake_date")
    src = date(1985, 7, 1)

    first_engine = MaskingEngine(MaskingConfig(
        dry_run=False, seed="s", seed_map=SeedMapConfig(enabled=True, url=url)))
    first = first_engine.mask_value(src, plan)
    first_engine.close()

    second_engine = MaskingEngine(MaskingConfig(
        dry_run=False, seed="s", seed_map=SeedMapConfig(enabled=True, url=url)))
    second = second_engine.mask_value(src, plan)
    second_engine.close()

    assert isinstance(first, date) and isinstance(second, date)
    assert first == second  # served from the recorded pair, typed correctly


def test_coerce_stored_covers_common_types():
    assert coerce_stored(5, "42") == 42
    assert coerce_stored(1.5, "2.75") == 2.75
    assert coerce_stored(Decimal("1.0"), "3.14") == Decimal("3.14")
    assert coerce_stored(date(2020, 1, 1), "2021-02-03") == date(2021, 2, 3)
    assert coerce_stored(datetime(2020, 1, 1), "2021-02-03 04:05:06") == datetime(2021, 2, 3, 4, 5, 6)
    u = uuid.uuid4()
    assert coerce_stored(u, str(u)) == u
    assert coerce_stored("text", "other") == "other"
    assert coerce_stored(5, "not-a-number") == "not-a-number"  # graceful fallback
