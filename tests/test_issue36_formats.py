"""Regression coverage for mixed representations reported in issue #36."""
from datetime import date

import pytest

from dbmask.config import MaskingConfig
from dbmask.dates import parse_date
from dbmask.detection.patterns import PatternMatcher
from dbmask.masking.engine import ColumnPlan, MaskingEngine
from dbmask.masking.rules import MaskContext, MaskingValidationError, get_strategy


@pytest.mark.parametrize("value,expected", [
    ("23-Dec-1974", "08-Sep-2001"),
    ("May 27, 1960", "September 08, 2001"),
    ("1-May-2024", "8-Sep-2001"),
    ("1 May 2024", "8 September 2001"),
    ("01-JANUARY-2024", "08-SEPTEMBER-2001"),
    ("jan 1, 2024", "sep 8, 2001"),
    ("January  01 2024", "September  08 2001"),
    ("01 february 2024", "08 september 2001"),
    ("23-Dec-1974T1:02:03.123456+05:30", "08-Sep-2001T1:02:03.123456+05:30"),
    ("May 27, 1960 23:59Z", "September 08, 2001 23:59Z"),
])
def test_named_dates_share_calendar_parser_and_preserve_layout(value, expected):
    parsed = parse_date(value)
    assert parsed is not None
    assert parsed.render(date(2001, 9, 8)) == expected
    assert parse_date(value, "DMY").value == parsed.value
    matcher = PatternMatcher(min_samples=1)
    assert matcher.match([value], column="date_of_birth").name == "date"
    ctx = MaskContext("date_of_birth", "date", "issue36")
    masked = get_strategy("fake_date")(value, ctx)
    assert get_strategy("fake_date")(value, ctx) == masked
    after = parse_date(masked)
    assert after is not None
    assert 30 <= abs((after.value - parsed.value).days) <= 730
    assert after.suffix == parsed.suffix
    assert masked == parsed.render(after.value)


@pytest.mark.parametrize("month,number", [
    ("January", 1), ("February", 2), ("March", 3), ("April", 4),
    ("May", 5), ("June", 6), ("July", 7), ("August", 8),
    ("September", 9), ("October", 10), ("November", 11), ("December", 12),
])
def test_english_month_names_do_not_depend_on_locale(month, number):
    for token in (month, month.upper(), month.lower(), month[:3]):
        assert parse_date(f"29-{token}-2024").value == date(2024, number, 29)


@pytest.mark.parametrize("value", [
    "29-Feb-2023", "31-April-2024", "February 30, 2024", "01-Foo-2024",
    "May 27, 60", "1-Jän-2024", "1-jAn-2024", "May 27, 1960 24:00",
    "May 27, 1960T12:00+24:00", "May 27, 1960 trailing text", "NULL", "-",
])
def test_bad_named_dates_and_unconfigured_markers_remain_strict(value):
    assert parse_date(value) is None
    with pytest.raises(MaskingValidationError) as exc:
        get_strategy("fake_date")(value, MaskContext("dob", "date", "s"))
    assert value not in str(exc.value)


def test_mixed_dates_report_actual_ratio_including_literal_placeholders():
    values = ["23-Dec-1974", "May 27, 1960", "2000-02-29"] * 6 + ["01/31/2024", "NULL"]
    match = PatternMatcher().match(values, column="date_of_birth")
    assert (match.name, match.hits, match.total, match.ratio) == ("date", 19, 20, 0.95)


@pytest.mark.parametrize("value", [
    "123 45 6789", "012 34 5678", "XXX-XX-5109", "xxx xx 5109",
    "***-**-5109", "XXXXX5109", "123-45-6789", "012345678", 123456789,
])
def test_full_and_partial_ssns_change_serial_and_preserve_shape(value):
    for seed in ("s", "issue36", "12377"):
        ctx = MaskContext("ssn", "ssn", seed)
        output = get_strategy("fake_ssn")(value, ctx)
        assert type(output) is type(value)
        assert str(output)[-4:] != str(value)[-4:]
        assert str(output)[-4:] != "0000"
        assert len(str(output)) == len(str(value))
        assert ''.join(c for c in str(output) if not c.isdigit()) == ''.join(c for c in str(value) if not c.isdigit())
        assert get_strategy("fake_ssn")(value, ctx) == output
        assert PatternMatcher(min_samples=1).match([str(output)], column="ssn").name == "ssn"


@pytest.mark.parametrize("value", ["XXX-XX-5109", "xxx xx 5109", "***-**-5109", "XXXXX5109"])
def test_partial_ssn_requires_explicit_ssn_context(value):
    matcher = PatternMatcher(min_samples=1)
    assert matcher.match([value]) is None
    assert matcher.match([value], column="account_number") is None
    assert matcher.match([value], column="customer_ssn").name == "ssn"


@pytest.mark.parametrize("value", [
    "000 12 3456", "666 12 3456", "900 12 3456", "123 00 3456", "123 45 0000",
    "123 45-6789", "XXX-XX-0000", "XXX XX-5109", "XXX-XX-XXXX", "XX*-XX-5109",
    "123-XX-6789", "XXX-XX-123", "１２３ ４５ ６７８９", "NULL", "-",
])
def test_invalid_ssns_do_not_become_accepted(value):
    assert PatternMatcher(min_samples=1).match([value], column="ssn") is None
    with pytest.raises(MaskingValidationError) as exc:
        get_strategy("fake_ssn")(value, MaskContext("ssn", "ssn", "s"))
    if len(value) > 1:
        assert value not in str(exc.value)


def test_old_ssn_cache_cannot_reuse_original_last_four(tmp_path):
    config = MaskingConfig(dry_run=False, seed="12377", seed_map={"url": f"sqlite:///{tmp_path / 'seeds.db'}"})
    engine = MaskingEngine(config)
    plan = ColumnPlan("main", "customers", "ssn", "ssn", "fake_ssn")
    try:
        store = engine.seed_store()
        store.record("fake_ssn", "123-45-6789", "402-28-6789", "fake_ssn")
        masked = engine.mask_value("123-45-6789", plan)
        assert masked[-4:] != "6789"
        assert store.lookup("fake_ssn", "123-45-6789") == "402-28-6789"
        assert store.lookup("fake_ssn:format-v2", "123-45-6789") == masked
        assert engine.mask_value("123-45-6789", plan) == masked
    finally:
        engine.close()
