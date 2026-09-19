"""Public-contract regression coverage for contextual, unweighted detection."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import date
from types import SimpleNamespace

import pytest

from dbmask.cli import cli
from dbmask.config import Config, DetectionConfig, MaskingConfig
from dbmask.dates import parse_date
from dbmask.detection.patterns import Pattern, PatternMatcher, column_hints
from dbmask.detection.pipeline import DetectionPipeline
from dbmask.detection.result import Sensitivity
from dbmask.masking.engine import ColumnPlan, MaskingEngine
from dbmask.masking.format import luhn_check_digit
from dbmask.masking.rules import MaskContext, strat_fake_date
from dbmask.runner import Runner


@pytest.mark.parametrize("ratio,hits,expected", [(0.9, 90, True), (0.899, 899, False), (0.96, 96, True)])
def test_ratio_boundary_and_unweighted_confidence(ratio, hits, expected):
    total = 1000 if hits == 899 else 100
    values = ["a@example.org"] * hits + ["invalid"] * (total - hits)
    result = PatternMatcher().analyze(values, column="email")
    email = next(c for c in result.candidates if c.name == "email")
    assert (email.hits, email.total, email.ratio) == (hits, total, ratio)
    assert bool(result.match) is expected
    if result.match:
        assert result.match.confidence == ratio


@pytest.mark.parametrize("count,expected", [(0, False), (1, False), (19, False), (20, True)])
def test_default_minimum_sample_size(count, expected):
    result = PatternMatcher().analyze(["a@example.org"] * count, column="email")
    assert bool(result.match) is expected
    assert result.total == count
    if not expected:
        assert any("Insufficient" in reason for reason in result.reasons)


def test_blanks_excluded_without_losing_invalid_nonblank_values():
    values = [" a@example.org "] * 18 + ["invalid", "unknown", None, "", " \t\n"]
    result = PatternMatcher().analyze(values, column="email")
    assert result.match is not None
    assert (result.match.hits, result.match.total, result.match.ratio) == (18, 20, 0.9)


def test_weights_and_catalogue_order_cannot_choose_a_winner():
    patterns = [Pattern("alpha", lambda v: True, weight=100), Pattern("beta", lambda v: True, weight=0.01)]
    for catalogue in [patterns, list(reversed(patterns))]:
        result = PatternMatcher(catalogue).analyze(["x"] * 20)
        assert result.match is None
        assert {c.name for c in result.candidates if c.eligible} == {"alpha", "beta"}
        assert "Multiple eligible" in result.summary()


@pytest.mark.parametrize(
    "value,column,expected",
    [
        ("202-555-0123", "phone_number", "phone"),
        ("+1 (202) 555-0123 ext. 42", "mobile", "phone"),
        ("202.555.0123 x9", "tel", "phone"),
        ("12025550123", "phone", "phone"),
        ("2025550123", "identifier", None),
        ("2025550123", "date", None),
        ("202-555-0123", "date", None),
        ("+44 20 7946 0958", "phone", None),
        ("555-0123", "phone", None),
        ("102-555-0123", "phone", None),
        ("202-155-0123", "phone", None),
        ("202) 555-0123", "phone", None),
        ("(202 555-0123", "phone", None),
        ("202--555-0123", "phone", None),
        ("03-15-1994", "dob", "date"),
        ("9/8/2026", "date", "date"),
        ("20260908", "date", "date"),
        ("20260908", "order_id", None),
        ("2026-02-30", "date", None),
        ("2026-13-01", "date", None),
        ("2025-02-29", "date", None),
        ("2024-02-29", "date", "date"),
        ("012-34-5678", "ssn", "ssn"),
        ("012345678", "ssn", "ssn"),
        ("012345678", "code", None),
        ("000-12-3456", "ssn", None),
        ("666-12-3456", "ssn", None),
        ("900-12-3456", "ssn", None),
        ("999-12-3456", "ssn", None),
        ("123-00-3456", "ssn", None),
        ("123-12-0000", "ssn", None),
        ("12345-6789", "ssn", None),
        ("123-456789", "ssn", None),
        ("***-**-1234", "ssn", "ssn"),
        ("02108", "zip", "zip_code"),
        ("02108-1234", "postalCode", "zip_code"),
        ("021081234", "zip", None),
        ("02108", "identifier", None),
        ("Austin", "city", "city"),
        ("Austin", "first_name", "full_name"),
        ("Ann Arbor", "city", None),
        ("Palo Alto", "city", None),
        ("Chapel Hill", "city", None),
        ("Mary Johnson", "product_name", None),
        ("Mary Johnson", "full_name", "full_name"),
        ("菡婷 冯", "full_name", "full_name"),
        ("Élodie O’Connor", "fullName", "full_name"),
        ("jane+test@example.org", "email_address", "email"),
        ("jane@example.io", "email", "email"),
        ("jane@example.edu", "email", "email"),
        (".jane@example.org", "email", None),
        ("jane..doe@example.org", "email", None),
        ("jane@-example.org", "email", None),
        ("jane@example..org", "email", None),
        ("Call jane@example.org please", "notes", None),
        ("192.0.2.1", "ip_address", "ip_address"),
        ("999.999.999.999", "ip_address", None),
        ("192.168.01.1", "ip_address", None),
        ("4111111111111111", "card_number", "credit_card"),
        ("4111-1111-1111-1111", "credit_card", "credit_card"),
        ("4111111111111112", "card_number", None),
        ("4111111111111111", "identifier", None),
        ("card 4111111111111111", "card_number", None),
        ("0000000000000000", "card_number", None),
    ],
)
def test_format_and_context_regressions(value, column, expected):
    result = PatternMatcher().analyze([value] * 20, column=column)
    assert (result.match.name if result.match else None) == expected
    assert all(0 <= c.ratio <= 1 for c in result.candidates)


@pytest.mark.parametrize("prefix,length,expected", [
    ("4", 13, True), ("4", 16, True), ("4", 19, True), ("4", 15, False),
    ("51", 16, True), ("55", 16, True), ("2221", 16, True), ("2720", 16, True),
    ("2220", 16, False), ("2721", 16, False), ("34", 15, True), ("37", 15, True),
    ("34", 16, False), ("6011", 16, True), ("6011", 19, True),
])
def test_card_prefix_length_and_luhn(prefix, length, expected):
    stem = prefix + "0" * (length - len(prefix) - 1)
    value = stem + str(luhn_check_digit(stem))
    assert bool(PatternMatcher().match([value] * 20, column="card_number")) is expected


@pytest.mark.parametrize("column,expected", [
    ("socialSecurityNumber", {"ssn"}), ("emailAddress", {"email"}),
    ("IP_ADDRESS", {"ip_address"}), ("hotel", set()), ("candidate", set()),
    ("update_count", set()), ("firstName", {"full_name"}),
])
def test_column_token_boundaries(column, expected):
    assert column_hints(column) == expected


def test_typed_dates_supply_context_and_detect_conflicts():
    matcher = PatternMatcher()
    assert matcher.match(["20260908"] * 20, column="value", data_type="DATE").name == "date"
    result = matcher.analyze(["202-555-0123"] * 20, column="value", data_type="TIMESTAMP")
    assert result.match is None
    assert "conflicts" in result.summary()
    result = matcher.analyze(["2026-09-08"] * 20, column="phone", data_type="DATE")
    assert result.match is None
    assert "Conflicting column/type context" in result.summary()


@pytest.mark.parametrize("value,order", [
    ("1994-03-15", "MDY"), ("2026-9-6", "MDY"), ("2026/09/06", "MDY"),
    ("2026-09-06T12:30", "MDY"), ("03-15-1994", "MDY"), ("3/15/1994", "MDY"),
    ("20260908", "MDY"), ("2000-02-29 12:30:01.123456Z", "MDY"),
    ("2026-09-08T12:30:45+05:30", "MDY"), ("15/03/1994", "DMY"),
    ("03/04/2026", "DMY"), ("03/04/2026", "MDY"), ("15.03.1994", "MDY"),
    ("0001-01-01", "MDY"), ("9999-12-31", "MDY"),
])
def test_recognized_dates_mask_as_valid_dates(value, order):
    parsed = parse_date(value, order)
    assert parsed is not None
    assert PatternMatcher(date_order=order).match([value] * 20, column="date").name == "date"
    masked = strat_fake_date(value, MaskContext("date", "date", "test", date_order=order))
    after = parse_date(masked, order)
    assert after is not None
    assert 30 <= abs((after.value - parsed.value).days) <= 730
    assert (after.separator, after.suffix) == (parsed.separator, parsed.suffix)


@pytest.mark.parametrize("value", [
    "2026-02-30", "2025-02-29", "2026-13-01", "2026-00-01", "2026-01-00",
    "2026/09-08", "2026-09-08T24:00", "2026-09-08T12:60", "2026-09-08T12:30:60",
    "2026-09-08T12:30+05:99", "2026-09-08T12:30+24:00", "2026-09-08junk",
])
def test_impossible_dates_and_times_rejected(value):
    assert parse_date(value) is None


def test_date_order_is_explicit_not_guessed():
    assert parse_date("03/04/2026", "MDY").value == date(2026, 3, 4)
    assert parse_date("03/04/2026", "DMY").value == date(2026, 4, 3)
    assert parse_date("15/03/1994", "MDY") is None


@pytest.mark.parametrize("kwargs", [
    {"min_ratio": 0}, {"min_ratio": 1.1}, {"min_ratio": float("nan")},
    {"min_samples": 0}, {"min_samples": 1.5}, {"min_samples": True}, {"date_order": "guess"},
])
def test_invalid_matcher_configuration_rejected(kwargs):
    with pytest.raises(ValueError):
        PatternMatcher(**kwargs)
    config_kwargs = {("pattern_" + k if k in {"min_ratio", "min_samples"} else k): v for k, v in kwargs.items()}
    with pytest.raises(ValueError):
        DetectionConfig(**config_kwargs)


def test_custom_stricter_threshold_and_empty_catalogue():
    pattern = Pattern("custom", lambda value: value == "a", min_ratio=0.95)
    assert PatternMatcher([pattern]).match(["a"] * 18 + ["b"] * 2) is None
    assert PatternMatcher([]).match(["a@example.org"] * 20) is None
    assert PatternMatcher(min_ratio=0.8).match(["a@example.org"] * 16 + ["bad"] * 4)
    with pytest.raises(ValueError):
        Pattern("invalid", lambda value: True, min_ratio=0)


def _fake_connector(values, dtype="TEXT"):
    return SimpleNamespace(
        name="synthetic", column_type=lambda *args: dtype, sample_values=lambda *args: values,
    )


def test_llm_fallback_keeps_pattern_evidence():
    provider = SimpleNamespace(classify=lambda *args: SimpleNamespace(
        sensitive=True, rule="email", confidence=0.7, token_usage=10,
    ))
    pipeline = DetectionPipeline(Config(), llm=provider)
    result = pipeline.analyze_column(_fake_connector(["a@example.org"] * 16 + ["bad"] * 4), "s", "t", "email")
    assert result.source == "llm"
    assert result.confidence == 0.7  # LLM confidence must not become a match ratio.
    assert next(c for c in result.pattern_candidates if c.name == "email").ratio == 0.8
    assert "16/20 (80.00%)" in result.detail


def test_strong_conflict_is_held_for_human_even_with_llm():
    def forbidden(*args):
        raise AssertionError("LLM must not erase a strong conflict")
    result = DetectionPipeline(Config(), llm=SimpleNamespace(classify=forbidden)).analyze_column(
        _fake_connector(["202-555-0123"] * 20), "s", "t", "date",
    )
    assert result.sensitivity is Sensitivity.UNKNOWN
    assert result.source == "pattern_conflict"
    assert result.rule is None
    assert {c.name for c in result.pattern_candidates} >= {"date", "phone"}


def test_sql_distinct_sampling_and_reports_are_explicit(cli_env):
    # Row ratio is 99%, but DISTINCT sample ratio is only 50%; don't mislabel it.
    with sqlite3.connect(cli_env.db) as conn:
        conn.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, email TEXT)")
        conn.executemany("INSERT INTO contacts (email) VALUES (?)", [("a@example.org",)] * 99 + [("bad",)])
    cfg_path = cli_env.make_config()
    result = cli_env.runner.invoke(cli, ["scan", "--config", cfg_path, "--json"])
    assert result.exit_code == 0, result.output
    decision = next(d for d in json.loads(result.output) if d["table"] == "contacts" and d["column"] == "email")
    assert decision["pattern_sample_basis"] == "distinct_values"
    assert decision["pattern_sample_count"] == 2
    candidate = next(c for c in decision["pattern_candidates"] if c["name"] == "email")
    assert candidate["ratio"] == 0.5
    assert decision["sensitivity"] == "unknown"


def test_cli_and_review_export_show_96_percent(cli_env):
    with sqlite3.connect(cli_env.db) as conn:
        conn.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, email TEXT)")
        conn.executemany("INSERT INTO contacts (email) VALUES (?)", [(f"u{i}@example.org",) for i in range(96)] + [(f"invalid{i}",) for i in range(4)])
    config = cli_env.make_config(detection={"sample_size": 100, "pattern_min_samples": 20})
    output = cli_env.tmp_path / "review.csv"
    result = cli_env.runner.invoke(cli, ["scan", "--config", config, "--output", str(output)])
    assert result.exit_code == 0, result.output
    assert "match=96.00%" in result.output
    assert "96/100 (96.00%)" in result.output
    assert "96/100 (96.00%)" in output.read_text(encoding="utf-8-sig")
    with Runner(Config.load(config)) as runner:
        report = runner.scan()
    decision = next(d for d in report.decisions if d.table == "contacts" and d.column == "email")
    assert decision.rule == "email"
    assert decision.review_status == "pending"
    assert asdict(decision)["pattern_sample_count"] == 100


def test_date_order_seed_maps_are_separate(tmp_path):
    cfg = MaskingConfig(seed_map={"url": f"sqlite:///{tmp_path / 'seed.db'}"})
    plan = ColumnPlan("s", "t", "date", "date", "fake_date")
    outcomes = {}
    for order in ["MDY", "DMY"]:
        engine = MaskingEngine(cfg, date_order=order)
        before = "03/04/2026"
        after = engine.mask_value(before, plan)
        assert 30 <= abs((parse_date(after, order).value - parse_date(before, order).value).days) <= 730
        outcomes[order] = after
        engine.close()
    for order, expected in outcomes.items():
        engine = MaskingEngine(cfg, date_order=order)
        assert engine.mask_value("03/04/2026", plan) == expected
        engine.close()


def test_partly_known_cities_fail_90_percent_threshold():
    result = PatternMatcher(min_samples=1).analyze(
        ["New York", "Chicago", "Salt Lake City"], column="city",
    )
    assert result.match is None
    assert next(c for c in result.candidates if c.name == "city").ratio == 2 / 3


def test_city_reference_updates_are_not_hidden_by_cache(monkeypatch):
    from dbmask.masking import dictionaries

    matcher = PatternMatcher()
    assert matcher.match(["Ann Arbor"] * 20, column="city") is None
    monkeypatch.setattr(dictionaries, "_CUSTOM", {"us_cities": ["Ann Arbor"]})
    assert matcher.match(["Ann Arbor"] * 20, column="city").name == "city"
