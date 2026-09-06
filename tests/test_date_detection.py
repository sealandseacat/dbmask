"""Date-shaped values must select calendar-preserving masking, not phone masking."""
from __future__ import annotations

import sqlite3
from datetime import date

import pytest

from dbmask.config import Config
from dbmask.detection.patterns import PatternMatcher
from dbmask.runner import Runner


@pytest.mark.parametrize("value", ["1994-03-15", "2026-9-6", "2026/09/06", "2026-09-06T12:30"])
def test_dates_are_not_classified_as_phones(value):
    match = PatternMatcher().match([value])
    assert match is not None
    assert match.name == "date"


@pytest.mark.parametrize("value", ["+1 (202) 555-0123", "202-555-0123", "2025550123"])
def test_phone_detection_is_preserved(value):
    match = PatternMatcher().match([value])
    assert match is not None
    assert match.name == "phone"


def test_dates_below_date_threshold_do_not_fall_back_to_phone():
    values = ["1994-03-15"] * 7 + ["unknown"] * 3
    assert PatternMatcher().match(values) is None


def test_scan_and_mask_text_dates_preserves_calendar_dates(cli_env):
    originals = ["1994-03-15", "2000-02-29", "2026-01-31"]
    with sqlite3.connect(cli_env.db) as conn:
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, happened_on TEXT)")
        conn.executemany("INSERT INTO events (happened_on) VALUES (?)", [(v,) for v in originals])

    cfg = Config.load(cli_env.make_config(masking={"dry_run": False}))
    with Runner(cfg) as runner:
        report = runner.scan()
        assert not report.errors
        decision = next(d for d in report.decisions if d.column == "happened_on")
        assert decision.rule == "date"
        runner.mask(report.decisions)

    masked = cli_env.read("happened_on", table="events")
    for original, replacement in zip(originals, masked):
        assert replacement != original
        assert 30 <= abs((date.fromisoformat(replacement) - date.fromisoformat(original)).days) <= 730
