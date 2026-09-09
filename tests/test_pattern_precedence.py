"""Patterns must not steal columns from each other.

Three regressions are covered here:

* dates were classified as ``phone`` (the phone regex matches digits and
  hyphens, and outweighed ``date``), so date columns were masked with
  ``format_random`` and stopped being valid calendar dates;
* city columns were classified as ``full_name`` (``New York`` is two
  capitalized words), so cities were replaced with person names;
* plain integers (amounts, counters) matched the phone regex.
"""
from __future__ import annotations

import pytest

from dbmask.detection.patterns import PatternMatcher


@pytest.fixture
def matcher() -> PatternMatcher:
    return PatternMatcher(min_samples=1)


@pytest.mark.parametrize(
    "expected, values",
    [
        ("date", ["1994-03-15", "2001-11-02", "1978-06-30"]),
        ("date", ["2024-01-15 09:30:00", "2023-12-01 14:05:11", "2022-07-04 00:00:00"]),
        ("date", ["2024/01/15", "2023/12/01", "2022/7/4"]),
        ("phone", ["(415) 555-0132", "+1 415 555 0132", "415-555-0132"]),
        ("phone", ["4155550132", "2125550199", "9175550111"]),
        ("city", ["New York", "Chicago", "Boston"]),
        ("city", ["Los Angeles", "San Francisco", "Boston"]),
        ("full_name", ["Mary Johnson", "Robert Smith", "Linda Davis"]),
        ("address", ["1409 Lake St", "88 Sunset Blvd", "12 Oak Avenue"]),
        ("ssn", ["123-45-6789", "321-65-4321", "555-12-3456"]),
        ("zip_code", ["94105", "10001", "60601"]),
        ("email", ["a@b.com", "c.d@e.org", "x@y.net"]),
        ("credit_card", ["4539578763621486", "4916338506082832", "4485275742308327"]),
    ],
)
def test_expected_pattern_wins(matcher: PatternMatcher, expected: str, values: list[str]) -> None:
    match = matcher.match(values, column=expected)
    assert match is not None, f"no pattern matched {values!r}"
    assert match.name == expected


@pytest.mark.parametrize(
    "values",
    [
        ["1234567", "98765432", "4500000"],          # integer amounts
        ["1,234,567.89", "4500.00", "12.50"],        # decimal amounts
    ],
)
def test_amounts_are_not_phone_numbers(matcher: PatternMatcher, values: list[str]) -> None:
    match = matcher.match(values)
    assert match is None or match.name != "phone"


def test_city_does_not_shadow_person_names(matcher: PatternMatcher) -> None:
    """A person-name column must not be captured by the city dictionary."""
    match = matcher.match(["Mary Johnson", "Robert Smith", "Linda Davis"], column="full_name")
    assert match is not None
    assert match.name == "full_name"


def test_unknown_city_does_not_fall_back_to_full_name(matcher: PatternMatcher) -> None:
    """Unlisted cities require review; capitalized words do not prove a name."""
    values = ["Ann Arbor", "Palo Alto", "Chapel Hill"]
    assert matcher.match(values, column="city") is None
    assert matcher.match(values) is None
