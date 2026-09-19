"""An explicit marker policy changes only listed cells at an exact location."""
import sqlite3

import pytest

from dbmask.cli import cli
from dbmask.config import Config, MaskingConfig
from dbmask.masking.engine import ColumnPlan, MaskingEngine
from dbmask.masking.rules import MaskingValidationError


def policy(**changes):
    return {"schema": "main", "table": "customers", "column": "dob", "values": ["NULL", "-"], **changes}


@pytest.mark.parametrize("strategy,valid", [
    ("fake_date", "May 27, 1960"), ("fake_ssn", "XXX-XX-5109"),
    ("fake_phone", "202-555-0123"), ("fake_credit_card", "4111111111111111"),
    ("fake_ip", "192.0.2.1"),
])
def test_only_allowlisted_markers_become_null(strategy, valid):
    engine = MaskingEngine(MaskingConfig(null_placeholders=[policy()], seed_map={"enabled": False}))
    plan = ColumnPlan("main", "customers", "dob", None, strategy)
    for marker in ("NULL", "-", " NULL "):
        assert engine.mask_value(marker, plan) is None
    assert engine.mask_value(valid, plan) not in (None, "", valid)
    assert engine.mask_value(None, plan) is None


@pytest.mark.parametrize("schema,table,column", [
    ("other", "customers", "dob"), ("main", "staff", "dob"),
    ("main", "customers", "other_date"), ("MAIN", "customers", "dob"),
])
def test_policy_does_not_leak_to_other_column_locations(schema, table, column):
    engine = MaskingEngine(MaskingConfig(null_placeholders=[policy()], seed_map={"enabled": False}))
    with pytest.raises(MaskingValidationError):
        engine.mask_value("NULL", ColumnPlan(schema, table, column, "date", "fake_date"))


def test_policy_is_case_sensitive_and_does_not_exempt_unknown_invalid_values():
    engine = MaskingEngine(MaskingConfig(null_placeholders=[policy()], seed_map={"enabled": False}))
    plan = ColumnPlan("main", "customers", "dob", "date", "fake_date")
    for value in ("null", "UNKNOWN", "bad private input", "2024-02-30"):
        with pytest.raises(MaskingValidationError) as exc:
            engine.mask_value(value, plan)
        assert value not in str(exc.value)


@pytest.mark.parametrize("dry_run", [True, False])
def test_placeholder_policy_precedes_seed_lookup_and_creates_no_pairs(tmp_path, dry_run):
    config = MaskingConfig(null_placeholders=[policy()], dry_run=dry_run, seed_map={"url": f"sqlite:///{tmp_path / 'seed.db'}"})
    engine = MaskingEngine(config)
    plan = ColumnPlan("main", "customers", "dob", "date", "fake_date")
    try:
        store = engine.seed_store()
        store.record("fake_date:calendar-v2:MDY", "NULL", "2020-01-01", "fake_date")
        before = store.count()
        assert engine.mask_value("NULL", plan) is None
        assert engine.mask_value("-", plan) is None
        assert store.count() == before
    finally:
        engine.close()


@pytest.mark.parametrize("values", [None, "NULL", [], [None], [False], [123], [""], [" \t "]])
def test_bad_placeholder_values_are_configuration_errors(values):
    with pytest.raises(ValueError, match="null_placeholders"):
        MaskingConfig(null_placeholders=[policy(values=values)])


@pytest.mark.parametrize("policies", [None, {}, "dob", [42], [policy(), policy()], [policy(column="")]])
def test_bad_or_duplicate_policy_is_rejected(policies):
    with pytest.raises(ValueError, match="null_placeholders"):
        MaskingConfig(null_placeholders=policies)


def test_wildcards_are_literal_and_policy_is_not_global():
    engine = MaskingEngine(MaskingConfig(null_placeholders=[policy(table="*")], seed_map={"enabled": False}))
    with pytest.raises(MaskingValidationError):
        engine.mask_value("NULL", ColumnPlan("main", "customers", "dob", "date", "fake_date"))


def test_yaml_quoted_markers_and_cli_preview_apply(cli_env):
    with sqlite3.connect(cli_env.db) as conn:
        conn.execute("CREATE TABLE dates (id INTEGER PRIMARY KEY, dob TEXT, status TEXT)")
        conn.executemany("INSERT INTO dates VALUES (?, ?, ?)", [(1, "May 27, 1960", "active"), (2, "NULL", "active"), (3, "-", "pending")])
    overrides = cli_env.tmp_path / "overrides.yaml"
    overrides.write_text("sensitive:\n  - match: main.dates.dob\n    rule: date\n", encoding="utf-8")
    config = cli_env.make_config(detection={"overrides_file": str(overrides)}, masking={"null_placeholders": [policy(table="dates")]})
    assert Config.load(config).masking.null_placeholders[0].values == ["NULL", "-"]
    before = cli_env.read("dob", "dates")
    result = cli_env.runner.invoke(cli, ["mask", "--config", config])
    assert result.exit_code == 0, result.output
    assert cli_env.read("dob", "dates") == before
    result = cli_env.runner.invoke(cli, ["mask", "--config", config, "--apply"])
    assert result.exit_code == 0, result.output
    after = cli_env.read("dob", "dates")
    assert after[0] not in (None, before[0])
    assert after[1:] == [None, None]
    assert cli_env.read("status", "dates") == ["active", "active", "pending"]


def test_without_policy_marker_still_stops_cli_and_keeps_first_batch(cli_env):
    with sqlite3.connect(cli_env.db) as conn:
        conn.execute("CREATE TABLE dates (id INTEGER PRIMARY KEY, dob TEXT)")
        conn.executemany("INSERT INTO dates VALUES (?, ?)", [(1, "May 27, 1960"), (2, "NULL")])
    overrides = cli_env.tmp_path / "overrides.yaml"
    overrides.write_text("sensitive:\n  - match: main.dates.dob\n    rule: date\n", encoding="utf-8")
    config = cli_env.make_config(detection={"overrides_file": str(overrides)})
    before = cli_env.read("dob", "dates")
    result = cli_env.runner.invoke(cli, ["mask", "--config", config, "--apply"])
    assert result.exit_code != 0
    assert "fake_date requires" in result.output
    assert cli_env.read("dob", "dates") == before
