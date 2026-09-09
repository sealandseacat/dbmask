"""Regression tests: "we could not tell" is UNKNOWN, not "not sensitive".

The bug: when no pattern matched and the LLM was disabled, the pipeline
returned NOT_SENSITIVE with confidence 0.5 and SAVED that to history. An
empty table, a column with too few rows, or simply a data type the patterns
don't know yet was permanently stamped "safe" and silently reused forever —
even after the data arrived.

Now: inconclusive columns are Sensitivity.UNKNOWN, confidence 0.0, are never
persisted to history (every run re-evaluates them), are never masked, and
both `scan` and `mask` surface them as needing human review.
"""
from __future__ import annotations

import sqlite3

from dbmask.cli import cli
from dbmask.config import Config
from dbmask.detection.result import Sensitivity
from dbmask.history.store import HistoryStore
from dbmask.runner import Runner


def _config(cli_env, **overrides) -> Config:
    return Config.load(cli_env.make_config(**overrides))


def test_inconclusive_column_is_unknown_not_safe(cli_env):
    with Runner(_config(cli_env)) as runner:
        report = runner.scan()
    by_col = {d.column: d for d in report.decisions}
    # status_code holds 'A'/'B' -- no pattern matches, LLM is off.
    d = by_col["status_code"]
    assert d.sensitivity is Sensitivity.UNKNOWN
    assert d.confidence == 0.0
    assert not d.is_sensitive


def test_empty_column_is_unknown_no_data(cli_env):
    conn = sqlite3.connect(cli_env.db)
    conn.execute("CREATE TABLE empty_table (id INTEGER PRIMARY KEY, notes TEXT)")
    conn.commit()
    conn.close()

    with Runner(_config(cli_env)) as runner:
        report = runner.scan()
    by_key = {(d.table, d.column): d for d in report.decisions}
    d = by_key[("empty_table", "notes")]
    assert d.sensitivity is Sensitivity.UNKNOWN
    assert d.source == "no_data"


def test_unknown_is_never_persisted_to_history(cli_env):
    cfg = _config(cli_env)
    with Runner(cfg) as runner:
        runner.scan()

    with HistoryStore(cfg.history.url) as store:
        stored = store.all_decisions()
    assert stored, "conclusive decisions (email, full_name) should be stored"
    assert all(d.sensitivity is not Sensitivity.UNKNOWN for d in stored)
    stored_cols = {d.column for d in stored}
    assert "status_code" not in stored_cols


def test_unknown_is_reevaluated_every_run(cli_env):
    """A column that was inconclusive must not be served from history later."""
    cfg = _config(cli_env)
    with Runner(cfg) as runner:
        runner.scan()
    # Second run: all unreviewed columns, including status_code, are re-analyzed.
    with Runner(cfg) as runner:
        report = runner.scan()
    d = {x.column: x for x in report.decisions}["status_code"]
    assert d.source != "history"
    assert d.sensitivity is Sensitivity.UNKNOWN


def test_unknown_columns_are_not_masked(cli_env):
    before = cli_env.read("status_code")
    with Runner(_config(cli_env, masking={"dry_run": False})) as runner:
        runner.mask()
    assert cli_env.read("status_code") == before


def test_scan_report_unknown_property(cli_env):
    with Runner(_config(cli_env)) as runner:
        report = runner.scan()
    assert {d.column for d in report.unknown} >= {"status_code"}


# -- CLI surfacing -------------------------------------------------------------

def test_cli_scan_shows_unknown_and_review_hint(cli_env):
    result = cli_env.runner.invoke(cli, ["scan", "--config", cli_env.make_config()])
    assert result.exit_code == 0, result.output
    assert "UNKNOWN" in result.output
    assert "Needs review" in result.output
    assert "NOT masked" in result.output


def test_cli_mask_lists_unclassified_columns(cli_env):
    result = cli_env.runner.invoke(
        cli, ["mask", "--config", cli_env.make_config(), "--apply"]
    )
    assert result.exit_code == 0, result.output
    assert "could not be classified" in result.output
    assert "status_code" in result.output
