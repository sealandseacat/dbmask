"""Regression tests for the PK-aligned masking-completeness check.

The old check compared *whole rows*: a row counted as unmasked only when
EVERY column matched the source. So a row where the email survived unmasked
but the name changed slipped through as "masked". With a primary key there is
no need to guess row correspondence — align on the key and compare the
sensitive column directly.

Also covered here: honest reporting (partial coverage is stated, keyless
heuristic results are WARNINGs, tables missing on one side are surfaced) and
the --strict gate.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import yaml

from dbmask.cli import cli
from dbmask.config import DatabaseConfig, ValidationConfig
from dbmask.connectors.sql import SQLConnector
from dbmask.validation.result import Status
from dbmask.validation.validator import Validator


def _make(path: Path, rows, ddl=None):
    conn = sqlite3.connect(path)
    conn.executescript(ddl or """
        CREATE TABLE people (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            email TEXT
        );
    """)
    conn.executemany(
        "INSERT INTO people VALUES (?, ?, ?)", rows
    )
    conn.commit()
    conn.close()


def _run(src_path, tgt_path, sensitive, cfg: ValidationConfig = None):
    source = SQLConnector(DatabaseConfig(url=f"sqlite:///{src_path}", name="source"))
    target = SQLConnector(DatabaseConfig(url=f"sqlite:///{tgt_path}", name="target"))
    source.connect()
    target.connect()
    try:
        validator = Validator(cfg or ValidationConfig(enabled=True))
        return validator.validate(source, target, schemas=["main"],
                                  sensitive_columns=sensitive)
    finally:
        source.close()
        target.close()


def _completeness(report):
    return [i for i in report.issues if i.check == "masking_completeness"]


# -- the case the old whole-row check could not catch --------------------------

def test_partially_masked_row_is_caught(tmp_path):
    """Name masked, email NOT masked: the row differs as a whole, so the old
    heuristic called it masked. PK alignment must flag the surviving email."""
    _make(tmp_path / "s.db", [(1, "Mary Johnson", "mary@corp.com"),
                              (2, "Robert Smith", "bob@corp.com")])
    _make(tmp_path / "t.db", [(1, "Rita Book", "mary@corp.com"),      # email SURVIVED
                              (2, "Alan Turing", "masked@example.invalid")])

    report = _run(str(tmp_path / "s.db"), str(tmp_path / "t.db"),
                  sensitive=[("main", "people", "email")])
    mc = _completeness(report)
    assert len(mc) == 1
    assert mc[0].status == Status.FAIL
    assert mc[0].detail["mode"] == "pk_aligned"
    assert mc[0].detail["unmasked_rows"] == 1
    assert "mary@corp.com" not in str(mc[0].detail)  # samples are redacted


def test_fully_masked_column_passes_with_row_count(tmp_path):
    _make(tmp_path / "s.db", [(1, "Mary Johnson", "mary@corp.com")])
    _make(tmp_path / "t.db", [(1, "Rita Book", "x@example.invalid")])
    report = _run(str(tmp_path / "s.db"), str(tmp_path / "t.db"),
                  sensitive=[("main", "people", "email")])
    mc = _completeness(report)
    assert mc[0].status == Status.PASS
    assert mc[0].detail["rows_compared"] == 1
    assert report.passed and report.passed_strict


def test_partial_coverage_is_stated(tmp_path):
    rows_src = [(i, f"Person {i}", f"p{i}@corp.com") for i in range(1, 8)]
    rows_tgt = [(i, "Masked Name", f"m{i}@example.invalid") for i in range(1, 8)]
    _make(tmp_path / "s.db", rows_src)
    _make(tmp_path / "t.db", rows_tgt)

    cfg = ValidationConfig(enabled=True, pk_row_limit=3)
    report = _run(str(tmp_path / "s.db"), str(tmp_path / "t.db"),
                  sensitive=[("main", "people", "email")], cfg=cfg)
    mc = _completeness(report)
    assert mc[0].status == Status.WARNING
    assert "partial" in mc[0].detail["coverage"]
    assert "partial" in mc[0].message
    assert not report.passed_strict


# -- keyless fallback stays honest ---------------------------------------------

_KEYLESS_DDL = "CREATE TABLE people (id INTEGER, full_name TEXT, email TEXT);"


def test_keyless_clean_result_is_warning_not_pass(tmp_path):
    # Dictionary-swap lookalike on a table with no primary key.
    _make(tmp_path / "s.db", [(1, "Tesla", "a@x.io"), (2, "Apple", "b@x.io")],
          ddl=_KEYLESS_DDL)
    _make(tmp_path / "t.db", [(1, "Apple", "c@x.io"), (2, "Tesla", "d@x.io")],
          ddl=_KEYLESS_DDL)
    report = _run(str(tmp_path / "s.db"), str(tmp_path / "t.db"),
                  sensitive=[("main", "people", "full_name")])
    mc = _completeness(report)
    assert mc[0].status == Status.WARNING
    assert "no usable primary key" in mc[0].message
    assert report.passed            # warnings pass by default...
    assert not report.passed_strict  # ...but not in strict mode


def test_keyless_identical_row_still_fails(tmp_path):
    _make(tmp_path / "s.db", [(1, "Tesla", "a@x.io"), (2, "Apple", "b@x.io")],
          ddl=_KEYLESS_DDL)
    _make(tmp_path / "t.db", [(1, "Tesla", "a@x.io"), (2, "Ford", "z@x.io")],
          ddl=_KEYLESS_DDL)
    report = _run(str(tmp_path / "s.db"), str(tmp_path / "t.db"),
                  sensitive=[("main", "people", "full_name")])
    mc = _completeness(report)
    assert mc[0].status == Status.FAIL
    assert mc[0].detail["mode"] == "overlap_heuristic"


# -- table presence ------------------------------------------------------------

def test_source_only_table_is_surfaced(tmp_path):
    _make(tmp_path / "s.db", [(1, "Mary Johnson", "m@x.io")])
    _make(tmp_path / "t.db", [(1, "Rita Book", "r@example.invalid")])
    conn = sqlite3.connect(tmp_path / "s.db")
    conn.execute("CREATE TABLE forgotten (secret TEXT)")
    conn.commit()
    conn.close()

    report = _run(str(tmp_path / "s.db"), str(tmp_path / "t.db"), sensitive=[])
    presence = [i for i in report.issues if i.check == "table_presence"]
    assert len(presence) == 1
    assert presence[0].status == Status.WARNING
    assert presence[0].table == "forgotten"
    assert "only in the SOURCE" in presence[0].message


# -- CLI --strict gate ---------------------------------------------------------

def _cli_config(tmp_path, src, tgt) -> str:
    cfg = {
        "database": {"url": f"sqlite:///{tgt}", "name": "target"},
        "source_database": {"url": f"sqlite:///{src}", "name": "source"},
        "history": {"enabled": False},
        "llm": {"enabled": False},
        "validation": {"enabled": True, "columns": ["main.people.full_name"]},
    }
    path = tmp_path / "validate.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return str(path)


def test_cli_strict_fails_on_warnings(tmp_path, cli_env):
    _make(tmp_path / "s.db", [(1, "Tesla", "a@x.io"), (2, "Apple", "b@x.io")],
          ddl=_KEYLESS_DDL)
    _make(tmp_path / "t.db", [(1, "Apple", "c@x.io"), (2, "Tesla", "d@x.io")],
          ddl=_KEYLESS_DDL)
    cfg = _cli_config(tmp_path, tmp_path / "s.db", tmp_path / "t.db")

    relaxed = cli_env.runner.invoke(cli, ["validate", "--config", cfg])
    assert relaxed.exit_code == 0, relaxed.output
    assert "PASSED" in relaxed.output
    assert "not everything could be verified" in relaxed.output

    strict = cli_env.runner.invoke(cli, ["validate", "--config", cfg, "--strict"])
    assert strict.exit_code == 1
    assert "FAILED" in strict.output
