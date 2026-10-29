"""Safety, evidence and real CLI regressions for the disposable test tool."""
from __future__ import annotations

import importlib
import json
import shutil
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

SOURCE = "postgresql+psycopg2://dbmask:dbmask-contract-only@localhost:5432/dbmask_contract_source"
TARGET = SOURCE.replace("_source", "_target")


@pytest.fixture()
def tool(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("postgres_contract")


@pytest.mark.parametrize("source,target", [
    ("", TARGET), (SOURCE, ""),
    (SOURCE.replace("localhost", "production.example"), TARGET),
    (SOURCE, TARGET.replace("localhost", "127.0.0.1")),
    (SOURCE.replace("postgresql+psycopg2", "postgresql"), TARGET),
    (SOURCE.replace("dbmask_contract_source", "customer_database"), TARGET),
    (SOURCE, SOURCE), (SOURCE, TARGET.replace("5432", "5433")),
    (SOURCE.replace("dbmask-contract-only", "other-password"), TARGET),
    (SOURCE + "?options=-csearch_path%3Dpublic", TARGET),
    (SOURCE.replace(":5432", ":not-a-port"), TARGET),
])
def test_rejects_unapproved_destinations_before_connecting(tool, monkeypatch, source, target):
    fixture = importlib.import_module("_postgres_contract_fixture")
    def forbidden(*args, **kwargs):
        pytest.fail("unapproved destination reached the database driver")
    monkeypatch.setattr(fixture, "create_engine", forbidden)
    with pytest.raises(ValueError):
        fixture.recreate_and_seed(source, target, 10001)


@pytest.mark.parametrize("rows", [True, 0, 5000, 200002, 1.5, "10001"])
def test_bad_scale_cannot_reset_databases(tool, monkeypatch, rows):
    fixture = importlib.import_module("_postgres_contract_fixture")
    monkeypatch.setattr(fixture, "create_engine", lambda *a, **k: pytest.fail("invalid rows reached database"))
    with pytest.raises(ValueError):
        fixture.recreate_and_seed(SOURCE, TARGET, rows)


@pytest.mark.parametrize("reset", [False, True])
def test_requires_reset_consent_and_preserves_existing_evidence(tool, monkeypatch, tmp_path, reset):
    monkeypatch.setenv(tool.SOURCE_ENV, SOURCE)
    monkeypatch.setenv(tool.TARGET_ENV, TARGET)
    monkeypatch.setattr(tool, "recreate_and_seed", lambda *a: pytest.fail("unsafe reset"))
    output = tmp_path / "evidence"
    output.mkdir()
    (output / "prior-result.txt").write_text("keep", encoding="utf-8")
    args = SimpleNamespace(rows=10001, output=output, seed_map="off",
                           allow_reset_disposable_databases=reset)
    with pytest.raises(ValueError):
        tool.run_contract(args)
    assert (output / "prior-result.txt").read_text(encoding="utf-8") == "keep"


def test_expected_refusal_cannot_be_replaced_by_unrelated_error(tool):
    for bad in ([], [{"status": "error"}], [{"status": "warning"}], [
        {"status": "fail", "check": "row_count", "location": "public.customers"},
    ]):
        with pytest.raises(AssertionError):
            tool.check_negative("restore_email_5001", bad)


def test_worker_rejects_unguarded_configuration_before_cli(tool, monkeypatch, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        "database": {"url": TARGET.replace("localhost", "production.example")},
        "source_database": {"url": SOURCE},
    }), encoding="utf-8")
    monkeypatch.setattr(tool, "execute_cli", lambda *a: pytest.fail("unsafe worker invoked apply"))
    with pytest.raises(ValueError):
        tool.worker(["apply", str(config), str(tmp_path / "result.json")])


def test_real_cli_masks_and_fully_checks_more_than_5000_rows(tool, tmp_path):
    """Supplemental SQLite exercise; does not substitute for native PostgreSQL CI."""
    rows = 10001
    source, target = tmp_path / "source.db", tmp_path / "target.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT, status TEXT)")
        connection.executemany("INSERT INTO customers VALUES (?, ?, ?)", [
            (i, f"original{i}@example.test", "active") for i in range(1, rows + 1)
        ])
    shutil.copy2(source, target)
    fields = tmp_path / "fields.yaml"
    fields.write_text(yaml.safe_dump({"sensitive": [{"match": "main.customers.email", "rule": "email"}],
                                     "not_sensitive": ["main.customers.id", "main.customers.status"]}), encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        "database": {"url": "sqlite:///" + target.as_posix(), "schemas": ["main"]},
        "source_database": {"url": "sqlite:///" + source.as_posix(), "schemas": ["main"]},
        "detection": {"overrides_file": str(fields), "use_patterns": False, "use_history": False},
        "history": {"enabled": False}, "llm": {"enabled": False},
        "masking": {"seed": "contract-unit-private-seed", "seed_map": {"enabled": False}},
        "validation": {"pk_row_limit": None, "ignore_test_data": False,
                       "columns": ["main.customers.email"]},
    }), encoding="utf-8")
    applied = tool.execute_cli(["mask", "--config", str(config), "--apply"], tmp_path / "apply.log")
    assert applied["exit_code"] == 0
    assert "written=10001" in (tmp_path / "apply.log").read_text(encoding="utf-8")
    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT COUNT(*) FROM customers WHERE email LIKE 'original%@example.test'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM customers WHERE status='active'").fetchone()[0] == rows
    positive = tool.execute_cli(["validate", "--config", str(config), "--strict", "--json"], tmp_path / "positive.log")
    assert positive["exit_code"] == 0
    issue = next(i for i in positive["result"] if i["check"] == "masking_completeness")
    assert issue["detail"]["coverage"] == "all rows" and issue["detail"]["rows_compared"] == rows
    with sqlite3.connect(target) as connection:
        connection.execute("UPDATE customers SET email='original5001@example.test' WHERE id=5001")
    negative = tool.execute_cli(["validate", "--config", str(config), "--strict", "--json"], tmp_path / "negative.log")
    assert negative["exit_code"] == 1
    normalized = json.loads(json.dumps(negative["result"]).replace("main.customers", "public.customers"))
    tool.check_negative("restore_email_5001", normalized)


def test_seed_map_preview_is_allowed_to_initialize_an_empty_store(tool, tmp_path):
    from dbmask.masking.seed_store import SeedStore

    assert tool.mapping_count(tmp_path) == 0
    with SeedStore(url="sqlite:///" + (tmp_path / "seedmap.db").as_posix(), salt="synthetic"):
        pass
    assert tool.mapping_count(tmp_path) == 0
