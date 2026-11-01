"""Review-export regressions using SQLite reads, not a PostgreSQL capacity claim."""
from __future__ import annotations

import csv
import hashlib
import importlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url

SOURCE = "postgresql+psycopg2://dbmask:dbmask-contract-only@localhost:5432/dbmask_contract_source"
TARGET = SOURCE.replace("_source", "_target")
ROWS = 5001
SCRIPT_VALUE = '<script>alert("demo")</script> & 海豹'
MULTILINE_VALUE = 'A, "quoted"\nsecond line\r\n海豹'


@pytest.fixture()
def review(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("_postgres_contract_review")


@pytest.fixture()
def report():
    locations = [
        "public.customers.full_name", "public.customers.email", "public.customers.phone",
        "public.customers.birth_date", "public.orders.contact_email",
    ]
    return {
        "status": "passed", "rows_per_table": ROWS, "total_fixture_rows": ROWS * 2,
        "environment": {"source_commit": "a" * 40, "seed_map_enabled": False},
        "stages": {"final-strict": {"exit_code": 0, "result": [
            {"status": "pass", "check": "masking_completeness", "location": location,
             "detail": {"rows_compared": ROWS, "coverage": "all rows"}}
            for location in locations
        ]}},
        "negative_controls": {name: {"expected_refusal_confirmed": True, "exit_code": 1}
                              for name in ("restore_email_5001", "restore_email_last",
                                           "missing_order", "replace_order_key", "drop_unique")},
    }


def _seed_file(path: Path, masked: bool) -> None:
    """Preserve export edge values and real composite keys in a small local DB."""
    with sqlite3.connect(path) as connection:
        connection.execute("""CREATE TABLE customers (
            id INTEGER PRIMARY KEY, customer_ref TEXT, full_name TEXT, email TEXT,
            phone TEXT, birth_date TEXT, status TEXT, credit_limit TEXT
        )""")
        connection.execute("""CREATE TABLE orders (
            tenant_id INTEGER, order_id INTEGER, customer_id INTEGER, contact_email TEXT,
            quantity INTEGER, unit_price TEXT, total TEXT,
            PRIMARY KEY (tenant_id, order_id)
        )""")
        customers = []
        orders = []
        names = {1: SCRIPT_VALUE, 2: "", 3: r"\N", 34: MULTILINE_VALUE}
        for row_id in range(1, ROWS + 1):
            name = names.get(row_id, f"Source Customer {row_id}")
            if row_id % 23 == 0:
                name = None
            elif masked:
                name = f"Masked Customer {row_id}"
            email = f"source{row_id}@example.test"
            if masked:
                email = f"masked{row_id}@example.invalid"
            phone = None if row_id % 17 == 0 else ("101-010-0101" if masked else "202-555-1234")
            customers.append((row_id, f"C{row_id:08d}", name, email, phone,
                              "1990-02-03" if masked else "1980-01-01", "active", "1200.00"))
            orders.append(((row_id - 1) // 700 + 1, (row_id - 1) % 700 + 1,
                           row_id, email, 2, "12.50", "25.00"))
        connection.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?, ?)", customers)
        connection.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?, ?)", orders)


def _attached_engine(path: Path):
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def attach_public(dbapi_connection, _connection_record):
        dbapi_connection.execute("ATTACH DATABASE ? AS public", (str(path),))

    return engine


@pytest.fixture()
def databases(review, monkeypatch, tmp_path):
    paths = {"dbmask_contract_source": tmp_path / "source.sqlite",
             "dbmask_contract_target": tmp_path / "target.sqlite"}
    for name, path in paths.items():
        _seed_file(path, masked=name.endswith("target"))
    engines = {name: _attached_engine(path) for name, path in paths.items()}
    monkeypatch.setattr(review, "create_engine", lambda url: engines[make_url(url).database])
    yield paths
    for engine in engines.values():
        engine.dispose()


@pytest.fixture()
def output(tmp_path, report):
    path = tmp_path / "run"
    path.mkdir()
    (path / "report.json").write_text(json.dumps(report), encoding="utf-8")
    return path


def _csv_records(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def test_complete_bundle_preserves_values_and_links_integrity(review, report, output, databases, monkeypatch):
    monkeypatch.setattr(review.subprocess, "run", lambda *a, **k: pytest.fail("dump was not requested"))
    result = review.export_review_bundle(SOURCE, TARGET, ROWS, output, report)
    bundle = output / "review"
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert result["manifest_sha256"] == hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
    assert manifest["source_commit"] == "a" * 40
    assert manifest["rows_per_table"] == ROWS
    assert manifest["seed_map_enabled"] is False
    entries = {item["path"]: item for item in manifest["files"]}
    assert set(entries) == {"index.html", "csv/customers.before.csv", "csv/customers.after.csv",
                            "csv/orders.before.csv", "csv/orders.after.csv"}
    for name, item in entries.items():
        data = (bundle / name).read_bytes()
        assert item["bytes"] == len(data)
        assert item["sha256"] == hashlib.sha256(data).hexdigest()

    for table, primary_key in (("customers", ["id"]), ("orders", ["tenant_id", "order_id"])):
        before = _csv_records(bundle / "csv" / f"{table}.before.csv")
        after = _csv_records(bundle / "csv" / f"{table}.after.csv")
        assert len(before) == len(after) == ROWS
        before_keys = [tuple(int(row[column]) for column in primary_key) for row in before]
        after_keys = [tuple(int(row[column]) for column in primary_key) for row in after]
        assert before_keys == after_keys == sorted(before_keys)
        for side in ("before", "after"):
            entry = entries[f"csv/{table}.{side}.csv"]
            assert entry["rows"] == ROWS and entry["primary_key"] == primary_key
        if table == "orders":
            assert before_keys[699:701] == [(1, 700), (2, 1)]

    customers = _csv_records(bundle / "csv/customers.before.csv")
    assert customers[0]["full_name"] == SCRIPT_VALUE
    assert customers[1]["full_name"] == ""
    assert customers[2]["full_name"] == r"\N"
    assert customers[33]["full_name"] == MULTILINE_VALUE
    raw_csv = (bundle / "csv/customers.before.csv").read_bytes().decode("utf-8")
    # PostgreSQL CSV null semantics: an unquoted null marker differs from its literal string.
    assert '"2","C00000002","",' in raw_csv
    assert '"3","C00000003","\\N",' in raw_csv
    assert '"23","C00000023",\\N,' in raw_csv
    assert '"A, ""quoted""\nsecond line\r\n海豹"' in raw_csv

    html = (bundle / "index.html").read_text(encoding="utf-8")
    assert SCRIPT_VALUE not in html
    assert "&lt;script&gt;" in html and "&amp; 海豹" in html
    assert "5,001" in html or "5001" in html
    assert SOURCE not in html and "dbmask-contract-only" not in html
    assert "dbmask-contract-only" not in json.dumps(manifest)
    assert not (bundle / "source.dump").exists()
    assert not (bundle / "masked.dump").exists()


@pytest.mark.parametrize("change", [
    "UPDATE orders SET tenant_id=tenant_id+100",
    "UPDATE orders SET order_id=order_id+1000",
    "DELETE FROM orders WHERE customer_id=5001",
])
def test_mismatched_composite_keys_or_missing_rows_do_not_publish_a_bundle(
    review, report, output, databases, change,
):
    with sqlite3.connect(databases["dbmask_contract_target"]) as connection:
        connection.execute(change)
    with pytest.raises(AssertionError):
        review.export_review_bundle(SOURCE, TARGET, ROWS, output, report)
    assert {path.name for path in output.iterdir()} == {"report.json"}


@pytest.mark.parametrize("source,target", [
    (SOURCE.replace("localhost", "production.example"), TARGET),
    (SOURCE, TARGET.replace("dbmask_contract_target", "customer_database")),
    (TARGET, SOURCE),
])
def test_export_guard_rejects_other_databases_before_connecting(review, report, output, monkeypatch, source, target):
    monkeypatch.setattr(review, "create_engine", lambda *a, **k: pytest.fail("unapproved connection"))
    with pytest.raises(ValueError):
        review.export_review_bundle(source, target, ROWS, output, report)
    assert {path.name for path in output.iterdir()} == {"report.json"}


@pytest.mark.parametrize("incomplete", ["not_passed", "partial_coverage", "missing_refusal"])
def test_unverified_results_cannot_be_exported_as_a_pass(review, report, output, monkeypatch, incomplete):
    if incomplete == "not_passed":
        report["status"] = "running"
    elif incomplete == "partial_coverage":
        report["stages"]["final-strict"]["result"][0]["detail"]["coverage"] = "partial"
    else:
        del report["negative_controls"]["restore_email_last"]
    monkeypatch.setattr(review, "create_engine", lambda *a, **k: pytest.fail("unverified export reached database"))
    with pytest.raises(ValueError):
        review.export_review_bundle(SOURCE, TARGET, ROWS, output, report)
    assert {path.name for path in output.iterdir()} == {"report.json"}


def test_previous_review_is_not_overwritten(review, report, output, monkeypatch):
    old = output / "review"
    old.mkdir()
    (old / "index.html").write_text("prior review", encoding="utf-8")
    monkeypatch.setattr(review, "create_engine", lambda *a, **k: pytest.fail("existing review should be rejected first"))
    with pytest.raises(FileExistsError):
        review.export_review_bundle(SOURCE, TARGET, ROWS, output, report)
    assert (old / "index.html").read_text(encoding="utf-8") == "prior review"


@pytest.mark.parametrize("failure", ["missing_client", "dump_error"])
def test_requested_dump_failure_removes_incomplete_review(
    review, report, output, databases, monkeypatch, failure,
):
    calls = []

    def fake_run(arguments, **kwargs):
        calls.append(arguments)
        if failure == "missing_client":
            raise FileNotFoundError("test client not found")
        if "--version" in arguments:
            version = "pg_dump (PostgreSQL) 16.10\n"
            return SimpleNamespace(returncode=0, stdout=version if kwargs.get("text") else version.encode(), stderr="")
        stream = kwargs.get("stdout")
        if hasattr(stream, "write"):
            stream.write(b"PGDMPpartial")
        if kwargs.get("check"):
            raise subprocess.CalledProcessError(1, arguments, stderr=b"deliberate dump failure")
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"deliberate dump failure")

    monkeypatch.setattr(review.subprocess, "run", fake_run)
    with pytest.raises(review.ReviewExportError):
        review.export_review_bundle(SOURCE, TARGET, ROWS, output, report, include_dumps=True)
    assert calls
    assert {path.name for path in output.iterdir()} == {"report.json"}


def test_dump_environment_cannot_redirect_the_guarded_connection(
    review, report, output, databases, monkeypatch,
):
    for name, value in {"PGHOSTADDR": "192.0.2.1", "PGSERVICE": "other-database",
                        "PGOPTIONS": "-c search_path=other", "PGPASSWORD": "ambient-password",
                        "DBMASK_CONTRACT_POSTGRES_CONTAINER": "unit-container"}.items():
        monkeypatch.setenv(name, value)
    calls = []

    def fake_run(arguments, **kwargs):
        calls.append(arguments)
        environment = kwargs["env"]
        assert not {"PGHOSTADDR", "PGSERVICE", "PGOPTIONS"}.intersection(environment)
        assert environment["PGPASSWORD"] == "dbmask-contract-only"
        assert environment["PGCONNECT_TIMEOUT"] == "10"
        assert environment["DBMASK_CONTRACT_POSTGRES_CONTAINER"] == "unit-container"
        assert environment["PATH"] == os.environ["PATH"]
        assert "dbmask-contract-only" not in " ".join(arguments)
        if "--version" in arguments:
            return SimpleNamespace(returncode=0, stdout="pg_dump (PostgreSQL) 16.10\n", stderr="")
        assert arguments[arguments.index("--host") + 1] == "localhost"
        assert arguments[arguments.index("--port") + 1] == "5432"
        assert arguments[arguments.index("--username") + 1] == "dbmask"
        assert arguments[arguments.index("--dbname") + 1] == "dbmask_contract_source"
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"deliberate dump failure")

    monkeypatch.setattr(review.subprocess, "run", fake_run)
    with pytest.raises(review.ReviewExportError):
        review.export_review_bundle(SOURCE, TARGET, ROWS, output, report, include_dumps=True)
    assert len(calls) == 2
    assert {path.name for path in output.iterdir()} == {"report.json"}


@pytest.mark.parametrize("stage", ["version", "dump"])
def test_dump_timeout_is_bounded_and_does_not_publish_or_leak_output(
    review, report, output, databases, monkeypatch, stage,
):
    def fake_run(arguments, **kwargs):
        if "--version" in arguments:
            assert kwargs["timeout"] == 30
            if stage == "dump":
                return SimpleNamespace(returncode=0, stdout="pg_dump (PostgreSQL) 16.10\n", stderr="")
        else:
            assert kwargs["timeout"] == 300
        raise subprocess.TimeoutExpired(arguments, kwargs["timeout"], stderr=b"private-process-detail")

    monkeypatch.setattr(review.subprocess, "run", fake_run)
    with pytest.raises(review.ReviewExportError) as caught:
        review.export_review_bundle(SOURCE, TARGET, ROWS, output, report, include_dumps=True)
    assert "private-process-detail" not in str(caught.value)
    assert {path.name for path in output.iterdir()} == {"report.json"}
