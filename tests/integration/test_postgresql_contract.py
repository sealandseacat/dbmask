"""Real PostgreSQL contract; explicitly opt in outside the dedicated CI job."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine


def test_generated_postgresql_contract(tmp_path):
    if os.environ.get("DBMASK_RUN_POSTGRES_CONTRACT") != "1":
        pytest.skip("set DBMASK_RUN_POSTGRES_CONTRACT=1 with the disposable PostgreSQL service")
    # Opted-in CI must fail, never skip, when its service/driver/URLs are missing.
    assert os.environ.get("DBMASK_CONTRACT_SOURCE_URL"), "missing disposable source URL"
    assert os.environ.get("DBMASK_CONTRACT_TARGET_URL"), "missing disposable target URL"
    repository = Path(__file__).resolve().parents[2]
    output = Path(os.environ.get("DBMASK_CONTRACT_OUTPUT", str(tmp_path / "evidence"))).resolve()
    result = subprocess.run(
        [sys.executable, str(repository / "scripts" / "postgres_contract.py"),
         "--rows", "10001", "--seed-map", "off", "--output", str(output),
         "--allow-reset-disposable-databases"],
        cwd=repository, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["status"] == "passed"
    assert report["rows_per_table"] == 10001 and report["total_fixture_rows"] == 20002
    assert report["environment"]["seed_map_enabled"] is False
    assert report["independent_checks"]["rows_compared_per_table"] == {
        "customers": 10001, "orders": 10001,
    }
    assert set(report["negative_controls"]) == {
        "restore_email_5001", "restore_email_last", "missing_order", "replace_order_key", "drop_unique",
    }
    assert all(case["expected_refusal_confirmed"] for case in report["negative_controls"].values())
    assert report["review_artifacts"]["status"] == "created"
    assert report["review_artifacts"]["dumps_requested"] is False
    bundle = output / "review"
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["rows_per_table"] == 10001
    assert not (bundle / "source.dump").exists()
    for item in manifest["files"]:
        content = (bundle / item["path"]).read_bytes()
        assert len(content) == item["bytes"]
        assert hashlib.sha256(content).hexdigest() == item["sha256"]

    # PostgreSQL itself must decode the exported CSV back to exactly the original
    # typed values, including NULLs, dates, numerics and the generated total.
    for side, variable in (("before", "DBMASK_CONTRACT_SOURCE_URL"),
                           ("after", "DBMASK_CONTRACT_TARGET_URL")):
        engine = create_engine(os.environ[variable])
        try:
            connection = engine.raw_connection()
            try:
                with connection.cursor() as cursor:
                    for table in ("customers", "orders"):
                        temporary = "review_csv_" + table
                        cursor.execute(f"CREATE TEMP TABLE {temporary} AS SELECT * FROM public.{table} WITH NO DATA")
                        with (bundle / "csv" / f"{table}.{side}.csv").open(encoding="utf-8", newline="") as stream:
                            cursor.copy_expert(
                                f"COPY {temporary} FROM STDIN WITH (FORMAT CSV, HEADER TRUE, NULL '\\N')",
                                stream,
                            )
                        cursor.execute(f"SELECT count(*) FROM {temporary}")
                        assert cursor.fetchone()[0] == 10001
                        cursor.execute(
                            f"SELECT EXISTS (SELECT * FROM public.{table} EXCEPT ALL SELECT * FROM {temporary}) "
                            f"OR EXISTS (SELECT * FROM {temporary} EXCEPT ALL SELECT * FROM public.{table})"
                        )
                        assert cursor.fetchone()[0] is False, f"{table}.{side}.csv changed a database value"
            finally:
                connection.rollback()
                connection.close()
        finally:
            engine.dispose()
