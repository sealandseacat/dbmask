"""Real PostgreSQL contract; explicitly opt in outside the dedicated CI job."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


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
