"""Exercise the shipped demo as a user command, including paths with spaces."""
import csv
import json
import subprocess
import sys
from pathlib import Path


def test_demo_generates_checked_before_after_and_refuses_overwrite(tmp_path):
    output = tmp_path / "Github Test 演示"
    script = Path(__file__).resolve().parents[1] / "examples" / "issue36_demo.py"
    command = [sys.executable, str(script), "--output", str(output)]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS:" in result.stdout
    report = json.loads((output / "verification.json").read_text())
    assert report["validation_ok"] and report["dry_run_unchanged"] and report["original_unchanged"]
    with (output / "after.csv").open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == report["rows"] == report["rows_written"] == 6
    assert rows[1]["ssn"].startswith("XXX-XX-") and not rows[1]["ssn"].endswith("5109")
    assert rows[3]["date_of_birth"] == ""
    assert all(report["columns"][c]["masked"] > 0 for c in report["columns"])
    saved = (output / "after.csv").read_bytes()
    repeat = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert repeat.returncode != 0
    assert (output / "after.csv").read_bytes() == saved
