"""Synthetic issue #36 demo: python examples/issue36_demo.py [--output NEW_DIR].

Uses an explicit reviewed plan for eight columns, no LLM or external database.
Creates separate original/masked SQLite files, previews, applies, validates and
exports before.csv / after.csv. Every run requires a fresh output directory.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from ipaddress import ip_address
from pathlib import Path

import yaml

from dbmask.config import Config
from dbmask.dates import parse_date
from dbmask.detection.patterns import PatternMatcher
from dbmask.runner import Runner

RULES = {
    "date_of_birth": "date", "signup_date": "date", "last_login_at": "date",
    "phone_number": "phone", "mobile_phone": "phone", "ssn": "ssn",
    "credit_card_number": "credit_card", "ip_address": "ip_address",
}
MARKERS = ["NULL", "null", "N/A", "n/a", "-", "???", "unknown", "TBD"]


def read_rows(path: Path) -> list[dict]:
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM customers ORDER BY id")]


def export_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_demo(output: Path) -> dict:
    source, target = output / "original.db", output / "masked.db"
    data = [
        (1, "active", "23-Dec-1974", "2020-01-31", "2024-02-29T12:30:45Z",
         "+1 (202) 555-0123 x42", "212 555 0199", "123 45 6789", "4111-1111-1111-1111", "192.0.2.1"),
        (2, "pending", "May 27, 1960", "2021/02/28", "29-Feb-2024 1:02+05:30",
         "202-555-0199", "+1 212 555 0100", "XXX-XX-5109", "3782 822463 10005", "198.51.100.2"),
        (3, "active", "2000-02-29", "01/31/2022", "2023-12-31 23:59:59",
         "2025550198", "212.555.0198", "012345678", "5555555555554444", "203.0.113.3"),
        (4, "pending", "NULL", "2023-03-01", "-", "N/A", "unknown", "TBD", "???", "null"),
        (5, "active", "", "2024-01-01", None, "", None, None, None, None),
        (6, "active", "1 JANUARY 1980", "2024-01-02", "May 27, 1960T10:11:12",
         "202 555 0101", "2125550102", "***-**-4321", "6011111111111117", "2001:db8::4"),
    ]
    with closing(sqlite3.connect(source)) as conn:
        conn.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, account_status TEXT, "
                     + ", ".join(f"{column} TEXT" for column in RULES) + ")")
        conn.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)", data)
        conn.commit()
    shutil.copyfile(source, target)
    before = read_rows(source)
    export_csv(output / "before.csv", before)

    # A small fixture with placeholders can fall below the distinct-sample
    # threshold. Record its real evidence; the explicit demo review below
    # supplies the plan rather than changing production detection thresholds.
    matcher = PatternMatcher()
    evidence = {
        column: matcher.analyze(list(dict.fromkeys(row[column] for row in before)), column=column).summary()
        for column in RULES
    }
    (output / "pattern_evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    fields = output / "reviewed_fields.yaml"
    fields.write_text(yaml.safe_dump({"sensitive": [
        {"database": "issue36_demo", "schema": "main", "table": "customers", "column": column, "rule": rule}
        for column, rule in RULES.items()
    ], "not_sensitive": ["main.customers.id", "main.customers.account_status"]}), encoding="utf-8")
    config_path = output / "config.yaml"
    config_path.write_text(yaml.safe_dump({
        "database": {"url": f"sqlite:///{target.as_posix()}", "name": "issue36_demo"},
        "source_database": {"url": f"sqlite:///{source.as_posix()}"},
        "history": {"enabled": False}, "llm": {"enabled": False},
        "detection": {"overrides_file": str(fields)},
        "masking": {
            "seed": "issue36-synthetic-demo", "seed_map": {"url": f"sqlite:///{(output / 'seeds.db').as_posix()}"},
            "null_placeholders": [
                {"schema": "main", "table": "customers", "column": column, "values": MARKERS}
                for column in RULES
            ],
        },
        "validation": {"columns": [f"main.customers.{column}" for column in RULES]},
    }), encoding="utf-8")
    config = Config.load(config_path)
    with Runner(config) as runner:
        scan = runner.scan()
        if scan.errors or {d.column for d in scan.sensitive} != set(RULES):
            raise RuntimeError("The explicit demo review did not cover the expected columns")
        preview = runner.mask(scan.decisions)
        if read_rows(target) != before or any(result.rows_written for result in preview):
            raise RuntimeError("Dry run changed the target")
        config.masking.dry_run = False
        applied = runner.mask(scan.decisions)
        report = runner.validate()
        if not report.passed_strict:
            raise RuntimeError("Post-masking validation failed")
    after = read_rows(target)
    if read_rows(source) != before or len(before) != len(after):
        raise RuntimeError("Original data or row count changed")
    counts = {c: {"masked": 0, "markers_to_null": 0, "missing_preserved": 0} for c in RULES}
    for original, masked in zip(before, after):
        if any(original[c] != masked[c] for c in ("id", "account_status")):
            raise RuntimeError("A non-sensitive column changed")
        for column, rule in RULES.items():
            value, replacement = original[column], masked[column]
            if value is None or not value.strip():
                if replacement != value:
                    raise RuntimeError("A missing value changed")
                counts[column]["missing_preserved"] += 1
            elif value.strip() in MARKERS:
                if replacement is not None:
                    raise RuntimeError("An allowlisted marker was not converted to NULL")
                counts[column]["markers_to_null"] += 1
            else:
                if replacement in (None, "", value):
                    raise RuntimeError("A useful value was erased or left unchanged")
                if rule == "ip_address":
                    # The detector's IP catalogue is IPv4-only. The existing
                    # fake_ip strategy also supports IPv6; check both directly.
                    if ip_address(value).version != ip_address(replacement).version:
                        raise RuntimeError("An IP address changed family")
                else:
                    match = PatternMatcher(min_samples=1).match([replacement], column=rule)
                    if match is None or match.name != rule:
                        raise RuntimeError("A replacement does not satisfy its format")
                if rule == "ssn" and replacement[-4:] == value[-4:]:
                    raise RuntimeError("An SSN retained its original serial")
                if rule == "date":
                    parsed, shifted = parse_date(value), parse_date(replacement)
                    if parsed is None or shifted is None or parsed.render(shifted.value) != replacement:
                        raise RuntimeError("A date representation changed")
                counts[column]["masked"] += 1
    export_csv(output / "after.csv", after)
    summary = {"rows": len(after), "rows_written": sum(r.rows_written for r in applied),
               "dry_run_unchanged": True, "original_unchanged": True, "validation_ok": True,
               "columns": counts, "scope": "Synthetic eight-column masking demo; explicit reviewed plan; no LLM"}
    (output / "verification.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New directory; an existing directory is never overwritten")
    args = parser.parse_args()
    if args.output is None:
        output = Path(tempfile.mkdtemp(prefix="issue36-demo-", dir=Path.cwd())).resolve()
    else:
        output = args.output.resolve()
        try:
            output.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            parser.error("--output must name a new directory")
    summary = run_demo(output)
    print(f"PASS: {summary['rows']} rows; valid values masked; only configured markers become NULL.")
    print(f"Before: {output / 'before.csv'}")
    print(f"After:  {output / 'after.csv'}")
    print(f"Checks: {output / 'verification.json'}")


if __name__ == "__main__":
    main()
