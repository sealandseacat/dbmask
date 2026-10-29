"""Generate disposable PostgreSQL data and verify the real dbmask CLI.

Run from a source checkout; this is a test tool, not a production database copier.
Only the explicitly guarded local synthetic databases can be reset.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy
import yaml
from _postgres_contract_fixture import (
    KEEP,
    SENSITIVE,
    assert_postconditions,
    negative_control,
    recreate_and_seed,
    snapshot,
    validate_rows,
    validate_urls,
)
from sqlalchemy import create_engine, text

SOURCE_ENV = "DBMASK_CONTRACT_SOURCE_URL"
TARGET_ENV = "DBMASK_CONTRACT_TARGET_URL"
CASES = (
    "restore_email_5001", "restore_email_last", "missing_order",
    "replace_order_key", "drop_unique",
)


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, default=str) + "\n", encoding="utf-8")


def peak_memory() -> dict:
    """Peak RSS of this Python process only; excludes the PostgreSQL server."""
    try:
        import resource

        factor = 1 if sys.platform == "darwin" else 1024
        return {"bytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * factor),
                "method": "resource.ru_maxrss", "scope": "single Python CLI worker; excludes database"}
    except ImportError:
        return {"bytes": None, "method": "unavailable on this platform",
                "scope": "single Python CLI worker; excludes database"}


def execute_cli(arguments: list[str], log: Path) -> dict:
    """Run the actual Click entry point and retain its real exit code/output."""
    from click.testing import CliRunner

    import dbmask
    from dbmask.cli import cli

    expected_module = Path(__file__).resolve().parents[1] / "src" / "dbmask" / "__init__.py"
    require(Path(dbmask.__file__).resolve() == expected_module,
            "install this source checkout with pip install -e '.[dev,postgres]' before testing")
    started = time.perf_counter()
    result = CliRunner().invoke(cli, arguments)
    payload = {"exit_code": result.exit_code,
               "elapsed_seconds": round(time.perf_counter() - started, 6),
               "peak_memory": peak_memory(), "dbmask_module": str(Path(dbmask.__file__).resolve())}
    log.write_text(result.output, encoding="utf-8")
    if result.exception is not None:
        payload["exception_type"] = type(result.exception).__name__
    if "--json" in arguments:
        try:
            payload["result"] = json.loads(result.output)
        except json.JSONDecodeError:
            payload["json_parse_failed"] = True
    else:
        payload["tables"] = {
            match.group(1): {"scanned": int(match.group(2)), "written": int(match.group(3))}
            for match in re.finditer(r"(public\.\w+)\s+\(scanned=(\d+), written=(\d+)\)", result.output)
        }
    return payload


def worker(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("scan", "dry-run", "apply", "validate"))
    parser.add_argument("config", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(arguments)
    # Recheck the destination in every new process before invoking --apply.
    from dbmask.config import Config

    config = Config.load(args.config)
    validate_urls(config.source_database.url, config.database.url)
    command = "mask" if args.stage in {"dry-run", "apply"} else args.stage
    cli_arguments = [command, "--config", str(args.config)]
    if args.stage == "apply":
        cli_arguments.append("--apply")
    elif args.stage == "validate":
        cli_arguments.extend(["--strict", "--json"])
    elif args.stage == "scan":
        cli_arguments.append("--json")
    payload = execute_cli(cli_arguments, args.output.with_suffix(".log"))
    write_json(args.output, payload)
    return payload["exit_code"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_stage(stage: str, config: Path, output: Path, name: str, expected_exit: int = 0) -> dict:
    destination = output / (name + ".json")
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "_worker", stage,
         str(config), str(destination)], capture_output=True, text=True, check=False,
    )
    # Save startup/import failures too, without treating them as expected refusals.
    (output / (name + "-process.log")).write_text(result.stdout + result.stderr, encoding="utf-8")
    require(destination.is_file(), f"{name}: CLI worker did not produce its result")
    payload = json.loads(destination.read_text(encoding="utf-8"))
    require(result.returncode == expected_exit and payload.get("exit_code") == expected_exit,
            f"{name}: CLI returned an unexpected exit code")
    require(not payload.get("json_parse_failed"), f"{name}: CLI output is not valid JSON")
    return payload


def check_positive(issues: list[dict], rows: int) -> None:
    require(bool(issues) and all(i.get("status") == "pass" for i in issues),
            "positive strict validation did not pass every check")
    required = {f"public.{table}.{column}" for table, columns in SENSITIVE.items() for column in columns}
    completeness = [i for i in issues if i.get("check") == "masking_completeness"]
    require(len(completeness) == len(required)
            and {i.get("location") for i in completeness} == required,
            "strict validation did not check exactly the intended sensitive columns")
    for issue in completeness:
        detail = issue.get("detail", {})
        require(detail.get("rows_compared") == rows and detail.get("coverage") == "all rows"
                and detail.get("source_rows_inspected") == rows
                and detail.get("target_rows_inspected") == rows,
                "strict validation did not inspect all source and target rows")
    for table in SENSITIVE:
        require(any(i.get("check") == "row_count" and i.get("location") == f"public.{table}"
                    for i in issues), "a table was omitted from row-count validation")
        elements = [i for i in issues if i.get("check") == "schema_elements"
                    and i.get("location") == f"public.{table}"]
        require({i.get("detail", {}).get("element") for i in elements} == {
            "columns", "primary_key", "indexes", "foreign_keys", "unique_constraints", "check_constraints",
        }, "a table was omitted from structural validation")
    require(any(i.get("check") == "classification_coverage" for i in issues),
            "classification coverage was not checked")


def check_negative(case: str, issues: list[dict]) -> None:
    """Refuse accidental failures, wrong locations and unrelated warnings."""
    bad = [i for i in issues if i.get("status") != "pass"]
    require(bool(bad) and all(i.get("status") == "fail" for i in bad),
            f"{case}: expected a specific failure, not an error/warning/skip")
    if case in {"restore_email_5001", "restore_email_last"}:
        require(len(bad) == 1 and bad[0].get("check") == "masking_completeness"
                and bad[0].get("location") == "public.customers.email"
                and bad[0].get("detail", {}).get("unmasked_rows") == 1,
                f"{case}: did not detect exactly the deliberately restored email")
    elif case in {"missing_order", "replace_order_key"}:
        expected = {("masking_completeness", "public.orders.contact_email")}
        if case == "missing_order":
            expected.add(("row_count", "public.orders"))
        require(len(bad) == len(expected)
                and {(i.get("check"), i.get("location")) for i in bad} == expected,
                f"{case}: did not report the expected row/key checks")
        issue = next(i for i in bad if i.get("check") == "masking_completeness")
        detail = issue.get("detail", {})
        require(detail.get("source_only_keys") == 1
                and detail.get("target_only_keys") == (0 if case == "missing_order" else 1),
                f"{case}: did not identify the expected key-set mismatch")
    elif case == "drop_unique":
        require(all(i.get("check") == "schema_elements" and i.get("location") == "public.customers"
                    for i in bad)
                and {i.get("detail", {}).get("element") for i in bad} == {"indexes", "unique_constraints"}
                and len(bad) == 2,
                "drop_unique: did not detect the missing unique constraint and backing index")
    else:
        raise ValueError("unknown negative-control case")


def write_config(output: Path, seed_map: bool) -> Path:
    fields = {
        "sensitive": [{"match": f"public.{table}.{column}", "rule": rule}
                      for table, columns in SENSITIVE.items() for column, rule in columns.items()],
        "not_sensitive": [f"public.{table}.{column}" for table, columns in KEEP.items() for column in columns],
    }
    fields_path = output / "fields.yaml"
    fields_path.write_text(yaml.safe_dump(fields, sort_keys=False), encoding="utf-8")
    config = {
        "database": {"url": "${DBMASK_CONTRACT_TARGET_URL}", "name": "contract-target", "schemas": ["public"]},
        "source_database": {"url": "${DBMASK_CONTRACT_SOURCE_URL}", "name": "contract-source", "schemas": ["public"]},
        "detection": {"overrides_file": str(fields_path), "use_patterns": False, "use_history": False},
        "history": {"enabled": False}, "llm": {"enabled": False},
        "masking": {"seed": "dbmask-contract-synthetic-v1", "seed_map": {
            "enabled": seed_map, "url": "sqlite:///" + (output / "seedmap.db").as_posix(),
            "salt": "contract-synthetic-salt-v1",
        }},
        "validation": {"enabled": True, "pk_row_limit": None, "ignore_test_data": False,
                       "columns": [f"public.{table}.{column}" for table, columns in SENSITIVE.items()
                                   for column in columns]},
    }
    config_path = output / "config.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return config_path


def mapping_count(output: Path) -> int:
    """A preview may initialize an empty store, but must not record mappings."""
    path = output / "seedmap.db"
    if not path.exists():
        return 0
    with sqlite3.connect(path) as connection:
        return connection.execute("SELECT COUNT(*) FROM dbmask_seed_map").fetchone()[0]


def metadata(source: str, seed_map: bool) -> dict:
    import psycopg2

    repository = Path(__file__).resolve().parents[1]
    def git(*args):
        result = subprocess.run(["git", "-C", str(repository), *args],
                                capture_output=True, text=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    engine = create_engine(source)
    try:
        with engine.connect() as connection:
            server_version = connection.execute(text("SELECT version()")).scalar_one()
    finally:
        engine.dispose()
    return {
        "source_commit": git("rev-parse", "HEAD"),
        "working_tree_dirty": bool(git("status", "--porcelain")),
        "python": platform.python_version(), "platform": platform.platform(),
        "sqlalchemy": sqlalchemy.__version__, "psycopg2": psycopg2.__version__,
        "postgresql": server_version, "seed_map_enabled": seed_map,
        "llm_enabled": False, "detection_scope": "explicit reviewed synthetic columns",
        "fixture_version": 1, "masking_seed": "dbmask-contract-synthetic-v1",
        "file_sha256": {name: hashlib.sha256((repository / "scripts" / name).read_bytes()).hexdigest()
                        for name in ("postgres_contract.py", "_postgres_contract_fixture.py")},
        "memory_scope": "per-stage Python worker peaks; excludes PostgreSQL and other processes",
    }


def run_contract(args) -> int:
    source, target = os.environ.get(SOURCE_ENV, ""), os.environ.get(TARGET_ENV, "")
    validate_rows(args.rows)
    validate_urls(source, target)
    if not args.allow_reset_disposable_databases:
        raise ValueError("pass --allow-reset-disposable-databases to recreate the fixed synthetic pair")
    output = args.output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output must be a new or empty directory; keep earlier evidence separately")
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "running", "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "rows_per_table": args.rows, "total_fixture_rows": args.rows * 2,
              "stages": {}, "negative_controls": {}, "limitations": [
                  "Only this synthetic fixture, selected types, engine/version and configuration are exercised.",
                  "No detection accuracy benchmark, sensitive-key rewriting, release-wheel gate or resume guarantee.",
              ]}
    phase = "seed"
    started = time.perf_counter()
    try:
        config = write_config(output, args.seed_map == "on")
        report["configuration_sha256"] = {
            name: hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in ("config.yaml", "fields.yaml")
        }
        recreate_and_seed(source, target, args.rows)
        report["environment"] = metadata(source, args.seed_map == "on")
        baseline = snapshot(source)
        require(snapshot(target) == baseline, "source and target fixtures do not initially match")
        report["initial_source"] = baseline
        phase = "scan"
        scan = run_stage("scan", config, output, "scan")
        require(isinstance(scan.get("result"), list) and bool(scan["result"]), "scan did not return decisions")
        expected_sensitive = {f"public.{table}.{column}" for table, columns in SENSITIVE.items() for column in columns}
        decisions = scan["result"]
        expected_inventory = expected_sensitive | {
            f"public.{table}.{column}" for table, columns in KEEP.items() for column in columns
        }
        actual_inventory = {f"{d.get('schema')}.{d.get('table')}.{d.get('column')}" for d in decisions}
        actual_sensitive = {f"{d.get('schema')}.{d.get('table')}.{d.get('column')}"
                            for d in decisions if d.get("sensitivity") == "sensitive"}
        require(actual_sensitive == expected_sensitive and actual_inventory == expected_inventory
                and len(decisions) == len(expected_inventory)
                and all(d.get("sensitivity") in {"sensitive", "not_sensitive"} for d in decisions),
                "scan did not classify the reviewed fixture exactly as intended")
        report["stages"][phase] = scan
        phase = "dry-run"
        dry = run_stage("dry-run", config, output, "dry-run")
        require(snapshot(source) == baseline and snapshot(target) == baseline, "dry-run changed a fixture")
        require(dry.get("tables") == {f"public.{table}": {"scanned": args.rows, "written": 0}
                                      for table in SENSITIVE}, "dry-run did not preview every row")
        require(mapping_count(output) == 0, "dry-run recorded a seed-map mapping")
        report["stages"][phase] = dry
        phase = "apply"
        applied = run_stage("apply", config, output, "apply")
        require(applied.get("tables") == {f"public.{table}": {"scanned": args.rows, "written": args.rows}
                                          for table in SENSITIVE}, "apply did not report every row written")
        report["stages"][phase] = applied
        report["seed_map_pairs_after_apply"] = mapping_count(output)
        require((report["seed_map_pairs_after_apply"] > 0) == (args.seed_map == "on"),
                "apply did not use the selected seed-map mode")
        phase = "independent-sql-checks"
        report["independent_checks"] = assert_postconditions(source, target, args.rows, baseline)
        positive_target = snapshot(target)
        phase = "positive-strict"
        positive = run_stage("validate", config, output, "positive-strict")
        check_positive(positive.get("result", []), args.rows)
        report["stages"][phase] = positive
        phase = "bounded-coverage"
        bounded_data = yaml.safe_load(config.read_text(encoding="utf-8"))
        bounded_data["validation"]["pk_row_limit"] = 5000
        bounded_path = output / "bounded-config.yaml"
        bounded_path.write_text(yaml.safe_dump(bounded_data, sort_keys=False), encoding="utf-8")
        bounded = run_stage("validate", bounded_path, output, "bounded-coverage", expected_exit=1)
        bad = [i for i in bounded.get("result", []) if i.get("status") != "pass"]
        require(len(bad) == len(expected_sensitive)
                and all(i.get("status") == "warning" and i.get("check") == "masking_completeness"
                        and i.get("detail", {}).get("rows_compared") == 5000
                        and str(i.get("detail", {}).get("coverage", "")).startswith("partial") for i in bad)
                and {i.get("location") for i in bad} == expected_sensitive,
                "bounded comparison did not reject exactly the expected partial coverage")
        report["stages"][phase] = bounded
        for case in CASES:
            phase = case
            with negative_control(target, case, args.rows):
                negative = run_stage("validate", config, output, case, expected_exit=1)
                check_negative(case, negative.get("result", []))
                report["negative_controls"][case] = {"expected_refusal_confirmed": True, **negative}
            require(snapshot(target) == positive_target, f"{case}: the target was not restored")
            require(snapshot(source) == baseline, f"{case}: the source changed")
        phase = "final-strict"
        final = run_stage("validate", config, output, "final-strict")
        check_positive(final.get("result", []), args.rows)
        report["stages"][phase] = final
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        report["failure"] = {"phase": phase, "error_type": type(exc).__name__}
        if isinstance(exc, AssertionError):
            report["failure"]["message"] = str(exc)
    finally:
        report["elapsed_seconds"] = round(time.perf_counter() - started, 6)
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(output / "report.json", report)
    print(f"PostgreSQL contract: {report['status']} ({args.rows:,} rows per table)")
    print(f"Report: {output / 'report.json'}")
    if report["status"] != "passed":
        print(f"Stopped in phase: {phase}", file=sys.stderr)
        return 1
    return 0


def main(arguments=None) -> int:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if arguments and arguments[0] == "_worker":
        return worker(arguments[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=10001, help="Customers and orders each have this many rows (5001..200001).")
    parser.add_argument("--output", type=Path, default=Path("postgres-contract-evidence"))
    parser.add_argument("--seed-map", choices=("on", "off"), default="off")
    parser.add_argument("--allow-reset-disposable-databases", action="store_true",
                        help="Allow recreation of only the two fixed local synthetic databases.")
    args = parser.parse_args(arguments)
    try:
        return run_contract(args)
    except ValueError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
