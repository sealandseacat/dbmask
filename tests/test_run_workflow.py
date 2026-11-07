"""A frozen, confirmed plan must survive the entire scan/mask/validate run.

These tests use real SQLite writes and the actual Runner/CLI entry points.
They deliberately classify the tiny fixture explicitly: detection accuracy
is tested elsewhere, while these tests pin down scope, audit and retry safety.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner

from dbmask.cli import cli
from dbmask.config import Config
from dbmask.connectors.sql import SQLConnector
from dbmask.detection.pipeline import DetectionPipeline
from dbmask.detection.result import Decision, Sensitivity
from dbmask.masking.engine import MaskingEngine
from dbmask.run_record import RunRecord
from dbmask.runner import Runner, ScanReport


def _emails(path: Path) -> list[str]:
    with sqlite3.connect(path) as conn:
        return [row[0] for row in conn.execute("SELECT email FROM users ORDER BY id")]


@pytest.fixture()
def run_env(tmp_path):
    target = tmp_path / "target.db"
    source = tmp_path / "source.db"
    with sqlite3.connect(target) as conn:
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)")
        conn.executemany("INSERT INTO users VALUES (?, ?)", [
            (1, "alice@example.com"), (2, "bob@example.com"),
        ])
    shutil.copyfile(target, source)
    settings = {
        "database": {"url": f"sqlite:///{target}", "name": "trial", "schemas": ["main"]},
        "source_database": {"url": f"sqlite:///{source}", "schemas": ["main"]},
        "history": {"enabled": False},
        "llm": {"enabled": False, "api_key": "llm-secret-must-not-appear"},
        "masking": {
            "seed": "seed-secret-must-not-appear",
            "seed_map": {"enabled": False},
        },
        "validation": {"pk_row_limit": None, "ignore_test_data": False},
        "audit": {"directory": str(tmp_path / "runs")},
    }

    def config():
        # A fresh object avoids a changed dry-run flag leaking into another step.
        return Config.from_dict(json.loads(json.dumps(settings)))

    def scan():
        return ScanReport(decisions=[
            Decision(database="trial", schema="main", table="users", column="id",
                     sensitivity=Sensitivity.NOT_SENSITIVE, source="override"),
            Decision(database="trial", schema="main", table="users", column="email",
                     sensitivity=Sensitivity.SENSITIVE, rule="email", source="override",
                     detail="raw-sample@example.com", confidence=1.0),
        ])

    def plan(name="run.json", approve=True):
        path = tmp_path / "runs" / name
        with Runner(config()) as runner:
            record = runner.create_run(str(path), scan=scan())
        if approve:
            record.approve("Independent tester")
        return path

    return SimpleNamespace(target=target, source=source, settings=settings,
                           config=config, scan=scan, plan=plan, tmp=tmp_path)


def test_confirmed_plan_preview_apply_and_validate_use_same_columns(run_env):
    path = run_env.plan()
    before = _emails(run_env.target)
    with Runner(run_env.config()) as runner:
        preview = runner.mask(run_file=str(path))
    assert preview[0].rows_written == 0
    assert _emails(run_env.target) == before

    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        result = runner.mask(run_file=str(path))
        report = runner.validate(run_file=str(path))
    assert result[0].rows_written == 2
    assert _emails(run_env.target) != before
    checks = [issue for issue in report.issues if issue.check == "masking_completeness"]
    assert any(issue.column == "email" for issue in checks)
    assert report.passed
    saved = RunRecord.load(path).data
    assert saved["execution"]["status"] == "applied"
    assert saved["validations"]


def test_draft_plan_cannot_be_applied(run_env):
    path = run_env.plan(approve=False)
    before = _emails(run_env.target)
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.mask(run_file=str(path))
    assert _emails(run_env.target) == before


@pytest.mark.parametrize("new_plan", [False, True])
def test_repeat_apply_is_blocked_for_same_or_another_record(run_env, new_plan):
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))
    after = _emails(run_env.target)
    if new_plan:
        path = run_env.plan("another.json")
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.mask(run_file=str(path))
    assert _emails(run_env.target) == after


def test_validation_config_cannot_silently_narrow_frozen_plan(run_env):
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))
    config.validation.columns = ["main.users.id"]
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.validate(run_file=str(path))


def test_frozen_validation_does_not_reclassify_when_detection_settings_change(run_env, monkeypatch):
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))
    config.detection.use_patterns = False
    config.detection.use_history = False
    config.detection.skip_table_patterns = ["users"]

    def no_reclassification(*args, **kwargs):
        pytest.fail("Frozen validation must not invoke the detection pipeline")

    monkeypatch.setattr(DetectionPipeline, "analyze_column", no_reclassification)
    with Runner(config) as runner:
        report = runner.validate(run_file=str(path))
    assert report.passed
    assert any(issue.check == "masking_completeness" and issue.column == "email"
               for issue in report.issues)


def test_validation_before_apply_cannot_pass(run_env):
    path = run_env.plan()
    with Runner(run_env.config()) as runner:
        report = runner.validate(run_file=str(path))
    assert not report.passed
    assert any(issue.check == "run_execution" and issue.status.value == "error"
               for issue in report.issues)


def test_disabled_validation_check_is_visible_in_frozen_run_coverage(run_env):
    run_env.settings["validation"]["check_masking_completeness"] = False
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))
        report = runner.validate(run_file=str(path))
    assert not report.passed
    assert any(issue.check == "run_coverage" and issue.status.value == "error"
               for issue in report.issues)


def test_source_schema_drift_is_recorded_as_validation_error(run_env):
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))
    with sqlite3.connect(run_env.source) as conn:
        conn.execute("ALTER TABLE users ADD COLUMN source_email TEXT")
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.validate(run_file=str(path))
    assert RunRecord.load(path).data["validations"][-1]["status"] == "error"


def test_failed_preview_after_apply_cannot_erase_commit_history(run_env, monkeypatch):
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))

    def fail_preview(self, row, plans):
        raise RuntimeError("preview could not transform a row")

    monkeypatch.setattr(MaskingEngine, "mask_row", fail_preview)
    with Runner(run_env.config()) as runner, pytest.raises(RuntimeError):
        runner.mask(run_file=str(path))
    saved = RunRecord.load(path).data
    assert saved["execution"]["status"] == "applied"
    assert sum(item["rows_written"] for item in saved["execution"]["tables"]) == 2
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.mask(run_file=str(path))


def test_explicit_repeat_override_reason_is_persisted(run_env):
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))
    with Runner(config) as runner:
        runner.mask(run_file=str(path), remask_reason="Verified target restored from original copy")
    assert "Verified target restored from original copy" in path.read_text(encoding="utf-8")


def test_failed_repeat_attempt_cannot_erase_an_earlier_apply_guard(run_env, monkeypatch):
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))
    after = _emails(run_env.target)

    def fail_preflight(*args, **kwargs):
        raise RuntimeError("preflight failed before the repeat attempt wrote any rows")

    with monkeypatch.context() as patch:
        patch.setattr(MaskingEngine, "preflight_table", fail_preflight)
        with Runner(config) as runner, pytest.raises(RuntimeError):
            runner.mask(run_file=str(path), remask_reason="restored and reviewed")
    assert _emails(run_env.target) == after
    with Runner(config) as runner, pytest.raises(ValueError, match="already affected"):
        runner.mask(run_file=str(path))


def test_schema_drift_refuses_before_first_update(run_env):
    path = run_env.plan()
    before = _emails(run_env.target)
    with sqlite3.connect(run_env.target) as conn:
        conn.execute("ALTER TABLE users ADD COLUMN newly_added_email TEXT")
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.mask(run_file=str(path))
    assert _emails(run_env.target) == before


def test_target_identity_mismatch_refuses_before_first_update(run_env):
    path = run_env.plan()
    other = run_env.tmp / "other.db"
    shutil.copyfile(run_env.target, other)
    config = run_env.config()
    config.database.url = f"sqlite:///{other}"
    config.masking.dry_run = False
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.mask(run_file=str(path))
    assert _emails(other) == ["alice@example.com", "bob@example.com"]


@pytest.mark.parametrize("explicit_plan", [False, True])
def test_same_source_and_target_refused_before_apply(run_env, explicit_plan):
    run_env.settings["source_database"]["url"] = run_env.settings["database"]["url"]
    path = run_env.plan() if explicit_plan else None
    config = run_env.config()
    config.masking.dry_run = False
    before = _emails(run_env.target)
    with Runner(config) as runner, pytest.raises(ValueError):
        if explicit_plan:
            runner.mask(run_file=str(path))
        else:
            runner.mask(scan_report=run_env.scan())
    assert _emails(run_env.target) == before


def test_unresolved_column_cannot_be_approved(run_env):
    scan = run_env.scan()
    scan.decisions[0].sensitivity = Sensitivity.UNKNOWN
    with Runner(run_env.config()) as runner:
        record = runner.create_run(str(run_env.tmp / "runs" / "unknown.json"), scan=scan)
    with pytest.raises(ValueError):
        record.approve("Independent tester")


def test_run_file_does_not_contain_values_seed_or_credentials(run_env):
    path = run_env.plan()
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        runner.mask(run_file=str(path))
        runner.validate(run_file=str(path))
    text = path.read_text(encoding="utf-8")
    for secret in ["alice@example.com", "bob@example.com", "raw-sample@example.com",
                   "seed-secret-must-not-appear", "llm-secret-must-not-appear", "sqlite:///"]:
        assert secret not in text


def test_skipped_sensitive_primary_key_remains_in_validation_scope(run_env):
    scan = run_env.scan()
    scan.decisions[0].sensitivity = Sensitivity.SENSITIVE
    scan.decisions[0].rule = "format_random"
    path = run_env.tmp / "runs" / "sensitive-key.json"
    with Runner(run_env.config()) as runner:
        record = runner.create_run(str(path), scan=scan)
    record.approve("Independent tester")
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner:
        result = runner.mask(run_file=str(path))
        report = runner.validate(run_file=str(path))
    assert any(plan.column == "id" for plan in result[0].skipped_columns)
    assert any(issue.column == "id" and issue.status.value == "fail"
               for issue in report.issues)
    assert not report.passed


def test_audit_write_failure_before_apply_leaves_database_untouched(run_env, monkeypatch):
    path = run_env.plan()
    before = _emails(run_env.target)
    save = RunRecord.save

    def fail_before_update(self):
        if self.data["execution"]["status"] == "applying":
            raise OSError("audit destination became unavailable")
        return save(self)

    monkeypatch.setattr(RunRecord, "save", fail_before_update)
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner, pytest.raises(OSError):
        runner.mask(run_file=str(path))
    assert _emails(run_env.target) == before


def test_audit_failure_after_commit_preserves_uncertain_intent_and_blocks_retry(run_env, monkeypatch):
    path = run_env.plan()
    before = _emails(run_env.target)
    save = RunRecord.save

    def fail_after_target_commit(self):
        if any(table.get("rows_written", 0) for table in self.data["execution"]["tables"]):
            raise OSError("audit storage failed after target transaction returned")
        return save(self)

    monkeypatch.setattr(RunRecord, "save", fail_after_target_commit)
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner, pytest.raises(OSError):
        runner.mask(run_file=str(path))
    assert _emails(run_env.target) != before
    execution = RunRecord.load(path).data["execution"]
    assert execution["status"] == "applying"
    assert execution["tables"][0]["in_flight"] is True
    # The JSON cannot confirm this batch's commit even though the target did.
    assert execution["tables"][0]["rows_written"] == 0
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.mask(run_file=str(path))


def test_partial_failure_keeps_committed_rows_and_uncertain_batch(run_env, monkeypatch):
    with sqlite3.connect(run_env.target) as conn:
        conn.executemany("INSERT INTO users VALUES (?, ?)", [
            (n, f"person{n}@example.com") for n in range(3, 1206)
        ])
    shutil.copyfile(run_env.target, run_env.source)
    path = run_env.plan()
    update = SQLConnector.update_rows
    calls = 0

    def fail_second(self, schema, table, keys, rows):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("failure containing raw-sample@example.com and a password")
        return update(self, schema, table, keys, rows)

    monkeypatch.setattr(SQLConnector, "update_rows", fail_second)
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner, pytest.raises(RuntimeError):
        runner.mask(run_file=str(path))
    saved = RunRecord.load(path).data
    execution = saved["execution"]
    assert execution["status"] == "failed"
    tables = execution["tables"]
    assert sum(item["rows_written"] for item in tables) == 1000
    assert tables[0]["committed_batches"] == 1
    assert tables[0]["in_flight"] is True
    assert "raw-sample@example.com" not in path.read_text(encoding="utf-8")
    # The real target is the independent evidence of the recorded commit.
    emails = _emails(run_env.target)
    assert emails[0] != "alice@example.com"
    assert emails[1000] == "person1001@example.com"
    with Runner(config) as runner, pytest.raises(ValueError):
        runner.mask(run_file=str(path))
    with Runner(config) as runner, pytest.raises(ValueError, match="no safe resume point"):
        runner.mask(run_file=str(path), resume=True)
    assert _emails(run_env.target) == emails


@pytest.mark.parametrize("options", [
    ["--resume"],
    ["--apply", "--resume", "--resumable"],
    ["--apply", "--resume", "--remask-reason", "restored the target"],
])
def test_resume_flags_require_explicit_apply_without_conflicting_modes(run_env, options):
    path = run_env.plan()
    config_path = run_env.tmp / "config.yaml"
    config_path.write_text(yaml.safe_dump(run_env.settings), encoding="utf-8")
    before = _emails(run_env.target)
    result = CliRunner().invoke(cli, ["mask", "--config", str(config_path),
                                     "--run-file", str(path), *options])
    assert result.exit_code == 2
    assert "Use either --resumable or --resume with --apply and --run-file" in result.output
    assert _emails(run_env.target) == before
    assert RunRecord.load(path).data["execution"]["status"] == "planned"


def test_resumable_apply_refuses_unsupported_database_before_writes(run_env):
    path = run_env.plan()
    before = _emails(run_env.target)
    config = run_env.config()
    config.masking.dry_run = False
    with Runner(config) as runner, pytest.raises(ValueError, match="requires a PostgreSQL target"):
        runner.mask(run_file=str(path), resumable=True)
    assert _emails(run_env.target) == before
    assert RunRecord.load(path).data["execution"]["status"] == "planned"


def test_cli_plan_and_approval_are_reviewable_without_database_writes(run_env):
    config_path = run_env.tmp / "config.yaml"
    # The scanner can resolve fixture columns through explicit overrides.
    override = run_env.tmp / "overrides.yaml"
    override.write_text(yaml.safe_dump({
        "not_sensitive": ["main.users.id"],
        "sensitive": [{"match": "main.users.email", "rule": "email"}],
    }), encoding="utf-8")
    settings = json.loads(json.dumps(run_env.settings))
    settings["detection"] = {"overrides_file": str(override), "pattern_min_samples": 1}
    config_path.write_text(yaml.safe_dump(settings), encoding="utf-8")
    path = run_env.tmp / "runs" / "cli.json"
    runner = CliRunner()
    result = runner.invoke(cli, ["plan", "--config", str(config_path), "--run-file", str(path)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(cli, ["approve", "--run-file", str(path), "--reviewed-by", "Tester"])
    assert result.exit_code == 0, result.output
    assert _emails(run_env.target) == ["alice@example.com", "bob@example.com"]
    assert RunRecord.load(path).data["approval"]["status"] == "approved"
