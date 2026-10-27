"""Release gates must account for coverage, row alignment and source UNKNOWNs."""
from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from dbmask.cli import cli
from dbmask.config import Config, DatabaseConfig, ValidationConfig
from dbmask.connectors.sql import SQLConnector
from dbmask.history.records import HistoryRecord
from dbmask.history.store import HistoryStore
from dbmask.runner import Runner
from dbmask.validation.result import Status
from dbmask.validation.validator import Validator


def _database(path: Path, rows, *, notes: bool = False):
    with sqlite3.connect(path) as conn:
        extra = ", notes TEXT" if notes else ""
        conn.execute(f"CREATE TABLE people (id INTEGER PRIMARY KEY, email TEXT{extra})")
        conn.executemany(
            "INSERT INTO people VALUES (" + ("?, ?, ?" if notes else "?, ?") + ")", rows
        )


def _report(tmp_path, source_rows, target_rows, **options):
    _database(tmp_path / "source.db", source_rows)
    _database(tmp_path / "target.db", target_rows)
    cfg = ValidationConfig(**options)
    with (
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'source.db'}")) as source,
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}")) as target,
    ):
        report = Validator(cfg).validate(
            source, target, schemas=["main"], sensitive_columns=[("main", "people", "email")]
        )
    issue = next(i for i in report.issues if i.check == "masking_completeness")
    return report, issue


@pytest.mark.parametrize("count, status", [
    (4999, Status.PASS), (5000, Status.PASS), (5001, Status.WARNING),
])
def test_default_budget_distinguishes_exact_limit_from_partial(tmp_path, count, status):
    source = [(i, f"original{i}@corp.example") for i in range(count)]
    target = [(i, f"masked{i}@example.invalid") for i in range(count)]
    report, issue = _report(tmp_path, source, target)
    assert issue.status == status
    assert issue.detail["rows_compared"] == min(count, 5000)
    assert report.passed_strict is (count <= 5000)
    assert ("partial" in issue.detail["coverage"]) is (count > 5000)


@pytest.mark.parametrize("limit, status", [(5000, Status.WARNING), (None, Status.FAIL)])
def test_unmasked_row_5001_cannot_pass_strict(tmp_path, limit, status):
    source = [(i, f"original{i}@corp.example") for i in range(1, 5002)]
    target = [(i, f"masked{i}@example.invalid") for i in range(1, 5001)] + [source[-1]]
    report, issue = _report(tmp_path, source, target, pk_row_limit=limit)
    assert issue.status == status
    assert not report.passed_strict
    if limit is None:
        assert issue.detail["unmasked_rows"] == 1
        assert issue.detail["coverage"] == "all rows"


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "5000"])
def test_invalid_pk_row_budget_is_rejected(limit):
    with pytest.raises(ValueError, match="pk_row_limit"):
        ValidationConfig(pk_row_limit=limit)


@pytest.mark.parametrize("source_ids, target_ids", [
    ([1, 2], [101, 102]), ([1, 2], [1, 3]), ([1, 2], [1]), ([], [1]), ([1], []),
])
def test_missing_or_different_keys_fail_even_without_row_count_check(
    tmp_path, source_ids, target_ids,
):
    source = [(i, f"original{i}@corp.example") for i in source_ids]
    target = [(i, f"masked{i}@example.invalid") for i in target_ids]
    report, issue = _report(tmp_path, source, target, check_row_counts=False)
    assert issue.status == Status.FAIL
    assert not report.passed
    assert "key" in issue.message.lower()
    assert issue.detail["source_only_keys"] == len(set(source_ids) - set(target_ids))
    assert issue.detail["target_only_keys"] == len(set(target_ids) - set(source_ids))


def test_partial_key_ranges_are_unverified_not_claimed_missing_globally(tmp_path):
    source = [(i, f"original{i}@corp.example") for i in (1, 2, 3)]
    target = [(i, f"masked{i}@example.invalid") for i in (2, 3, 4)]
    report, issue = _report(tmp_path, source, target, pk_row_limit=2)
    assert issue.status == Status.WARNING
    assert not report.passed_strict
    assert "inspected" in issue.message.lower()
    assert issue.detail["rows_compared"] == 1


def test_composite_primary_key_mismatch_fails(tmp_path):
    for name, rows in [
        ("source", [("a", 1, "original@corp.example")]),
        ("target", [("b", 1, "masked@example.invalid")]),
    ]:
        with sqlite3.connect(tmp_path / f"{name}.db") as conn:
            conn.execute("CREATE TABLE people (tenant TEXT, id INTEGER, email TEXT, PRIMARY KEY (tenant, id))")
            conn.executemany("INSERT INTO people VALUES (?, ?, ?)", rows)
    with (
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'source.db'}")) as source,
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}")) as target,
    ):
        report = Validator(ValidationConfig()).validate(
            source, target, schemas=["main"], sensitive_columns=[("main", "people", "email")]
        )
    assert not report.passed_strict
    assert next(i for i in report.issues if i.check == "masking_completeness").status == Status.FAIL


def test_two_empty_tables_do_not_claim_to_have_compared_sensitive_values(tmp_path):
    report, issue = _report(tmp_path, [], [])
    assert issue.status == Status.SKIPPED
    assert not report.passed_strict
    assert issue.detail["rows_compared"] == 0


def _scope_config(tmp_path, *, history=True, explicit=False, keep_notes=False):
    _database(tmp_path / "source.db", [
        (1, "alpha@corp.example", "Private memo: SSN 123-45-6789"),
        (2, "beta@corp.example", "Private memo: SSN 321-54-9876"),
    ], notes=True)
    shutil.copy2(tmp_path / "source.db", tmp_path / "target.db")
    fields = {
        "sensitive": [{"match": "email", "rule": "email"}],
        "not_sensitive": ["id", *( ["notes"] if keep_notes else [])],
    }
    fields_path = tmp_path / "fields.yaml"
    fields_path.write_text(yaml.safe_dump(fields), encoding="utf-8")
    data = {
        "database": {"url": f"sqlite:///{tmp_path / 'target.db'}", "name": "masked-copy"},
        "source_database": {"url": f"sqlite:///{tmp_path / 'source.db'}", "name": "original"},
        "history": {"enabled": history, "url": f"sqlite:///{tmp_path / 'history.db'}"},
        "detection": {"use_patterns": False, "overrides_file": str(fields_path)},
        "masking": {"seed": "test-private-seed", "seed_map": {"enabled": False}},
        "validation": {"columns": ["main.people.email"] if explicit else []},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _apply(path):
    result = CliRunner().invoke(cli, ["mask", "--config", str(path), "--apply"])
    assert result.exit_code == 0, result.output
    return result


def _coverage_issues(report):
    return [i for i in report.issues if i.check == "classification_coverage"]


@pytest.mark.parametrize("history", [True, False])
@pytest.mark.parametrize("explicit", [True, False])
def test_unknown_source_notes_block_strict_even_with_history_or_explicit_columns(
    tmp_path, history, explicit,
):
    path = _scope_config(tmp_path, history=history, explicit=explicit)
    assert "could not be classified" in _apply(path).output
    with Runner(Config.load(path)) as runner:
        report = runner.validate()
    assert report.passed
    assert not report.passed_strict
    unknown = next(i for i in _coverage_issues(report) if i.column == "notes")
    assert unknown.status == Status.WARNING
    assert unknown.schema == "main" and unknown.table == "people"
    assert "123-45-6789" not in json.dumps(unknown.to_dict())
    with sqlite3.connect(tmp_path / "target.db") as conn:
        assert "123-45-6789" in conn.execute("SELECT notes FROM people WHERE id=1").fetchone()[0]


def test_cli_strict_blocks_unknowns_but_relaxed_mode_keeps_warning(tmp_path):
    path = _scope_config(tmp_path, explicit=True)
    _apply(path)
    runner = CliRunner()
    relaxed = runner.invoke(cli, ["validate", "--config", str(path)])
    strict = runner.invoke(cli, ["validate", "--config", str(path), "--strict", "--json"])
    assert relaxed.exit_code == 0, relaxed.output
    assert "warning" in relaxed.output
    assert strict.exit_code == 1, strict.output
    assert any(i["check"] == "classification_coverage" and i["status"] == "warning"
               for i in json.loads(strict.output))


def test_explicit_review_of_non_sensitive_notes_resolves_coverage(tmp_path):
    path = _scope_config(tmp_path, keep_notes=True)
    _apply(path)
    with Runner(Config.load(path)) as runner:
        report = runner.validate()
    assert report.passed_strict
    assert all(i.status == Status.PASS for i in _coverage_issues(report))


def _notes_history(*, status="approved", decision="keep"):
    return HistoryRecord(
        "masked-copy", "main", "people", "notes", decision=decision,
        detected_type="ssn" if decision == "mask" else "",
        masking_strategy="blank" if decision == "mask" else "",
        review_status=status, user_id="analyst", reviewed_by="reviewer",
        analysis_date="2026-10-26", reviewed_at="2026-10-26T10:00:00Z", data_type="TEXT",
    )


def test_source_inventory_uses_target_history_scope_and_does_not_append_suggestions(tmp_path):
    path = _scope_config(tmp_path)
    cfg = Config.load(path)
    with HistoryStore(cfg.history.url) as history:
        history.import_records([_notes_history()])
    _apply(path)
    with sqlite3.connect(tmp_path / "history.db") as conn:
        before = conn.execute("SELECT COUNT(*) FROM dbmask_history_suggestions").fetchone()[0]
    with Runner(cfg) as runner:
        report = runner.validate()
    assert report.passed_strict
    with sqlite3.connect(tmp_path / "history.db") as conn:
        after = conn.execute("SELECT COUNT(*) FROM dbmask_history_suggestions").fetchone()[0]
    assert after == before


@pytest.mark.parametrize("status", ["pending", "superseded"])
def test_pending_review_cannot_be_bypassed_by_explicit_validation_columns(tmp_path, status):
    path = _scope_config(tmp_path, explicit=True)
    cfg = Config.load(path)
    with HistoryStore(cfg.history.url) as history:
        history.import_records([_notes_history(status=status, decision="mask")])
    _apply(path)
    with sqlite3.connect(tmp_path / "target.db") as conn:
        conn.execute("UPDATE people SET notes=NULL")
    cfg.validation.columns.append("main.people.notes")
    with Runner(cfg) as runner:
        report = runner.validate()
    assert not report.passed_strict
    assert any(i.column == "notes" and i.status == Status.WARNING for i in _coverage_issues(report))


def test_explicit_columns_can_declare_unknown_values_sensitive_for_comparison(tmp_path):
    path = _scope_config(tmp_path, explicit=True)
    _apply(path)
    with sqlite3.connect(tmp_path / "target.db") as conn:
        conn.execute("UPDATE people SET notes=NULL")
    cfg = Config.load(path)
    cfg.validation.columns.append("main.people.notes")
    with Runner(cfg) as runner:
        report = runner.validate()
    assert report.passed_strict


def test_known_sensitive_source_column_outside_explicit_list_is_unverified(tmp_path):
    path = _scope_config(tmp_path, explicit=True)
    cfg = Config.load(path)
    fields_path = Path(cfg.detection.overrides_file)
    fields = yaml.safe_load(fields_path.read_text(encoding="utf-8"))
    fields["sensitive"].append({"match": "notes", "rule": "blank"})
    fields_path.write_text(yaml.safe_dump(fields), encoding="utf-8")
    _apply(path)
    with Runner(cfg) as runner:
        report = runner.validate()
    assert not report.passed_strict
    issue = next(i for i in _coverage_issues(report) if i.column == "notes")
    assert issue.status == Status.WARNING
    assert "outside" in issue.message


def test_source_analysis_error_cannot_hide_behind_explicit_columns(tmp_path, monkeypatch):
    path = _scope_config(tmp_path, explicit=True)
    _apply(path)
    cfg = Config.load(path)
    original = SQLConnector.sample_values

    def fail_source_notes(self, schema, table, column, limit=100):
        if self.url == cfg.source_database.url and column == "notes":
            raise RuntimeError("synthetic read failure")
        return original(self, schema, table, column, limit)

    monkeypatch.setattr(SQLConnector, "sample_values", fail_source_notes)
    with Runner(cfg) as runner:
        report = runner.validate()
    assert not report.passed
    assert any(i.status == Status.ERROR for i in _coverage_issues(report))


def test_validation_classification_never_sends_samples_to_an_llm(tmp_path, monkeypatch):
    path = _scope_config(tmp_path, explicit=True)
    _apply(path)
    calls = []

    class Provider:
        def classify(self, column_name, sample):
            calls.append(column_name)
            raise AssertionError("validation must not invoke the LLM")

    monkeypatch.setattr("dbmask.runner.create_provider", lambda config: Provider())
    cfg = Config.load(path)
    cfg.llm.enabled = True
    with Runner(cfg) as runner:
        report = runner.validate()
    assert not calls
    assert not report.passed_strict
