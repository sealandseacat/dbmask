"""Validation reports must not copy natural keys or driver parameters to logs."""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from dbmask.cli import cli
from dbmask.config import DatabaseConfig, ValidationConfig
from dbmask.connectors.sql import SQLConnector
from dbmask.validation.masking_completeness import MaskingCompletenessValidator
from dbmask.validation.result import Status
from dbmask.validation.row_count import RowCountValidator
from dbmask.validation.schema_elements import SchemaElementValidator


def _db(path: Path, key, *, composite: bool = False):
    with sqlite3.connect(path) as conn:
        if composite:
            conn.execute(
                "CREATE TABLE people (account TEXT, number INTEGER, secret TEXT, "
                "PRIMARY KEY (account, number))"
            )
            conn.execute("INSERT INTO people VALUES (?, ?, ?)", (*key, "private-payload"))
        else:
            column_type = "INTEGER" if isinstance(key, int) else "TEXT"
            conn.execute(f"CREATE TABLE people (identity {column_type} PRIMARY KEY, secret TEXT)")
            conn.execute("INSERT INTO people VALUES (?, ?)", (key, "private-payload"))


def _issue(tmp_path, key, *, composite=False):
    _db(tmp_path / "source.db", key, composite=composite)
    _db(tmp_path / "target.db", key, composite=composite)
    with (
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'source.db'}")) as source,
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}")) as target,
    ):
        return MaskingCompletenessValidator(ValidationConfig()).validate_column(
            source, target, "main", "people", "secret"
        )


@pytest.mark.parametrize("key", [
    "person-private@corp.example", "123-45-6789", 9876543210123, "@#$%^&![]{}",
])
def test_failure_samples_do_not_contain_raw_natural_keys(tmp_path, key):
    issue = _issue(tmp_path, key)
    assert issue.status == Status.FAIL
    encoded = json.dumps(issue.to_dict())
    assert str(key) not in encoded
    assert "private-payload" not in encoded
    sample = issue.detail["samples_redacted"][0]
    assert "key" not in sample
    assert re.fullmatch(r"row-[0-9a-f]{24}", sample["row_ref"])
    assert sample["source_row_number"] == 1
    assert sample["value"] == "*" * len("private-payload")
    assert issue.detail["key"] == ["identity"]  # column metadata remains useful


def test_composite_keys_are_not_serialized_in_failure_samples(tmp_path):
    key = ("person-private@corp.example", 8765432109876)
    issue = _issue(tmp_path, key, composite=True)
    assert issue.status == Status.FAIL
    encoded = json.dumps(issue.to_dict())
    assert all(str(part) not in encoded for part in key)
    assert issue.detail["key"] == ["account", "number"]
    assert issue.detail["unmasked_rows"] == 1


def test_row_references_are_new_for_each_report(tmp_path):
    key = "person-private@corp.example"
    _db(tmp_path / "source.db", key)
    _db(tmp_path / "target.db", key)
    with (
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'source.db'}")) as source,
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}")) as target,
    ):
        validator = MaskingCompletenessValidator(ValidationConfig())
        first = validator.validate_column(source, target, "main", "people", "secret")
        second = validator.validate_column(source, target, "main", "people", "secret")
    assert first.detail["samples_redacted"][0]["row_ref"] != second.detail["samples_redacted"][0]["row_ref"]


def test_punctuation_only_values_are_fully_redacted(tmp_path):
    key = "person-private@corp.example"
    secret = "@#$%^&![]{}"
    _db(tmp_path / "source.db", key)
    _db(tmp_path / "target.db", key)
    for name in ("source", "target"):
        with sqlite3.connect(tmp_path / f"{name}.db") as conn:
            conn.execute("UPDATE people SET secret=?", (secret,))
    with (
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'source.db'}")) as source,
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}")) as target,
    ):
        issue = MaskingCompletenessValidator(ValidationConfig()).validate_column(
            source, target, "main", "people", "secret"
        )
    assert issue.status == Status.FAIL
    assert secret not in json.dumps(issue.to_dict())
    assert issue.detail["samples_redacted"][0]["value"] == "*" * len(secret)


def _cli_config(tmp_path):
    config = {
        "database": {"url": f"sqlite:///{tmp_path / 'target.db'}"},
        "source_database": {"url": f"sqlite:///{tmp_path / 'source.db'}"},
        "history": {"enabled": False},
        "detection": {"skip_column_patterns": ["^identity$"]},
        "validation": {"columns": ["main.people.secret"]},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def test_real_cli_json_does_not_leak_email_primary_key(tmp_path):
    key = "person-private@corp.example"
    _db(tmp_path / "source.db", key)
    _db(tmp_path / "target.db", key)
    result = CliRunner().invoke(cli, [
        "validate", "--config", str(_cli_config(tmp_path)), "--strict", "--json",
    ])
    assert result.exit_code == 1
    issues = json.loads(result.output)
    assert any(item["check"] == "masking_completeness" and item["status"] == "fail"
               for item in issues)
    assert key not in result.output
    assert "private-payload" not in result.output


def test_completeness_exception_does_not_leak_driver_parameters(tmp_path, monkeypatch):
    key = "person-private@corp.example"
    _db(tmp_path / "source.db", key)
    _db(tmp_path / "target.db", key)

    def fail(self, *args, **kwargs):
        raise RuntimeError(f"query error WHERE identity={key!r}; password=do-not-log-me")

    monkeypatch.setattr(SQLConnector, "iter_pages", fail)
    with (
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'source.db'}")) as source,
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}")) as target,
    ):
        issue = MaskingCompletenessValidator(ValidationConfig()).validate_column(
            source, target, "main", "people", "secret"
        )
    assert issue.status == Status.ERROR
    assert issue.detail["error_type"] == "RuntimeError"
    assert key not in json.dumps(issue.to_dict())
    assert "do-not-log-me" not in json.dumps(issue.to_dict())
    assert "suppressed" in issue.message


def test_cli_error_json_does_not_leak_driver_parameters(tmp_path, monkeypatch):
    key = "person-private@corp.example"
    _db(tmp_path / "source.db", key)
    _db(tmp_path / "target.db", key)

    def fail(self, *args, **kwargs):
        raise RuntimeError(f"query error WHERE identity={key!r}; password=do-not-log-me")

    monkeypatch.setattr(SQLConnector, "iter_pages", fail)
    result = CliRunner().invoke(cli, [
        "validate", "--config", str(_cli_config(tmp_path)), "--strict", "--json",
    ])
    assert result.exit_code == 1
    issues = json.loads(result.output)
    assert any(item["check"] == "masking_completeness" and item["status"] == "error"
               for item in issues)
    assert key not in result.output
    assert "do-not-log-me" not in result.output


@pytest.mark.parametrize("check, method", [
    ("row_count", "row_count"), ("schema_elements", "schema_elements"),
])
def test_table_validator_exceptions_do_not_copy_driver_parameters(
    tmp_path, monkeypatch, check, method,
):
    key = "person-private@corp.example"
    _db(tmp_path / "source.db", key)
    _db(tmp_path / "target.db", key)

    def fail(self, *args, **kwargs):
        raise RuntimeError(f"query error WHERE identity={key!r}; password=do-not-log-me")

    monkeypatch.setattr(SQLConnector, method, fail)
    with (
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'source.db'}")) as source,
        SQLConnector(DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}")) as target,
    ):
        if check == "row_count":
            issue = RowCountValidator().validate_table(source, target, "main", "people")
        else:
            issue = SchemaElementValidator().validate_table(source, target, "main", "people")[0]
    assert issue.status == Status.ERROR
    assert issue.detail == {"error_type": "RuntimeError"}
    assert key not in json.dumps(issue.to_dict())
    assert "do-not-log-me" not in json.dumps(issue.to_dict())


@pytest.mark.parametrize("check, method", [
    ("row_count", "row_count"), ("schema_elements", "schema_elements"),
])
def test_cli_table_error_json_does_not_copy_driver_parameters(
    tmp_path, monkeypatch, check, method,
):
    key = "person-private@corp.example"
    _db(tmp_path / "source.db", key)
    _db(tmp_path / "target.db", key)

    def fail(self, *args, **kwargs):
        raise RuntimeError(f"query error WHERE identity={key!r}; password=do-not-log-me")

    monkeypatch.setattr(SQLConnector, method, fail)
    result = CliRunner().invoke(cli, [
        "validate", "--config", str(_cli_config(tmp_path)), "--strict", "--json",
    ])
    assert result.exit_code == 1
    issues = json.loads(result.output)
    assert any(item["check"] == check and item["status"] == "error" for item in issues)
    assert key not in result.output
    assert "do-not-log-me" not in result.output
