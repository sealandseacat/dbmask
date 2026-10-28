"""Only intended writable columns may appear in masking UPDATE statements."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner
from sqlalchemy import event

from dbmask.cli import cli
from dbmask.config import Config, DatabaseConfig, HistoryConfig, MaskingConfig
from dbmask.connectors.base import Connector
from dbmask.connectors.sql import SQLConnector
from dbmask.detection.result import Decision, Sensitivity
from dbmask.masking.engine import MaskingEngine
from dbmask.masking.rules import MaskingValidationError
from dbmask.runner import Runner


def _make(path: Path, *, generated: str = "STORED") -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, "
            "status TEXT DEFAULT 'active', email_lower TEXT "
            f"GENERATED ALWAYS AS (lower(email)) {generated})"
        )
        conn.executemany(
            "INSERT INTO users (id, email, status) VALUES (?, ?, ?)",
            [(1, "ALICE@corp.example", "active"), (2, "BOB@corp.example", "pending")],
        )


def _decision(column="email", table="users") -> Decision:
    return Decision("test", "main", table, column, Sensitivity.SENSITIVE,
                    rule="email", source="override", confidence=1.0)


def _masker(*, dry_run=False) -> MaskingEngine:
    return MaskingEngine(MaskingConfig(
        dry_run=dry_run, seed="generated-column-test", seed_map={"enabled": False},
    ))


def _updates(connector):
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE"):
            statements.append(statement)

    event.listen(connector.engine, "before_cursor_execute", capture)
    return statements


@pytest.mark.parametrize("generated", ["STORED", "VIRTUAL"])
def test_unselected_generated_column_is_recomputed_and_never_updated(tmp_path, generated):
    path = tmp_path / "generated.db"
    _make(path, generated=generated)
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        statements = _updates(connector)
        result = _masker().mask_table(
            connector, "main", "users", [_decision()], batch_size=1,
        )
    assert result.rows_written == 2
    assert len(statements) == 2
    for statement in statements:
        assigned = statement.split(" SET ", 1)[1].split(" WHERE ", 1)[0]
        assert "email=" in assigned
        assert "email_lower" not in assigned
        assert "status" not in assigned
        assert "id=" not in assigned
    with sqlite3.connect(path) as conn:
        rows = conn.execute("SELECT email, status, email_lower FROM users ORDER BY id").fetchall()
    assert [row[1] for row in rows] == ["active", "pending"]
    assert all(row[0].endswith("@example.invalid") for row in rows)
    assert all(row[2] == row[0].lower() for row in rows)


@pytest.mark.parametrize("generated", ["STORED", "VIRTUAL"])
@pytest.mark.parametrize("dry_run", [True, False])
def test_selected_generated_column_fails_before_updates_in_preview_and_apply(
    tmp_path, generated, dry_run,
):
    path = tmp_path / "selected.db"
    _make(path, generated=generated)
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        statements = _updates(connector)
        with pytest.raises(MaskingValidationError, match="email_lower.*generated/computed"):
            _masker(dry_run=dry_run).mask_table(
                connector, "main", "users", [_decision(), _decision("email_lower")],
            )
        assert not statements
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT email FROM users WHERE id=1").fetchone()[0] == "ALICE@corp.example"


def test_runner_preflights_later_table_before_updating_first_table(tmp_path):
    path = tmp_path / "multi.db"
    _make(path)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE first_table (id INTEGER PRIMARY KEY, email TEXT)")
        conn.execute("INSERT INTO first_table VALUES (1, 'first@corp.example')")
    config = Config(
        database=DatabaseConfig(url=f"sqlite:///{path}"),
        history=HistoryConfig(enabled=False),
        masking=MaskingConfig(dry_run=False, seed_map={"enabled": False}),
    )
    with Runner(config) as runner:
        statements = _updates(runner.connector)
        with pytest.raises(MaskingValidationError, match="generated/computed"):
            runner.mask([_decision(table="first_table"), _decision("email_lower")])
        assert not statements
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT email FROM first_table").fetchone()[0] == "first@corp.example"


def test_cli_reports_selected_generated_column_without_raw_values(tmp_path):
    path = tmp_path / "cli.db"
    _make(path)
    fields = tmp_path / "fields.yaml"
    fields.write_text(yaml.safe_dump({
        "sensitive": [{"match": "email_lower", "rule": "email"}],
    }), encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        "database": {"url": f"sqlite:///{path}"},
        "history": {"enabled": False},
        "detection": {"use_patterns": False, "overrides_file": str(fields)},
        "masking": {"seed_map": {"enabled": False}},
    }), encoding="utf-8")
    result = CliRunner().invoke(cli, ["mask", "--config", str(config), "--apply"])
    assert result.exit_code != 0
    assert "email_lower" in result.output
    assert "generated/computed" in result.output
    assert "ALICE@corp.example" not in result.output


def test_unselected_ordinary_column_does_not_fire_update_of_trigger(tmp_path):
    path = tmp_path / "trigger.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, status TEXT);"
            "INSERT INTO users VALUES (1, 'alice@corp.example', 'active');"
            "CREATE TABLE status_updates (id INTEGER);"
            "CREATE TRIGGER log_status_update AFTER UPDATE OF status ON users "
            "BEGIN INSERT INTO status_updates VALUES (NEW.id); END;"
        )
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        result = _masker().mask_table(connector, "main", "users", [_decision()])
    assert result.rows_written == 1
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM status_updates").fetchone()[0] == 0
        assert conn.execute("SELECT status FROM users").fetchone()[0] == "active"


def test_direct_update_rows_refuses_generated_field_before_any_update(tmp_path):
    path = tmp_path / "direct.db"
    _make(path)
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        statements = _updates(connector)
        with pytest.raises(ValueError, match="not writable.*email_lower"):
            connector.update_rows("main", "users", ["id"], [
                {"id": 1, "email": "masked1@example.invalid"},
                {"id": 2, "email_lower": "masked2@example.invalid"},
            ])
        assert not statements


@pytest.mark.parametrize("bad_row", [
    {"id": 2, "unknown_column": "private-data"},
    {"email": "private-data"},
])
def test_direct_update_rows_checks_all_payloads_before_writing(tmp_path, bad_row):
    path = tmp_path / "invalid.db"
    _make(path)
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        statements = _updates(connector)
        with pytest.raises(ValueError) as error:
            connector.update_rows("main", "users", ["id"], [
                {"id": 1, "email": "masked1@example.invalid"}, bad_row,
            ])
        assert "private-data" not in str(error.value)
        assert not statements


def test_direct_update_rows_rejects_unknown_key_columns(tmp_path):
    path = tmp_path / "unknown-key.db"
    _make(path)
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        statements = _updates(connector)
        with pytest.raises(ValueError, match="unknown key columns"):
            connector.update_rows("main", "users", ["other_id"], [
                {"other_id": 1, "email": "masked@example.invalid"},
            ])
        assert not statements


@pytest.mark.parametrize("metadata, reason", [
    ({"computed": {"sqltext": "lower(email)"}}, "generated/computed"),
    ({"identity": {"always": True}}, "identity-managed"),
    ({"identity": {"always": False}}, "identity-managed"),
    ({"read_only": True}, "read-only"),
    ({"readonly": True}, "read-only"),
])
def test_reflected_unsupported_column_metadata_is_detected(tmp_path, monkeypatch, metadata, reason):
    path = tmp_path / "metadata.db"
    _make(path)
    inspector = SimpleNamespace(get_columns=lambda *args, **kwargs: [
        {"name": "secret", **metadata}, {"name": "ordinary", "default": "42"},
    ])
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        monkeypatch.setattr("dbmask.connectors.sql.inspect", lambda engine: inspector)
        blocked = connector.non_writable_columns("main", "users")
    assert reason in blocked["secret"]
    assert "ordinary" not in blocked


def test_readonly_primary_key_selection_is_rejected_before_pk_skip(tmp_path, monkeypatch):
    path = tmp_path / "identity.db"
    _make(path)
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        monkeypatch.setattr(connector, "non_writable_columns", lambda *args: {
            "id": "identity-managed column (masking is not supported)",
        })
        with pytest.raises(MaskingValidationError, match="identity-managed"):
            _masker().mask_table(connector, "main", "users", [_decision("id")])


def test_custom_connector_can_keep_default_writability_hook(tmp_path):
    class LegacyConnector(SQLConnector):
        non_writable_columns = Connector.non_writable_columns

    path = tmp_path / "legacy.db"
    _make(path)
    with LegacyConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        # Even without a metadata hook, the unselected generated field is not
        # part of the UPDATE payload, so ordinary masking still works.
        result = _masker().mask_table(connector, "main", "users", [_decision()])
    assert result.rows_written == 2


def test_generator_of_decisions_is_not_consumed_by_preflight(tmp_path):
    path = tmp_path / "generator.db"
    _make(path)
    with SQLConnector(DatabaseConfig(url=f"sqlite:///{path}")) as connector:
        result = _masker().mask_table(
            connector, "main", "users", (d for d in [_decision()]),
        )
    assert result.rows_written == 2
