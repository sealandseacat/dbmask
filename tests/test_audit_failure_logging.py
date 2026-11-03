"""Failure-audit diagnostics must be useful without exposing chained values."""
from __future__ import annotations

import logging

import pytest
from sqlalchemy.exc import StatementError

from dbmask.config import Config
from dbmask.connectors.sql import SQLConnector
from dbmask.detection.result import Decision, Sensitivity
from dbmask.run_record import RunRecord
from dbmask.runner import Runner


@pytest.mark.parametrize("error_kind", ["runtime", "statement"])
def test_failed_status_save_logs_safe_warning_and_preserves_original_error(
    cli_env, monkeypatch, caplog, error_kind,
):
    source_value = "synthetic-sensitive-person@example.test"
    secondary_detail = "synthetic-sensitive-path"
    if error_kind == "statement":
        original_error = StatementError(
            "synthetic driver failure",
            "UPDATE customers SET email = :email",
            {"email": source_value},
            RuntimeError("synthetic driver detail"),
        )
    else:
        original_error = RuntimeError("masking failed for " + source_value)
    assert source_value in str(original_error)

    config = Config.load(cli_env.make_config(
        history={"enabled": False},
        masking={"dry_run": False, "seed_map": {"enabled": False}},
        audit={"directory": str(cli_env.tmp_path / "runs")},
    ))
    decisions = [Decision(
        database="sample", schema="main", table="customers", column="email",
        sensitivity=Sensitivity.SENSITIVE, rule="email", source="override",
    )]

    def fail_update(*args, **kwargs):
        raise original_error

    save = RunRecord.save

    def fail_status_save(self):
        if self.data["execution"]["status"] == "failed":
            raise OSError(secondary_detail)
        return save(self)

    monkeypatch.setattr(SQLConnector, "update_rows", fail_update)
    monkeypatch.setattr(RunRecord, "save", fail_status_save)
    with caplog.at_level(logging.WARNING, logger="dbmask.runner"):
        with Runner(config) as runner, pytest.raises(type(original_error)) as raised:
            runner.mask(decisions)
    assert raised.value is original_error
    assert runner.last_run_file is not None

    warnings = [record for record in caplog.records if record.name == "dbmask.runner"]
    assert len(warnings) == 1
    assert warnings[0].levelno == logging.WARNING
    assert warnings[0].getMessage() == (
        "Could not save failed execution status (OSError); "
        "preserving the original error and last saved checkpoint."
    )
    assert warnings[0].exc_info is None
    assert warnings[0].stack_info is None
    assert source_value not in caplog.text
    assert secondary_detail not in caplog.text
    assert "UPDATE customers" not in caplog.text

    # The failed diagnostic save must leave its earlier uncertainty marker
    # intact, and the original update failure must not permit a blind retry.
    saved = RunRecord.load(runner.last_run_file)
    assert saved.data["execution"]["status"] == "applying"
    assert saved.data["execution"]["tables"][0]["in_flight"] is True
    assert saved.data["execution"]["tables"][0]["rows_written"] == 0
    assert "mary.johnson@example.com" in cli_env.read("email")
    with Runner(config) as retry, pytest.raises(ValueError, match="already affected"):
        retry.mask(decisions)
