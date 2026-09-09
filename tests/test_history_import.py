"""Reviewed history: file interchange, atomic imports and real scan/mask behavior."""
from __future__ import annotations

import csv
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from dbmask.cli import cli
from dbmask.config import Config
from dbmask.detection.result import Decision, Sensitivity
from dbmask.history.files import read_history_file, write_history_file
from dbmask.history.records import (
    HISTORY_FIELDS,
    HistoryConflictError,
    HistoryRecord,
    HistoryValidationError,
)
from dbmask.history.store import HistoryStore, decisions_table
from dbmask.masking.engine import MaskingEngine
from dbmask.masking.rules import STRATEGIES
from dbmask.runner import Runner


def approved(**changes):
    base = HistoryRecord(
        "sample", "main", "customers", "email", decision="mask", detected_type="email",
        masking_strategy="blank", review_status="approved", user_id="00123",
        reviewed_by="reviewer-02", reviewed_at="2026-09-09T10:00:00Z",
        reason="Approved blank replacement", analysis_date="2026-09-08",
        data_type="TEXT",
    )
    return replace(base, **changes)


@pytest.fixture()
def store(tmp_path):
    with HistoryStore(f"sqlite:///{tmp_path / 'history.db'}") as value:
        yield value


@pytest.mark.parametrize("suffix", ["csv", "xlsx", "md"])
def test_file_round_trip_with_analyst_and_reviewer(tmp_path, suffix):
    path = tmp_path / f"history.{suffix}"
    records = [approved(), approved(column="status_code", decision="keep", masking_strategy="")]
    write_history_file(path, records)
    assert read_history_file(path) == records


def test_approved_history_is_exact_and_case_preserving(store):
    original = approved()
    store.import_records([original])
    d = store.get("sample", "main", "customers", "email", current_type="text")
    assert d.source == "history"
    assert d.masking_strategy == "blank"
    assert d.user_id == "00123"
    assert d.reviewed_by == "reviewer-02"
    assert d.decided_at == datetime(2026, 9, 8, tzinfo=timezone.utc)
    for field in ("database", "schema", "table", "column"):
        other = replace(original, **{field: getattr(original, field) + "2"})
        assert store.get(other.database, other.schema, other.table, other.column, current_type="TEXT") is None
    assert store.get("Sample", "main", "customers", "email", current_type="TEXT") is None
    assert replace(original, database="a.b", schema="c").key != replace(original, database="a", schema="b.c").key


@pytest.mark.parametrize("status", ["pending", "superseded"])
def test_unapproved_import_blocks_automatic_fallback(cli_env, status):
    cfg = Config.load(cli_env.make_config())
    with HistoryStore(cfg.history.url) as history:
        history.import_records([approved(review_status=status)])
    with Runner(cfg) as runner:
        report = runner.scan()
    d = next(d for d in report.decisions if d.column == "email")
    assert d.sensitivity is Sensitivity.UNKNOWN
    assert d.source == "history_pending"
    assert d.masking_strategy is None


@pytest.mark.parametrize("changes, reason", [
    ({"expires_at": "2000-01-01"}, "expired"),
    ({"masking_strategy": "invented_function()"}, "Unknown"),
    ({"masking_strategy": ""}, "missing"),
    ({"data_type": ""}, "data_type"),
])
def test_unusable_approved_import_becomes_pending(store, changes, reason):
    result = store.import_records([approved(**changes)])
    assert result["pending"] == 1
    assert result["warnings"]
    record = store.records_for_review()[0]
    assert record.review_status == "pending"
    assert reason in record.reason


@pytest.mark.parametrize("current_type", ["INTEGER", None])
def test_type_drift_creates_pending_revision(store, current_type):
    store.import_records([approved()])
    decision = store.get("sample", "main", "customers", "email", current_type=current_type)
    assert decision.sensitivity is Sensitivity.UNKNOWN
    assert decision.review_status == "pending"
    records = store.audit_records()
    assert len(records) == 2
    assert records[0]["record"]["review_status"] == "approved"
    assert records[1]["record"]["review_status"] == "pending"
    assert store.records_for_review()[0].revision == 2


def test_strategy_disappearing_after_import_is_pending(store, monkeypatch):
    store.import_records([approved()])
    monkeypatch.delitem(STRATEGIES, "blank")
    assert store.get("sample", "main", "customers", "email", current_type="TEXT").review_status == "pending"


def test_expiration_boundary_and_timezone():
    record = approved(expires_at="2026-09-09T12:00:00+02:00")
    assert record.validated(datetime(2026, 9, 9, 9, 59, tzinfo=timezone.utc)).review_status == "approved"
    assert record.validated(datetime(2026, 9, 9, 10, 0, tzinfo=timezone.utc)).review_status == "pending"


@pytest.mark.parametrize("changes", [
    {"database": ""}, {"table": ""}, {"column": ""}, {"user_id": ""},
    {"analysis_date": ""}, {"analysis_date": "09/08/2026"},
    {"reviewed_at": "not-a-date"}, {"expires_at": "tomorrow"},
    {"decision": "maybe"}, {"review_status": "yes"},
    {"reviewed_by": ""}, {"reviewed_at": ""}, {"decision": "review"},
    {"decision": "keep"}, {"revision": -1},
])
def test_invalid_rows_reject_entire_batch(store, changes):
    with pytest.raises(HistoryValidationError):
        store.import_records([approved(column="city"), approved(**changes)])
    assert store.records_for_review() == []


@pytest.mark.parametrize("reverse", [False, True])
def test_conflicting_file_rows_reject_in_either_order(store, reverse):
    rows = [approved(), approved(decision="keep", masking_strategy="")]
    with pytest.raises(HistoryConflictError):
        store.import_records(list(reversed(rows)) if reverse else rows)
    assert store.records_for_review() == []


def test_duplicate_import_and_dry_run(store):
    rows = [approved(), approved()]
    assert store.import_records(rows, dry_run=True)["inserted"] == 1
    assert store.records_for_review() == []
    assert store.audit_records() == []
    assert store.import_records(rows)["inserted"] == 1
    assert store.import_records(rows)["unchanged"] == 1
    assert len(store.audit_records()) == 1


def test_existing_conflict_rolls_back_earlier_rows(store):
    store.import_records([approved()])
    changed = approved(decision="keep", masking_strategy="", revision=1)
    with pytest.raises(HistoryConflictError, match="replace-approved"):
        store.import_records([approved(column="city"), changed])
    assert len(store.records_for_review()) == 1
    assert len(store.audit_records()) == 1
    result = store.import_records([changed], replace_approved=True)
    assert result["updated"] == 1
    assert store.get("sample", "main", "customers", "email", current_type="TEXT").sensitivity is Sensitivity.NOT_SENSITIVE
    assert store.audit_records()[0]["record"]["decision"] == "mask"
    assert store.audit_records()[1]["record"]["decision"] == "keep"


def test_stale_reviewer_file_cannot_overwrite(store):
    store.import_records([approved()])
    with pytest.raises(HistoryConflictError, match="Stale revision"):
        store.import_records([approved(masking_strategy="redact")], replace_approved=True)
    assert store.records_for_review()[0].masking_strategy == "blank"


def test_pending_can_be_reviewed_and_promoted(store):
    store.import_records([approved(review_status="pending")])
    row = store.records_for_review()[0]
    store.import_records([replace(row, review_status="approved")])
    assert store.get("sample", "main", "customers", "email", current_type="TEXT").source == "history"


def test_machine_suggestions_do_not_overwrite_approval(store):
    store.import_records([approved()])
    suggestion = Decision("sample", "main", "customers", "email", Sensitivity.SENSITIVE,
                          rule="phone", source="llm", user_id="analyst-2", data_type="TEXT")
    store.save(suggestion)
    store.save(replace(suggestion, sensitivity=Sensitivity.UNKNOWN))
    assert store.records_for_review()[0].user_id == "00123"
    assert store.get("sample", "main", "customers", "email", current_type="TEXT").rule == "email"


def test_legacy_history_is_preserved_but_never_reused(store):
    with store.engine.begin() as conn:
        conn.execute(decisions_table.insert().values(
            col_key="sample.main.customers.email", database="sample", schema="main",
            table="customers", column="email", sensitivity="sensitive", rule="phone",
            source="pattern", detail="Old result", decided_at=datetime(2026, 9, 1),
        ))
    assert store.get("sample", "main", "customers", "email", current_type="TEXT") is None
    row = store.records_for_review()[0]
    assert row.review_status == "pending"
    assert row.user_id == ""  # No invented analyst or reviewer identity.
    assert "Legacy" in row.reason
    assert row.analysis_date.startswith("2026-09-01")


@pytest.mark.parametrize("suffix", ["csv", "xlsx", "md"])
def test_cli_import_scan_export_and_mask_blank(cli_env, suffix):
    config = cli_env.make_config(masking={"column_strategies": {"email": "fake_email"}})
    file = cli_env.tmp_path / f"import.{suffix}"
    write_history_file(file, [approved()])
    args = ["history-import", "--config", config, "--file", str(file)]
    dry = cli_env.runner.invoke(cli, [*args, "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert json.loads(dry.output)["dry_run"] is True
    imported = cli_env.runner.invoke(cli, args)
    assert imported.exit_code == 0, imported.output
    out = cli_env.tmp_path / f"export.{suffix}"
    scanned = cli_env.runner.invoke(cli, ["scan", "--config", config, "--output", str(out)])
    assert scanned.exit_code == 0, scanned.output
    record = next(r for r in read_history_file(out) if r.column == "email")
    assert record.review_status == "approved"
    assert record.revision == 1
    masked = cli_env.runner.invoke(cli, ["mask", "--config", config, "--apply"])
    assert masked.exit_code == 0, masked.output
    assert cli_env.read("email") == ["", "", ""]


def test_notes_all_null_history_reused_without_sampling(cli_env, monkeypatch):
    with sqlite3.connect(cli_env.db) as conn:
        conn.execute("CREATE TABLE notes_table (id INTEGER PRIMARY KEY, notes TEXT)")
        conn.execute("INSERT INTO notes_table (notes) VALUES (NULL)")
    cfg = Config.load(cli_env.make_config())
    with HistoryStore(cfg.history.url) as hist:
        hist.import_records([approved(table="notes_table", column="notes", detected_type="free_text")])
    with Runner(cfg) as runner:
        monkeypatch.setattr(runner.connector, "sample_values", lambda *args: pytest.fail("History should not sample"))
        d = runner.pipeline.analyze_column(runner.connector, "main", "notes_table", "notes")
    assert d.source == "history"
    assert d.masking_strategy == "blank"


def test_analysis_id_saved_and_pending_rescanned(cli_env):
    cfg = Config.load(cli_env.make_config(detection={"user_id": "007"}))
    with Runner(cfg) as runner:
        first = runner.scan()
        assert all(d.user_id == "007" for d in first.decisions)
    with Runner(cfg) as runner:
        second = runner.scan()
    assert all(d.source != "history" for d in second.decisions)
    with HistoryStore(cfg.history.url) as hist:
        rows = hist.records_for_review()
    assert all(r.user_id == "007" and r.review_status == "pending" for r in rows)


def test_history_json_audit_export_and_errors(cli_env):
    config = cli_env.make_config()
    with HistoryStore(Config.load(config).history.url) as hist:
        hist.import_records([approved()])
    for flags in (["--json"], ["--audit"], []):
        result = cli_env.runner.invoke(cli, ["history", "--config", config, *flags])
        assert result.exit_code == 0, result.output
        assert "00123" in result.output
    out = cli_env.tmp_path / "review.xlsx"
    args = ["history-export", "--config", config, "--output", str(out)]
    assert cli_env.runner.invoke(cli, args).exit_code == 0
    assert read_history_file(out)[0].revision == 1
    assert cli_env.runner.invoke(cli, args).exit_code != 0  # Do not overwrite review work.
    bad = cli_env.tmp_path / "bad.csv"
    bad.write_text("bad_header\nabc\n")
    result = cli_env.runner.invoke(cli, ["history-import", "--config", config, "--file", str(bad)])
    assert result.exit_code != 0
    assert "Invalid headers" in result.output
    disabled = cli_env.make_config(history={"enabled": False})
    for command, args in [("history-import", ["--file", str(out)]), ("history-export", ["--output", str(out)])]:
        assert cli_env.runner.invoke(cli, [command, "--config", disabled, *args]).exit_code != 0


def test_excel_text_ids_dates_formulas_and_sheet(tmp_path):
    import openpyxl

    path = tmp_path / "data.xlsx"
    write_history_file(path, [approved(reason="=this is literal text")])
    assert read_history_file(path)[0].reason.startswith("=")
    with pytest.raises(HistoryValidationError, match="worksheet"):
        read_history_file(path, sheet="missing")
    book = openpyxl.load_workbook(path)
    book.active["M2"] = datetime(2026, 9, 8)
    book.save(path)
    assert read_history_file(path)[0].analysis_date == "2026-09-08T00:00:00"
    book.active["I2"] = 123
    book.save(path)
    with pytest.raises(HistoryValidationError, match="must be text"):
        read_history_file(path)
    book.active["I2"] = "00123"
    book.active["L2"] = "=1+1"
    book.save(path)
    book.close()
    with pytest.raises(HistoryValidationError, match="formulas"):
        read_history_file(path)


@pytest.mark.parametrize("content", ["", "a,b\n1,2", "| a |\n", "| a |\n| bad |", "text\ntext"])
def test_bad_markdown_and_csv(tmp_path, content):
    for suffix in ("csv", "md"):
        path = tmp_path / f"bad.{suffix}"
        path.write_text(content)
        with pytest.raises(HistoryValidationError):
            read_history_file(path)


def test_header_row_width_and_revision_errors(tmp_path):
    path = tmp_path / "bad.csv"
    def write(headers, row):
        with path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            writer.writerow(row)
    for headers in ([*HISTORY_FIELDS, "decision"], [*HISTORY_FIELDS, "surprise"], ["", *HISTORY_FIELDS]):
        write(headers, [])
        with pytest.raises(HistoryValidationError):
            read_history_file(path)
    write(HISTORY_FIELDS, ["too-short"])
    with pytest.raises(HistoryValidationError, match="number of cells"):
        read_history_file(path)
    write(HISTORY_FIELDS, [*approved().to_dict().values(), "extra"])
    with pytest.raises(HistoryValidationError):
        read_history_file(path)
    row = list(approved().to_dict().values())
    row[-1] = "1.5"
    write(HISTORY_FIELDS, row)
    with pytest.raises(HistoryValidationError, match="revision"):
        read_history_file(path)


def test_unsupported_formats_and_formula_csv(tmp_path):
    for operation in (read_history_file, lambda p: write_history_file(p, [])):
        with pytest.raises(HistoryValidationError, match="formats"):
            operation(tmp_path / "history.xls")
    with pytest.raises(HistoryValidationError, match="Formula-looking"):
        write_history_file(tmp_path / "bad.csv", [approved(reason="=1+1")])


def test_explicit_method_never_falls_back():
    cfg = Config()
    decision = approved().as_decision()
    cfg.masking.column_strategies = {"email": "fake_email"}
    assert MaskingEngine(cfg.masking).resolve_strategy(decision) == "blank"
    decision.masking_strategy = "missing"
    with pytest.raises(KeyError):
        MaskingEngine(cfg.masking).resolve_strategy(decision)


def test_closed_store_error():
    with pytest.raises(RuntimeError, match="connect"):
        HistoryStore().records_for_review()


def test_notes_blank_and_keep_are_applied_with_exact_scope(cli_env):
    with sqlite3.connect(cli_env.db) as conn:
        conn.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, notes TEXT, code TEXT)")
        conn.execute("INSERT INTO contacts VALUES (1, 'Contact alice@example.org', 'UNCHANGED')")
    cfg = Config.load(cli_env.make_config(masking={"dry_run": False}))
    with HistoryStore(cfg.history.url) as hist:
        hist.import_records([
            approved(table="contacts", column="notes", detected_type="free_text"),
            approved(table="contacts", column="code", decision="keep", masking_strategy="", detected_type=""),
        ])
    with Runner(cfg) as runner:
        runner.mask()
    assert cli_env.read("notes", "contacts") == [""]
    assert cli_env.read("code", "contacts") == ["UNCHANGED"]


def test_pending_import_is_not_masked(cli_env):
    cfg = Config.load(cli_env.make_config(masking={"dry_run": False}))
    before = cli_env.read("email")
    with HistoryStore(cfg.history.url) as hist:
        hist.import_records([approved(review_status="pending")])
    with Runner(cfg) as runner:
        runner.mask()
    assert cli_env.read("email") == before


def test_fresh_manual_override_wins_over_import(cli_env):
    file = cli_env.tmp_path / "overrides.yaml"
    file.write_text("not_sensitive:\n  - main.customers.email\n")
    cfg = Config.load(cli_env.make_config(detection={"overrides_file": str(file)}))
    with HistoryStore(cfg.history.url) as hist:
        hist.import_records([approved()])
    with Runner(cfg) as runner:
        report = runner.scan()
    d = next(d for d in report.decisions if d.column == "email")
    assert d.source == "override"
    assert not d.is_sensitive
    with HistoryStore(cfg.history.url) as hist:
        assert next(r for r in hist.records_for_review() if r.column == "email").review_status == "approved"


def test_runtime_expiration_retains_audit(store, monkeypatch):

    store.import_records([approved(expires_at="2090-01-01")])
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2090, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr("dbmask.history.records.datetime", Clock)
    d = store.get("sample", "main", "customers", "email", current_type="TEXT")
    assert d.review_status == "pending"
    assert "expired" in d.detail
    assert len(store.audit_records()) == 2


def test_no_excel_extra_has_actionable_error(tmp_path, monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "openpyxl", None)
    with pytest.raises(HistoryValidationError, match=r"dbmask\[excel\]"):
        read_history_file(tmp_path / "history.xlsx")


def test_blank_lines_bom_crlf_and_markdown_escaped_pipe(tmp_path):
    path = tmp_path / "history.csv"
    write_history_file(path, [approved()])
    with path.open("a") as file:
        file.write("\r\n")
    assert read_history_file(path) == [approved()]
    md = tmp_path / "history.md"
    row = approved(reason="Context | decision\nSecond line")
    write_history_file(md, [row])
    assert read_history_file(md) == [row]
    with pytest.raises(HistoryValidationError, match="round-trip"):
        write_history_file(tmp_path / "backslash.md", [approved(reason="a\\b")])


def test_csv_syntax_error_is_friendly(tmp_path):
    file = tmp_path / "broken.csv"
    file.write_text('"unterminated')
    with pytest.raises(HistoryValidationError, match="Invalid CSV"):
        read_history_file(file)
