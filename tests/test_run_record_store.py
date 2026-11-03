"""The run store must fail closed around immutable plans and interrupted writes."""
from __future__ import annotations

import json
from dataclasses import asdict

import pytest

from dbmask.config import Config, DatabaseConfig
from dbmask.run_record import RunRecord, config_fingerprint, target_identity


def _config(tmp_path):
    config = Config(database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}"))
    config.masking.seed_map.enabled = False
    return config


def _record(tmp_path, name="run.json", *, sensitivity="sensitive", errors=0, source="pattern"):
    config = _config(tmp_path)
    return RunRecord.create(
        tmp_path / name, target=target_identity(config.database), source=None,
        config_digest=config_fingerprint(config),
        scope=[{"schema": "main", "table": "people", "columns": ["id", "email"]}],
        decisions=[{"schema": "main", "table": "people", "column": "email",
                    "sensitivity": sensitivity, "source": source, "strategy": "fake_email"},
                   {"schema": "main", "table": "people", "column": "id",
                    "sensitivity": "not_sensitive", "source": "override"}],
        scan_error_count=errors, validation=asdict(config.validation),
    )


def test_approval_is_bound_to_the_unchanged_plan(tmp_path):
    record = _record(tmp_path)
    with pytest.raises(ValueError, match="Approve"):
        record.require_approved()
    record.approve(" Reviewer ")
    loaded = RunRecord.load(record.path)
    loaded.require_approved()
    assert loaded.data["approval"]["reviewed_by"] == "Reviewer"
    loaded.data["plan"]["decisions"][0]["strategy"] = "blank"
    with pytest.raises(ValueError, match="changed"):
        loaded.save()
    assert RunRecord.load(record.path).data["plan"]["decisions"][0]["strategy"] == "fake_email"


@pytest.mark.parametrize("options", [{"sensitivity": "unknown"}, {"errors": 1}, {"source": "history_pending"}])
def test_incomplete_or_unresolved_plans_cannot_be_approved(tmp_path, options):
    record = _record(tmp_path, **options)
    with pytest.raises(ValueError, match="Cannot approve"):
        record.approve("reviewer")
    assert RunRecord.load(record.path).data["approval"]["status"] == "draft"


def test_create_never_overwrites_an_existing_run(tmp_path):
    record = _record(tmp_path)
    before = record.path.read_bytes()
    with pytest.raises(FileExistsError):
        _record(tmp_path)
    assert record.path.read_bytes() == before


def test_invalid_json_and_nonfinite_values_are_rejected(tmp_path):
    record = _record(tmp_path)
    content = record.path.read_text()
    record.path.write_text(content.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
    with pytest.raises(ValueError, match="Duplicate"):
        RunRecord.load(record.path)
    record.path.write_text(content)
    record.data["execution"]["invalid"] = float("nan")
    with pytest.raises(ValueError):
        record.save()
    assert "invalid" not in RunRecord.load(record.path).data["execution"]


def test_guard_blocks_another_run_after_committed_write(tmp_path):
    first = _record(tmp_path, "first.json")
    first.data["execution"] = {"status": "failed", "tables": [
        {"rows_written": 1000, "committed_batches": 1, "in_flight": False},
    ]}
    first.save()
    second = _record(tmp_path, "second.json")
    with pytest.raises(ValueError, match="already affected"):
        with second.apply_guard(tmp_path):
            pytest.fail("repeat masking was allowed")
    with second.apply_guard(tmp_path, "Target restored from untouched backup"):
        pass
    assert second.data["repeat_overrides"][0]["reason"].startswith("Target restored")


def test_guard_blocks_uncertain_batch_and_its_own_applied_run(tmp_path):
    record = _record(tmp_path)
    record.data["execution"] = {"status": "failed", "tables": [
        {"rows_written": 0, "committed_batches": 0, "in_flight": True},
    ]}
    record.save()
    with pytest.raises(ValueError, match="already affected"):
        with record.apply_guard(tmp_path):
            pass
    record.data["execution"] = {"status": "applied", "tables": []}
    record.save()
    with pytest.raises(ValueError, match="already affected"):
        with record.apply_guard(tmp_path):
            pass


def test_guard_allows_failed_run_with_no_writes_and_releases_only_own_lock(tmp_path):
    record = _record(tmp_path)
    record.data["execution"] = {"status": "failed", "tables": [
        {"rows_written": 0, "committed_batches": 0, "in_flight": False},
    ]}
    record.save()
    with record.apply_guard(tmp_path):
        locks = list(tmp_path.glob(".*.lock"))
        assert len(locks) == 1
        with pytest.raises(ValueError, match="lock exists"):
            with record.apply_guard(tmp_path, "override"):
                pass
        assert locks[0].exists()
    assert not list(tmp_path.glob(".*.lock"))


def test_endpoint_identity_excludes_credentials_and_canonicalizes_paths(tmp_path):
    a = target_identity(DatabaseConfig(url="postgresql://user:secret@EXAMPLE.COM/test"))
    b = target_identity(DatabaseConfig(url="postgresql://other:changed@example.com:5432/test?password=hidden"))
    assert a["id"] == b["id"]
    assert "secret" not in json.dumps(a)
    assert "EXAMPLE" not in json.dumps(a)
    plain = target_identity(DatabaseConfig(url=f"sqlite:///{tmp_path / 'target.db'}"))
    alternative = target_identity(DatabaseConfig(url=f"sqlite:///{tmp_path / 'sub' / '..' / 'target.db'}"))
    assert plain["id"] == alternative["id"]
    assert str(tmp_path) not in json.dumps(plain)


def test_config_binding_allows_only_dry_run_changes(tmp_path):
    record = _record(tmp_path)
    config = _config(tmp_path)
    config.masking.dry_run = False
    record.check_config(config)
    config.validation.pk_row_limit = 1
    with pytest.raises(ValueError, match="policy changed"):
        record.check_config(config)
    config = _config(tmp_path)
    config.database.url = f"sqlite:///{tmp_path / 'other.db'}"
    with pytest.raises(ValueError, match="target"):
        record.check_config(config)


def test_guard_rejects_untracked_record_location(tmp_path):
    record = _record(tmp_path)
    with pytest.raises(ValueError, match="audit.directory"):
        with record.apply_guard(tmp_path / "other"):
            pass


def test_approval_requires_every_scoped_column(tmp_path):
    record = _record(tmp_path)
    record.data["plan"]["decisions"].pop()
    # Recompute a valid plan checksum through a newly created record, as an
    # externally supplied partial scan would do; approval must still refuse.
    plan = record.data["plan"]
    partial = RunRecord.create(tmp_path / "partial.json", **plan)
    with pytest.raises(ValueError, match="missing or out-of-scope"):
        partial.approve("reviewer")


def test_stale_loaded_object_cannot_erase_a_completed_apply(tmp_path):
    record = _record(tmp_path)
    stale = RunRecord.load(record.path)
    with record.apply_guard(tmp_path):
        record.data["execution"]["status"] = "applied"
        record.save()
    assert stale.data["execution"]["status"] == "planned"
    with pytest.raises(ValueError, match="already affected"):
        with stale.apply_guard(tmp_path):
            pass
    assert stale.data["execution"]["status"] == "applied"


def test_approval_cannot_race_with_apply_or_overwrite_newer_execution(tmp_path):
    record = _record(tmp_path)
    stale = RunRecord.load(record.path)
    with record.operation_lock():
        with pytest.raises(ValueError, match="lock exists"):
            stale.approve("reviewer")
        record.data["execution"]["status"] = "applying"
        record.save()
    with pytest.raises(ValueError, match="after execution"):
        stale.approve("reviewer")
    assert RunRecord.load(record.path).data["execution"]["status"] == "applying"


def test_failed_empty_retry_cannot_erase_prior_applied_history(tmp_path):
    record = _record(tmp_path)
    record.data["execution_history"] = [{"status": "applied", "tables": [
        {"rows_written": 10, "committed_batches": 1, "in_flight": False},
    ]}]
    record.data["execution"] = {"status": "failed", "tables": [
        {"rows_written": 0, "committed_batches": 0, "in_flight": False},
    ]}
    record.save()
    with pytest.raises(ValueError, match="already affected"):
        with record.apply_guard(tmp_path):
            pass


@pytest.mark.parametrize("prior", [
    {"status": "failed", "tables": [{"in_flight": True, "rows_written": 0}]},
    {"status": "failed", "tables": [{"rows_written": 10}]},
    {"status": "applying", "tables": []},
])
def test_uncertain_or_partial_history_survives_a_later_empty_failure(tmp_path, prior):
    record = _record(tmp_path)
    record.data["execution_history"] = [prior]
    record.data["execution"] = {"status": "failed", "tables": []}
    record.save()
    with pytest.raises(ValueError, match="already affected"):
        with record.apply_guard(tmp_path):
            pass
