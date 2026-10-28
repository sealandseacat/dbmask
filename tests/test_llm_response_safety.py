"""Unparseable, ambiguous and low-confidence model answers never mean safe."""
from __future__ import annotations

import json
import shutil
from collections.abc import Sequence

import pytest
import yaml

from dbmask.cli import cli
from dbmask.config import Config, LLMConfig
from dbmask.detection.pipeline import DetectionPipeline, TokenBudgetExceeded
from dbmask.detection.result import Sensitivity
from dbmask.history.store import HistoryStore
from dbmask.llm.base import LLMProvider, LLMResult


@pytest.mark.parametrize("answer", [
    "", "I cannot determine this.", "not sensitive", "yes", "{}", "[]", "null", '"safe"',
    '{"sensitive": false}',
    '{"sensitive": "false", "rule": null, "confidence": 0.99}',
    '{"sensitive": 0, "rule": null, "confidence": 0.99}',
    '{"sensitive": null, "rule": null, "confidence": 0.99}',
    '{"sensitive": false, "rule": null, "confidence": "0.99"}',
    '{"sensitive": false, "rule": null, "confidence": true}',
    '{"sensitive": false, "rule": null, "confidence": NaN}',
    '{"sensitive": false, "rule": null, "confidence": Infinity}',
    '{"sensitive": false, "rule": null, "confidence": -0.1}',
    '{"sensitive": false, "rule": null, "confidence": 1.1}',
    '{"sensitive": true, "rule": null, "confidence": 0.99}',
    '{"sensitive": true, "rule": "", "confidence": 0.99}',
    '{"sensitive": true, "rule": "full-name", "confidence": 0.99}',
    '{"sensitive": true, "rule": "Email", "confidence": 0.99}',
    '{"sensitive": true, "rule": ["email"], "confidence": 0.99}',
    '{"sensitive": false, "rule": "email", "confidence": 0.99}',
    '{"sensitive": false, "sensitive": true, "rule": "email", "confidence": 0.99}',
    '{"sensitive": false, "rule": null, "confidence": 0.99, "extra": "do not guess"}',
    'Explanation: {"sensitive": false, "rule": null, "confidence": 0.99}',
    '{"sensitive": false, "rule": null, "confidence": 0.99}\n{}',
    '```json\n{"sensitive": false, "rule": null, "confidence": 0.99}\n```\nExplanation',
])
def test_invalid_or_ambiguous_responses_are_explicitly_unknown(answer):
    result = LLMProvider.parse_response(answer)
    assert result.sensitive is None
    assert result.rule is None
    assert result.confidence == 0.0
    assert result.validation_error() is not None


@pytest.mark.parametrize("sensitive, rule", [(True, "email"), (False, None)])
@pytest.mark.parametrize("fenced", [False, True])
def test_single_valid_json_result_is_accepted(sensitive, rule, fenced):
    text = json.dumps({"sensitive": sensitive, "rule": rule, "confidence": 0.95})
    answer = f"```json\n{text}\n```" if fenced else text
    result = LLMProvider.parse_response(answer)
    assert result.sensitive is sensitive
    assert result.rule == rule
    assert result.confidence == 0.95
    assert result.validation_error() is None


@pytest.mark.parametrize("threshold", [0, 0.8, 1])
def test_valid_confidence_threshold_can_be_loaded_from_config(threshold):
    assert Config.from_dict({"llm": {"min_confidence": threshold}}).llm.min_confidence == threshold


@pytest.mark.parametrize("threshold", [True, False, None, "0.8", -0.1, 1.1, float("nan"), float("inf")])
def test_invalid_confidence_threshold_is_rejected(threshold):
    with pytest.raises(ValueError, match="min_confidence"):
        LLMConfig(min_confidence=threshold)


class Connector:
    name = "synthetic"

    def sample_values(self, schema, table, column, limit=100):
        return ["free-text contact details"]


class Provider(LLMProvider):
    def __init__(self, result):
        self.result = result

    def classify(self, column_name: str, sample: Sequence[str]) -> LLMResult:
        return self.result


def _pipeline(result, *, minimum=0.8, history=None):
    config = Config()
    config.detection.use_patterns = False
    config.llm.min_confidence = minimum
    return DetectionPipeline(config, llm=Provider(result), history=history)


@pytest.mark.parametrize("result", [
    LLMResult(None, None, 0.0),
    LLMResult("false", None, 0.99),
    LLMResult(False, None, "0.99"),
    LLMResult(False, None, True),
    LLMResult(False, None, float("nan")),
    LLMResult(False, None, float("inf")),
    LLMResult(False, None, -0.1),
    LLMResult(False, None, 1.1),
    LLMResult(True, None, 0.99),
    LLMResult(False, "email", 0.99),
    LLMResult(True, "private-person@example.test", 0.99),
    LLMResult(False, None, 0.99, token_usage="secret-provider-data"),
    LLMResult(False, None, 0.99, token_usage=-1),
    LLMResult(False, None, 0.99, error="private-person@example.test"),
    None,
    {"sensitive": False, "rule": None, "confidence": 0.99},
])
def test_custom_provider_results_are_revalidated_even_with_zero_threshold(result):
    pipeline = _pipeline(result, minimum=0)
    decision = pipeline.analyze_column(Connector(), "main", "people", "contact")
    assert decision.sensitivity is Sensitivity.UNKNOWN
    assert decision.source == "llm_invalid"
    assert decision.rule is None
    assert "private-person" not in decision.detail
    assert "secret-provider-data" not in decision.detail


@pytest.mark.parametrize("override", [None, "private-person@example.test"])
def test_custom_result_subclass_cannot_override_contract_validation(override):
    class BypassedResult(LLMResult):
        def validation_error(self):
            return override

    result = BypassedResult(False, None, float("nan"))
    decision = _pipeline(result, minimum=0).analyze_column(
        Connector(), "main", "people", "contact"
    )
    assert decision.sensitivity is Sensitivity.UNKNOWN
    assert decision.source == "llm_invalid"
    assert "private-person" not in decision.detail


@pytest.mark.parametrize("sensitive, rule", [(True, "email"), (False, None)])
def test_low_confidence_positive_and_negative_results_need_review(sensitive, rule):
    pipeline = _pipeline(LLMResult(sensitive, rule, 0.79, token_usage=7))
    decision = pipeline.analyze_column(Connector(), "main", "people", "contact")
    assert decision.sensitivity is Sensitivity.UNKNOWN
    assert decision.source == "llm_low_confidence"
    assert decision.rule is None
    assert pipeline.stats.unknown == 1
    assert pipeline.stats.tokens == 7


@pytest.mark.parametrize("sensitive, rule, sensitivity", [
    (True, "email", Sensitivity.SENSITIVE), (False, None, Sensitivity.NOT_SENSITIVE),
])
def test_confident_results_at_threshold_remain_usable(sensitive, rule, sensitivity):
    pipeline = _pipeline(LLMResult(sensitive, rule, 0.8, token_usage=7))
    decision = pipeline.analyze_column(Connector(), "main", "people", "contact")
    assert decision.sensitivity is sensitivity
    assert decision.source == "llm"
    assert decision.rule == rule
    assert pipeline.stats.tokens == 7


def test_zero_threshold_only_opts_out_of_confidence_gate():
    result = LLMProvider.parse_response('{"sensitive": false, "rule": null, "confidence": 0}')
    assert _pipeline(result, minimum=0).analyze_column(
        Connector(), "main", "people", "contact"
    ).sensitivity is Sensitivity.NOT_SENSITIVE
    malformed = LLMProvider.parse_response("I cannot determine this.")
    assert _pipeline(malformed, minimum=0).analyze_column(
        Connector(), "main", "people", "contact"
    ).sensitivity is Sensitivity.UNKNOWN


def test_invalid_response_tokens_count_toward_budget_without_saving_a_decision(tmp_path):
    result = LLMProvider.parse_response("I cannot determine this.")
    result.token_usage = 7
    with HistoryStore(f"sqlite:///{tmp_path / 'history.db'}") as history:
        pipeline = _pipeline(result, history=history)
        pipeline.config.llm.max_tokens_budget = 7
        pipeline.analyze_column(Connector(), "main", "people", "contact")
        assert pipeline.stats.tokens == 7
        assert history.all_decisions() == []
        with pytest.raises(TokenBudgetExceeded):
            pipeline.analyze_column(Connector(), "main", "people", "other")


def _cli_config(cli_env):
    fields = cli_env.tmp_path / "fields.yaml"
    fields.write_text(yaml.safe_dump({"not_sensitive": ["id", "full_name", "city", "status_code"]}))
    source = cli_env.tmp_path / "original.db"
    shutil.copy2(cli_env.db, source)
    return cli_env.make_config(
        detection={"use_patterns": False, "overrides_file": str(fields)},
        source_database={"url": f"sqlite:///{source}"},
        llm={"enabled": True, "provider": "local", "min_confidence": 0.8},
    )


@pytest.mark.parametrize("result", [
    LLMProvider.parse_response("I cannot determine this."),
    LLMProvider.parse_response("{}"),
    LLMResult(False, None, 0.3, raw="private-person@example.test"),
    LLMResult(True, "email", 0.3, raw="private-person@example.test"),
])
def test_cli_unknown_result_is_not_masked_or_persisted_and_cannot_pass_strict(
    cli_env, monkeypatch, result,
):
    config_path = _cli_config(cli_env)
    monkeypatch.setattr("dbmask.runner.create_provider", lambda cfg: Provider(result))
    before = cli_env.read("email")
    scan = cli_env.runner.invoke(cli, ["scan", "--config", config_path, "--json"])
    assert scan.exit_code == 0, scan.output
    decision = next(d for d in json.loads(scan.output) if d["column"] == "email")
    assert decision["sensitivity"] == "unknown"
    assert "private-person" not in scan.output
    applied = cli_env.runner.invoke(cli, ["mask", "--config", config_path, "--apply"])
    assert applied.exit_code == 0, applied.output
    assert "could not be classified" in applied.output
    assert cli_env.read("email") == before
    with HistoryStore(Config.load(config_path).history.url) as history:
        assert not any(d.column == "email" for d in history.all_decisions())
    checked = cli_env.runner.invoke(cli, ["validate", "--config", config_path, "--strict"])
    assert checked.exit_code == 1, checked.output


def test_cli_valid_confident_sensitive_result_still_masks_email(cli_env, monkeypatch):
    config_path = _cli_config(cli_env)
    result = LLMProvider.parse_response('{"sensitive": true, "rule": "email", "confidence": 0.99}')
    monkeypatch.setattr("dbmask.runner.create_provider", lambda cfg: Provider(result))
    before = cli_env.read("email")
    applied = cli_env.runner.invoke(cli, ["mask", "--config", config_path, "--apply"])
    assert applied.exit_code == 0, applied.output
    assert cli_env.read("email") != before
    assert all(v.endswith("@example.invalid") for v in cli_env.read("email"))


def test_cli_valid_confident_negative_result_keeps_email_but_stays_pending(cli_env, monkeypatch):
    config_path = _cli_config(cli_env)
    result = LLMProvider.parse_response('{"sensitive": false, "rule": null, "confidence": 0.99}')
    monkeypatch.setattr("dbmask.runner.create_provider", lambda cfg: Provider(result))
    before = cli_env.read("email")
    scan = cli_env.runner.invoke(cli, ["scan", "--config", config_path, "--json"])
    assert scan.exit_code == 0, scan.output
    decision = next(d for d in json.loads(scan.output) if d["column"] == "email")
    assert decision["sensitivity"] == "not_sensitive"
    applied = cli_env.runner.invoke(cli, ["mask", "--config", config_path, "--apply"])
    assert applied.exit_code == 0, applied.output
    assert cli_env.read("email") == before
    with HistoryStore(Config.load(config_path).history.url) as history:
        record = next(r for r in history.records_for_review() if r.column == "email")
        assert record.review_status == "pending"


def test_provider_exception_remains_scan_error_without_leaking_its_payload(cli_env, monkeypatch):
    config_path = _cli_config(cli_env)
    secret = "private-person@example.test api_key=secret-key"

    class FailingProvider(LLMProvider):
        def classify(self, column_name, sample):
            raise RuntimeError(secret)

    monkeypatch.setattr("dbmask.runner.create_provider", lambda cfg: FailingProvider())
    before = cli_env.read("email")
    scan = cli_env.runner.invoke(cli, ["scan", "--config", config_path])
    assert scan.exit_code == 3, scan.output
    assert "LLM provider failed" in scan.output
    assert "private-person" not in scan.output and "secret-key" not in scan.output
    masked = cli_env.runner.invoke(cli, ["mask", "--config", config_path, "--apply"])
    assert masked.exit_code == 2, masked.output
    assert "private-person" not in masked.output and "secret-key" not in masked.output
    assert cli_env.read("email") == before
