"""Masking must honor the stricter detection contract and real chosen strategy."""
import sqlite3
from dataclasses import replace
from datetime import date, datetime

import pytest

from dbmask.cli import cli
from dbmask.config import MaskingConfig
from dbmask.detection.patterns import PatternMatcher
from dbmask.detection.result import Decision, Sensitivity
from dbmask.history.files import read_history_file
from dbmask.masking import dictionaries
from dbmask.masking.engine import ColumnPlan, MaskingEngine
from dbmask.masking.rules import MaskContext, MaskingValidationError, get_strategy


@pytest.mark.parametrize('rule,strategy,value', [
    ('phone', 'fake_phone', '202-555-0123'),
    ('phone', 'fake_phone', '+1 (202) 555-0123 ext. 001'),
    ('phone', 'fake_phone', '12025550123'),
    ('phone', 'fake_phone', 2025550123),
    ('ssn', 'fake_ssn', '012-34-5678'),
    ('ssn', 'fake_ssn', '012345678'),
    ('ssn', 'fake_ssn', 123456789),
    ('credit_card', 'fake_credit_card', '4111-1111-1111-1111'),
    ('credit_card', 'fake_credit_card', '5555555555554444'),
    ('credit_card', 'fake_credit_card', '378282246310005'),
    ('credit_card', 'fake_credit_card', '6011111111111117'),
])
def test_strategies_produce_values_accepted_by_detection(rule, strategy, value):
    for seed in map(str, range(25)):
        ctx = MaskContext('x', rule, seed)
        output = get_strategy(strategy)(value, ctx)
        assert output != value
        assert type(output) is type(value)
        assert len(str(output)) == len(str(value))
        assert get_strategy(strategy)(value, ctx) == output
        assert PatternMatcher(min_samples=1).match([str(output)], column=rule).name == rule
        assert ''.join(c for c in str(value) if not c.isdigit()) == ''.join(c for c in str(output) if not c.isdigit())
        if rule == 'credit_card':
            assert str(output).replace('-', '')[0] == str(value).replace('-', '')[0]
        if str(value).startswith('+1'):
            assert str(output).startswith('+1')


@pytest.mark.parametrize('strategy,value', [
    ('fake_phone', '555-0123'), ('fake_ssn', '000-12-3456'),
    ('fake_credit_card', '4111111111111112'), ('fake_date', '2026-02-30'),
])
def test_invalid_remaining_values_raise_without_exposing_input(strategy, value):
    with pytest.raises(MaskingValidationError) as error:
        get_strategy(strategy)(value, MaskContext('x', None, 's'))
    assert value not in str(error.value)


@pytest.mark.parametrize('strategy', ['fake_phone', 'fake_ssn', 'fake_credit_card', 'fake_date'])
def test_new_strict_strategies_preserve_missing_values(strategy):
    engine = MaskingEngine(MaskingConfig(seed_map={'enabled': False}))
    for value in (None, '', ' \t '):
        assert get_strategy(strategy)(value, MaskContext('x', None, 's')) == value
        assert engine.mask_value(value, ColumnPlan('s', 't', 'c', None, strategy)) == value


@pytest.mark.parametrize('value', [date.min, date.max, datetime.min, datetime.max])
def test_typed_date_extremes_stay_typed_and_in_range(value):
    output = get_strategy('fake_date')(value, MaskContext('x', 'date', 's'))
    assert type(output) is type(value)
    assert 30 <= abs((output - value).days) <= 730


@pytest.mark.parametrize('column,expected', [('first_name','fake_first_name'), ('lastName','fake_last_name'), ('full_name','fake_name')])
def test_name_default_and_explicit_strategy_precedence(column, expected):
    d = Decision('a', 'main', 't', column, Sensitivity.SENSITIVE, rule='full_name')
    engine = MaskingEngine(MaskingConfig(seed_map={'enabled': False}))
    assert engine.resolve_strategy(d) == expected
    assert engine.resolve_strategy(replace(d, masking_strategy='blank')) == 'blank'
    configured = MaskingEngine(MaskingConfig(rule_strategies={'full_name': 'redact'}, seed_map={'enabled': False}))
    assert configured.resolve_strategy(d) == 'redact'


def test_dictionary_does_not_pick_unchanged_original(monkeypatch):
    monkeypatch.setattr(dictionaries, '_CUSTOM', {'us_cities': ['Austin', 'Boston']})
    for seed in map(str, range(20)):
        assert get_strategy('fake_city')('Austin', MaskContext('city', 'city', seed)) == 'Boston'
    monkeypatch.setattr(dictionaries, '_CUSTOM', {'us_cities': ['Austin']})
    with pytest.raises(MaskingValidationError):
        get_strategy('fake_city')('Austin', MaskContext('city', 'city', 's'))


@pytest.mark.parametrize('tracked', [False, True])
def test_unchanged_outputs_are_reported_even_without_seed_map(tmp_path, tracked):
    engine = MaskingEngine(MaskingConfig(seed_map={'enabled': tracked, 'url': f'sqlite:///{tmp_path / "seeds.db"}'}))
    try:
        with pytest.raises(MaskingValidationError, match='unchanged'):
            engine.mask_value('AAAA', ColumnPlan('s', 't', 'c', 'unknown', 'shuffle'))
    finally:
        engine.close()


def test_review_export_uses_actual_configured_strategy(cli_env):
    output = cli_env.tmp_path / 'review.csv'
    result = cli_env.runner.invoke(cli, ['scan', '--config', cli_env.make_config(masking={'column_strategies': {'email': 'redact'}}), '--output', str(output)])
    assert result.exit_code == 0, result.output
    assert next(r for r in read_history_file(output) if r.column == 'email').masking_strategy == 'redact'


def test_card_seed_scope_bypasses_older_non_brand_mappings(tmp_path):
    cfg = MaskingConfig(dry_run=False, seed_map={'url': f'sqlite:///{tmp_path / "seeds.db"}'})
    engine = MaskingEngine(cfg)
    try:
        engine.seed_store().record('fake_credit_card', '4111111111111111', '9999999999999999', 'fake_credit_card')
        result = engine.mask_value('4111111111111111', ColumnPlan('s', 't', 'c', 'credit_card', 'fake_credit_card'))
        assert result.startswith('4')
        assert result != '9999999999999999'
        assert engine.mask_value('4111111111111111', ColumnPlan('s', 't', 'c', 'credit_card', 'fake_credit_card')) == result
    finally:
        engine.close()


def test_end_to_end_phone_and_ssn_remain_valid(cli_env):
    with sqlite3.connect(cli_env.db) as conn:
        conn.execute('CREATE TABLE contacts (id INTEGER PRIMARY KEY, phone TEXT, ssn TEXT)')
        conn.execute('INSERT INTO contacts (phone,ssn) VALUES (?,?)', ('+1 (202) 555-0123 x42', '012-34-5678'))
    config = cli_env.make_config()
    result = cli_env.runner.invoke(cli, ['mask', '--config', config, '--apply'])
    assert result.exit_code == 0, result.output
    for column in ['phone','ssn']:
        values = cli_env.read(column, 'contacts')
        assert PatternMatcher(min_samples=1).match(values, column=column).name == column
