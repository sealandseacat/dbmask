"""Shared fixtures for CLI-level regression tests.

They build a small throwaway SQLite database plus a real config YAML on disk,
then drive the actual ``dbmask`` command line through click's ``CliRunner`` —
the same code path a user hits, including config loading.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def make_sample_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            email TEXT,
            city TEXT,
            status_code TEXT
        );
        INSERT INTO customers (full_name, email, city, status_code) VALUES
            ('Mary Johnson', 'mary.johnson@example.com', 'New York', 'A'),
            ('Robert Smith', 'robert.smith@test.org', 'Chicago', 'B'),
            ('Linda Davis', 'linda.davis@mail.net', 'Dallas', 'A');
        """
    )
    conn.commit()
    conn.close()


def read_column(db_path: Path, column: str, table: str = "customers") -> list:
    with closing(sqlite3.connect(db_path)) as conn:
        return [r[0] for r in conn.execute(f"SELECT {column} FROM {table}")]  # noqa: S608


@pytest.fixture()
def cli_env(tmp_path: Path) -> SimpleNamespace:
    """Sample DB + config-file factory + CliRunner, isolated in tmp_path."""
    db_path = tmp_path / "sample.db"
    make_sample_db(db_path)

    base_config = {
        "database": {"url": f"sqlite:///{db_path}", "name": "sample"},
        # These integration fixtures deliberately contain only three distinct values.
        "detection": {"sample_size": 10, "pattern_min_samples": 1, "use_patterns": True, "use_history": True},
        "history": {"enabled": True, "url": f"sqlite:///{tmp_path / 'history.db'}"},
        "llm": {"enabled": False},
        "masking": {
            "seed": "test-seed",
            "seed_map": {"enabled": True, "url": f"sqlite:///{tmp_path / 'seedmap.db'}"},
        },
    }

    def make_config(name: str = "config.yaml", **overrides) -> str:
        merged = _deep_merge(base_config, overrides)
        cfg_path = tmp_path / name
        cfg_path.write_text(yaml.safe_dump(merged), encoding="utf-8")
        return str(cfg_path)

    return SimpleNamespace(
        db=db_path,
        tmp_path=tmp_path,
        runner=CliRunner(),
        make_config=make_config,
        read=lambda column, table="customers": read_column(db_path, column, table),
    )
