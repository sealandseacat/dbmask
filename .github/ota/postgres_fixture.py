"""Create a disposable PostgreSQL source/target pair for Ota pressure testing."""

from __future__ import annotations

import os
import sys

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

DDL = """
DROP TABLE IF EXISTS customers;
CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    account_status TEXT NOT NULL
);
INSERT INTO customers (id, full_name, email, account_status) VALUES
    (1, 'Avery Stone', 'avery.stone@example.test', 'active'),
    (2, 'Jordan Reed', 'jordan.reed@example.test', 'active'),
    (3, 'Morgan Vale', 'morgan.vale@example.test', 'inactive');
"""

EXPECTED_ROWS = [
    {
        "id": 1,
        "full_name": "Avery Stone",
        "email": "avery.stone@example.test",
        "account_status": "active",
    },
    {
        "id": 2,
        "full_name": "Jordan Reed",
        "email": "jordan.reed@example.test",
        "account_status": "active",
    },
    {
        "id": 3,
        "full_name": "Morgan Vale",
        "email": "morgan.vale@example.test",
        "account_status": "inactive",
    },
]


def require_disposable_database(url: str, expected_database: str) -> URL:
    parsed = make_url(url)
    if parsed.drivername != "postgresql+psycopg2":
        raise ValueError("the PostgreSQL pressure fixture requires postgresql+psycopg2")
    if parsed.host != "localhost" or parsed.port != 5432:
        raise ValueError("the PostgreSQL pressure fixture requires localhost:5432")
    if parsed.username != "dbmask" or parsed.password != "dbmask-pressure-only":
        raise ValueError("the PostgreSQL pressure fixture requires its synthetic service account")
    if parsed.database != expected_database:
        raise ValueError(f"expected disposable database {expected_database!r}")
    if parsed.query:
        raise ValueError("the PostgreSQL pressure fixture does not accept URL query parameters")
    return parsed


def recreate_database(url: URL, database: str) -> None:
    admin_url = url.set(database="postgres")
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
        connection.execute(text(f'CREATE DATABASE "{database}"'))


def seed(url: URL) -> None:
    engine = create_engine(url)
    with engine.begin() as connection:
        for statement in DDL.split(";"):
            if statement.strip():
                connection.execute(text(statement))


def rows(url: URL) -> list[dict[str, object]]:
    engine = create_engine(url)
    with engine.connect() as connection:
        result = connection.execute(
            text(
                "SELECT id, full_name, email, account_status "
                "FROM customers ORDER BY id"
            )
        )
        return [dict(row) for row in result.mappings()]


def assert_dry_run(source: URL, target: URL) -> None:
    if rows(source) != EXPECTED_ROWS or rows(target) != EXPECTED_ROWS:
        raise AssertionError("the dry-run postcondition changed a synthetic database")


def assert_apply(source: URL, target: URL) -> None:
    if rows(source) != EXPECTED_ROWS:
        raise AssertionError("apply changed the synthetic source database")

    target_rows = rows(target)
    if len(target_rows) != len(EXPECTED_ROWS):
        raise AssertionError("apply changed the synthetic target row count")
    for expected, observed in zip(EXPECTED_ROWS, target_rows, strict=True):
        if observed["id"] != expected["id"]:
            raise AssertionError("apply changed a synthetic target primary key")
        if observed["account_status"] != expected["account_status"]:
            raise AssertionError("apply changed a synthetic non-sensitive field")
        for column in ("full_name", "email"):
            if observed[column] == expected[column]:
                raise AssertionError(f"apply left {column} unchanged for id={expected['id']}")


def restore_sensitive_negative_control(target: URL) -> None:
    engine = create_engine(target)
    with engine.begin() as connection:
        result = connection.execute(
            text("UPDATE customers SET full_name = :value WHERE id = :id"),
            {"value": EXPECTED_ROWS[0]["full_name"], "id": EXPECTED_ROWS[0]["id"]},
        )
    if result.rowcount != 1:
        raise AssertionError("negative control did not restore exactly one synthetic value")


def main() -> None:
    if len(sys.argv) > 2:
        raise ValueError("the PostgreSQL pressure fixture accepts at most one command")

    source = require_disposable_database(os.environ["DBMASK_SOURCE_URL"], "dbmask_source")
    target = require_disposable_database(os.environ["DBMASK_TARGET_URL"], "dbmask_target")
    command = sys.argv[1] if len(sys.argv) == 2 else "seed"
    if command == "seed":
        recreate_database(source, "dbmask_source")
        recreate_database(target, "dbmask_target")
        seed(source)
        seed(target)
    elif command == "assert-dry-run":
        assert_dry_run(source, target)
    elif command == "assert-apply":
        assert_apply(source, target)
    elif command == "restore-sensitive-negative-control":
        restore_sensitive_negative_control(target)
    else:
        raise ValueError(f"unknown PostgreSQL pressure fixture command: {command}")


if __name__ == "__main__":
    main()
