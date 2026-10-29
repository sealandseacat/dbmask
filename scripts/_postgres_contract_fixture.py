"""Disposable PostgreSQL fixtures and checks independent of dbmask validators.

The destructive entry point accepts only two fixed local synthetic databases.
The caller must additionally obtain the operator's explicit reset flag before
calling ``recreate_and_seed``. No production connection is accepted here.
"""
from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager
from datetime import date
from itertools import zip_longest
from typing import Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError, IntegrityError

SOURCE_DATABASE = "dbmask_contract_source"
TARGET_DATABASE = "dbmask_contract_target"
MIN_ROWS = 5001
MAX_ROWS = 200001

SENSITIVE = {
    "customers": {
        "full_name": "full_name", "email": "email", "phone": "phone", "birth_date": "date",
    },
    "orders": {"contact_email": "email"},
}
KEEP = {
    "customers": ["id", "customer_ref", "status", "credit_limit"],
    "orders": ["tenant_id", "order_id", "customer_id", "quantity", "unit_price", "total"],
}
COLUMNS = {
    "customers": [
        "id", "customer_ref", "full_name", "email", "phone", "birth_date", "status", "credit_limit",
    ],
    "orders": [
        "tenant_id", "order_id", "customer_id", "contact_email", "quantity", "unit_price", "total",
    ],
}
ORDER = {"customers": "id", "orders": "tenant_id, order_id"}

DDL = (
    """CREATE TABLE public.customers (
        id INTEGER PRIMARY KEY,
        customer_ref VARCHAR(24) NOT NULL CONSTRAINT customers_ref_key UNIQUE,
        full_name TEXT,
        email VARCHAR(96) NOT NULL,
        phone VARCHAR(20),
        birth_date DATE NOT NULL,
        status VARCHAR(12) NOT NULL CHECK (status IN ('active', 'inactive')),
        credit_limit NUMERIC(12,2) NOT NULL CHECK (credit_limit >= 0)
    )""",
    "CREATE INDEX customers_status_idx ON public.customers (status)",
    """CREATE TABLE public.orders (
        tenant_id INTEGER NOT NULL,
        order_id INTEGER NOT NULL,
        customer_id INTEGER NOT NULL REFERENCES public.customers(id),
        contact_email VARCHAR(96) NOT NULL,
        quantity SMALLINT NOT NULL CHECK (quantity > 0),
        unit_price NUMERIC(10,2) NOT NULL CHECK (unit_price >= 0),
        total NUMERIC(12,2) GENERATED ALWAYS AS (quantity * unit_price) STORED,
        PRIMARY KEY (tenant_id, order_id)
    )""",
    "CREATE INDEX orders_customer_idx ON public.orders (customer_id)",
)


def validate_rows(rows: int) -> int:
    """Require enough rows to exercise the previous 5,000-row boundary."""
    if isinstance(rows, bool) or not isinstance(rows, int) or not MIN_ROWS <= rows <= MAX_ROWS:
        raise ValueError(f"rows must be an integer between {MIN_ROWS} and {MAX_ROWS}")
    return rows


def validate_urls(source: str, target: str) -> tuple[URL, URL]:
    """Reject all destinations except the exact local disposable pair."""
    parsed = []
    for raw, expected in ((source, SOURCE_DATABASE), (target, TARGET_DATABASE)):
        try:
            url = make_url(raw)
            port = url.port or 5432
        except (ArgumentError, TypeError, ValueError) as exc:
            raise ValueError("invalid disposable PostgreSQL connection URL") from exc
        if url.drivername != "postgresql+psycopg2":
            raise ValueError("contract requires postgresql+psycopg2")
        if url.host not in {"localhost", "127.0.0.1"} or not 1 <= port <= 65535:
            raise ValueError("contract requires a local TCP PostgreSQL service")
        if url.username != "dbmask" or url.password != "dbmask-contract-only":
            raise ValueError("contract requires its fixed synthetic service account")
        if url.database != expected:
            raise ValueError(f"expected disposable database {expected}")
        if url.query:
            raise ValueError("contract does not accept connection URL query parameters")
        parsed.append(url)
    if (parsed[0].host, parsed[0].port or 5432) != (parsed[1].host, parsed[1].port or 5432):
        raise ValueError("source and target must use the same local PostgreSQL service")
    return parsed[0], parsed[1]


def _validate_one(raw: str) -> URL:
    """Guard read/check/mutation helpers as well as database creation."""
    try:
        parsed = make_url(raw)
    except (ArgumentError, TypeError, ValueError) as exc:
        raise ValueError("invalid disposable PostgreSQL connection URL") from exc
    if parsed.database == SOURCE_DATABASE:
        source, _ = validate_urls(raw, parsed.set(database=TARGET_DATABASE).render_as_string(hide_password=False))
        return source
    if parsed.database == TARGET_DATABASE:
        _, target = validate_urls(parsed.set(database=SOURCE_DATABASE).render_as_string(hide_password=False), raw)
        return target
    raise ValueError("expected a contract source or target database")


def _target(raw: str) -> URL:
    parsed = _validate_one(raw)
    if parsed.database != TARGET_DATABASE:
        raise ValueError("negative controls may mutate only the disposable target")
    return parsed


def recreate_and_seed(source: str, target: str, rows: int) -> None:
    """Recreate only the guarded synthetic databases and populate both alike."""
    source_url, target_url = validate_urls(source, target)
    validate_rows(rows)
    admin = create_engine(source_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            for database in (SOURCE_DATABASE, TARGET_DATABASE):
                # Names are fixed constants, never operator-supplied identifiers.
                connection.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
                connection.execute(text(f'CREATE DATABASE "{database}"'))
    finally:
        admin.dispose()
    for url in (source_url, target_url):
        engine = create_engine(url)
        try:
            with engine.begin() as connection:
                for statement in DDL:
                    connection.execute(text(statement))
                connection.execute(text("""
                    INSERT INTO public.customers
                        (id, customer_ref, full_name, email, phone, birth_date, status, credit_limit)
                    SELECT i, 'C' || lpad(i::text, 8, '0'),
                        CASE WHEN i % 23 = 0 THEN NULL ELSE 'Source Customer ' || i::text END,
                        CASE WHEN i IN (1, :rows) THEN 'repeat@example.test'
                             ELSE 'source' || i::text || '@example.test' END,
                        CASE WHEN i % 17 = 0 THEN NULL
                             ELSE '202-555-' || lpad((i % 10000)::text, 4, '0') END,
                        DATE '1980-01-01' + (i % 12000),
                        CASE WHEN i % 2 = 0 THEN 'active' ELSE 'inactive' END,
                        (1000 + i % 1000)::numeric(12,2)
                    FROM generate_series(1, :rows) AS series(i)
                """), {"rows": rows})
                connection.execute(text("""
                    INSERT INTO public.orders
                        (tenant_id, order_id, customer_id, contact_email, quantity, unit_price)
                    SELECT ((id - 1) / 700) + 1, ((id - 1) % 700) + 1,
                        id, email, (id % 5) + 1, (10 + id % 100)::numeric(10,2)
                    FROM public.customers ORDER BY id
                """))
        finally:
            engine.dispose()


def _schema(connection) -> dict:
    """Catalog definitions without cluster-dependent OIDs or database names."""
    queries = {
        "columns": """SELECT table_name, column_name, ordinal_position, data_type,
            is_nullable, column_default, character_maximum_length, numeric_precision,
            numeric_scale, is_identity, identity_generation, is_generated, generation_expression
            FROM information_schema.columns WHERE table_schema='public'
            AND table_name IN ('customers','orders') ORDER BY table_name, ordinal_position""",
        "constraints": """SELECT cls.relname, con.conname, con.contype,
            pg_get_constraintdef(con.oid, true)
            FROM pg_constraint con JOIN pg_class cls ON cls.oid=con.conrelid
            JOIN pg_namespace ns ON ns.oid=cls.relnamespace
            WHERE ns.nspname='public' AND cls.relname IN ('customers','orders')
            ORDER BY cls.relname, con.conname""",
        "indexes": """SELECT tablename, indexname, indexdef FROM pg_indexes
            WHERE schemaname='public' AND tablename IN ('customers','orders')
            ORDER BY tablename, indexname""",
    }
    return {
        label: [list(row) for row in connection.execute(text(query))]
        for label, query in queries.items()
    }


def _encoded(value) -> bytes:
    return json.dumps(value, default=str, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def snapshot(url: str) -> dict:
    """Fingerprint every fixture value and relevant schema definition."""
    engine = create_engine(_validate_one(url))
    result = {"tables": {}}
    try:
        with engine.connect() as connection:
            result["schema_sha256"] = hashlib.sha256(_encoded(_schema(connection))).hexdigest()
            for table in COLUMNS:
                digest = hashlib.sha256()
                count = 0
                query = f"SELECT {', '.join(COLUMNS[table])} FROM public.{table} ORDER BY {ORDER[table]}"
                cursor = connection.execute(text(query).execution_options(stream_results=True))
                for row in cursor:
                    digest.update(_encoded(list(row)))
                    digest.update(b"\n")
                    count += 1
                result["tables"][table] = {"rows": count, "data_sha256": digest.hexdigest()}
    finally:
        engine.dispose()
    return result


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _expect_constraint(connection, statement: str, expected_state: str) -> None:
    """A savepoint keeps the fixture unchanged after a deliberate violation."""
    transaction = connection.begin_nested()
    try:
        connection.execute(text(statement))
    except IntegrityError as exc:
        state = getattr(exc.orig, "pgcode", None)
        transaction.rollback()
        _check(state == expected_state, "constraint failed with an unexpected SQLSTATE")
    else:
        transaction.rollback()
        raise AssertionError("PostgreSQL unexpectedly accepted a constraint violation")


def assert_postconditions(source: str, target: str, rows: int, baseline: dict) -> dict:
    """Independently compare all rows, schema and actual constraint behavior."""
    source_url, target_url = validate_urls(source, target)
    validate_rows(rows)
    _check(snapshot(source) == baseline, "the untouched source database changed")
    target_snapshot = snapshot(target)
    _check(target_snapshot["schema_sha256"] == baseline["schema_sha256"], "target schema changed")
    for table in COLUMNS:
        _check(baseline["tables"][table]["rows"] == rows, "source fixture has an unexpected row count")
        _check(target_snapshot["tables"][table]["rows"] == rows, "target row count changed")
    counts = {table: {column: {"changed": 0, "null_preserved": 0}
                      for column in SENSITIVE[table]} for table in COLUMNS}
    source_engine, target_engine = create_engine(source_url), create_engine(target_url)
    try:
        with source_engine.connect() as original, target_engine.connect() as masked:
            for table in COLUMNS:
                query = text(f"SELECT {', '.join(COLUMNS[table])} FROM public.{table} ORDER BY {ORDER[table]}")
                left = original.execute(query.execution_options(stream_results=True)).mappings()
                right = masked.execute(query.execution_options(stream_results=True)).mappings()
                seen = 0
                for before, after in zip_longest(left, right):
                    _check(before is not None and after is not None, "source/target row alignment changed")
                    for column in KEEP[table]:
                        _check(before[column] == after[column], f"a kept {table}.{column} value changed")
                    for column in SENSITIVE[table]:
                        if before[column] is None:
                            _check(after[column] is None, f"NULL changed in {table}.{column}")
                            counts[table][column]["null_preserved"] += 1
                        else:
                            _check(after[column] is not None and before[column] != after[column],
                                   f"an eligible {table}.{column} value was not replaced")
                            counts[table][column]["changed"] += 1
                            if column in {"email", "contact_email"}:
                                _check(bool(re.fullmatch(r"[^\s@]+@example\.invalid", after[column])),
                                       "a masked email has an invalid output format")
                            elif column == "phone":
                                _check(bool(re.fullmatch(r"\d{3}-\d{3}-\d{4}", after[column])),
                                       "a masked phone has an invalid output format")
                            elif column == "birth_date":
                                _check(isinstance(after[column], date), "a masked date lost its database type")
                    seen += 1
                _check(seen == rows, "a direct comparison did not inspect every fixture row")
            orphan_count = masked.execute(text("""SELECT COUNT(*) FROM public.orders o
                LEFT JOIN public.customers c ON c.id=o.customer_id WHERE c.id IS NULL""")).scalar_one()
            _check(orphan_count == 0, "an order lost its customer relationship")
            inconsistent = masked.execute(text("""SELECT COUNT(*) FROM public.orders o
                JOIN public.customers c ON c.id=o.customer_id
                WHERE o.contact_email IS DISTINCT FROM c.email""")).scalar_one()
            _check(inconsistent == 0, "email mappings differ between customer and order tables")
            repeated = list(masked.execute(text(
                "SELECT email FROM public.customers WHERE id IN (1, :rows) ORDER BY id"
            ), {"rows": rows}).scalars())
            _check(len(repeated) == 2 and repeated[0] == repeated[1],
                   "a repeated input differs between the first and final page")
            _check(masked.execute(text("SELECT COUNT(*) FROM public.orders WHERE total <> quantity * unit_price")).scalar_one() == 0,
                   "a generated total no longer matches its inputs")
            _expect_constraint(masked, """INSERT INTO public.customers
                SELECT -1, customer_ref, full_name, email, phone, birth_date, status, credit_limit
                FROM public.customers WHERE id=1""", "23505")
            _expect_constraint(masked, "UPDATE public.orders SET customer_id=-1 WHERE tenant_id=1 AND order_id=1", "23503")
            _expect_constraint(masked, "UPDATE public.orders SET quantity=0 WHERE tenant_id=1 AND order_id=1", "23514")
    finally:
        source_engine.dispose()
        target_engine.dispose()
    _check(snapshot(target) == target_snapshot, "constraint probes changed the masked fixture")
    return {
        "rows_compared_per_table": {table: rows for table in COLUMNS},
        "sensitive_values": counts,
        "source_unchanged": True, "schema_unchanged": True,
        "kept_values_unchanged": True, "relationships_preserved": True,
        "cross_table_email_mapping_consistent": True,
        "first_last_duplicate_mapping_consistent": True,
        "generated_total_correct": True,
        "constraint_sqlstates": {"unique": "23505", "foreign_key": "23503", "check": "23514"},
    }


@contextmanager
def negative_control(target: str, case: str, rows: int):
    """Commit one deliberate fault, then restore the exact pre-control state."""
    target_url = _target(target)
    validate_rows(rows)
    allowed = {"restore_email_5001", "restore_email_last", "missing_order", "replace_order_key", "drop_unique"}
    if case not in allowed:
        raise ValueError("unknown PostgreSQL contract negative control")
    engine = create_engine(target_url)
    restore_statement: Optional[str] = None
    restore_parameters = {}
    try:
        with engine.begin() as connection:
            if case in {"restore_email_5001", "restore_email_last"}:
                row_id = 5001 if case == "restore_email_5001" else rows
                value = connection.execute(text("SELECT email FROM public.customers WHERE id=:id"), {"id": row_id}).scalar_one()
                original = "repeat@example.test" if row_id in (1, rows) else f"source{row_id}@example.test"
                connection.execute(text("UPDATE public.customers SET email=:value WHERE id=:id"), {"value": original, "id": row_id})
                restore_statement = "UPDATE public.customers SET email=:value WHERE id=:id"
                restore_parameters = {"value": value, "id": row_id}
            elif case == "missing_order":
                saved = connection.execute(text("""SELECT tenant_id, order_id, customer_id, contact_email,
                    quantity, unit_price FROM public.orders WHERE customer_id=:id"""), {"id": rows}).mappings().one()
                restore_parameters = dict(saved)
                connection.execute(text("DELETE FROM public.orders WHERE tenant_id=:tenant_id AND order_id=:order_id"), restore_parameters)
                restore_statement = """INSERT INTO public.orders
                    (tenant_id, order_id, customer_id, contact_email, quantity, unit_price)
                    VALUES (:tenant_id, :order_id, :customer_id, :contact_email, :quantity, :unit_price)"""
            elif case == "replace_order_key":
                connection.execute(text("UPDATE public.orders SET order_id=999999 WHERE tenant_id=1 AND order_id=1"))
                restore_statement = "UPDATE public.orders SET order_id=1 WHERE tenant_id=1 AND order_id=999999"
            else:
                connection.execute(text("ALTER TABLE public.customers DROP CONSTRAINT customers_ref_key"))
                restore_statement = "ALTER TABLE public.customers ADD CONSTRAINT customers_ref_key UNIQUE (customer_ref)"
        try:
            yield
        finally:
            with engine.begin() as connection:
                connection.execute(text(restore_statement), restore_parameters)
    finally:
        engine.dispose()
