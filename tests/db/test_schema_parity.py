"""Rule 10: the schema Alembic builds is the schema the models describe.

A relay on SQLite without migrations (the local Swarmify relay, tests) builds
its tables with ``create_tables`` (``SQLModel.metadata.create_all``); every
other relay runs ``alembic upgrade head``.  When the two drift, code that
passes its tests on one breaks on the other.  This test builds both and
compares tables, columns (name, nullability, type affinity), primary keys,
foreign keys, indexes and unique constraints.

A difference that is known and harmless goes in KNOWN_DIFFERENCES with the
reason.  Anything else fails: fix the model or add a migration.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlmodel import SQLModel

import uam.db.models  # noqa: F401  (registers every table on SQLModel.metadata)

ROOT = Path(__file__).resolve().parents[2]

#: (table, kind, detail) -> why it doesn't matter.
KNOWN_DIFFERENCES: dict[tuple[str, str, str], str] = {}


def _affinity(column_type: sa.types.TypeEngine) -> str:
    """The storage class a type lands in, so VARCHAR(255) and TEXT compare equal."""
    name = type(column_type).__name__.upper()
    text = str(column_type).upper()
    if "BOOL" in name or "BOOL" in text:
        return "bool"
    if "INT" in name or "INT" in text:
        return "int"
    if any(k in text for k in ("CHAR", "TEXT", "CLOB", "STRING", "UUID", "JSON")):
        return "text"
    if any(k in text for k in ("TIMESTAMP", "DATETIME")):
        return "datetime"
    if "DATE" in text:
        return "date"
    if any(k in text for k in ("REAL", "FLOA", "DOUB", "NUMERIC", "DECIMAL")):
        return "real"
    if any(k in text for k in ("BLOB", "BYTEA", "BINARY")):
        return "blob"
    return text


def _describe(engine: sa.Engine) -> set[tuple[str, str, str]]:
    """Every fact about the schema worth comparing, as (table, kind, detail)."""
    inspector = sa.inspect(engine)
    facts: set[tuple[str, str, str]] = set()
    for table in inspector.get_table_names():
        if table == "alembic_version":
            continue
        facts.add((table, "table", ""))
        for col in inspector.get_columns(table):
            nullable = "null" if col["nullable"] else "not null"
            facts.add((table, "column", f"{col['name']} {_affinity(col['type'])} {nullable}"))
        pk = inspector.get_pk_constraint(table).get("constrained_columns") or []
        facts.add((table, "primary key", ",".join(pk)))
        for fk in inspector.get_foreign_keys(table):
            on_delete = (fk.get("options") or {}).get("ondelete") or ""
            facts.add((
                table,
                "foreign key",
                f"{','.join(fk['constrained_columns'])} -> {fk['referred_table']}"
                f"({','.join(fk['referred_columns'])}) {on_delete.lower()}".rstrip(),
            ))
        # An index and a unique constraint enforce the same thing; compare what
        # they enforce, not which of the two a dialect reports.
        for ix in inspector.get_indexes(table):
            kind = "unique" if ix.get("unique") else "index"
            facts.add((table, kind, ",".join(c or "" for c in ix["column_names"])))
        for uq in inspector.get_unique_constraints(table):
            facts.add((table, "unique", ",".join(uq["column_names"])))
    return facts


def _diff(migrated: set, created: set) -> list[str]:
    lines = []
    for fact in sorted(migrated - created):
        if fact not in KNOWN_DIFFERENCES:
            lines.append(f"only after alembic upgrade head: {fact}")
    for fact in sorted(created - migrated):
        if fact not in KNOWN_DIFFERENCES:
            lines.append(f"only after create_tables: {fact}")
    return lines


def _alembic_config(url: str) -> Config:
    os.environ["DATABASE_URL"] = url
    return Config(str(ROOT / "alembic.ini"))


@pytest.fixture()
def database_url_env():
    previous = os.environ.get("DATABASE_URL")
    yield
    if previous is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = previous


def test_sqlite_migrations_match_the_models(tmp_path, database_url_env, monkeypatch):
    # Migration 0003 hashes stored tokens; an empty database has none to hash.
    monkeypatch.setenv("UAM_TOKEN_PEPPER", os.environ.get("UAM_TOKEN_PEPPER") or "x" * 32)
    migrated_path = tmp_path / "migrated.db"
    command.upgrade(_alembic_config(f"sqlite+aiosqlite:///{migrated_path}"), "head")

    created = sa.create_engine(f"sqlite:///{tmp_path / 'created.db'}")
    SQLModel.metadata.create_all(created)
    migrated = sa.create_engine(f"sqlite:///{migrated_path}")
    try:
        problems = _diff(_describe(migrated), _describe(created))
    finally:
        created.dispose()
        migrated.dispose()

    assert problems == [], "\n".join(problems)


@pytest.mark.postgres
def test_postgres_migrations_match_the_models(postgres_url, database_url_env, monkeypatch):
    monkeypatch.setenv("UAM_TOKEN_PEPPER", os.environ.get("UAM_TOKEN_PEPPER") or "x" * 32)
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
    engine = sa.create_engine(sync_url)

    def reset():
        with engine.begin() as conn:
            conn.execute(sa.text("DROP SCHEMA public CASCADE"))
            conn.execute(sa.text("CREATE SCHEMA public"))

    try:
        reset()
        command.upgrade(_alembic_config(postgres_url), "head")
        migrated = _describe(engine)
        reset()
        SQLModel.metadata.create_all(engine)
        created = _describe(engine)
        reset()
    finally:
        engine.dispose()

    problems = _diff(migrated, created)
    assert problems == [], "\n".join(problems)
