"""Validate the deployment SQL against the Gateway models without a database."""

import re
from pathlib import Path

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from hypermesh_gateway_service.models import (
    HistoryAudit,
    HistoryEntry,
    HistoryPreference,
    TrainingConsent,
    TrainingDeletion,
    TrainingSubmission,
)

MIGRATIONS = Path(__file__).resolve().parents[1] / "deployment" / "retained-data"
STORES = (
    (
        "history",
        (
            (HistoryPreference, "SELECT, INSERT, UPDATE"),
            (HistoryEntry, "SELECT, DELETE"),
            (HistoryAudit, "SELECT, INSERT"),
        ),
    ),
    (
        "training",
        (
            (TrainingConsent, "SELECT, INSERT, UPDATE, DELETE"),
            (TrainingSubmission, "SELECT, DELETE"),
            (TrainingDeletion, "SELECT, INSERT"),
        ),
    ),
)
TENANT_PREDICATE = "tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid"


@pytest.mark.parametrize(("store", "tables"), STORES, ids=["history", "training"])
def test_retained_store_migration_matches_models_and_runtime_access(store, tables):
    sql = (MIGRATIONS / f"0001-{store}.sql").read_text()
    normalized_sql = " ".join(sql.split())
    database = f"gateway_{store}"
    role = f"{database}_runtime"
    assert re.findall(r"CREATE TABLE public\.(\w+)", sql) == [
        "tenants", *(model.__tablename__ for model, _ in tables)
    ]
    assert "CREATE TABLE public.tenants (id UUID PRIMARY KEY);" in sql
    assert "REVOKE ALL ON TABLE public.tenants FROM PUBLIC;" in sql
    assert f"current_database() <> '{database}'" in sql
    assert f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;" in sql
    assert "REVOKE ALL ON SCHEMA public FROM PUBLIC;" in sql
    assert re.findall(r"^GRANT .+;$", sql, re.MULTILINE) == [
        f"GRANT CONNECT ON DATABASE {database} TO {role};",
        f"GRANT USAGE ON SCHEMA public TO {role};",
        *(f"GRANT {access} ON TABLE public.{model.__tablename__} TO {role};"
          for model, access in tables),
    ]
    for model, _ in tables:
        table = model.__table__
        name = f"public.{table.name}"
        for statement in (CreateTable(table), *(CreateIndex(index) for index in table.indexes)):
            compiled = statement.compile(
                dialect=postgresql.dialect(),
                schema_translate_map={None: "public"},
                render_schema_translate=True,
            )
            assert " ".join(str(compiled).split()) + ";" in normalized_sql

        assert f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY;" in sql
        assert f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY;" in sql
        assert f"REVOKE ALL ON TABLE {name} FROM PUBLIC;" in sql
        assert (
            f"CREATE POLICY tenant_scope ON {name} TO {role} "
            f"USING ({TENANT_PREDICATE}) WITH CHECK ({TENANT_PREDICATE});"
        ) in normalized_sql

    assert re.findall(r"^CREATE POLICY (\w+) ", sql, re.MULTILINE) == ["tenant_scope"] * len(tables)
