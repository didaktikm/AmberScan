"""Kubeconfig schema safety on isolated SQLite with active FK enforcement."""

import pytest
import sqlalchemy as sa
from test_namespace_migrations import KEY, all_rows, create_frozen, table_rows
from test_namespace_migrations import b1 as namespace_source

from workbench import migrations
from workbench.alembic.schema_v05 import metadata
from workbench.backup import verify_database_key
from workbench.db import Cluster, database
from workbench.domain import DomainError

b1 = namespace_source


@pytest.mark.parametrize("b1", ["0.3.0"], indirect=True)
def test_namespace_upgrade_preserves_dependents_and_invalidates_work(b1):
    with b1.connect() as connection:
        before = all_rows(connection)
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
    preview = migrations.upgrade_database(b1)
    assert preview["from_version"] == "0.3.0" and preview["to_version"] == "0.5.0"
    assert preview["invalidate"] == {"cluster_credentials": 2, "oidc_transactions": 1}
    with b1.connect() as connection:
        assert all_rows(connection) == before
    migrations.upgrade_database(
        b1, apply=True, backup_confirmed=True, offline_confirmed=True
    )
    with b1.connect() as connection:
        assert migrations.verify_schema(connection) == "0.5.0"
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert not connection.exec_driver_sql("PRAGMA foreign_key_check").all()
        for name in (
            "users",
            "sessions",
            "cluster_grants",
            "findings",
            "observations",
            "workers",
        ):
            assert table_rows(connection, name) == before[name]
        assert table_rows(connection, "clusters") == [
            {
                **{k: v for k, v in row.items() if k != "oidc_provider_id"},
                "auth_type": "kubeconfig",
                "auth_generation": row["auth_generation"] + 2,
            }
            for row in before["clusters"]
        ]
        assert table_rows(connection, "authorization_bindings") == [
            {**row, "generation": row["generation"] + 2}
            for row in before["authorization_bindings"]
        ]
        assert not table_rows(connection, "cluster_credentials")
        assert "oidc_transactions" not in sa.inspect(connection).get_table_names()
        assert verify_database_key(connection, KEY) == 0
        after = {row["id"]: row for row in table_rows(connection, "runs")}
        for old in before["runs"]:
            new = after[old["id"]]
            assert new["credential"] is None
            assert new["lease_until"] is None
            if old["status"] in {"queued", "running"}:
                assert (
                    new["status"]
                    == {"queued": "cancelled", "running": "interrupted"}[old["status"]]
                )
                assert new["finished_at"] and new["credential_expires_at"] is None
                assert new["worker_id"] is None and new["stage"] == "cleanup"
                assert "kubeconfig authentication upgrade" in new["error"]
                for name in (
                    "scope",
                    "coverage",
                    "limitations",
                    "versions",
                    "created_at",
                    "started_at",
                ):
                    assert new[name] == old[name]
            else:
                expected = {
                    k: v
                    for k, v in {**old, "credential": None}.items()
                    if k != "provider_revision"
                }
                if old["lease_until"]:
                    expected.update(lease_until=None, worker_id=None)
                assert new == expected
        assert before["audit_events"][0] in table_rows(connection, "audit_events")


@pytest.mark.parametrize("b1", ["0.3.0", "0.4.0"], indirect=True)
@pytest.mark.parametrize("failure", ["post-ddl", "foreign-key"])
def test_sqlite_rebuild_rollback_restores_rows_schema_and_fk_enforcement(
    b1, monkeypatch, failure
):
    with b1.connect() as connection:
        before = all_rows(connection)
    original = migrations.command.upgrade

    def fail(config, revision):
        original(config, revision)
        if failure == "post-ddl":
            raise RuntimeError("synthetic post-DDL failure")
        config.attributes["connection"].exec_driver_sql(
            "INSERT INTO cluster_grants VALUES ('missing-user','cluster')"
        )

    monkeypatch.setattr(migrations.command, "upgrade", fail)
    with pytest.raises((RuntimeError, DomainError)):
        migrations.upgrade_database(
            b1, apply=True, backup_confirmed=True, offline_confirmed=True
        )
    with b1.connect() as connection:
        assert migrations.verify_schema(connection) == before["workbench_schema"][0]["version"]
        assert all_rows(connection) == before
        assert verify_database_key(connection, KEY) == 10
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        with pytest.raises(sa.exc.IntegrityError):
            connection.exec_driver_sql(
                "INSERT INTO cluster_grants VALUES ('missing-user','cluster')"
            )


@pytest.mark.parametrize(
    "auth_type,valid",
    [
        ("kubeconfig", True),
        ("oidc", False),
        ("token", False),
        ("client_certificate", False),
        ("unknown", False),
    ],
)
def test_auth_type_database_invariant(auth_type, valid):
    engine, sessions = database("sqlite+pysqlite:///:memory:")
    try:
        migrations.init_database(engine)
        with sessions() as session:
            session.add(
                Cluster(
                    name="test",
                    context="ctx",
                    server="https://kube.example.test",
                    namespaces=[],
                    auth_type=auth_type,
                )
            )
            if valid:
                session.commit()
            else:
                with pytest.raises(sa.exc.IntegrityError):
                    session.commit()
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "weaker", "name", "nullable", "default"]
)
def test_only_exact_expected_check_and_auth_shape_are_accepted(mutation):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    schema = metadata()
    table = schema.tables["clusters"]
    check = next(c for c in table.constraints if isinstance(c, sa.CheckConstraint))
    if mutation == "missing":
        table.constraints.remove(check)
    elif mutation == "extra":
        table.append_constraint(
            sa.CheckConstraint("length(name) > 0", name="unapproved")
        )
    elif mutation == "weaker":
        check.sqltext = sa.text(str(check.sqltext) + " OR 1=1")
    elif mutation == "name":
        check.name = "unapproved"
    elif mutation == "nullable":
        table.c.auth_type.nullable = True
    else:
        table.c.auth_type.server_default = sa.DefaultClause("oidc")
    try:
        with engine.begin() as connection:
            create_frozen(connection, "0.5.0", "0005_remove_oidc", schema)
        with engine.connect() as connection, pytest.raises(DomainError):
            migrations.verify_schema(connection)
    finally:
        engine.dispose()


def test_previous_frozen_schemas_are_unchanged_and_revision_mapping_is_explicit():
    metadata()
    for version in ("0.1.0", "0.2.0", "0.3.0"):
        table = migrations.schema_metadata(version).tables["clusters"]
        assert "auth_type" not in table.c and not table.c.oidc_provider_id.nullable
        assert not any(isinstance(c, sa.CheckConstraint) for c in table.constraints)
    assert migrations.VERSION_REVISIONS["0.3.0"] == "0003_namespace_selection"
    assert migrations.VERSION_REVISIONS["0.4.0"] == "0004_kubeconfig_auth"

    assert migrations.VERSION_REVISIONS["0.5.0"] == "0005_remove_oidc"
    previous = migrations.schema_metadata("0.4.0")
    assert "oidc_providers" in previous.tables
    assert "provider_revision" in previous.tables["runs"].c
    assert str(previous.tables["clusters"].c.auth_type.server_default.arg) == "oidc"
