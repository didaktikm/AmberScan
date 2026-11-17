"""Isolated SQLite shape/transaction tests; these are NOT a PostgreSQL smoke test."""

import base64
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from workbench.alembic.schema_v01 import metadata as baseline_metadata
from workbench.alembic.schema_v05 import metadata as current_metadata
from workbench.db import Base, database
from workbench.domain import DomainError
from workbench.migrations import (
    BASELINE_VERSION,
    HEAD_REVISION,
    SCHEMA_VERSION,
    init_database,
    require_latest,
    schema_status,
    upgrade_database,
    verify_schema,
)
from workbench.security import Vault

KEY = base64.urlsafe_b64encode(b"m" * 32).decode()


@pytest.fixture
def legacy():
    engine, _ = database("sqlite+pysqlite:///:memory:")
    schema = baseline_metadata()
    timestamp = datetime.now(UTC)
    vault = Vault(KEY)
    with engine.begin() as connection:
        # Frozen versioned schema, never current Base. The marker exactly matches
        # the raw SQL used by 0.1 init-db (including SQLite's nullable PK quirk).
        for table in schema.sorted_tables:
            table.create(connection)
        connection.execute(
            schema.tables["workbench_schema"].insert().values(version=BASELINE_VERSION)
        )
        connection.execute(
            schema.tables["users"].insert(),
            [
                {
                    "id": "u1",
                    "username": "operator",
                    "password_hash": "unchanged-password-hash",
                    "role": "administrator",
                    "active": True,
                    "failed_logins": 2,
                    "locked_until": None,
                },
                {
                    "id": "u2",
                    "username": "auditor",
                    "password_hash": "unchanged-auditor-hash",
                    "role": "auditor",
                    "active": True,
                    "failed_logins": 0,
                    "locked_until": None,
                },
            ],
        )
        connection.execute(
            schema.tables["clusters"]
            .insert()
            .values(
                id="c1",
                name="retained-cluster",
                environment="test",
                context="context",
                server="https://cluster.example:6443",
                ca_data=None,
                oidc_provider_id="original-provider-id",
                namespaces=["default"],
                created_at=timestamp,
            )
        )
        connection.execute(
            schema.tables["cluster_grants"]
            .insert()
            .values(user_id="u2", cluster_id="c1")
        )
        connection.execute(
            schema.tables["sessions"]
            .insert()
            .values(
                token_hash="session-hash",
                user_id="u1",
                csrf_token="csrf",
                expires_at=timestamp + timedelta(hours=1),
            )
        )
        connection.execute(
            schema.tables["cluster_credentials"]
            .insert()
            .values(
                user_id="u1",
                cluster_id="c1",
                expires_at=timestamp + timedelta(hours=1),
                encrypted=vault.encrypt(
                    {"id_token": "synthetic-only"}, "credential:u1:c1"
                ),
            )
        )
        connection.execute(
            schema.tables["oidc_transactions"]
            .insert()
            .values(
                state_hash="state",
                session_hash="session-hash",
                cluster_id="c1",
                expires_at=timestamp + timedelta(minutes=5),
                encrypted=vault.encrypt({"verifier": "synthetic-only"}, "oidc:state"),
            )
        )
        for status in ("completed", "queued", "running"):
            connection.execute(
                schema.tables["runs"]
                .insert()
                .values(
                    id=status,
                    cluster_id="c1",
                    actor_id="u1",
                    status=status,
                    stage="observe",
                    scope={"scope": "retained"},
                    credential=vault.encrypt(
                        {"token": "synthetic-only"}, f"run:{status}"
                    ),
                    cancel_requested=False,
                    worker_id="old-worker" if status == "running" else None,
                    lease_until=timestamp + timedelta(minutes=1)
                    if status == "running"
                    else None,
                    created_at=timestamp,
                    started_at=timestamp if status != "queued" else None,
                    finished_at=timestamp if status == "completed" else None,
                    error=None,
                    coverage=["retained"],
                    limitations=["retained"],
                    versions={"scanner": "v1"},
                    source="api",
                )
            )
        connection.execute(
            schema.tables["findings"]
            .insert()
            .values(
                id="f1",
                cluster_id="c1",
                fingerprint="stable-fingerprint",
                disposition="accepted",
                first_seen=timestamp,
                last_seen=timestamp,
                latest_run_id="completed",
                data={"evidence": "retained"},
            )
        )
        connection.execute(
            schema.tables["observations"]
            .insert()
            .values(
                run_id="completed", finding_id="f1", data={"observation": "retained"}
            )
        )
        connection.execute(
            schema.tables["audit_events"]
            .insert()
            .values(
                id="audit1",
                created_at=timestamp,
                actor="operator",
                action="past-event",
                target="c1",
                detail={"kept": True},
            )
        )
    yield engine
    engine.dispose()


def rows(connection, name):
    return list(connection.execute(sa.text(f"SELECT * FROM {name}")).mappings())


def test_preview_and_initialization_never_upgrade_legacy(legacy):
    with legacy.connect() as connection:
        before = {name: rows(connection, name) for name in baseline_metadata().tables}
    preview = upgrade_database(legacy)
    assert preview["applied"] is False
    assert preview["invalidate"] == {"cluster_credentials": 1, "oidc_transactions": 1}
    assert preview["runs"] == {"queued": 1, "running": 1}
    assert preview["clear_run_credentials"] == 3
    assert "synthetic-only" not in str(preview)
    with pytest.raises(DomainError, match="upgrade"):
        init_database(legacy)
    with legacy.connect() as connection:
        assert verify_schema(connection) == BASELINE_VERSION
        assert {
            name: rows(connection, name) for name in baseline_metadata().tables
        } == before


@pytest.mark.parametrize(
    "backup,offline", [(False, False), (True, False), (False, True)]
)
def test_apply_requires_both_acknowledgements(legacy, backup, offline):
    with pytest.raises(DomainError, match="backup-confirmed"):
        upgrade_database(
            legacy, apply=True, backup_confirmed=backup, offline_confirmed=offline
        )
    with legacy.connect() as connection:
        assert verify_schema(connection) == BASELINE_VERSION
        assert len(rows(connection, "cluster_credentials")) == 1


def test_upgrade_preserves_identities_acl_observations_and_history(legacy):
    retained = [
        "users",
        "clusters",
        "cluster_grants",
        "sessions",
        "findings",
        "observations",
    ]
    with legacy.connect() as connection:
        before = {name: rows(connection, name) for name in retained}
        completed = dict(
            connection.execute(sa.text("SELECT * FROM runs WHERE id='completed'"))
            .mappings()
            .one()
        )
    result = upgrade_database(
        legacy, apply=True, backup_confirmed=True, offline_confirmed=True
    )
    assert result["applied"]
    with legacy.connect() as connection:
        assert verify_schema(connection) == SCHEMA_VERSION
        for name in retained:
            after = rows(connection, name)
            for original, updated in zip(before[name], after, strict=True):
                assert {
                    key: updated[key] for key in original if key != "oidc_provider_id"
                } == {
                    key: value
                    for key, value in original.items()
                    if key != "oidc_provider_id"
                }
        assert not rows(connection, "cluster_credentials")
        assert "oidc_transactions" not in sa.inspect(connection).get_table_names()
        runs = {row["id"]: row for row in rows(connection, "runs")}
        for key, value in completed.items():
            assert runs["completed"][key] == (None if key == "credential" else value)
        assert runs["queued"]["status"] == "cancelled"
        assert runs["running"]["status"] == "interrupted"
        for run_id in ("queued", "running"):
            run = runs[run_id]
            assert run["finished_at"] is not None
            assert run["credential"] is None
            assert run["worker_id"] is None
            assert run["lease_until"] is None
        assert len(rows(connection, "audit_events")) == 5
        assert "oidc_providers" not in sa.inspect(connection).get_table_names()
        assert rows(connection, "integration_policy")[0]["revision"] == 0
    repeat = upgrade_database(legacy, apply=True)
    assert not repeat["changes_required"] and not repeat["applied"]


@pytest.mark.parametrize(
    "mutation",
    [
        "ALTER TABLE users ADD COLUMN foreign_data TEXT",
        "CREATE TABLE unrelated (id INTEGER)",
        "DROP INDEX ix_runs_status",
        "CREATE INDEX unapproved_index ON users(role)",
        "DELETE FROM workbench_schema",
        "INSERT INTO workbench_schema VALUES ('foreign')",
        "UPDATE workbench_schema SET version='0.2.0'",
        "CREATE VIEW foreign_view AS SELECT id FROM users",
        "ALTER TABLE clusters RENAME COLUMN context TO altered_context",
    ],
)
def test_marker_never_authorizes_unrecognized_shape(legacy, mutation):
    with legacy.begin() as connection:
        connection.exec_driver_sql(mutation)
    with pytest.raises(DomainError):
        upgrade_database(
            legacy, apply=True, backup_confirmed=True, offline_confirmed=True
        )
    assert "alembic_version" not in sa.inspect(legacy).get_table_names()


@pytest.mark.parametrize(
    "change", ["nullable", "length", "fk", "unique", "default", "check"]
)
def test_precise_baseline_checks_constraints_and_types(change):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    schema = baseline_metadata()
    users = schema.tables["users"]
    if change == "nullable":
        users.c.username.nullable = True
    elif change == "length":
        users.c.username.type = sa.String(101)
    elif change == "fk":
        grant = schema.tables["cluster_grants"]
        constraint = next(iter(grant.foreign_key_constraints))
        grant.constraints.remove(constraint)
    elif change == "unique":
        users.constraints.remove(
            next(
                constraint
                for constraint in users.constraints
                if isinstance(constraint, sa.UniqueConstraint)
            )
        )
    elif change == "default":
        users.c.username.server_default = sa.DefaultClause("unexpected")
    elif change == "check":
        users.append_constraint(sa.CheckConstraint("failed_logins >= 0"))
    with engine.begin() as connection:
        schema.create_all(connection)
        connection.execute(sa.text("INSERT INTO workbench_schema VALUES ('0.1.0')"))
    try:
        with pytest.raises(DomainError):
            upgrade_database(
                engine, apply=True, backup_confirmed=True, offline_confirmed=True
            )
    finally:
        engine.dispose()


def test_transaction_rolls_back_ddl_and_invalidations(legacy, monkeypatch):
    from workbench import migrations

    original = migrations.command.upgrade

    def fail_after_migration(config, revision):
        original(config, revision)
        raise RuntimeError("synthetic failure after DDL and data cleanup")

    monkeypatch.setattr(migrations.command, "upgrade", fail_after_migration)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        upgrade_database(
            legacy, apply=True, backup_confirmed=True, offline_confirmed=True
        )
    with legacy.connect() as connection:
        assert verify_schema(connection) == BASELINE_VERSION
        assert len(rows(connection, "cluster_credentials")) == 1
        assert len(rows(connection, "oidc_transactions")) == 1
        assert {row["status"] for row in rows(connection, "runs")} == {
            "completed",
            "queued",
            "running",
        }


def test_fresh_initialization_has_head_marker_and_matches_current_models():
    engine, _ = database("sqlite+pysqlite:///:memory:")
    try:
        with engine.connect() as connection:
            assert schema_status(connection) == "empty"
        init_database(engine)
        with engine.connect() as connection:
            require_latest(connection)
            assert (
                connection.execute(
                    sa.text("SELECT version_num FROM alembic_version")
                ).scalar_one()
                == HEAD_REVISION
            )
        frozen = current_metadata()
        assert set(frozen.tables) - {"alembic_version", "workbench_schema"} == set(
            Base.metadata.tables
        )
        for name, table in Base.metadata.tables.items():
            assert set(table.columns.keys()) == set(frozen.tables[name].columns.keys())
            for column in table.columns:
                expected = frozen.tables[name].c[column.name]
                assert str(column.type) == str(expected.type)
                assert column.nullable == expected.nullable
                assert (
                    str(column.server_default) == str(expected.server_default)
                    if column.server_default is None
                    else str(column.server_default.arg)
                    == str(expected.server_default.arg)
                )
    finally:
        engine.dispose()


def test_head_requires_exact_alembic_revision(legacy):
    upgrade_database(legacy, apply=True, backup_confirmed=True, offline_confirmed=True)
    with legacy.begin() as connection:
        connection.execute(
            sa.text("UPDATE alembic_version SET version_num='unapproved'")
        )
    with pytest.raises(DomainError):
        init_database(legacy)
