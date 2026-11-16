"""Namespace schema upgrades on disposable SQLite only; no user data or services."""

import base64
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from workbench import migrations
from workbench.alembic.schema_v01 import metadata as baseline_metadata
from workbench.alembic.schema_v02 import metadata as b1_metadata
from workbench.alembic.schema_v03 import metadata as namespace_metadata
from workbench.alembic.schema_v04 import metadata as kubeconfig_metadata
from workbench.alembic.schema_v05 import metadata as current_metadata
from workbench.backup import verify_database_key
from workbench.db import Cluster, User, database
from workbench.domain import DomainError
from workbench.security import Vault

KEY = base64.urlsafe_b64encode(b"n" * 32).decode()
TIMESTAMP = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
VERSIONS = (
    ("0.1.0", None, baseline_metadata),
    ("0.2.0", "0002_b1", b1_metadata),
    ("0.3.0", "0003_namespace_selection", namespace_metadata),
    ("0.4.0", "0004_kubeconfig_auth", kubeconfig_metadata),
    ("0.5.0", "0005_remove_oidc", current_metadata),
)


def create_frozen(connection, version, revision, schema):
    schema.create_all(connection)
    connection.execute(
        schema.tables["workbench_schema"].insert().values(version=version)
    )
    if revision:
        connection.execute(
            schema.tables["alembic_version"].insert().values(version_num=revision)
        )


def table_rows(connection, name):
    return [
        dict(row)
        for row in connection.execute(sa.text(f"SELECT * FROM {name}")).mappings()
    ]


def all_rows(connection):
    return {
        name: table_rows(connection, name)
        for name in sa.inspect(connection).get_table_names()
    }


@pytest.fixture
def b1(request):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    version = getattr(request, "param", "0.2.0")
    schema = migrations.schema_metadata(version)
    vault = Vault(KEY)
    with engine.begin() as connection:
        create_frozen(
            connection, version, migrations.VERSION_REVISIONS[version], schema
        )
        for user_id, role in (("owner", "administrator"), ("auditor", "auditor")):
            connection.execute(
                schema.tables["users"]
                .insert()
                .values(
                    id=user_id,
                    username=user_id,
                    password_hash="synthetic-hash",
                    role=role,
                    active=True,
                    failed_logins=0,
                )
            )
            connection.execute(
                schema.tables["sessions"]
                .insert()
                .values(
                    token_hash=f"session-{user_id}",
                    user_id=user_id,
                    csrf_token="csrf",
                    expires_at=TIMESTAMP + timedelta(hours=1),
                    reauthenticated_at=TIMESTAMP,
                )
            )
        connection.execute(
            schema.tables["clusters"]
            .insert()
            .values(
                id="cluster",
                name="retained",
                environment="lab",
                context="ctx",
                server="https://kube.example.test",
                ca_data=None,
                oidc_provider_id="idp",
                namespaces=["default", "app"],
                created_at=TIMESTAMP,
                auth_generation=4,
            )
        )
        connection.execute(
            schema.tables["integration_policy"]
            .insert()
            .values(
                id=1,
                revision=7,
                rules=[
                    {
                        "id": "kube",
                        "purpose": "kubernetes",
                        "host": "kube.example.test",
                        "port": 443,
                        "cidrs": ["192.0.2.0/24"],
                    }
                ],
                legacy_imported=True,
                updated_at=TIMESTAMP,
            )
        )
        connection.execute(
            schema.tables["oidc_providers"]
            .insert()
            .values(
                id="idp",
                revision=3,
                enabled=True,
                display_name="Retained identity",
                config={"issuer": "https://idp.example.test", "client_id": "workbench"},
                encrypted_secret=vault.encrypt(
                    {"client_secret": "synthetic-only"}, "provider:idp:3"
                ),
                verification={"status": "verified"},
                created_at=TIMESTAMP,
                updated_at=TIMESTAMP,
            )
        )
        for user_id, mode in (("owner", "run_only"), ("auditor", "persistent")):
            connection.execute(
                schema.tables["authorization_bindings"]
                .insert()
                .values(
                    user_id=user_id,
                    cluster_id="cluster",
                    generation=6,
                )
            )
            connection.execute(
                schema.tables["cluster_grants"]
                .insert()
                .values(user_id=user_id, cluster_id="cluster")
            )
            connection.execute(
                schema.tables["cluster_credentials"]
                .insert()
                .values(
                    user_id=user_id,
                    cluster_id="cluster",
                    encrypted=vault.encrypt(
                        {"id_token": "synthetic-only"}, f"credential:{user_id}:cluster"
                    ),
                    expires_at=TIMESTAMP + timedelta(hours=1),
                    provider_revision=3,
                    policy_revision=7,
                    auth_generation=6,
                    cluster_generation=4,
                    storage_mode=mode,
                    session_hash=f"session-{user_id}" if mode == "run_only" else None,
                )
            )
        connection.execute(
            schema.tables["oidc_transactions"]
            .insert()
            .values(
                state_hash="pending",
                session_hash="session-owner",
                cluster_id="cluster",
                encrypted=vault.encrypt({"verifier": "synthetic-only"}, "oidc:pending"),
                expires_at=TIMESTAMP + timedelta(minutes=5),
                provider_revision=3,
                policy_revision=7,
                auth_generation=6,
                cluster_generation=4,
                storage_mode="persistent",
            )
        )
        for status in (
            "completed",
            "queued",
            "running",
            "failed",
            "cancelled",
            "interrupted",
        ):
            connection.execute(
                schema.tables["runs"]
                .insert()
                .values(
                    id=status,
                    cluster_id="cluster",
                    actor_id="owner",
                    status=status,
                    stage="observe",
                    scope={"namespaces": ["default"], "legacy_detail": "keep"},
                    credential=vault.encrypt(
                        {"id_token": "synthetic-only"}, f"run:{status}"
                    ),
                    cancel_requested=status == "cancelled",
                    worker_id=f"historic-{status}",
                    lease_until=TIMESTAMP + timedelta(minutes=2)
                    if status in {"running", "failed"}
                    else None,
                    created_at=TIMESTAMP,
                    started_at=TIMESTAMP if status != "queued" else None,
                    finished_at=None if status in {"queued", "running"} else TIMESTAMP,
                    error=None
                    if status in {"queued", "running", "completed"}
                    else "historic explanation",
                    coverage=[{"retained": True}],
                    limitations=["retained"],
                    versions={"scanner": "v1"},
                    source="api",
                    provider_revision=3,
                    policy_revision=7,
                    auth_generation=6,
                    cluster_generation=4,
                    credential_expires_at=TIMESTAMP + timedelta(hours=1),
                )
            )
        connection.execute(
            schema.tables["findings"]
            .insert()
            .values(
                id="finding",
                cluster_id="cluster",
                fingerprint="stable",
                disposition="accepted",
                first_seen=TIMESTAMP,
                last_seen=TIMESTAMP,
                latest_run_id="completed",
                data={"kept": True},
            )
        )
        connection.execute(
            schema.tables["observations"]
            .insert()
            .values(
                run_id="completed",
                finding_id="finding",
                data={"observation": "keep"},
            )
        )
        connection.execute(
            schema.tables["audit_events"]
            .insert()
            .values(
                id="past",
                created_at=TIMESTAMP,
                actor="owner",
                action="historic",
                target="cluster",
                detail={"kept": True},
            )
        )
        connection.execute(
            schema.tables["workers"]
            .insert()
            .values(id="old-worker", heartbeat_at=TIMESTAMP, status="idle")
        )
    yield engine
    engine.dispose()


@pytest.mark.parametrize("version,revision,factory", VERSIONS)
def test_all_supported_frozen_schemas_validate_and_runtime_requires_latest(
    version, revision, factory
):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    try:
        with engine.begin() as connection:
            create_frozen(connection, version, revision, factory())
            assert migrations.verify_schema(connection) == version
            if version == "0.5.0":
                migrations.require_runtime_schema(connection)
            else:
                with pytest.raises(DomainError) as error:
                    migrations.require_runtime_schema(connection)
                assert error.value.code == "schema_upgrade_required"
    finally:
        engine.dispose()


def test_b1_preview_and_initialization_leave_every_row_unchanged(b1):
    with b1.connect() as connection:
        before = all_rows(connection)
    preview = migrations.upgrade_database(b1)
    assert preview["from_version"] == "0.2.0" and preview["to_version"] == "0.5.0"
    assert preview["invalidate"] == {"cluster_credentials": 2, "oidc_transactions": 1}
    assert preview["runs"] == {"queued": 1, "running": 1}
    assert preview["clear_run_credentials"] == 6 and preview["clear_run_leases"] == 2
    assert "integration_policy (non-OIDC rules only)" in preview["preserved"]
    assert "oidc_providers" in preview["removed"]
    assert "reconfigure/import policy and providers" not in preview["requirements"]
    with pytest.raises(DomainError, match="upgrade"):
        migrations.init_database(b1)
    with b1.connect() as connection:
        assert all_rows(connection) == before


def test_b1_advances_directly_preserving_history_and_kubernetes_policy(b1, monkeypatch):
    monkeypatch.setattr(
        migrations.command, "stamp", lambda *_: pytest.fail("B1 must never be stamped")
    )
    with b1.connect() as connection:
        before = all_rows(connection)
        assert verify_database_key(connection, KEY) == 10
    result = migrations.upgrade_database(
        b1, apply=True, backup_confirmed=True, offline_confirmed=True
    )
    assert result["applied"] is True
    with b1.connect() as connection:
        assert migrations.verify_schema(connection) == "0.5.0"
        assert (
            verify_database_key(connection, KEY) == 0
        )  # every legacy ciphertext is removed
        for name in (
            "users",
            "sessions",
            "cluster_grants",
            "findings",
            "observations",
            "workers",
        ):
            assert table_rows(connection, name) == before[name]
        cluster = table_rows(connection, "clusters")[0]
        assert cluster == {
            **{
                k: v
                for k, v in before["clusters"][0].items()
                if k != "oidc_provider_id"
            },
            "auth_generation": 7,
            "auth_type": "kubeconfig",
            "lifecycle": "ready",
            "draft_owner_id": None,
            "draft_expires_at": None,
            "context_namespace_hint": None,
        }
        assert table_rows(connection, "authorization_bindings") == [
            {**binding, "generation": 9} for binding in before["authorization_bindings"]
        ]
        assert not table_rows(connection, "cluster_credentials")
        assert "oidc_transactions" not in sa.inspect(connection).get_table_names()
        assert "oidc_providers" not in sa.inspect(connection).get_table_names()
        policy = table_rows(connection, "integration_policy")[0]
        assert policy["revision"] == 8
        assert policy["rules"] == before["integration_policy"][0]["rules"]
        runs = {run["id"]: run for run in table_rows(connection, "runs")}
        for old in before["runs"]:
            run = runs[old["id"]]
            if old["status"] in {"queued", "running"}:
                assert (
                    run["status"]
                    == {"queued": "cancelled", "running": "interrupted"}[old["status"]]
                )
                assert run["stage"] == "cleanup" and run["cancel_requested"]
                assert run["finished_at"] and run["credential_expires_at"] is None
                assert run["worker_id"] is None and run["lease_until"] is None
                assert "namespace selection upgrade" in run["error"]
                for field in (
                    "scope",
                    "coverage",
                    "limitations",
                    "versions",
                    "created_at",
                    "started_at",
                    "source",
                ):
                    assert run[field] == old[field]
            else:
                expected = {
                    k: v
                    for k, v in dict(old, credential=None).items()
                    if k != "provider_revision"
                }
                if old["lease_until"]:
                    expected.update(lease_until=None, worker_id=None)
                assert run == expected
            assert run["credential"] is None
        events = table_rows(connection, "audit_events")
        assert before["audit_events"][0] in events and len(events) == 4
    assert not migrations.upgrade_database(b1, apply=True)["changes_required"]


@pytest.mark.parametrize(
    "backup,offline", [(False, False), (True, False), (False, True)]
)
def test_b1_requires_both_confirmations_without_modification(b1, backup, offline):
    with b1.connect() as connection:
        before = all_rows(connection)
    with pytest.raises(DomainError, match="backup-confirmed"):
        migrations.upgrade_database(
            b1, apply=True, backup_confirmed=backup, offline_confirmed=offline
        )
    with b1.connect() as connection:
        assert all_rows(connection) == before


def test_b1_failed_upgrade_restores_ddl_data_revisions_and_credentials(b1, monkeypatch):
    with b1.connect() as connection:
        before = all_rows(connection)
    original = migrations.command.upgrade

    def fail_after_upgrade(config, revision):
        original(config, revision)
        raise RuntimeError("synthetic post-DDL failure")

    monkeypatch.setattr(migrations.command, "upgrade", fail_after_upgrade)
    with pytest.raises(RuntimeError, match="synthetic"):
        migrations.upgrade_database(
            b1, apply=True, backup_confirmed=True, offline_confirmed=True
        )
    with b1.connect() as connection:
        assert migrations.verify_schema(connection) == "0.2.0"
        assert all_rows(connection) == before
        assert verify_database_key(connection, KEY) == 10


@pytest.mark.parametrize("version,revision,factory", VERSIONS[:2])
def test_only_exact_unversioned_baseline_is_stamped(
    version, revision, factory, monkeypatch
):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    original = migrations.command.stamp
    stamps = []

    def record_stamp(config, target):
        stamps.append(target)
        original(config, target)

    monkeypatch.setattr(migrations.command, "stamp", record_stamp)
    try:
        with engine.begin() as connection:
            create_frozen(connection, version, revision, factory())
        migrations.upgrade_database(
            engine, apply=True, backup_confirmed=True, offline_confirmed=True
        )
        assert stamps == (["0001_baseline"] if version == "0.1.0" else [])
    finally:
        engine.dispose()


@pytest.mark.parametrize("version,revision,factory", VERSIONS[1:])
@pytest.mark.parametrize("marker", ["missing", "wrong", "multiple", "old-version"])
def test_version_and_revision_must_match_exact_frozen_shape(
    version, revision, factory, marker
):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    try:
        with engine.begin() as connection:
            create_frozen(connection, version, revision, factory())
            if marker == "missing":
                connection.exec_driver_sql("DROP TABLE alembic_version")
            elif marker == "wrong":
                connection.exec_driver_sql(
                    "UPDATE alembic_version SET version_num='0001_baseline'"
                )
            elif marker == "multiple":
                connection.exec_driver_sql(
                    "INSERT INTO alembic_version VALUES ('unknown')"
                )
            else:
                connection.exec_driver_sql(
                    "UPDATE workbench_schema SET version='0.1.0'"
                )
            before = all_rows(connection)
        with pytest.raises(DomainError):
            migrations.upgrade_database(
                engine, apply=True, backup_confirmed=True, offline_confirmed=True
            )
        with engine.connect() as connection:
            assert all_rows(connection) == before
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "mutation",
    [
        "nullable",
        "default",
        "default-case",
        "default-cast",
        "length",
        "fk",
        "index",
        "extra",
    ],
)
def test_namespace_shape_is_strict_even_with_valid_markers(mutation):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    schema = namespace_metadata()
    clusters = schema.tables["clusters"]
    if mutation == "nullable":
        clusters.c.lifecycle.nullable = True
    elif mutation == "default":
        clusters.c.lifecycle.server_default = sa.DefaultClause("draft")
    elif mutation == "default-case":
        clusters.c.lifecycle.server_default = sa.DefaultClause("READY")
    elif mutation == "default-cast":
        clusters.c.lifecycle.server_default = sa.DefaultClause("ready::not-a-cast")
    elif mutation == "length":
        clusters.c.context_namespace_hint.type = sa.String(64)
    elif mutation == "fk":
        next(iter(clusters.foreign_key_constraints)).ondelete = "SET NULL"
    elif mutation == "index":
        clusters.indexes.clear()
    else:
        clusters.append_column(sa.Column("scope_revision", sa.Integer))
    try:
        with engine.begin() as connection:
            create_frozen(connection, "0.3.0", "0003_namespace_selection", schema)
        with engine.connect() as connection, pytest.raises(DomainError):
            migrations.verify_schema(connection)
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "clause",
    ["ON DELETE SET NULL", "ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED"],
)
def test_inline_sqlite_fk_options_cannot_bypass_strict_schema_checks(clause):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    schema = b1_metadata()
    # Build the parent as B1 would and ADD the owner FK inline, as the SQLite
    # migration does. SQLAlchemy drops inline FK options during reflection.
    clusters = schema.tables["clusters"]
    clusters.append_column(
        sa.Column("lifecycle", sa.String(20), nullable=False, server_default="ready")
    )
    clusters.append_column(
        sa.Column("draft_expires_at", sa.DateTime(timezone=True), index=True)
    )
    clusters.append_column(sa.Column("context_namespace_hint", sa.String(63)))
    try:
        with engine.begin() as connection:
            create_frozen(connection, "0.3.0", "0003_namespace_selection", schema)
            connection.exec_driver_sql(
                "ALTER TABLE clusters ADD COLUMN draft_owner_id VARCHAR(36) "
                f"REFERENCES users (id) {clause}"
            )
        with engine.connect() as connection, pytest.raises(DomainError):
            migrations.verify_schema(connection)
    finally:
        engine.dispose()


def test_older_binary_runtime_constants_reject_namespace_schema(monkeypatch):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    try:
        migrations.init_database(engine)
        monkeypatch.setattr(migrations, "SCHEMA_VERSION", "0.2.0")
        monkeypatch.setattr(migrations, "HEAD_REVISION", "0002_b1")
        with engine.connect() as connection, pytest.raises(DomainError) as error:
            migrations.require_runtime_schema(connection)
        assert error.value.code == "schema_upgrade_required"
    finally:
        engine.dispose()


def test_frozen_01_02_metadata_is_not_mutated_by_namespace_snapshot():
    namespace_metadata()
    for factory in (baseline_metadata, b1_metadata):
        assert not {
            "lifecycle",
            "draft_owner_id",
            "draft_expires_at",
            "context_namespace_hint",
        } & set(factory().tables["clusters"].c.keys())


def test_draft_owner_cascade_and_ready_connection_survival():
    engine, sessions = database("sqlite+pysqlite:///:memory:")
    try:
        migrations.init_database(engine)
        with sessions.begin() as session:
            session.add(
                User(
                    id="owner",
                    username="owner",
                    password_hash="synthetic",
                    role="administrator",
                )
            )
            session.flush()
            for cluster_id in ("draft", "ready"):
                session.add(
                    Cluster(
                        id=cluster_id,
                        name=cluster_id,
                        context="ctx",
                        server="https://kube.example.test",
                        namespaces=[] if cluster_id == "draft" else ["app"],
                        **(
                            {
                                "lifecycle": "draft",
                                "draft_owner_id": "owner",
                                "draft_expires_at": TIMESTAMP,
                            }
                            if cluster_id == "draft"
                            else {}
                        ),
                    )
                )
        with sessions.begin() as session:
            assert session.get(Cluster, "ready").lifecycle == "ready"
            session.execute(sa.delete(User).where(User.id == "owner"))
        with sessions() as session:
            assert session.get(Cluster, "draft") is None
            assert session.get(Cluster, "ready").draft_owner_id is None
            migrations.require_latest(session.connection())
    finally:
        engine.dispose()
