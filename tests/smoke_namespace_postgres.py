"""Explicit disposable PostgreSQL smoke; no existing stack, volume or secrets.

PYTHONPATH=src uv run --frozen python tests/smoke_namespace_postgres.py
Requires cached postgres:17.5-bookworm and compatible Workbench maintenance image.
Only this script's random, labelled network:none containers are removed on exit.
"""

import argparse
import base64
import secrets
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABEL = "amberdata.namespace-smoke"


def inside() -> None:
    import sqlalchemy as sa
    from sqlalchemy.pool import NullPool

    from workbench import migrations
    from workbench.alembic.schema_v01 import metadata as v01
    from workbench.alembic.schema_v02 import metadata as v02
    from workbench.alembic.schema_v03 import metadata as v03
    from workbench.alembic.schema_v04 import metadata as v04
    from workbench.backup import backup_database, restore_database
    from workbench.domain import DomainError
    from workbench.migrations import (
        HEAD_REVISION,
        SCHEMA_VERSION,
        init_database,
        require_runtime_schema,
        upgrade_database,
        verify_schema,
    )
    from workbench.security import Vault

    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    vault = Vault(key)
    timestamp = datetime.now(UTC)
    admin = sa.create_engine(
        "postgresql+psycopg://postgres@127.0.0.1/postgres",
        isolation_level="AUTOCOMMIT",
        poolclass=NullPool,
    )

    def new_database(name):
        assert name.startswith("namespace_smoke_") and name.replace("_", "").isalnum()
        with admin.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
        return sa.create_engine(
            f"postgresql+psycopg://postgres@127.0.0.1/{name}",
            poolclass=NullPool,
        )

    def seed(engine, version, metadata):
        schema = metadata()
        with engine.begin() as connection:
            schema.create_all(connection)
            connection.execute(
                schema.tables["workbench_schema"].insert().values(version=version)
            )
            if version != "0.1.0":
                connection.execute(
                    schema.tables["alembic_version"]
                    .insert()
                    .values(version_num=migrations.VERSION_REVISIONS[version])
                )
            connection.execute(
                schema.tables["users"]
                .insert()
                .values(
                    id="owner",
                    username="owner",
                    password_hash="synthetic-only-hash",
                    role="administrator",
                    active=True,
                    failed_logins=0,
                )
            )
            connection.execute(
                schema.tables["clusters"]
                .insert()
                .values(
                    id="cluster",
                    name="retained",
                    environment="lab",
                    context="manual",
                    server="https://kube.example.test",
                    oidc_provider_id="idp",
                    namespaces=["payments", "apps"],
                    created_at=timestamp,
                )
            )
            if version != "0.1.0":
                connection.execute(
                    schema.tables["oidc_providers"]
                    .insert()
                    .values(
                        id="idp",
                        revision=2,
                        enabled=True,
                        display_name="Retained provider",
                        config={"issuer": "https://idp.example.test"},
                        encrypted_secret=vault.encrypt(
                            {"client_secret": "synthetic-only"}, "provider:idp:2"
                        ),
                        verification={},
                        created_at=timestamp,
                        updated_at=timestamp,
                    )
                )
                connection.execute(
                    schema.tables["integration_policy"]
                    .insert()
                    .values(
                        id=1,
                        revision=4,
                        rules=[],
                        legacy_imported=True,
                        updated_at=timestamp,
                    )
                )
            connection.execute(
                schema.tables["sessions"]
                .insert()
                .values(
                    token_hash="web-session",
                    user_id="owner",
                    csrf_token="synthetic",
                    expires_at=timestamp + timedelta(hours=1),
                )
            )
            connection.execute(
                schema.tables["cluster_grants"]
                .insert()
                .values(user_id="owner", cluster_id="cluster")
            )
            connection.execute(
                schema.tables["cluster_credentials"]
                .insert()
                .values(
                    user_id="owner",
                    cluster_id="cluster",
                    expires_at=timestamp + timedelta(hours=1),
                    encrypted=vault.encrypt(
                        {"id_token": "synthetic-only"}, "credential:owner:cluster"
                    ),
                )
            )
            connection.execute(
                schema.tables["oidc_transactions"]
                .insert()
                .values(
                    state_hash="pending",
                    session_hash="web-session",
                    cluster_id="cluster",
                    expires_at=timestamp + timedelta(minutes=5),
                    encrypted=vault.encrypt(
                        {"verifier": "synthetic-only"}, "oidc:pending"
                    ),
                )
            )
            for status in ("completed", "queued", "running"):
                connection.execute(
                    schema.tables["runs"]
                    .insert()
                    .values(
                        id=status,
                        cluster_id="cluster",
                        actor_id="owner",
                        status=status,
                        stage="execute",
                        scope={"namespaces": ["payments"]},
                        credential=vault.encrypt(
                            {"id_token": "synthetic-only"}, f"run:{status}"
                        ),
                        cancel_requested=False,
                        created_at=timestamp,
                        started_at=timestamp if status != "queued" else None,
                        finished_at=timestamp if status == "completed" else None,
                        worker_id="old-worker" if status == "running" else None,
                        lease_until=timestamp + timedelta(minutes=1)
                        if status == "running"
                        else None,
                        coverage=[{"check": "retained", "status": "completed"}],
                        limitations=["retained"],
                        versions={},
                        source="api",
                    )
                )
            connection.execute(
                schema.tables["findings"]
                .insert()
                .values(
                    id="finding",
                    cluster_id="cluster",
                    fingerprint="retained",
                    disposition="open",
                    first_seen=timestamp,
                    last_seen=timestamp,
                    latest_run_id="completed",
                    data={"title": "synthetic observation"},
                )
            )
            connection.execute(
                schema.tables["observations"]
                .insert()
                .values(
                    run_id="completed",
                    finding_id="finding",
                    data={"retained": True},
                )
            )
            assert verify_schema(connection) == version

    fresh = new_database("namespace_smoke_fresh")
    init_database(fresh)
    with fresh.connect() as connection:
        assert verify_schema(connection) == SCHEMA_VERSION
        require_runtime_schema(connection)
    current_version, current_revision = (
        migrations.SCHEMA_VERSION,
        migrations.HEAD_REVISION,
    )
    try:
        migrations.SCHEMA_VERSION, migrations.HEAD_REVISION = (
            "0.3.0",
            "0003_namespace_selection",
        )
        with fresh.connect() as connection:
            try:
                require_runtime_schema(connection)
            except DomainError as error:
                assert error.code == "schema_upgrade_required"
            else:
                raise AssertionError("Older binary accepted 0.5 schema")
    finally:
        migrations.SCHEMA_VERSION, migrations.HEAD_REVISION = (
            current_version,
            current_revision,
        )
    # Exact PostgreSQL CHECK reflection and NOT VALID drift rejection are verified.
    with fresh.begin() as connection:
        connection.exec_driver_sql(
            "ALTER TABLE clusters ADD CONSTRAINT unexpected CHECK (length(name)>0)"
        )
        try:
            verify_schema(connection)
        except DomainError:
            pass
        else:
            raise AssertionError("Unapproved CHECK accepted")
        connection.exec_driver_sql("ALTER TABLE clusters DROP CONSTRAINT unexpected")
    from workbench.alembic.schema_v05 import AUTH_TYPE_CHECK

    for clause in (" NOT VALID", " NO INHERIT"):
        with fresh.connect() as connection, connection.begin() as transaction:
            connection.exec_driver_sql(
                "ALTER TABLE clusters DROP CONSTRAINT ck_clusters_auth_type"
            )
            connection.exec_driver_sql(
                "ALTER TABLE clusters ADD CONSTRAINT ck_clusters_auth_type CHECK ("
                + AUTH_TYPE_CHECK
                + ")"
                + clause
            )
            try:
                verify_schema(connection)
            except DomainError:
                pass
            else:
                raise AssertionError("Unvalidated or non-inherited CHECK accepted")
            transaction.rollback()
    print(
        "PASS PostgreSQL: fresh schema, exact constraints and older runtime refusal",
        flush=True,
    )

    with tempfile.TemporaryDirectory(prefix="namespace-backups-") as directory:
        for index, (version, metadata) in enumerate(
            (("0.1.0", v01), ("0.2.0", v02), ("0.3.0", v03), ("0.4.0", v04))
        ):
            engine = new_database(f"namespace_smoke_legacy_{index}")
            seed(engine, version, metadata)
            before_path = Path(directory) / f"before-{index}.dump"
            backup_database(engine, before_path, key, offline_confirmed=True)
            restored = new_database(f"namespace_smoke_restore_old_{index}")
            assert (
                restore_database(restored, before_path, key, offline_confirmed=True)[
                    "schema_version"
                ]
                == version
            )
            restored.dispose()
            assert not upgrade_database(engine)["applied"]
            assert upgrade_database(
                engine,
                apply=True,
                backup_confirmed=True,
                offline_confirmed=True,
            )["applied"]
            with engine.connect() as connection:
                assert verify_schema(connection) == SCHEMA_VERSION
                require_runtime_schema(connection)
                assert (
                    connection.execute(
                        sa.text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
                    == HEAD_REVISION
                )
                cluster = (
                    connection.execute(
                        sa.text("SELECT * FROM clusters WHERE id='cluster'")
                    )
                    .mappings()
                    .one()
                )
                assert cluster["lifecycle"] == "ready" and cluster["namespaces"] == [
                    "payments",
                    "apps",
                ]
                assert (
                    cluster["auth_type"] == "kubeconfig"
                    and "oidc_provider_id" not in cluster
                )
                assert (
                    connection.execute(
                        sa.text("SELECT count(*) FROM cluster_grants")
                    ).scalar_one()
                    == 1
                )
                assert (
                    connection.execute(
                        sa.text("SELECT count(*) FROM cluster_credentials")
                    ).scalar_one()
                    == 0
                )
                assert not {"oidc_transactions", "oidc_providers"} & set(
                    sa.inspect(connection).get_table_names()
                )
                assert (
                    cluster["draft_owner_id"] is None
                    and cluster["draft_expires_at"] is None
                )
                rows = (
                    connection.execute(
                        sa.text("SELECT id,status,scope,credential FROM runs")
                    )
                    .mappings()
                    .all()
                )
                assert {row["id"]: row["status"] for row in rows} == {
                    "completed": "completed",
                    "queued": "cancelled",
                    "running": "interrupted",
                }
                assert all(
                    row["scope"] == {"namespaces": ["payments"]}
                    and row["credential"] is None
                    for row in rows
                )
                assert (
                    connection.execute(
                        sa.text("SELECT count(*) FROM observations")
                    ).scalar_one()
                    == 1
                )
                if version != "0.1.0":
                    assert (
                        connection.execute(
                            sa.text("SELECT revision FROM integration_policy")
                        ).scalar_one()
                        == 5
                    )
            # Providerless credentials survive a real encrypted archive round-trip.
            current = migrations.schema_metadata(SCHEMA_VERSION)
            auth = {
                "version": 1,
                "kind": "token",
                "token": "synthetic-kubeconfig-token",
            }
            with engine.begin() as connection:
                connection.execute(
                    current.tables["clusters"]
                    .insert()
                    .values(
                        id="providerless",
                        name="kubeconfig",
                        environment="lab",
                        context="ctx",
                        server="https://kube.example.test",
                        namespaces=["apps"],
                        created_at=timestamp,
                        auth_type="kubeconfig",
                    )
                )
                connection.execute(
                    current.tables["cluster_credentials"]
                    .insert()
                    .values(
                        user_id="owner",
                        cluster_id="providerless",
                        expires_at=timestamp + timedelta(hours=1),
                        encrypted=vault.encrypt(auth, "credential:owner:providerless"),
                    )
                )
                verify_schema(connection)
            after_path = Path(directory) / f"after-{index}.dump"
            backup_database(engine, after_path, key, offline_confirmed=True)
            restored = new_database(f"namespace_smoke_restore_new_{index}")
            assert restore_database(restored, after_path, key, offline_confirmed=True)[
                "verified"
            ]
            with restored.connect() as connection:
                row = connection.execute(
                    sa.text(
                        "SELECT c.auth_type,k.encrypted "
                        "FROM clusters c JOIN cluster_credentials k ON k.cluster_id=c.id "
                        "WHERE c.id='providerless'"
                    )
                ).one()
                assert row.auth_type == "kubeconfig"
                assert (
                    vault.decrypt(row.encrypted, "credential:owner:providerless")
                    == auth
                )
            restored.dispose()
            engine.dispose()
            print(
                f"PASS PostgreSQL: {version} -> {SCHEMA_VERSION}, history, pre/post backup+restore",
                flush=True,
            )
    verify_concurrent_locks(fresh)
    fresh.dispose()
    admin.dispose()


def verify_concurrent_locks(engine) -> None:
    """Exercise actual PostgreSQL parent-FK and draft cleanup locking, without HTTP."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker

    from workbench.connections import cleanup_expired_drafts
    from workbench.db import Cluster, User, now

    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions.begin() as session:
        session.add(
            User(
                id="lock-owner",
                username="lock-owner",
                role="administrator",
                active=True,
                password_hash="synthetic",
            )
        )
        session.flush()
        session.add(
            Cluster(
                id="locked-draft",
                name="draft",
                environment="test",
                context="manual",
                server="https://example.test",
                namespaces=[],
                lifecycle="draft",
                draft_owner_id="lock-owner",
                draft_expires_at=now() - timedelta(seconds=1),
            )
        )

    # Cleanup skips a locked draft; after finalization the same expiry cannot delete it.
    with sessions.begin() as finalizer:
        finalizer.execute(sa.text("SET LOCAL lock_timeout='2s'"))
        cluster = finalizer.scalar(
            sa.select(Cluster).where(Cluster.id == "locked-draft").with_for_update()
        )
        with sessions.begin() as cleanup:
            cleanup.execute(sa.text("SET LOCAL lock_timeout='2s'"))
            assert cleanup_expired_drafts(cleanup) == 0
        assert cluster is not None
        cluster.lifecycle = "ready"
        cluster.namespaces = ["payments"]
        cluster.draft_owner_id = None
        cluster.draft_expires_at = None
    with sessions.begin() as cleanup:
        assert cleanup_expired_drafts(cleanup) == 0
        assert cleanup.get(Cluster, "locked-draft") is not None

    identity_locked, fk_inserted = Event(), Event()

    def identity_probe():
        with sessions.begin() as session:
            session.execute(sa.text("SET LOCAL lock_timeout='2s'"))
            # NO KEY UPDATE protects role/active state yet allows concurrent FK KEY SHARE.
            session.execute(
                sa.select(User)
                .where(User.id == "lock-owner")
                .with_for_update(key_share=True)
            )
            identity_locked.set()
            assert fk_inserted.wait(3)

    def insert_binding():
        assert identity_locked.wait(3)
        try:
            with engine.begin() as connection:
                connection.execute(sa.text("SET LOCAL lock_timeout='2s'"))
                connection.execute(
                    sa.text(
                        "INSERT INTO authorization_bindings(user_id,cluster_id,generation) VALUES ('lock-owner','locked-draft',0)"
                    )
                )
        finally:
            fk_inserted.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(identity_probe)
        second = executor.submit(insert_binding)
        first.result(timeout=5)
        second.result(timeout=5)
    print(
        "PASS PostgreSQL: locked draft cleanup/finalize and identity-lock/FK compatibility",
        flush=True,
    )


def run(maintenance_image: str) -> None:
    prefix = "amberdata-ns-smoke-" + secrets.token_hex(5)
    postgres_name, check_name = prefix + "-db", prefix + "-check"
    docker = ["docker", "--context", "desktop-linux"]

    def command(*args, timeout=120, check=True):
        return subprocess.run(
            [*docker, *args],
            check=check,
            text=True,
            capture_output=True,
            timeout=timeout,
        )

    # Inspect cache first. --pull=never below cannot fetch/publish an image.
    for image in ("postgres:17.5-bookworm", maintenance_image):
        command("image", "inspect", image)
    try:
        command(
            "run",
            "--detach",
            "--pull=never",
            "--name",
            postgres_name,
            "--label",
            f"{LABEL}={prefix}",
            "--network=none",
            "--tmpfs",
            "/var/lib/postgresql/data:rw,size=512m",
            "--env",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "postgres:17.5-bookworm",
        )
        command(
            "exec",
            postgres_name,
            "sh",
            "-c",
            "i=0; until pg_isready -U postgres -h 127.0.0.1; do i=$((i+1)); [ $i -lt 60 ] || exit 1; sleep 1; done",
            timeout=70,
        )
        result = command(
            "run",
            "--rm",
            "--pull=never",
            "--name",
            check_name,
            "--label",
            f"{LABEL}={prefix}",
            "--network",
            f"container:{postgres_name}",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=128m,mode=1777",
            "--mount",
            f"type=bind,src={ROOT / 'src'},dst=/app/src,readonly",
            "--mount",
            f"type=bind,src={Path(__file__).resolve()},dst=/check.py,readonly",
            "--entrypoint",
            "python",
            maintenance_image,
            "/check.py",
            "--inside",
            timeout=240,
        )
        print(result.stdout, end="")
    except subprocess.CalledProcessError as error:
        print(error.stdout or "", end="")
        print(error.stderr or "", end="")
        raise
    finally:
        # Names are random, and labels must match before removing test containers.
        for name in (check_name, postgres_name):
            result = command(
                "inspect",
                "--format",
                '{{index .Config.Labels "' + LABEL + '"}}',
                name,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip() == prefix:
                command("rm", "--force", name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--maintenance-image", default="amberdata-workbench-maintenance:0.5.3-local"
    )
    arguments = parser.parse_args()
    if arguments.inside:
        inside()
    else:
        run(arguments.maintenance_image)
