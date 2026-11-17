"""Recovery safety tests use subprocess mocks and synthetic data, never real PG."""

import base64
import json
import os
import stat
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import make_url

import workbench.backup as recovery
from workbench.db import database
from workbench.domain import DomainError
from workbench.migrations import (
    SCHEMA_VERSION,
    SUPPORTED_VERSIONS,
    init_database,
    schema_metadata,
)
from workbench.security import Vault

KEY = base64.urlsafe_b64encode(b"b" * 32).decode()
WRONG_KEY = base64.urlsafe_b64encode(b"w" * 32).decode()
# A wholly synthetic connection: no database is opened in these mock tests.
URL = make_url(
    "postgresql+psycopg://backupuser:synthetic-password%3A%5C@example.invalid:5432/testdb"
)
ARCHIVE = b"PGDMP\x01synthetic-custom-archive-for-mocks"


class Connection:
    dialect = SimpleNamespace(
        identifier_preparer=SimpleNamespace(quote=lambda name: f'"{name}"')
    )

    def __init__(self):
        self.sql = []

    def execute(self, statement):
        sql = str(statement)
        self.sql.append(sql)
        assert sql.startswith("LOCK TABLE ") or sql == "SELECT pg_export_snapshot()"
        return SimpleNamespace(scalar_one=lambda: "00000001-00000001-1")


@pytest.fixture
def mocked_pg(monkeypatch):
    engine = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"), url=URL)
    connection = Connection()
    events = []

    @contextmanager
    def transaction(_engine):
        assert _engine is engine
        events.append("connect")
        yield connection

    monkeypatch.setattr(recovery, "guarded_transaction", transaction)
    monkeypatch.setattr(recovery, "verify_schema", lambda _: SCHEMA_VERSION)
    monkeypatch.setattr(recovery, "verify_database_key", lambda *_: 2)
    monkeypatch.setattr(recovery, "require_offline", lambda _: events.append("offline"))
    monkeypatch.setattr(
        recovery, "assert_empty_database", lambda _: events.append("empty")
    )
    return engine, connection, events


def dump_mock(argv, **kwargs):
    assert argv[0] == "pg_dump"
    assert kwargs["shell"] is False
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["timeout"] == 300
    assert kwargs["stdout"] is not subprocess.DEVNULL
    kwargs["stdout"].write(ARCHIVE)
    return SimpleNamespace(returncode=0)


def make_backup(mocked_pg, monkeypatch, tmp_path):
    engine, _, _ = mocked_pg
    monkeypatch.setattr(recovery.subprocess, "run", dump_mock)
    path = tmp_path / "snapshot.dump"
    recovery.backup_database(engine, path, KEY, offline_confirmed=True)
    return path


def test_backup_private_outputs_snapshot_and_secure_pgpass(
    mocked_pg, monkeypatch, tmp_path
):
    engine, connection, events = mocked_pg
    seen = {}
    monkeypatch.setenv("PGPASSWORD", "inherited-password-must-not-leak")
    monkeypatch.setenv("PGSERVICE", "untrusted-service")
    monkeypatch.setenv("WORKBENCH_MASTER_KEY", KEY)

    def run(argv, **kwargs):
        seen.update(argv=argv, environment=dict(kwargs["env"]))
        pgpass = Path(kwargs["env"]["PGPASSFILE"])
        seen["pgpass"] = pgpass
        assert stat.S_IMODE(pgpass.stat().st_mode) == 0o600
        assert stat.S_IMODE(pgpass.parent.stat().st_mode) == 0o700
        assert (
            pgpass.read_text()
            == "example.invalid:5432:testdb:backupuser:synthetic-password\\:\\\\\n"
        )
        assert "synthetic-password" not in str(argv)
        assert "synthetic-password" not in str(kwargs["env"])
        assert "PGPASSWORD" not in kwargs["env"]
        assert "PGSERVICE" not in kwargs["env"]
        assert "WORKBENCH_MASTER_KEY" not in kwargs["env"]
        assert all(KEY not in str(value) for value in kwargs["env"].values())
        assert "--snapshot=00000001-00000001-1" in argv
        return dump_mock(argv, **kwargs)

    monkeypatch.setattr(recovery.subprocess, "run", run)
    path = tmp_path / "snapshot.dump"
    result = recovery.backup_database(engine, path, KEY, offline_confirmed=True)
    manifest = recovery._manifest_path(path)
    assert result == {
        "schema_version": SCHEMA_VERSION,
        "size": len(ARCHIVE),
        "encrypted_values_checked": 2,
        "master_key_included": False,
    }
    assert path.read_bytes() == ARCHIVE
    assert (
        stat.S_IMODE(path.stat().st_mode)
        == stat.S_IMODE(manifest.stat().st_mode)
        == 0o600
    )
    assert KEY not in manifest.read_text()
    assert "synthetic-password" not in manifest.read_text()
    assert not seen["pgpass"].exists()
    assert events == ["connect", "offline"]
    assert connection.sql[0].startswith("LOCK TABLE ")
    assert connection.sql[-1] == "SELECT pg_export_snapshot()"


def test_backup_never_overwrites_existing_output_or_sidecar(
    mocked_pg, monkeypatch, tmp_path
):
    engine, _, _ = mocked_pg
    monkeypatch.setattr(
        recovery.subprocess, "run", lambda *_a, **_kw: pytest.fail("must not run")
    )
    path = tmp_path / "snapshot.dump"
    path.write_bytes(b"existing backup")
    with pytest.raises(DomainError, match="never overwritten"):
        recovery.backup_database(engine, path, KEY, offline_confirmed=True)
    assert path.read_bytes() == b"existing backup"
    path.unlink()
    manifest = recovery._manifest_path(path)
    manifest.write_text("existing manifest")
    with pytest.raises(DomainError, match="never overwritten"):
        recovery.backup_database(engine, path, KEY, offline_confirmed=True)
    assert not path.exists()
    assert manifest.read_text() == "existing manifest"


@pytest.mark.parametrize("failure", ["missing", "timeout", "exit", "invalid"])
def test_failed_dump_removes_only_own_outputs_and_sanitizes_errors(
    mocked_pg, monkeypatch, tmp_path, failure
):
    engine, _, _ = mocked_pg
    passfiles = []

    def run(argv, **kwargs):
        passfiles.append(Path(kwargs["env"]["PGPASSFILE"]))
        if failure == "missing":
            raise FileNotFoundError("sensitive-server-and-password")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(
                argv, 300, output="sensitive-server-and-password"
            )
        if failure == "invalid":
            kwargs["stdout"].write(b"not-custom-format")
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(returncode=1, stderr="sensitive-server-and-password")

    monkeypatch.setattr(recovery.subprocess, "run", run)
    path = tmp_path / "failed.dump"
    with pytest.raises(DomainError) as error:
        recovery.backup_database(engine, path, KEY, offline_confirmed=True)
    assert "sensitive-server-and-password" not in str(error.value)
    assert not path.exists()
    assert not recovery._manifest_path(path).exists()
    assert all(not path.exists() for path in passfiles)


def test_backup_requires_offline_confirmation_before_files(mocked_pg, tmp_path):
    engine, _, events = mocked_pg
    with pytest.raises(DomainError, match="offline-confirmed"):
        recovery.backup_database(engine, tmp_path / "unused.dump", KEY)
    assert not list(tmp_path.iterdir())
    assert not events


def test_backup_rejects_live_database_clients(mocked_pg, monkeypatch, tmp_path):
    engine, _, _ = mocked_pg

    def reject(_):
        raise DomainError("Stop API/workers")

    monkeypatch.setattr(recovery, "require_offline", reject)
    monkeypatch.setattr(
        recovery.subprocess, "run", lambda *_a, **_kw: pytest.fail("must not run")
    )
    with pytest.raises(DomainError, match="Stop"):
        recovery.backup_database(
            engine, tmp_path / "unused.dump", KEY, offline_confirmed=True
        )
    assert not list(tmp_path.iterdir())


def test_restore_verifies_key_and_checksum_before_target_connection(
    mocked_pg, monkeypatch, tmp_path
):
    engine, _, events = mocked_pg
    path = make_backup(mocked_pg, monkeypatch, tmp_path)
    events.clear()
    monkeypatch.setattr(
        recovery.subprocess, "run", lambda *_a, **_kw: pytest.fail("must not restore")
    )
    with pytest.raises(DomainError, match="master key"):
        recovery.restore_database(engine, path, WRONG_KEY, offline_confirmed=True)
    assert not events
    path.write_bytes(ARCHIVE + b"tampered")
    with pytest.raises(DomainError, match="checksum"):
        recovery.restore_database(engine, path, KEY, offline_confirmed=True)
    assert not events


def test_manifest_metadata_is_authenticated(mocked_pg, monkeypatch, tmp_path):
    engine, _, events = mocked_pg
    path = make_backup(mocked_pg, monkeypatch, tmp_path)
    manifest_path = recovery._manifest_path(path)
    manifest = json.loads(manifest_path.read_text())
    manifest["encrypted_values_checked"] = 0
    manifest_path.write_text(json.dumps(manifest))
    events.clear()
    with pytest.raises(DomainError, match="manifest"):
        recovery.restore_database(engine, path, KEY, offline_confirmed=True)
    assert not events


def test_restore_empty_target_single_transaction_safe_argv(
    mocked_pg, monkeypatch, tmp_path
):
    engine, _, events = mocked_pg
    path = make_backup(mocked_pg, monkeypatch, tmp_path)
    events.clear()
    seen = []

    def restore(argv, **kwargs):
        seen.extend(argv)
        assert events == ["connect", "offline", "empty"]
        assert kwargs["shell"] is False
        # Match an exec child, which reads the inherited raw fd, not the
        # parent's Python buffer (regression: header verification moved it).
        assert os.lseek(kwargs["stdin"].fileno(), 0, os.SEEK_CUR) == 0
        assert os.read(kwargs["stdin"].fileno(), len(ARCHIVE) + 1) == ARCHIVE
        assert "--single-transaction" in argv
        assert "--exit-on-error" in argv
        assert "--clean" not in argv and "--create" not in argv
        assert "synthetic-password" not in str(argv)
        assert KEY not in str(argv)
        assert kwargs["stdout"] is subprocess.DEVNULL
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(recovery.subprocess, "run", restore)
    result = recovery.restore_database(engine, path, KEY, offline_confirmed=True)
    assert seen[0] == "pg_restore"
    assert result == {
        "schema_version": SCHEMA_VERSION,
        "encrypted_values_checked": 2,
        "verified": True,
    }


def test_restore_never_runs_on_nonempty_target(mocked_pg, monkeypatch, tmp_path):
    engine, _, _ = mocked_pg
    path = make_backup(mocked_pg, monkeypatch, tmp_path)

    def reject(_):
        raise DomainError("Database is not empty")

    monkeypatch.setattr(recovery, "assert_empty_database", reject)
    monkeypatch.setattr(
        recovery.subprocess, "run", lambda *_a, **_kw: pytest.fail("must not restore")
    )
    with pytest.raises(DomainError, match="not empty"):
        recovery.restore_database(engine, path, KEY, offline_confirmed=True)


def test_restore_postcheck_does_not_erase_unverified_target(
    mocked_pg, monkeypatch, tmp_path
):
    engine, _, _ = mocked_pg
    path = make_backup(mocked_pg, monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        recovery.subprocess,
        "run",
        lambda *a, **kw: calls.append(a) or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(recovery, "verify_database_key", lambda *_: 1)
    with pytest.raises(DomainError, match="keep target offline"):
        recovery.restore_database(engine, path, KEY, offline_confirmed=True)
    assert len(calls) == 1
    assert path.exists()


def test_restore_input_permissions_and_symlinks_fail_closed(
    mocked_pg, monkeypatch, tmp_path
):
    engine, _, _ = mocked_pg
    path = make_backup(mocked_pg, monkeypatch, tmp_path)
    path.chmod(0o644)
    with pytest.raises(DomainError, match="0600"):
        recovery.restore_database(engine, path, KEY, offline_confirmed=True)
    path.chmod(0o600)
    target = tmp_path / "link.dump"
    target.symlink_to(path)
    with pytest.raises(DomainError, match="symlinks"):
        recovery.restore_database(engine, target, KEY, offline_confirmed=True)


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///file",
        "postgresql://user:password@host/db?options=unsafe",
        "postgresql://user:new%0Aline@host/db",
        "postgresql://user:pass@host/a=b",
    ],
)
def test_unsafe_connection_configuration_rejected_without_secrets(url):
    with pytest.raises(DomainError) as error, recovery.postgres_environment(url):
        pytest.fail("connection configuration must be rejected")
    assert "password" not in str(error.value)
    assert "new" not in str(error.value)


def test_pgpass_and_ssl_environment_use_explicit_options():
    with recovery.postgres_environment(
        "postgresql://user:p%3Aa%5Css@host/db?sslmode=verify-full&sslrootcert=%2Fcert.pem"
    ) as environment:
        assert environment["PGSSLMODE"] == "verify-full"
        assert environment["PGSSLROOTCERT"] == "/cert.pem"
        path = Path(environment["PGPASSFILE"])
        assert "p\\:a\\\\ss" in path.read_text()
    assert not path.exists()


@pytest.mark.parametrize("version", ["0.2.0", "0.3.0", "0.4.0"])
def test_historical_database_key_verifies_ciphertexts_and_provider_revision(version):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    schema_metadata(version).create_all(engine)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text("""
                INSERT INTO oidc_providers
                (id, revision, enabled, display_name, config, encrypted_secret, verification, created_at, updated_at)
                VALUES ('idp', 3, true, 'Identity', '{}', :secret, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """),
                {
                    "secret": Vault(KEY).encrypt(
                        {"client_secret": "synthetic-only"}, "provider:idp:3"
                    )
                },
            )
            assert recovery.verify_database_key(connection, KEY) == 1
            with pytest.raises(DomainError, match="Master key"):
                recovery.verify_database_key(connection, WRONG_KEY)
            connection.execute(sa.text("UPDATE oidc_providers SET revision=4"))
            with pytest.raises(DomainError, match="Master key"):
                recovery.verify_database_key(connection, KEY)
    finally:
        engine.dispose()


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_backup_restore_each_frozen_schema_without_implicit_upgrade(
    mocked_pg, monkeypatch, tmp_path, version
):
    engine, connection, events = mocked_pg
    monkeypatch.setattr(recovery, "verify_schema", lambda _: version)
    path = make_backup(mocked_pg, monkeypatch, tmp_path)
    assert (
        json.loads(recovery._manifest_path(path).read_text())["schema_version"]
        == version
    )
    locked_names = (
        connection.sql[0].removeprefix("LOCK TABLE ").removesuffix(" IN SHARE MODE")
    )
    assert set(locked_names.split(", ")) == {
        f'"{name}"' for name in schema_metadata(version).tables
    }
    events.clear()
    calls = []

    def restore(argv, **kwargs):
        assert events == ["connect", "offline", "empty"]
        assert kwargs["stdin"].read() == ARCHIVE
        calls.append(argv[0])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(recovery.subprocess, "run", restore)
    result = recovery.restore_database(engine, path, KEY, offline_confirmed=True)
    assert result == {
        "schema_version": version,
        "encrypted_values_checked": 2,
        "verified": True,
    }
    assert calls == ["pg_restore"]


@pytest.mark.parametrize("version", ["0.0.0", "0.6.0", "0005_remove_oidc"])
def test_authenticated_unsupported_manifest_is_refused_before_target(
    mocked_pg, monkeypatch, tmp_path, version
):
    engine, _, events = mocked_pg
    path = make_backup(mocked_pg, monkeypatch, tmp_path)
    manifest_path = recovery._manifest_path(path)
    manifest = json.loads(manifest_path.read_text())
    claims = {key: value for key, value in manifest.items() if key != "key_check"}
    claims["schema_version"] = version
    manifest_path.write_text(
        json.dumps(
            dict(claims, key_check=Vault(KEY).encrypt(claims, recovery.KEY_PURPOSE))
        )
    )
    events.clear()
    monkeypatch.setattr(
        recovery.subprocess, "run", lambda *_a, **_kw: pytest.fail("must not restore")
    )
    with pytest.raises(DomainError, match="manifest"):
        recovery.restore_database(engine, path, KEY, offline_confirmed=True)
    assert not events


def test_restore_never_accepts_different_supported_schema_version(
    mocked_pg, monkeypatch, tmp_path
):
    engine, _, _ = mocked_pg
    monkeypatch.setattr(recovery, "verify_schema", lambda _: "0.2.0")
    path = make_backup(mocked_pg, monkeypatch, tmp_path)
    monkeypatch.setattr(recovery, "verify_schema", lambda _: "0.3.0")
    monkeypatch.setattr(
        recovery.subprocess, "run", lambda *_a, **_kw: SimpleNamespace(returncode=0)
    )
    with pytest.raises(DomainError, match="keep target offline"):
        recovery.restore_database(engine, path, KEY, offline_confirmed=True)
    assert path.exists()


def test_backup_refuses_schema_drift_without_outputs_or_dump(
    mocked_pg, monkeypatch, tmp_path
):
    engine, _, _ = mocked_pg

    def drift(_):
        raise DomainError("Unsupported schema structure", "schema_unsupported")

    monkeypatch.setattr(recovery, "verify_schema", drift)
    monkeypatch.setattr(
        recovery.subprocess, "run", lambda *_a, **_kw: pytest.fail("must not dump")
    )
    with pytest.raises(DomainError, match="Unsupported"):
        recovery.backup_database(
            engine, tmp_path / "refused.dump", KEY, offline_confirmed=True
        )
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "auth",
    [
        {"version": 1, "kind": "token", "token": "synthetic-token"},
        {
            "version": 1,
            "kind": "client_certificate",
            "certificate_pem": "synthetic-cert",
            "private_key_pem": "synthetic-key",
        },
    ],
)
def test_providerless_normalized_credentials_and_snapshots_are_key_verified(auth):
    from datetime import timedelta

    from workbench.db import Cluster, ClusterCredential, Run, User, now

    engine, sessions = database("sqlite+pysqlite:///:memory:")
    init_database(engine)
    try:
        vault = Vault(KEY)
        with sessions.begin() as session:
            session.add(
                User(id="u", username="u", role="auditor", password_hash="synthetic")
            )
            session.flush()
            session.add(
                Cluster(
                    id="c",
                    name="kubeconfig",
                    context="ctx",
                    server="https://kube.example.test",
                    namespaces=["app"],
                    auth_type="kubeconfig",
                )
            )
            session.flush()
            session.add(
                ClusterCredential(
                    user_id="u",
                    cluster_id="c",
                    encrypted=vault.encrypt(auth, "credential:u:c"),
                    expires_at=now() + timedelta(hours=1),
                )
            )
            session.add(
                Run(
                    id="r",
                    actor_id="u",
                    cluster_id="c",
                    scope={"namespaces": ["app"]},
                    credential=vault.encrypt({"auth": auth}, "run:r"),
                )
            )
        with engine.connect() as connection:
            assert recovery.verify_database_key(connection, KEY) == 2
            with pytest.raises(DomainError, match="Master key"):
                recovery.verify_database_key(connection, WRONG_KEY)
    finally:
        engine.dispose()


def test_sqlite_cannot_be_used_for_real_backup(tmp_path):
    engine, _ = database("sqlite+pysqlite:///:memory:")
    try:
        with pytest.raises(DomainError, match="require PostgreSQL"):
            recovery.backup_database(
                engine, tmp_path / "no.dump", KEY, offline_confirmed=True
            )
    finally:
        engine.dispose()
