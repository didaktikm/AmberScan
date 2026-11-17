"""CLI wiring is tested with synthetic settings and isolated database fixtures."""

import base64
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from workbench import admin
from workbench.config import Settings
from workbench.db import AuditEvent, Cluster, ClusterGrant, User, database, now
from workbench.domain import DomainError

KEY = base64.urlsafe_b64encode(b"a" * 32).decode()


@pytest.fixture
def configured(monkeypatch):
    settings = Settings(database_url="sqlite+pysqlite:///:memory:", master_key=KEY)
    engine, sessions = database(settings.database_url)
    monkeypatch.setattr(admin.Settings, "from_env", lambda: settings)
    monkeypatch.setattr(admin, "database", lambda _: (engine, sessions))
    return engine, sessions


def test_cli_upgrade_is_preview_by_default(configured, monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(
        admin,
        "upgrade_database",
        lambda engine, **kwargs: seen.append(kwargs) or {"applied": False},
    )
    admin.main(["upgrade"])
    assert seen == [
        {"apply": False, "backup_confirmed": False, "offline_confirmed": False}
    ]
    assert json.loads(capsys.readouterr().out) == {"applied": False}


def test_cli_upgrade_forwards_explicit_acknowledgements(configured, monkeypatch):
    seen = []
    monkeypatch.setattr(
        admin,
        "upgrade_database",
        lambda engine, **kwargs: seen.append(kwargs) or {"applied": True},
    )
    admin.main(["upgrade", "--apply", "--backup-confirmed", "--offline-confirmed"])
    assert seen == [
        {"apply": True, "backup_confirmed": True, "offline_confirmed": True}
    ]


@pytest.mark.parametrize("command", ["backup", "restore"])
def test_cli_recovery_passes_secrets_in_memory_not_output(
    configured, monkeypatch, capsys, command
):
    calls = []

    def operation(*args, **kwargs):
        calls.append((args, kwargs))
        return {"verified": True}

    monkeypatch.setattr(admin, f"{command}_database", operation)
    tool_option = "--pg-dump" if command == "backup" else "--pg-restore"
    admin.main(
        [
            command,
            "/disposable/archive.dump",
            "--offline-confirmed",
            tool_option,
            "/tools/client",
            "--timeout",
            "25",
        ]
    )
    assert calls[0][0][1:] == ("/disposable/archive.dump", KEY)
    assert calls[0][1]["offline_confirmed"] is True
    assert calls[0][1]["timeout"] == 25
    assert KEY not in capsys.readouterr().out


def test_cli_error_boundary_never_echoes_database_urls(monkeypatch):
    def fail():
        raise OperationalError(
            "SELECT secret",
            {"password": "private-password"},
            Exception("postgresql://user:private-password@server/db"),
        )

    monkeypatch.setattr(admin, "main", fail)
    with pytest.raises(SystemExit) as error:
        admin.cli()
    assert "private-password" not in str(error.value)
    assert "postgresql://" not in str(error.value)


def test_empty_status_has_no_unverifiable_key_claim(configured, capsys):
    admin.main(["status"])
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == "empty"
    assert result["encrypted_values_checked"] == 0
    assert "cannot be verified" in result["key_evidence"]


@pytest.mark.parametrize("auth_type", ["kubeconfig"])
@pytest.mark.parametrize("lifecycle", ["draft", "unknown", "ready"])
def test_offline_grant_requires_ready_connection(
    configured, monkeypatch, capsys, lifecycle, auth_type
):
    engine, sessions = configured
    admin.init_database(engine)
    # Keep the isolated in-memory database available after the CLI disposes its proxy.
    proxy = SimpleNamespace(dispose=lambda: None)
    monkeypatch.setattr(admin, "database", lambda _: (proxy, sessions))
    try:
        with sessions.begin() as session:
            session.add(
                User(
                    id="u", username="reader", password_hash="synthetic", role="viewer"
                )
            )
            session.flush()
            session.add(
                Cluster(
                    id="c",
                    name="connection",
                    context="ctx",
                    server="https://kube.example.test",
                    auth_type=auth_type,
                    namespaces=["app"] if lifecycle == "ready" else [],
                    lifecycle=lifecycle,
                    draft_owner_id=None if lifecycle == "ready" else "u",
                    draft_expires_at=None
                    if lifecycle == "ready"
                    else now() + timedelta(days=1),
                )
            )
        if lifecycle != "ready":
            with pytest.raises(DomainError) as error:
                admin.main(["grant", "reader", "c"])
            assert error.value.code == "connection_not_ready"
            assert capsys.readouterr().out == ""
        else:
            admin.main(["grant", "reader", "c"])
            assert "access granted" in capsys.readouterr().out
        with sessions() as session:
            assert (session.get(ClusterGrant, ("u", "c")) is not None) == (
                lifecycle == "ready"
            )
            events = list(
                session.scalars(
                    select(AuditEvent).where(AuditEvent.action == "cluster_grant")
                )
            )
            assert len(events) == (1 if lifecycle == "ready" else 0)
    finally:
        engine.dispose()


def test_legacy_import_cli_preview_and_apply_commit(monkeypatch, capsys):
    from workbench import configuration
    from workbench.db import IntegrationPolicy
    from workbench.migrations import init_database

    engine, sessions = database("sqlite+pysqlite:///:memory:")
    init_database(engine)
    # main disposes its engine; use a proxy so this test can inspect after each invocation.
    proxy = SimpleNamespace(connect=engine.connect, dispose=lambda: None)
    monkeypatch.setattr(admin, "database", lambda _: (proxy, sessions))
    monkeypatch.setattr(
        admin.Settings,
        "from_env",
        lambda: Settings(database_url="unused", master_key=KEY),
    )
    calls = []

    def import_configuration(session, settings, vault, apply=False):
        calls.append(apply)
        if apply:
            session.get(IntegrationPolicy, 1).legacy_imported = True
        return {"applied": apply}

    monkeypatch.setattr(
        configuration, "import_legacy_configuration", import_configuration
    )
    try:
        admin.main(["import-legacy"])
        assert calls == [False]
        with sessions() as session:
            assert session.get(IntegrationPolicy, 1).legacy_imported is False
        with pytest.raises(DomainError, match="offline-confirmed"):
            admin.main(["import-legacy", "--apply"])
        admin.main(["import-legacy", "--apply", "--offline-confirmed"])
        with sessions() as session:
            assert session.get(IntegrationPolicy, 1).legacy_imported is True
        assert KEY not in capsys.readouterr().out
    finally:
        engine.dispose()
