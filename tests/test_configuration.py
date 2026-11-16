"""Offline configuration/egress tests: no real IdP, registry, or cluster."""

import base64
import json
import secrets
import socket
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from workbench import configuration as cfg
from workbench.config import Settings
from workbench.db import (
    AuthorizationBinding,
    Base,
    Cluster,
    ClusterCredential,
    Run,
    User,
    WebSession,
    database,
    now,
    uid,
)
from workbench.domain import DomainError
from workbench.security import Vault


def rule(**updates):
    return {
        "id": "idp",
        "purpose": "registry",
        "host": "idp.example.test",
        "port": 443,
        "cidrs": ["10.42.0.10/32"],
        **updates,
    }


@pytest.fixture
def context(monkeypatch):
    for target, name in (
        (socket, "getaddrinfo"),
        (socket, "create_connection"),
        (socket.socket, "connect"),
    ):
        monkeypatch.setattr(
            target, name, Mock(side_effect=AssertionError("No network permitted"))
        )
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        master_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    )
    engine, sessions = database(settings.database_url)
    Base.metadata.create_all(engine)
    with sessions() as session:
        yield SimpleNamespace(
            settings=settings,
            engine=engine,
            sessions=sessions,
            session=session,
            vault=Vault(settings.master_key),
        )
    engine.dispose()










@pytest.mark.parametrize(
    "changes",
    [
        {"host": "localhost"},
        {"host": "127.0.0.1"},
        {"host": "169.254.169.254"},
        {"host": "metadata.google.internal"},
        {"host": "::1"},
        {"host": "*.example.test"},
        {"host": "https://idp.example.test"},
        {"host": "idp.example.test."},
        {"port": 0},
        {"port": True},
        {"port": 65536},
        {"purpose": "any"},
        {"cidrs": []},
        {"cidrs": ["10.0.0.1/24"]},
        {"cidrs": ["127.0.0.0/8"]},
        {"cidrs": ["10.42.0.10"]},
        {"cidrs": ["10.42.0.10/32", "10.42.0.10/32"]},
    ],
)
def test_invalid_egress_rules_rejected(changes):
    with pytest.raises(DomainError):
        cfg.validate_rules([rule(**changes)])


def test_rule_duplicate_endpoint_and_ids_rejected():
    with pytest.raises(DomainError):
        cfg.validate_rules([rule(), rule(id="other")])
    with pytest.raises(DomainError):
        cfg.validate_rules([rule(), rule(host="different.example.test")])


def test_empty_default_does_not_block_explicit_admin_policy(context):
    s = context.session
    saved = cfg.save_policy(
        s, {"expected_revision": 0, "rules": [rule()]}, context.settings, "admin"
    )
    s.commit()
    assert saved["revision"] == 1
    assert saved["rules"] == [rule()]
    with pytest.raises(DomainError) as failure:
        cfg.save_policy(
            s, {"expected_revision": 0, "rules": []}, context.settings, "admin"
        )
    assert failure.value.code == "conflict"


def test_explicit_deployment_ceiling_cannot_be_widened(context):
    deny_all = replace(context.settings, egress_ceiling=[])
    with pytest.raises(DomainError) as failure:
        cfg.save_policy(
            context.session,
            {"expected_revision": 0, "rules": [rule()]},
            deny_all,
            "admin",
        )
    assert failure.value.code == "forbidden"
    ceiling = replace(context.settings, egress_ceiling=[rule(cidrs=["10.42.0.0/24"])])
    saved = cfg.save_policy(
        context.session, {"expected_revision": 0, "rules": [rule()]}, ceiling, "admin"
    )
    assert saved["revision"] == 1
    with pytest.raises(DomainError):
        cfg.save_policy(
            context.session,
            {"expected_revision": 1, "rules": [rule(cidrs=["10.0.0.0/8"])]},
            ceiling,
            "admin",
        )


def test_transport_checks_matching_port_purpose_and_cidr_not_union(
    context, monkeypatch
):
    rules = [
        rule(),
        rule(id="other", host="other.example.test", cidrs=["10.43.0.0/24"]),
        rule(
            id="kube",
            purpose="kubernetes",
            host="idp.example.test",
            port=6443,
            cidrs=["10.44.0.0/24"],
        ),
    ]
    constructor = Mock()
    constructor.return_value.get_json.return_value = {"ok": True}
    monkeypatch.setattr(cfg, "PinnedHTTP", constructor)
    transport = cfg.PolicyHTTP(rules, "registry", "synthetic-ca")
    assert transport.get_json("https://idp.example.test/data?limit=1") == {"ok": True}
    constructor.assert_called_once_with(
        ["10.42.0.10/32"], ["idp.example.test"], "synthetic-ca"
    )
    for url in [
        "https://idp.example.test:6443/data",
        "https://idp.example.test:444/data",
        "https://unknown.example.test/data",
    ]:
        with pytest.raises(DomainError) as failure:
            transport.get_json(url)
        assert failure.value.code == "endpoint_denied"
    assert constructor.call_count == 1


def test_endpoint_validate_uses_matching_cidrs(context, monkeypatch):
    validate = Mock(return_value=["10.42.0.10"])
    monkeypatch.setattr(cfg, "validate_endpoint", validate)
    transport = cfg.PolicyHTTP(
        [rule(), rule(id="other", host="other.example.test", cidrs=["10.0.0.0/8"])],
        "registry",
    )
    assert transport.validate_endpoint("https://idp.example.test/dex") == ["10.42.0.10"]
    validate.assert_called_once_with(
        "https://idp.example.test/dex", ["10.42.0.10/32"], ["idp.example.test"]
    )


def seed_authorized_state(context):
    s = context.session
    cfg.save_policy(
        s, {"expected_revision": 0, "rules": [rule()]}, context.settings, "admin"
    )
    # Policy is the sole integration authorization configuration.
    user = User(
        id=uid(), username="test-user", role="auditor", password_hash="not-used"
    )
    cluster = Cluster(
        id=uid(),
        name="test",
        context="test",
        server="https://10.42.0.20:6443",
        auth_type="kubeconfig",
        namespaces=["test"],
    )
    s.add_all([user, cluster])
    s.flush()
    web = WebSession(
        token_hash="a" * 64,
        user_id=user.id,
        csrf_token="b" * 64,
        expires_at=now() + timedelta(hours=1),
    )
    s.add(web)
    s.flush()
    binding = AuthorizationBinding(user_id=user.id, cluster_id=cluster.id, generation=2)
    credential = ClusterCredential(
        user_id=user.id,
        cluster_id=cluster.id,
        encrypted="synthetic-encrypted",
        expires_at=now() + timedelta(minutes=5),
        policy_revision=1,
    )
    runs = [
        Run(
            id=uid(),
            cluster_id=cluster.id,
            actor_id=user.id,
            status=state,
            scope={"namespaces": ["test"]},
            credential="encrypted",
        )
        for state in ("queued", "running", "completed")
    ]
    s.add_all([binding, credential, *runs])
    s.commit()
    return user, cluster, binding, runs


def test_policy_edit_invalidates_auth_and_work_but_preserves_history(context):
    user, cluster, _, runs = seed_authorized_state(context)
    s = context.session
    cfg.save_policy(s, {"expected_revision": 1, "rules": []}, context.settings, "admin")
    s.commit()
    assert cluster.auth_generation == 1
    assert s.get(ClusterCredential, (user.id, cluster.id)) is None
    assert runs[0].status == "cancelled" and runs[0].credential is None
    assert (
        runs[1].status == "running"
        and runs[1].cancel_requested
        and runs[1].credential is None
    )
    assert runs[2].status == "completed" and not runs[2].cancel_requested


def test_personal_revoke_changes_generation_not_other_cluster(context):
    user, cluster, binding, runs = seed_authorized_state(context)
    cfg.invalidate_access(context.session, cluster_id=cluster.id, user_id=user.id)
    context.session.commit()
    assert binding.generation == 3
    assert cluster.auth_generation == 0
    assert runs[0].cancel_requested










def test_invalidation_refreshes_stale_cluster_generation(context):
    user, cluster, _binding, _ = seed_authorized_state(context)
    with context.sessions() as stale:
        stale_cluster = stale.get(Cluster, cluster.id)
        stale_binding = stale.get(AuthorizationBinding, (user.id, cluster.id))
        assert stale_cluster.auth_generation == 0
        assert stale_binding.generation == 2
        cfg.invalidate_access(context.session, cluster_id=cluster.id)
        cfg.invalidate_access(context.session, cluster_id=cluster.id, user_id=user.id)
        context.session.commit()
        cfg.invalidate_access(stale, cluster_id=cluster.id)
        cfg.invalidate_access(stale, cluster_id=cluster.id, user_id=user.id)
        stale.commit()
        assert stale_cluster.auth_generation == 2
        assert stale_binding.generation == 4




def test_legacy_import_explicit_once_does_not_resurrect_changes(context):
    settings = replace(
        context.settings,
        allowed_hosts=["idp.example.test"],
        allowed_cidrs=["10.42.0.10/32"],
    )
    s = context.session
    preview = cfg.import_legacy_configuration(s, settings, context.vault)
    assert preview["allowed_hosts"] == 1
    assert cfg.policy_view(s)["revision"] == 0
    result = cfg.import_legacy_configuration(s, settings, context.vault, apply=True)
    s.commit()
    assert result["applied"]
    cfg.save_policy(s, {"expected_revision": 1, "rules": []}, settings, "admin")
    s.commit()
    repeated = cfg.import_legacy_configuration(s, settings, context.vault, apply=True)
    assert not repeated["applied"]
    assert cfg.policy_view(s)["rules"] == []
    assert cfg.policy_view(s)["legacy_imported"]


def test_legacy_does_not_merge_into_admin_settings(context):
    s = context.session
    cfg.save_policy(s, {"expected_revision": 0, "rules": []}, context.settings, "admin")
    s.commit()
    with pytest.raises(DomainError) as failure:
        cfg.import_legacy_configuration(s, context.settings, context.vault, apply=True)
    assert failure.value.code == "conflict"


@pytest.mark.parametrize("ceiling,expected", [
    (None, None), ([], []),
    ([{"id": "old", "purpose": "oidc", "host": "idp.example.test", "port": 443, "cidrs": ["10.1.0.0/24"]}], []),
    ([{"id": "old", "purpose": "oidc", "host": "idp.example.test", "port": 443, "cidrs": ["10.1.0.0/24"]}, rule()], [rule()]),
])
def test_legacy_config_never_reads_provider_secrets_or_widens_ceiling(tmp_path, monkeypatch, ceiling, expected):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "providers": {"retired": {"client_secret_file": str(tmp_path / "must-not-exist")}},
        "egress_ceiling": ceiling,
    }))
    database_file = tmp_path / "database-url"
    database_file.write_text("postgresql+psycopg://synthetic:synthetic@db/workbench")
    key_file = tmp_path / "key"
    key_file.write_text(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setenv("WORKBENCH_CONFIG_FILE", str(config_file))
    monkeypatch.setenv("WORKBENCH_DATABASE_URL_FILE", str(database_file))
    monkeypatch.setenv("WORKBENCH_MASTER_KEY_FILE", str(key_file))
    settings = Settings.from_env()
    assert not hasattr(settings, "providers")
    assert settings.egress_ceiling == expected
    if expected == []:
        with pytest.raises(DomainError) as error:
            cfg._apply_ceiling([rule()], settings.egress_ceiling)
        assert error.value.code == "forbidden"


def test_removed_purpose_is_rejected_by_policy_and_transport(context):
    with pytest.raises(DomainError):
        cfg.save_policy(context.session, {"expected_revision": 0, "rules": [rule(purpose="oidc")]}, context.settings, "admin")
    with pytest.raises(DomainError):
        cfg.PolicyHTTP([], "oidc")


@pytest.mark.parametrize("ceiling", [
    [rule(), rule(purpose="oidc")],
    [rule(purpose="oidc"), rule(purpose="oidc", id="duplicate-endpoint")],
    [{"purpose": "oidc"}],
    [rule(purpose="oidc", cidrs=["127.0.0.0/8"])],
    [rule(purpose="unknown")],
])
def test_legacy_ceiling_is_validated_before_projection(tmp_path, monkeypatch, ceiling):
    from workbench import config

    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"egress_ceiling": ceiling}))
    monkeypatch.setenv("WORKBENCH_CONFIG_FILE", str(config_file))
    monkeypatch.setattr(config, "read_secret", lambda variable: "postgresql+psycopg://synthetic@db/workbench" if "DATABASE" in variable else "unused-test-key")
    with pytest.raises(DomainError):
        Settings.from_env()
