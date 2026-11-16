"""Safety rollout: local retention, explicit read-only schedules, no cluster writes."""

import base64
import secrets
from datetime import timedelta

import pytest

from sqlalchemy import func, select

from workbench.config import Settings
from workbench.db import (
    AuditEvent,
    AuthorizationBinding,
    Cluster,
    ClusterCredential,
    Finding,
    IntegrationPolicy,
    Observation,
    Run,
    User,
    database,
    now,
    uid,
)
from workbench.domain import DomainError
from workbench.migrations import init_database
from workbench.actions import queue_confirmed_action
from workbench.rollout import (
    enqueue_due_schedules,
    parse_runtime_report,
    purge_expired_results,
    record_schedule,
    refuse_cluster_change,
    storage_deadline,
)
from workbench.security import Vault, password_hash


def _world():
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        master_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        secure_cookie=False,
    )
    engine, sessions = database(settings.database_url)
    init_database(engine)
    vault = Vault(settings.master_key)
    user = User(username="admin", password_hash=password_hash("synthetic"), role="administrator")
    cluster = Cluster(
        name="demo",
        context="demo",
        server="https://10.23.0.10:6443",
        auth_type="kubeconfig",
        namespaces=["demo"],
        lifecycle="ready",
    )
    with sessions.begin() as session:
        session.add_all([user, cluster])
        session.flush()
        policy = session.get(IntegrationPolicy, 1)
        policy.revision = 1
        policy.rules = [{"id": "kube", "purpose": "kubernetes", "host": "10.23.0.10", "port": 6443, "cidrs": ["10.23.0.0/24"]}]
        session.add(AuthorizationBinding(user_id=user.id, cluster_id=cluster.id, generation=0))
        session.add(
            ClusterCredential(
                user_id=user.id,
                cluster_id=cluster.id,
                encrypted=vault.encrypt(
                    {"version": 1, "kind": "token", "token": "synthetic-token"},
                    f"credential:{user.id}:{cluster.id}",
                ),
                expires_at=now() + timedelta(days=10),
                policy_revision=1,
                auth_generation=0,
                cluster_generation=0,
                storage_mode="days_30",
            )
        )
        session.flush()
        ids = {"user": user.id, "cluster": cluster.id}
    return settings, sessions, vault, ids


def test_storage_deadline_is_explicit_and_bounded():
    current_session = now() + timedelta(hours=8)
    short = storage_deadline("run_only", session_expires_at=current_session, source_expires_at=None)
    day = storage_deadline("persistent", session_expires_at=current_session, source_expires_at=None)
    month = storage_deadline("days_30", session_expires_at=current_session, source_expires_at=None)
    assert short < now() + timedelta(hours=1, minutes=1)
    assert day - now() > timedelta(hours=23)
    assert timedelta(days=29) < month - now() <= timedelta(days=30)
    try:
        storage_deadline("forever", session_expires_at=current_session, source_expires_at=None)
    except DomainError as exc:
        assert exc.code == "invalid_input"
    else:
        raise AssertionError("unknown storage mode accepted")


def test_schedule_queues_read_only_run_without_consuming_credential():
    settings, sessions, vault, ids = _world()
    with sessions.begin() as session:
        user = session.get(User, ids["user"])
        cluster = session.get(Cluster, ids["cluster"])
        recorded = record_schedule(session, user, cluster, "periodic")
        assert recorded["cluster_changed"] is False
    with sessions.begin() as session:
        assert enqueue_due_schedules(session, vault, settings) == 1
    with sessions.begin() as session:
        run = session.scalar(select(Run))
        assert run.source == "schedule:periodic"
        assert run.scope["namespaces"] == ["demo"]
        assert session.get(ClusterCredential, (ids["user"], ids["cluster"])) is not None
        assert enqueue_due_schedules(session, vault, settings) == 0


def test_confirmed_scanner_is_queued_without_touching_the_cluster():
    settings, sessions, vault, ids = _world()
    with sessions.begin() as session:
        user = session.get(User, ids["user"])
        cluster = session.get(Cluster, ids["cluster"])
        result = queue_confirmed_action(session, vault, settings, user, cluster, "live_scanner")
        assert result["changes_cluster"] is False
        assert result["cluster_changed"] is False
    with sessions.begin() as session:
        run = session.scalar(select(Run))
        assert run.source == "scanners"
        assert run.status == "queued"


def test_operator_is_not_queued_without_an_image():
    settings, sessions, vault, ids = _world()
    with sessions.begin() as session:
        user = session.get(User, ids["user"])
        cluster = session.get(Cluster, ids["cluster"])
        with pytest.raises(DomainError) as exc:
            queue_confirmed_action(session, vault, settings, user, cluster, "operator")
        assert exc.value.code == "configuration_required"


def test_protected_action_is_recorded_and_not_applied():
    _settings, sessions, _vault, ids = _world()
    with sessions.begin() as session:
        user = session.get(User, ids["user"])
        cluster = session.get(Cluster, ids["cluster"])
        result = refuse_cluster_change(session, user, cluster, "remediate")
        assert result["cluster_changed"] is False
        assert "не изменён" in result["detail"]
    with sessions.begin() as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.action == "cluster_change_refused"))
        assert event.detail["cluster_changed"] is False
        assert event.detail["requested"] == "remediate"


def test_retention_deletes_local_results_only():
    _settings, sessions, _vault, ids = _world()
    old = now() - timedelta(days=100)
    with sessions.begin() as session:
        run = Run(
            id=uid(),
            cluster_id=ids["cluster"],
            actor_id=ids["user"],
            status="completed",
            stage="cleanup",
            scope={"namespaces": ["demo"]},
            finished_at=old,
            source="api",
        )
        session.add(run)
        session.flush()
        finding = Finding(
            cluster_id=ids["cluster"],
            fingerprint="old",
            latest_run_id=run.id,
            data={"title": "old"},
            first_seen=old,
            last_seen=old,
        )
        session.add(finding)
        session.flush()
        session.add(Observation(run_id=run.id, finding_id=finding.id, data={"title": "old"}))
        from workbench.db import audit

        audit(session, "admin", "kept", ids["cluster"])
    with sessions.begin() as session:
        assert purge_expired_results(session, retention_days=1) == 1
    with sessions.begin() as session:
        assert session.scalar(select(func.count(Run.id))) == 0
        assert session.scalar(select(func.count(Finding.id))) == 0
        assert session.scalar(select(AuditEvent).where(AuditEvent.action == "kept")) is not None
        assert session.get(Cluster, ids["cluster"]) is not None


def test_runtime_import_drops_command_output():
    result = parse_runtime_report(
        "falco",
        {"events": [{"rule": "Write.below.binary", "priority": "warning", "namespace": "demo"}]},
    )
    assert result.findings[0]["rule_id"] == "Write.below.binary"
    assert "output" not in result.findings[0]["evidence"]
    assert result.versions["provenance_verified"] is False
    try:
        parse_runtime_report("falco", {"events": [{"rule": "x", "output": "secret"}]})
    except DomainError as exc:
        assert exc.code == "malformed_report"
    else:
        raise AssertionError("command output was accepted")
