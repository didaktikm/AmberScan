"""Run scope and per-request transport fences use test-owned DBs and fake HTTP only."""

from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from test_api import clusters as clusters
from test_api import hashed_password as hashed_password
from test_api import no_network as no_network
from test_api import workbench as workbench
from test_worker_auth import fake_process_context
from test_worker_auth import running as running

from workbench import worker
from workbench.db import Cluster, Run, now
from workbench.domain import DomainError


@pytest.mark.parametrize(
    "scope",
    [
        {},
        {"namespaces": []},
        {"namespaces": ["*"]},
        {"namespaces": ["demo", "demo"]},
        {"namespaces": ["outside"]},
        {"namespaces": ["../demo"]},
        {"namespaces": "demo"},
        {"namespaces": ["demo"], "inventory_version": 2},
        {"namespaces": ["demo"], "cluster_resources": True},
        {"namespaces": ["demo"], "max_objects": True},
        {"namespaces": ["demo"], "timeout_seconds": 0},
    ],
)
def test_worker_rejects_invalid_or_expanded_persisted_scope_before_spawn(
    running, monkeypatch, scope
):
    with running.runner.sessions.begin() as session:
        run = session.get(Run, running.id)
        run.scope = {**run.scope, **scope} if scope else scope
    context, process = fake_process_context(monkeypatch)
    running.runner.execute(running.id)
    process.start.assert_not_called()
    context.Process.assert_not_called()
    with running.runner.sessions() as session:
        run = session.get(Run, running.id)
        assert run.status == "failed" and run.coverage == [] and run.credential is None


def test_worker_requires_versioned_scope_even_if_namespaces_are_valid(running):
    with running.runner.sessions.begin() as session:
        run = session.get(Run, running.id)
        run.scope = {key: value for key, value in run.scope.items() if key != "inventory_version"}
    with running.runner.sessions() as session, pytest.raises(DomainError) as exc:
        worker.authorized_run(session, running.id, running.runner.id)
    assert exc.value.code == "invalid_scope"


@pytest.mark.parametrize("allowlist", [[], ["elsewhere"], ["*"], ["demo", "demo"]])
def test_worker_does_not_trust_current_connection_allowlist(running, allowlist):
    with running.runner.sessions.begin() as session:
        session.get(Cluster, running.cluster.id).namespaces = allowlist
    with running.runner.sessions() as session, pytest.raises(DomainError):
        worker.authorized_run(session, running.id, running.runner.id)


def test_worker_scope_is_bound_to_encrypted_snapshot_not_mutable_json(running):
    with running.runner.sessions.begin() as session:
        cluster = session.get(Cluster, running.cluster.id)
        cluster.namespaces = ["demo", "new-namespace"]
        run = session.get(Run, running.id)
        run.scope = {**run.scope, "namespaces": ["new-namespace"]}
    with running.runner.sessions() as session:
        run = worker.authorized_run(session, running.id, running.runner.id)
        with pytest.raises(DomainError) as exc:
            worker.run_connection(running.runner.vault, run)
    assert exc.value.code == "authorization_required"


def test_allowlist_growth_does_not_expand_run_or_http_access(running, monkeypatch):
    with running.runner.sessions.begin() as session:
        session.get(Cluster, running.cluster.id).namespaces = ["demo", "later"]
    factory = Mock(return_value=Mock(get_json=Mock(return_value={"items": []})))
    monkeypatch.setattr(worker, "policy_http", factory)
    http = worker.RunHTTP(
        running.runner.sessions, running.runner.settings, running.id, running.runner.id
    )
    with pytest.raises(DomainError) as exc:
        http.get_json("https://10.23.0.10:6443/api/v1/namespaces/later/pods?limit=1")
    assert exc.value.code == "scope_denied"
    factory.assert_not_called()
    with running.runner.sessions() as session:
        run = session.get(Run, running.id)
        assert run.scope["namespaces"] == ["demo"]
        assert worker.run_connection(running.runner.vault, run)["scope"]["namespaces"] == ["demo"]


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/pods?limit=1",
        "/api/v1/namespaces?limit=1",
        "/api/v1/nodes?limit=1",
        "/apis/rbac.authorization.k8s.io/v1/clusterroles?limit=1",
        "/api/v1/namespaces/other/pods?limit=1",
        "/api/v1/namespaces/demo/secrets?limit=1",
        "/api/v1/namespaces/demo/configmaps?limit=1",
        "/api/v1/namespaces/demo/pods/test/log?limit=1",
        "/api/v1/namespaces/demo/pods/test/exec?limit=1",
        "/api/v1/namespaces/demo/../pods?limit=1",
        "/api/v1/namespaces/%64emo/pods?limit=1",
        "/api/v1/namespaces/demo/pods?limit=1&watch=true",
        "/api/v1/namespaces/demo/pods?limit=1&limit=500",
        "/api/v1/namespaces/demo/pods?limit=1&fieldSelector=metadata.name%3Dtoken",
    ],
)
def test_run_transport_rejects_noninventory_or_out_of_scope_requests(
    running, monkeypatch, path
):
    factory = Mock()
    monkeypatch.setattr(worker, "policy_http", factory)
    http = worker.RunHTTP(
        running.runner.sessions, running.runner.settings, running.id, running.runner.id
    )
    with pytest.raises(DomainError) as exc:
        http.get_json("https://10.23.0.10:6443" + path)
    assert exc.value.code == "scope_denied"
    factory.assert_not_called()


def test_run_transport_rejects_different_allowed_server(running, monkeypatch):
    factory = Mock()
    monkeypatch.setattr(worker, "policy_http", factory)
    http = worker.RunHTTP(
        running.runner.sessions, running.runner.settings, running.id, running.runner.id
    )
    with pytest.raises(DomainError) as exc:
        http.get_json("https://10.23.0.11:6443/api/v1/namespaces/demo/pods?limit=1")
    assert exc.value.code == "scope_denied"
    factory.assert_not_called()


def test_run_transport_rejects_response_after_allowlist_shrink(running, monkeypatch):
    def response(*_args, **_kwargs):
        with running.runner.sessions.begin() as session:
            session.get(Cluster, running.cluster.id).namespaces = ["other"]
        return {"items": []}

    transport = Mock(get_json=Mock(side_effect=response))
    monkeypatch.setattr(worker, "policy_http", Mock(return_value=transport))
    http = worker.RunHTTP(
        running.runner.sessions, running.runner.settings, running.id, running.runner.id
    )
    with pytest.raises(DomainError) as exc:
        http.get_json("https://10.23.0.10:6443/api/v1/namespaces/demo/pods?limit=1")
    assert exc.value.code == "invalid_scope"
    transport.get_json.assert_called_once()
    with pytest.raises(DomainError):
        http.get_json("https://10.23.0.10:6443/api/v1/namespaces/demo/services?limit=1")
    transport.get_json.assert_called_once()


def test_execute_refuses_changed_scope_before_publishing(running, monkeypatch):
    def mutate():
        with running.runner.sessions.begin() as session:
            run = session.get(Run, running.id)
            run.scope = {**run.scope, "max_objects": 2}

    _, process = fake_process_context(monkeypatch, on_result=mutate)
    running.runner.execute(running.id)
    process.start.assert_called_once()
    with running.runner.sessions() as session:
        run = session.get(Run, running.id)
        assert run.status == "failed" and run.coverage == [] and run.credential is None


def test_recovery_removes_only_expired_drafts(workbench):
    with workbench.app.state.sessions.begin() as session:
        base = {
            "environment": "test", "context": "manual", "server": "https://10.23.0.10:6443",
            "auth_type": "kubeconfig", "namespaces": [], "lifecycle": "draft",
            "draft_owner_id": workbench.users["admin"].id,
        }
        expired = Cluster(name="expired", draft_expires_at=now() - timedelta(seconds=1), **base)
        current = Cluster(name="current", draft_expires_at=now() + timedelta(hours=1), **base)
        ready = Cluster(
            name="ready", environment="test", context="manual", server=base["server"],
            auth_type="kubeconfig", namespaces=["demo"], lifecycle="ready",
            draft_expires_at=now() - timedelta(seconds=1),
        )
        session.add_all([expired, current, ready])
        session.flush()
        ids = expired.id, current.id, ready.id
        worker.cleanup_expired_drafts(session)
    with workbench.app.state.sessions() as session:
        assert session.get(Cluster, ids[0]) is None
        assert session.get(Cluster, ids[1]) is not None
        assert session.get(Cluster, ids[2]) is not None


def test_tick_commits_cascading_cleanup_before_run_recovery(monkeypatch):
    calls = []
    transaction = 0

    @contextmanager
    def begin():
        nonlocal transaction
        transaction += 1
        current = transaction
        calls.append((current, "begin"))
        yield SimpleNamespace(number=current)
        calls.append((current, "commit"))

    runner = worker.Runner.__new__(worker.Runner)
    runner.sessions = SimpleNamespace(begin=begin)
    monkeypatch.setattr(runner, "settings", SimpleNamespace(lease_seconds=60), raising=False)
    runner.id = "synthetic-worker"
    runner.vault = None
    monkeypatch.setattr(worker, "require_runtime_schema", lambda session: calls.append((session.number, "schema")))
    monkeypatch.setattr(worker, "cleanup_expired_drafts", lambda session: calls.append((session.number, "drafts")))
    monkeypatch.setattr(worker, "cleanup_expired_authorizations", lambda session: calls.append((session.number, "auth")))
    monkeypatch.setattr(worker, "purge_expired_results", lambda session, **_kwargs: calls.append((session.number, "retention")))
    monkeypatch.setattr(worker, "enqueue_due_schedules", lambda session, *_args: calls.append((session.number, "schedule")))
    monkeypatch.setattr(worker, "recover", lambda session: calls.append((session.number, "runs")))
    monkeypatch.setattr(worker, "claim", lambda session, *_: calls.append((session.number, "claim")))
    monkeypatch.setattr(runner, "pulse", lambda session, _: calls.append((session.number, "pulse")))
    assert runner.tick() is False
    assert calls == [
        (1, "begin"), (1, "schema"), (1, "drafts"), (1, "commit"),
        (2, "begin"), (2, "schema"), (2, "auth"), (2, "commit"),
        (3, "begin"), (3, "schema"), (3, "retention"), (3, "commit"),
        (4, "begin"), (4, "schema"), (4, "schedule"), (4, "commit"),
        (5, "begin"), (5, "schema"), (5, "runs"), (5, "pulse"),
        (5, "claim"), (5, "commit"),
    ]


def test_expired_authorization_cleanup_locks_sessions_before_children():
    session = Mock()
    worker.cleanup_expired_authorizations(session)
    assert [call.args[0].table.name for call in session.execute.call_args_list] == [
        "sessions", "cluster_credentials",
    ]
