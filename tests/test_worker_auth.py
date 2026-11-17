"""Offline worker fencing tests; no process, cluster, IdP or user stack is touched."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from sqlalchemy import delete
from test_api import clusters as clusters
from test_api import hashed_password as hashed_password
from test_api import login, store_credential
from test_api import no_network as no_network
from test_api import workbench as workbench

from workbench import worker
from workbench.db import (
    AuthorizationBinding,
    Cluster,
    ClusterCredential,
    ClusterGrant,
    IntegrationPolicy,
    Run,
    User,
    aware,
    now,
)
from workbench.domain import DomainError, ScanResult


@pytest.fixture
def running(workbench, clusters):
    login(workbench.client, "auditor")
    store_credential(workbench, clusters.granted, "auditor")
    response = workbench.client.post(
        "/api/runs", json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]}
    )
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]
    runner = worker.Runner.__new__(worker.Runner)
    runner.settings = workbench.app.state.settings
    runner.sessions = workbench.app.state.sessions
    runner.engine = workbench.app.state.engine
    runner.vault = workbench.app.state.vault
    runner.id, runner.stopping = "synthetic-worker", False
    with runner.sessions.begin() as session:
        assert worker.claim(session, runner.id, 60) == run_id
        # Exactly what one-shot enqueue leaves behind: run snapshot but no credential row.
        session.execute(
            delete(ClusterCredential).where(
                ClusterCredential.user_id == workbench.users["auditor"].id
            )
        )
    return SimpleNamespace(
        runner=runner,
        id=run_id,
        cluster=clusters.granted,
        user_id=workbench.users["auditor"].id,
    )


def test_worker_accepts_consumed_one_shot_immutable_run_snapshot(workbench, running):
    with running.runner.sessions() as session:
        run = worker.authorized_run(session, running.id, running.runner.id)
        assert (
            session.get(ClusterCredential, (running.user_id, running.cluster.id))
            is None
        )
        connection = worker.run_connection(running.runner.vault, run)
        assert connection["auth"]["token"] == "synthetic.auditor.id-token"
        assert connection["expires_at"] == aware(run.credential_expires_at).isoformat()
        assert connection["policy_revision"] == run.policy_revision == 1


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("policy_revision", "authorization_required"),
        ("auth_generation", "authorization_required"),
        ("cluster_generation", "authorization_required"),
        ("legacy_run", "authorization_required"),
        ("expired", "authorization_required"),
        ("wrong_owner", "interrupted"),
        ("lease_expired", "interrupted"),
        ("not_running", "interrupted"),
        ("cancelled", "cancelled"),
        ("missing_snapshot", "cancelled"),
        ("inactive_user", "forbidden"),
        ("viewer", "forbidden"),
        ("grant_removed", "forbidden"),
    ],
)
def test_worker_rejects_revocation_revisions_and_ownership(running, mutation, code):
    with running.runner.sessions.begin() as session:
        run = session.get(Run, running.id)
        if mutation == "policy_revision":
            session.get(IntegrationPolicy, 1).revision += 1
        elif mutation == "auth_generation":
            session.get(
                AuthorizationBinding, (running.user_id, running.cluster.id)
            ).generation += 1
        elif mutation == "cluster_generation":
            session.get(Cluster, running.cluster.id).auth_generation += 1
        elif mutation == "legacy_run":
            run.policy_revision = 0
        elif mutation == "expired":
            run.credential_expires_at = now() - timedelta(seconds=1)
        elif mutation == "wrong_owner":
            run.worker_id = "different-worker"
        elif mutation == "lease_expired":
            run.lease_until = now() - timedelta(seconds=1)
        elif mutation == "not_running":
            run.status = "queued"
        elif mutation == "cancelled":
            run.cancel_requested = True
        elif mutation == "missing_snapshot":
            run.credential = None
        elif mutation == "inactive_user":
            session.get(User, running.user_id).active = False
        elif mutation == "viewer":
            session.get(User, running.user_id).role = "viewer"
        elif mutation == "grant_removed":
            session.execute(
                delete(ClusterGrant).where(ClusterGrant.user_id == running.user_id)
            )
    with running.runner.sessions() as session, pytest.raises(DomainError) as raised:
        worker.authorized_run(session, running.id, running.runner.id)
    assert raised.value.code == code


def test_refreshing_current_credential_cannot_extend_snapshot_expiry(
    workbench, running
):
    store_credential(workbench, running.cluster, "auditor", seconds=3600)
    with running.runner.sessions.begin() as session:
        run = session.get(Run, running.id)
        run.credential_expires_at = now() - timedelta(seconds=1)
        assert (
            aware(
                session.get(
                    ClusterCredential, (running.user_id, running.cluster.id)
                ).expires_at
            )
            > now()
        )
    with running.runner.sessions() as session, pytest.raises(DomainError) as raised:
        worker.authorized_run(session, running.id, running.runner.id)
    assert raised.value.code == "authorization_required"


@pytest.mark.parametrize("mutation", ["expires_at", "missing_expiry", "revision"])
def test_encrypted_snapshot_must_match_immutable_run_fields(running, mutation):
    with running.runner.sessions() as session:
        run = worker.authorized_run(session, running.id, running.runner.id)
        connection = worker.run_connection(running.runner.vault, run)
        if mutation == "expires_at":
            connection["expires_at"] = (now() + timedelta(hours=1)).isoformat()
        elif mutation == "missing_expiry":
            del connection["expires_at"]
        else:
            connection["policy_revision"] += 1
        run.credential = running.runner.vault.encrypt(connection, f"run:{run.id}")
        with pytest.raises(DomainError) as raised:
            worker.run_connection(running.runner.vault, run)
        assert raised.value.code == "authorization_required"


def test_child_transport_reloads_policy_and_fences_each_get(running, monkeypatch):
    requested = []
    transports = []

    def factory(session, settings, purpose, ca_data):
        assert purpose == "kubernetes" and ca_data == running.cluster.ca_data
        requested.append(session.get(IntegrationPolicy, 1).revision)
        transport = Mock(get_json=Mock(return_value={"items": []}))
        transports.append(transport)
        return transport

    monkeypatch.setattr(worker, "policy_http", factory)
    http = worker.RunHTTP(
        running.runner.sessions,
        running.runner.settings,
        running.id,
        running.runner.id,
    )
    assert http.get_json(
        "https://10.23.0.10:6443/api/v1/namespaces/demo/pods?limit=1",
        headers={"Authorization": "Bearer ignored-caller-identity"},
    ) == {"items": []}
    assert http.get_json("https://10.23.0.10:6443/api/v1/namespaces/demo/services?limit=1") == {
        "items": []
    }
    assert requested == [1, 1]
    for transport in transports:
        assert transport.get_json.call_args.kwargs["headers"] == {
            "Authorization": "Bearer synthetic.auditor.id-token",
            "Accept": "application/json",
        }
    with running.runner.sessions.begin() as session:
        session.get(IntegrationPolicy, 1).revision += 1
    with pytest.raises(DomainError) as raised:
        http.get_json("https://10.23.0.10:6443/api/v1/namespaces/demo/pods?limit=1")
    assert raised.value.code == "authorization_required"
    assert requested == [1, 1]  # no old-policy HTTP call after revision change


def fake_process_context(monkeypatch, *, on_result=None):
    process = Mock()
    process.is_alive.return_value = False
    receiver, sender = Mock(), Mock()
    receiver.poll.return_value = True

    def recv():
        if on_result:
            on_result()
        return (
            "ok",
            ScanResult(
                findings=[],
                coverage=[{"check": "synthetic", "status": "completed"}],
                limitations=[],
                versions={},
            ),
        )

    receiver.recv.side_effect = recv
    context = Mock()
    context.Pipe.return_value = receiver, sender
    context.Process.return_value = process
    monkeypatch.setattr(
        worker.multiprocessing, "get_context", Mock(return_value=context)
    )
    return context, process


def test_execute_publishes_consumed_one_shot_without_current_credential(
    running, monkeypatch
):
    context, process = fake_process_context(monkeypatch)
    running.runner.execute(running.id)
    process.start.assert_called_once()
    assert context.Process.call_args.kwargs["args"][3:5] == (
        running.id,
        running.runner.id,
    )
    with running.runner.sessions() as session:
        run = session.get(Run, running.id)
        assert (
            run.status == "completed"
            and run.credential is None
            and run.lease_until is None
        )


@pytest.mark.parametrize("mutation", ["generation", "expired", "grant", "owner"])
def test_execute_rechecks_fence_before_publishing_child_result(
    running, monkeypatch, mutation
):
    def mutate():
        with running.runner.sessions.begin() as session:
            run = session.get(Run, running.id)
            if mutation == "generation":
                session.get(
                    AuthorizationBinding, (running.user_id, running.cluster.id)
                ).generation += 1
            elif mutation == "expired":
                run.credential_expires_at = now() - timedelta(seconds=1)
            elif mutation == "grant":
                session.execute(
                    delete(ClusterGrant).where(ClusterGrant.user_id == running.user_id)
                )
            else:
                run.worker_id = "new-owner"

    fake_process_context(monkeypatch, on_result=mutate)
    running.runner.execute(running.id)
    with running.runner.sessions() as session:
        run = session.get(Run, running.id)
        assert run.coverage == []
        if mutation == "owner":
            assert run.status == "running" and run.worker_id == "new-owner"
        else:
            assert run.status == "failed" and run.credential is None


def test_worker_recovery_cleans_expired_lease_not_immutable_history(running):
    with running.runner.sessions.begin() as session:
        run = session.get(Run, running.id)
        run.lease_until = now() - timedelta(seconds=1)
        count = worker.recover(session)
        assert count == 1
        assert run.status == "interrupted" and run.credential is None
        assert run.credential_expires_at is not None and run.policy_revision == 1
