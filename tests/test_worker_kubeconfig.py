"""Providerless worker leases with synthetic credentials and no network access."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import delete, select
from test_api import SERVER, login
from test_api import hashed_password as hashed_password
from test_api import no_network as no_network
from test_api import workbench as workbench
from test_worker_auth import fake_process_context

from workbench import worker
from workbench.db import (
    AuthorizationBinding,
    Cluster,
    ClusterCredential,
    ClusterGrant,
    IntegrationPolicy,
    Run,
    WebSession,
    now,
    uid,
)
from workbench.domain import DomainError


def certificate_auth():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-worker")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - timedelta(minutes=1))
        .not_valid_after(now() + timedelta(hours=2))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return {
        "version": 1,
        "kind": "client_certificate",
        "certificate_pem": certificate.public_bytes(serialization.Encoding.PEM).decode(),
        "private_key_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    }


@pytest.fixture(params=["token", "client_certificate"])
def imported_run(workbench, request):
    login(workbench.client, "auditor")
    user_id = workbench.users["auditor"].id
    cluster_id = uid()
    auth = (
        {"version": 1, "kind": "token", "token": "synthetic-providerless-token"}
        if request.param == "token"
        else certificate_auth()
    )
    with workbench.app.state.sessions.begin() as session:
        session.get(IntegrationPolicy, 1).rules = [
            {"id": "kube", "purpose": "kubernetes", "host": "10.23.0.10", "port": 6443, "cidrs": ["10.23.0.0/24"]}
        ]
        cluster = Cluster(
            id=cluster_id, name="imported", context="synthetic", server=SERVER,
            auth_type="kubeconfig", namespaces=["demo"],
        )
        session.add(cluster)
        session.flush()
        session.add(ClusterGrant(user_id=user_id, cluster_id=cluster_id))
        session.add(AuthorizationBinding(user_id=user_id, cluster_id=cluster_id, generation=0))
        session_hash = session.scalar(select(WebSession.token_hash).where(WebSession.user_id == user_id))
        session.add(ClusterCredential(
            user_id=user_id, cluster_id=cluster_id,
            encrypted=workbench.app.state.vault.encrypt(auth, f"credential:{user_id}:{cluster_id}"),
            expires_at=now() + timedelta(minutes=30),
            policy_revision=1, auth_generation=0, cluster_generation=0,
            storage_mode="run_only", session_hash=session_hash,
        ))
    response = workbench.client.post("/api/runs", json={"cluster_id": cluster_id, "namespaces": ["demo"]})
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]
    runner = worker.Runner.__new__(worker.Runner)
    runner.settings = workbench.app.state.settings
    runner.sessions = workbench.app.state.sessions
    runner.engine = workbench.app.state.engine
    runner.vault = workbench.app.state.vault
    runner.id, runner.stopping = "providerless-worker", False
    with runner.sessions.begin() as session:
        assert worker.claim(session, runner.id, 60) == run_id
        assert session.get(ClusterCredential, (user_id, cluster_id)) is None
    return SimpleNamespace(runner=runner, id=run_id, cluster_id=cluster_id, user_id=user_id, auth=auth)


def test_providerless_consumed_credential_runs_with_exact_transport(imported_run, monkeypatch):
    state = imported_run
    transport = Mock(get_json=Mock(return_value={"items": []}))
    factory = Mock(return_value=transport)
    monkeypatch.setattr(worker, "policy_http", factory)
    http = worker.RunHTTP(state.runner.sessions, state.runner.settings, state.id, state.runner.id)
    assert http.get_json(SERVER + "/api/v1/namespaces/demo/pods?limit=1", headers={"Authorization": "Bearer attacker"}) == {"items": []}
    headers = transport.get_json.call_args.kwargs["headers"]
    assert headers["Accept"] == "application/json"
    if state.auth["kind"] == "token":
        assert headers["Authorization"] == "Bearer " + state.auth["token"]
        assert "client_identity" not in factory.call_args.kwargs
    else:
        assert "Authorization" not in headers
        assert factory.call_args.kwargs["client_identity"] == state.auth
    with state.runner.sessions() as session:
        run = worker.authorized_run(session, state.id, state.runner.id)
        snapshot = worker.run_connection(state.runner.vault, run)
        assert snapshot["auth_type"] == "kubeconfig"
        assert snapshot["auth"] == state.auth
        assert "provider_revision" not in snapshot


@pytest.mark.parametrize("mutation", ["policy", "generation", "grant", "expired", "mode"])
def test_providerless_worker_stops_before_http_on_authorization_change(imported_run, monkeypatch, mutation):
    state = imported_run
    factory = Mock()
    monkeypatch.setattr(worker, "policy_http", factory)
    with state.runner.sessions.begin() as session:
        if mutation == "policy":
            session.get(IntegrationPolicy, 1).revision += 1
        elif mutation == "generation":
            session.get(AuthorizationBinding, (state.user_id, state.cluster_id)).generation += 1
        elif mutation == "grant":
            session.execute(delete(ClusterGrant).where(ClusterGrant.user_id == state.user_id))
        elif mutation == "expired":
            session.get(Run, state.id).credential_expires_at = now() - timedelta(seconds=1)
        else:
            run = session.get(Run, state.id)
            snapshot = state.runner.vault.decrypt(run.credential, f"run:{run.id}")
            snapshot["auth_type"] = "oidc"
            run.credential = state.runner.vault.encrypt(snapshot, f"run:{run.id}")
    http = worker.RunHTTP(state.runner.sessions, state.runner.settings, state.id, state.runner.id)
    with pytest.raises(DomainError):
        http.get_json(SERVER + "/api/v1/namespaces/demo/pods?limit=1")
    factory.assert_not_called()


def test_providerless_worker_publishes_and_cleans_snapshot(imported_run, monkeypatch):
    state = imported_run
    _, process = fake_process_context(monkeypatch)
    state.runner.execute(state.id)
    process.start.assert_called_once()
    with state.runner.sessions() as session:
        run = session.get(Run, state.id)
        assert run.status == "completed"
        assert run.credential is None
        assert run.lease_until is None


@pytest.mark.parametrize("field,value", [("auth_type", "oidc"), ("provider_revision", 1), ("auth", None)])
def test_providerless_snapshot_rejects_inconsistent_auth(imported_run, field, value):
    state = imported_run
    with state.runner.sessions() as session:
        run = worker.authorized_run(session, state.id, state.runner.id)
        snapshot = worker.run_connection(state.runner.vault, run)
        snapshot[field] = value
        run.credential = state.runner.vault.encrypt(snapshot, f"run:{run.id}")
        with pytest.raises(DomainError):
            worker.run_connection(state.runner.vault, run)
