"""Providerless onboarding against disposable SQLite and synthetic GET transports."""

import base64
import json
import secrets
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_api import ORIGIN, SERVER, assert_error, login
from test_api import hashed_password as hashed_password
from test_api import no_network as no_network
from test_api_connections import namespace_page, resource_page
from test_worker_kubeconfig import certificate_auth

from workbench import api, configuration
from workbench.config import Settings
from workbench.db import (
    AuditEvent,
    AuthorizationBinding,
    Cluster,
    ClusterCredential,
    ClusterGrant,
    IntegrationPolicy,
    Run,
    User,
    WebSession,
    aware,
    now,
)
from workbench.domain import DomainError
from workbench.migrations import init_database
from workbench.services import credential_for, digest


@pytest.fixture
def providerless(monkeypatch, tmp_path, hashed_password):
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        master_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        public_origin=ORIGIN, secure_cookie=False,
        web_dist_dir=str(tmp_path / "not-built"),
    )
    http = Mock(spec=configuration.PolicyHTTP)
    http.get_json.side_effect = AssertionError("Unexpected HTTP")
    factory = Mock(return_value=http)
    monkeypatch.setattr(api, "policy_http", factory)
    app = api.create_app(settings)
    init_database(app.state.engine)
    users = {name: User(username=name, password_hash=hashed_password, role=role) for name, role in (("admin", "administrator"), ("auditor", "auditor"), ("other", "administrator"))}
    with app.state.sessions.begin() as session:
        session.add_all(users.values())
        session.merge(IntegrationPolicy(id=1, revision=1, rules=[{"id": "kube", "purpose": "kubernetes", "host": "10.23.0.10", "port": 6443, "cidrs": ["10.23.0.0/24"]}]))
    try:
        with TestClient(app, headers={"Origin": ORIGIN}) as client:
            login(client)
            yield SimpleNamespace(app=app, client=client, http=http, factory=factory, users=users)
    finally:
        app.state.engine.dispose()


def config(auth=None, *, server=SERVER, context="selected", ca=None):
    auth = auth or {"version": 1, "kind": "token", "token": "synthetic-import-token"}
    user = {"token": auth["token"]} if auth["kind"] == "token" else {
        "client-certificate-data": base64.b64encode(auth["certificate_pem"].encode()).decode(),
        "client-key-data": base64.b64encode(auth["private_key_pem"].encode()).decode(),
    }
    cluster = {"server": server}
    if ca is not None:
        cluster["certificate-authority-data"] = ca
    return json.dumps({"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "cluster", "cluster": cluster}], "users": [{"name": "personal", "user": user}], "contexts": [{"name": context, "context": {"cluster": "cluster", "user": "personal", "namespace": "hint-not-selected"}}], "current-context": context})


def create(env, content=None, **options):
    response = env.client.post("/api/cluster-drafts", json={"name": "Providerless", "auth_type": "kubeconfig", "connection": {"kind": "kubeconfig", "context": "selected", "content": content or config()}, **options})
    assert response.status_code == 201, response.text
    return response.json()


def finalize(env, draft):
    env.http.get_json.side_effect = resource_page
    response = env.client.post(f"/api/cluster-drafts/{draft['id']}/finalize", json={"namespaces": ["chosen"], "expected_access_revision": draft["access_revision"]})
    assert response.status_code == 200, response.text
    return response.json()["cluster"]


def reimport(env, cluster, content=None, **options):
    return env.client.post(f"/api/clusters/{cluster['id']}/credential", json={"content": content or config(), "context": "selected", "expected_access_revision": cluster["access_revision"], **options})


@pytest.mark.parametrize("kind", ["token", "client_certificate"])
@pytest.mark.parametrize("storage", ["run_only", "persistent"])
def test_zero_provider_token_and_certificate_full_lifecycle(providerless, kind, storage):
    env = providerless
    auth = {"version": 1, "kind": "token", "token": "synthetic-import-token"} if kind == "token" else certificate_auth()
    content = config(auth)
    draft = create(env, content, storage_mode=storage)
    assert draft["auth_type"] == "kubeconfig" and "oidc_provider_id" not in draft
    assert draft["status"] == "authorized" and draft["namespaces"] == []
    assert draft["storage_mode"] == storage
    env.factory.assert_not_called()
    env.http.get_json.side_effect = lambda *a, **k: namespace_page(["chosen", "kube-system", "outside"])
    discovered = env.client.post(f"/api/clusters/{draft['id']}/namespaces/discover")
    assert discovered.status_code == 200, discovered.text
    assert [item["name"] for item in discovered.json()["items"]] == ["chosen", "kube-system", "outside"]
    assert discovered.json()["continuation"] is None
    assert discovered.json()["namespace_hint"] == "hint-not-selected"
    assert_error(env.client.post(f"/api/clusters/{draft['id']}/authorize", json={}), 404, "not_found")
    ready = finalize(env, draft)
    assert ready["namespaces"] == ["chosen"] and ready["status"] == "authorized"
    calls = env.http.get_json.call_args_list[1:]
    assert all("/namespaces/chosen/" in call.args[0] for call in calls)
    for call in env.http.get_json.call_args_list:
        assert ("Authorization" in call.kwargs["headers"]) is (kind == "token")
    for call in env.factory.call_args_list:
        assert call.args[2] == "kubernetes"
        assert call.kwargs == ({"client_identity": auth} if kind == "client_certificate" else {})
    queued = env.client.post("/api/runs", json={"cluster_id": draft["id"], "namespaces": ["chosen"]})
    assert queued.status_code == 201, queued.text
    with env.app.state.sessions() as session:
        run = session.get(Run, queued.json()["id"])
        snapshot = env.app.state.vault.decrypt(run.credential, f"run:{run.id}")
        assert snapshot["auth_type"] == "kubeconfig" and snapshot["auth"] == auth
        assert "provider_revision" not in snapshot and snapshot["scope"] == run.scope
        credential = session.get(ClusterCredential, (env.users["admin"].id, draft["id"]))
        assert (credential is None) is (storage == "run_only")
        serialized = json.dumps([row.detail for row in session.scalars(select(AuditEvent))])
        for secret in (auth.get("token"), auth.get("private_key_pem")):
            if secret:
                assert secret not in serialized + discovered.text + queued.text + json.dumps(draft)


@pytest.mark.parametrize("storage,short_session", [("run_only", False), ("run_only", True), ("persistent", False)])
def test_import_lease_caps(providerless, storage, short_session):
    env = providerless
    if short_session:
        with env.app.state.sessions.begin() as session:
            session.get(WebSession, digest(env.client.cookies.get(api.COOKIE))).expires_at = now() + timedelta(minutes=10)
    draft = create(env, storage_mode=storage)
    with env.app.state.sessions() as session:
        credential = session.get(ClusterCredential, (env.users["admin"].id, draft["id"]))
        seconds = (aware(credential.expires_at) - now()).total_seconds()
        expected = 600 if short_session else (3600 if storage == "run_only" else 86400)
        assert expected - 10 < seconds <= expected
        assert (credential.session_hash is None) is (storage == "persistent")
        stored = env.app.state.vault.decrypt(credential.encrypted, f"credential:{credential.user_id}:{draft['id']}")
        assert stored == {"version": 1, "kind": "token", "token": "synthetic-import-token"}


def test_source_expiry_only_shortens_app_lease(providerless):
    env = providerless
    auth = certificate_auth()
    cert = create(env, config(auth), storage_mode="persistent")
    with env.app.state.sessions() as session:
        credential = session.get(ClusterCredential, (env.users["admin"].id, cert["id"]))
        assert timedelta(hours=1, minutes=59) < aware(credential.expires_at) - now() <= timedelta(hours=2)
    encoded = base64.urlsafe_b64encode(json.dumps({"exp": int((now() + timedelta(minutes=7)).timestamp())}).encode()).decode().rstrip("=")
    token = create(env, config({"version": 1, "kind": "token", "token": f"e30.{encoded}.unverified"}), storage_mode="persistent")
    with env.app.state.sessions() as session:
        credential = session.get(ClusterCredential, (env.users["admin"].id, token["id"]))
        assert timedelta(minutes=6) < aware(credential.expires_at) - now() <= timedelta(minutes=7)


@pytest.mark.parametrize("data", [{"id_token": "legacy-not-permitted"}, {"version": 1, "kind": "token", "token": "valid", "unexpected": True}, {"auth": None, "id_token": "no-fallback"}])
def test_providerless_vault_rejects_legacy_or_malformed_normalized_auth(providerless, data):
    env = providerless
    draft = create(env)
    with env.app.state.sessions.begin() as session:
        user = session.get(User, env.users["admin"].id)
        cluster = session.get(Cluster, draft["id"])
        credential = session.get(ClusterCredential, (user.id, cluster.id))
        credential.encrypted = env.app.state.vault.encrypt(data, f"credential:{user.id}:{cluster.id}")
        with pytest.raises(DomainError):
            credential_for(session, env.app.state.vault, cluster, user, session_hash=credential.session_hash)


def test_missing_policy_rolls_back_created_draft_and_import(providerless):
    env = providerless
    with env.app.state.sessions.begin() as session:
        session.get(IntegrationPolicy, 1).revision = 0
    response = env.client.post("/api/cluster-drafts", json={"name": "atomic", "auth_type": "kubeconfig", "connection": {"kind": "kubeconfig", "content": config(), "context": "selected"}})
    assert_error(response, 409, "configuration_required")
    with env.app.state.sessions() as session:
        assert session.scalar(select(func.count(Cluster.id))) == 0
        assert session.scalar(select(func.count(ClusterCredential.user_id))) == 0


def test_reimport_personal_invalidation_cas_and_exact_metadata(providerless):
    env = providerless
    ready = finalize(env, create(env, storage_mode="persistent"))
    queued = env.client.post("/api/runs", json={"cluster_id": ready["id"], "namespaces": ["chosen"]}).json()
    replacement = config({"version": 1, "kind": "token", "token": "replacement-only"})
    assert_error(reimport(env, ready, replacement, expected_access_revision=0), 409, "conflict")
    assert_error(reimport(env, ready, config(server="https://10.23.0.11:6443")), 400, "connection_mismatch")
    assert_error(reimport(env, ready, config(context="different"), context="different"), 400, "connection_mismatch")
    ca = base64.b64encode(certificate_auth()["certificate_pem"].encode()).decode()
    assert_error(reimport(env, ready, config(ca=ca)), 400, "connection_mismatch")
    response = reimport(env, ready, replacement)
    assert response.status_code == 200, response.text
    assert response.json()["namespaces"] == ["chosen"] and response.json()["access_revision"] == ready["access_revision"]
    with env.app.state.sessions() as session:
        run = session.get(Run, queued["id"])
        assert run.status == "cancelled" and run.credential is None
        assert session.get(AuthorizationBinding, (env.users["admin"].id, ready["id"])).generation == 1
    assert env.client.delete(f"/api/clusters/{ready['id']}/authorization").status_code == 200
    assert_error(env.client.post(f"/api/clusters/{ready['id']}/namespaces/discover", json={}), 409, "authorization_required")


def test_reimport_is_personal_and_draft_owner_only(providerless):
    env = providerless
    draft = create(env, storage_mode="persistent")
    login(env.client, "other")
    assert_error(reimport(env, draft), 404, "not_found")
    login(env.client)
    ready = finalize(env, draft)
    with env.app.state.sessions.begin() as session:
        session.add(ClusterGrant(user_id=env.users["auditor"].id, cluster_id=ready["id"]))
    login(env.client, "auditor")
    assert_error(env.client.post(f"/api/clusters/{ready['id']}/namespaces/discover", json={}), 409, "authorization_required")
    assert reimport(env, ready).status_code == 200
    assert env.client.delete(f"/api/clusters/{ready['id']}/authorization").status_code == 200
    with env.app.state.sessions() as session:
        assert session.get(ClusterCredential, (env.users["admin"].id, ready["id"])) is not None
        assert session.get(ClusterCredential, (env.users["auditor"].id, ready["id"])) is None


def test_run_only_new_session_needs_reimport_persistent_does_not(providerless):
    env = providerless
    one = create(env)
    persistent = create(env, storage_mode="persistent")
    login(env.client)
    assert env.client.get(f"/api/cluster-drafts/{one['id']}").json()["status"] == "authorization_required"
    assert env.client.get(f"/api/cluster-drafts/{persistent['id']}").json()["status"] == "authorized"
    assert reimport(env, one).status_code == 200


@pytest.mark.parametrize("mutation", ["reimport", "revoke", "policy", "scope", "logout", "expire"])
def test_providerless_probe_races_stop_publication(providerless, mutation):
    env = providerless
    draft = create(env, storage_mode="persistent")
    def changed(url, headers):
        if mutation == "reimport":
            assert reimport(env, draft).status_code == 200
        elif mutation == "revoke":
            env.client.delete(f"/api/clusters/{draft['id']}/authorization")
        elif mutation == "logout":
            env.client.post("/api/logout")
        else:
            with env.app.state.sessions.begin() as session:
                if mutation == "policy":
                    session.get(IntegrationPolicy, 1).revision += 1
                elif mutation == "scope":
                    session.get(Cluster, draft["id"]).namespaces = ["outside"]
                else:
                    session.get(ClusterCredential, (env.users["admin"].id, draft["id"])).expires_at = now() - timedelta(seconds=1)
        return namespace_page(["chosen"], cursor="more")
    env.http.get_json.side_effect = changed
    response = env.client.post(f"/api/clusters/{draft['id']}/namespaces/discover", json={})
    assert response.status_code in {401, 409}, response.text
    assert env.http.get_json.call_count == 1


def paging(env, draft):
    def page(url, headers):
        cursor = parse_qs(urlsplit(url).query).get("continue", ["0"])[0]
        start = int(cursor)
        names = ["kube-system" if i == 0 else f"ns-{i:04}" for i in range(start, min(start + 200, 1205))]
        return namespace_page(names, cursor=str(start + 200) if start + 200 < 1205 else "", revision="fixed-snapshot")
    env.http.get_json.side_effect = page
    return env.client.post(f"/api/clusters/{draft['id']}/namespaces/discover", json={})


def test_namespace_paging_over_1000_encrypted_replay_and_expiry(providerless):
    env = providerless
    draft = create(env)
    first = paging(env, draft)
    assert first.status_code == 200, first.text
    batch = first.json()
    assert len(batch["items"]) == 1000 and not batch["complete"]
    token = batch["continuation"]
    assert token and "fixed-snapshot" not in token and "synthetic-import-token" not in first.text
    path = f"/api/clusters/{draft['id']}/namespaces/discover"
    second = env.client.post(path, json={"continuation": token})
    assert second.status_code == 200, second.text
    assert len(second.json()["items"]) == 205 and second.json()["complete"]
    assert second.json()["continuation"] is None
    names = [item["name"] for item in batch["items"] + second.json()["items"]]
    assert len(set(names)) == 1205 and "kube-system" in names
    # A replay can only repeat the same read-only snapshot, never skip fences.
    assert env.client.post(path, json={"continuation": token}).json() == second.json()
    assert_error(env.client.post(path, json={"continuation": "tampered" + token}), 400, "invalid_namespace_continuation")
    data = env.app.state.vault.decrypt(token, "namespace-discovery:v1")
    data["expires_at"] = (now() - timedelta(seconds=1)).isoformat()
    expired = env.app.state.vault.encrypt(data, "namespace-discovery:v1")
    assert_error(env.client.post(path, json={"continuation": expired}), 400, "namespace_snapshot_expired")
    assert_error(env.client.post(f"/api/clusters/{draft['id']}/preflight", json={"namespaces": names[:101]}), 422, "invalid_input")
    assert env.client.get(f"/api/cluster-drafts/{draft['id']}").json()["namespaces"] == []


@pytest.mark.parametrize("mutation", ["reimport", "session", "cluster", "snapshot", "410", "policy"])
def test_namespace_continuation_exact_fences(providerless, mutation):
    env = providerless
    draft = create(env, storage_mode="persistent")
    token = paging(env, draft).json()["continuation"]
    path = f"/api/clusters/{draft['id']}/namespaces/discover"
    expected = "invalid_namespace_continuation"
    if mutation == "reimport":
        assert reimport(env, draft, storage_mode="persistent").status_code == 200
    elif mutation == "session":
        login(env.client)
    elif mutation == "cluster":
        other = create(env)
        path = f"/api/clusters/{other['id']}/namespaces/discover"
    elif mutation == "policy":
        with env.app.state.sessions.begin() as session:
            session.get(IntegrationPolicy, 1).revision += 1
        expected = "authorization_required"
    else:
        expected = "namespace_snapshot_expired"
        env.http.get_json.side_effect = (DomainError("private-cursor", "http_410") if mutation == "410" else lambda *a, **k: namespace_page(["different"], revision="changed"))
    before = env.http.get_json.call_count
    response = env.client.post(path, json={"continuation": token})
    assert_error(response, 409 if mutation == "policy" else 400, expected)
    assert env.http.get_json.call_count == before + (1 if mutation in {"snapshot", "410"} else 0)
    assert "private-cursor" not in response.text


def test_capabilities_only_expose_kubernetes_setup(providerless):
    env = providerless
    result = env.client.get("/api/capabilities").json()
    assert "oidc_providers" not in result and "oidc_setup_required" not in result
    assert not result["setup_required"] and not result["kubernetes_setup_required"]
    with env.app.state.sessions.begin() as session:
        session.get(IntegrationPolicy, 1).rules = []
    assert env.client.get("/api/capabilities").json()["kubernetes_setup_required"]


def test_invalid_import_rolls_back_draft_and_never_logs_secret(providerless):
    env = providerless
    content = config({"version": 1, "kind": "token", "token": "secret\ninvalid"})
    response = env.client.post("/api/cluster-drafts", json={"name": "bad", "auth_type": "kubeconfig", "connection": {"kind": "kubeconfig", "content": content, "context": "selected"}})
    assert response.status_code == 400 and "secret" not in response.text
    with env.app.state.sessions() as session:
        assert session.scalar(select(func.count(Cluster.id))) == 0
        assert session.scalar(select(func.count(ClusterCredential.user_id))) == 0
    env.factory.assert_not_called()


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/clusters"),
    ("POST", "/api/clusters/removed/authorize"),
    ("GET", "/api/oidc/callback?state=legacy&code=legacy"),
    ("POST", "/api/admin/oidc-providers"),
    ("PATCH", "/api/admin/oidc-providers/removed"),
    ("POST", "/api/admin/oidc-providers/removed/verify"),
])
def test_removed_routes_return_json_404_even_with_frontend(providerless, tmp_path, method, path):
    from dataclasses import replace

    from fastapi.routing import APIRoute

    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>frontend must not handle API</html>")
    app = api.create_app(replace(providerless.app.state.settings, web_dist_dir=str(dist)))
    try:
        with TestClient(app, headers={"Origin": ORIGIN}) as client:
            response = client.request(method, path, json={} if method != "GET" else None)
            assert_error(response, 404, "not_found")
            assert response.headers["content-type"].startswith("application/json")
        routes = [route.path for route in app.routes if isinstance(route, APIRoute)]
        assert not any("oidc" in route or "authorize" in route for route in routes)
    finally:
        app.state.engine.dispose()


@pytest.mark.parametrize("extra", [
    {"auth_type": "oidc"}, {"oidc_provider_id": "legacy"},
    {"oidc_provider_id": None}, {"provider_revision": 0},
    {"connection": {"kind": "manual", "server": SERVER, "context": "selected"}},
])
def test_draft_rejects_legacy_authentication_fields(providerless, extra):
    response = providerless.client.post("/api/cluster-drafts", json={
        "name": "rejected", "auth_type": "kubeconfig",
        "connection": {"kind": "kubeconfig", "content": config(), "context": "selected"},
        **extra,
    })
    assert_error(response, 422, "invalid_input")
    providerless.factory.assert_not_called()


def test_removed_protocol_module_and_dependency_are_absent():
    import importlib.util
    import tomllib
    from pathlib import Path

    assert importlib.util.find_spec("workbench.oidc") is None
    root = Path(__file__).resolve().parents[1]
    metadata = tomllib.loads((root / "pyproject.toml").read_text())
    assert not any("pyjwt" in dependency.lower() for dependency in metadata["project"]["dependencies"])
