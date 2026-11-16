"""B1 HTTP contract and lifecycle tests: synthetic DB and transport, never live IdP."""

import json
import secrets
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete
from test_api import ORIGIN, PASSWORD, assert_error, login, store_credential
from test_api import clusters as clusters
from test_api import hashed_password as hashed_password
from test_api import no_network as no_network
from test_api import workbench as workbench

from workbench import api, configuration
from workbench.db import (
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
from workbench.services import digest


def reauth(client):
    result = client.post("/api/admin/reauth", json={"password": PASSWORD})
    assert result.status_code == 200, result.text
    return result.json()




def import_personal(workbench, cluster, storage_mode=None):
    content = json.dumps({"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "c", "cluster": {"server": cluster.server}}], "users": [{"name": "u", "user": {"token": "synthetic-imported-token"}}], "contexts": [{"name": cluster.context, "context": {"cluster": "c", "user": "u"}}]})
    response = workbench.client.post(f"/api/clusters/{cluster.id}/credential", json={"content": content, "context": cluster.context, "storage_mode": storage_mode or "run_only", "expected_access_revision": 0})
    assert response.status_code == 200, response.text
    return response


def mutate_access(workbench, cluster, mutation):
    with workbench.app.state.sessions.begin() as session:
        if mutation == "policy":
            session.get(IntegrationPolicy, 1).revision += 1
        elif mutation == "personal":
            configuration.invalidate_access(
                session, cluster_id=cluster.id, user_id=workbench.users["auditor"].id
            )
        elif mutation == "global":
            configuration.invalidate_access(session, cluster_id=cluster.id)
        elif mutation == "disabled":
            session.get(User, workbench.users["auditor"].id).active = False
        elif mutation == "logout":
            session.execute(
                delete(WebSession).where(
                    WebSession.token_hash
                    == digest(workbench.client.cookies.get(api.COOKIE))
                )
            )
        elif mutation == "grant":
            session.execute(
                delete(ClusterGrant).where(
                    ClusterGrant.user_id == workbench.users["auditor"].id,
                    ClusterGrant.cluster_id == cluster.id,
                )
            )
        elif mutation == "role":
            session.get(User, workbench.users["auditor"].id).role = "viewer"
        else:
            raise AssertionError(mutation)


def test_setup_passive_db_only_no_legacy_fallback(workbench):
    client = workbench.client
    login(client)
    before = client.get("/api/admin/setup")
    assert before.status_code == 200
    assert "providers" not in before.json() and "redirect_uri" not in before.json()
    assert before.json()["reauthenticated_until"] is None
    assert before.json()["legacy_configuration_available"] is True
    with workbench.app.state.sessions.begin() as session:
        session.execute(delete(IntegrationPolicy))
    # Static Settings still contains the legacy provider and allowlist: neither is active.
    empty = client.get("/api/admin/setup").json()
    assert "providers" not in empty
    assert empty["policy"] == {"revision": 0, "rules": [], "legacy_imported": False}
    capabilities = client.get("/api/capabilities").json()
    assert (
        "oidc_providers" not in capabilities and capabilities["setup_required"] is True
    )
    workbench.http_factory.assert_not_called()
    with workbench.app.state.sessions() as session:
        assert session.get(IntegrationPolicy, 1) is None


@pytest.mark.parametrize("username", ["viewer", "auditor", "lead"])
def test_admin_routes_role_guard_before_reauth_or_network(workbench, username):
    client = workbench.client
    login(client, username)
    for method, path, payload in (
        ("GET", "/api/admin/setup", None),
        ("POST", "/api/admin/reauth", {"password": PASSWORD}),
        ("PUT", "/api/admin/egress-policy", {"expected_revision": 1, "rules": []}),
    ):
        assert_error(client.request(method, path, json=payload), 403, "forbidden")
    workbench.http_factory.assert_not_called()


def test_admin_mutations_need_csrf_and_five_minute_reauth(workbench, clusters):
    client = workbench.client
    login(client)
    paths = [
        ("PUT", "/api/admin/egress-policy", {"expected_revision": 1, "rules": []}),
        ("DELETE", f"/api/clusters/{clusters.granted.id}/credential", None),
    ]
    for method, path, payload in paths:
        assert_error(
            client.request(method, path, json=payload), 403, "reauthentication_required"
        )
        assert_error(
            client.request(method, path, json=payload, headers={"x-csrf-token": "bad"}),
            403,
            "csrf",
        )
    assert_error(
        client.post(
            "/api/admin/reauth",
            json={"password": PASSWORD},
            headers={"x-csrf-token": "bad"},
        ),
        403,
        "csrf",
    )
    until = reauth(client)["reauthenticated_until"]
    assert until == client.get("/api/session").json()["reauthenticated_until"]
    assert until == client.get("/api/admin/setup").json()["reauthenticated_until"]
    with workbench.app.state.sessions.begin() as session:
        session.get(
            WebSession, digest(client.cookies.get(api.COOKIE))
        ).reauthenticated_at = now() - timedelta(minutes=5, seconds=1)
    for method, path, payload in paths:
        assert_error(
            client.request(method, path, json=payload), 403, "reauthentication_required"
        )


def test_reauth_uses_login_lockout_and_never_echoes_password(workbench):
    client = workbench.client
    login(client)
    reauth(client)
    for _ in range(5):
        response = client.post(
            "/api/admin/reauth", json={"password": "not-the-synthetic-password"}
        )
        assert_error(response, 403, "reauthentication_failed")
        assert "not-the-synthetic-password" not in response.text
    assert client.get("/api/session").json()["reauthenticated_until"] is None
    assert_error(
        client.post("/api/admin/reauth", json={"password": PASSWORD}),
        429,
        "rate_limited",
    )
    assert_error(
        client.post("/api/login", json={"username": "admin", "password": PASSWORD}),
        429,
        "rate_limited",
    )
    with workbench.app.state.sessions.begin() as session:
        session.get(User, workbench.users["admin"].id).locked_until = now() - timedelta(
            seconds=1
        )
    reauth(client)
    assert PASSWORD not in client.get("/api/audit").text
    assert "not-the-synthetic-password" not in client.get("/api/audit").text




def test_policy_api_mutation_invalidates_auth_work_and_is_revision_bound(
    workbench, clusters
):
    client = workbench.client
    login(client)
    store_credential(workbench, clusters.granted)
    run = client.post(
        "/api/runs", json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]}
    ).json()
    reauth(client)
    response = client.put(
        "/api/admin/egress-policy", json={"expected_revision": 1, "rules": []}
    )
    assert response.status_code == 200, response.text
    assert response.json()["revision"] == 2 and response.json()["rules"] == []
    assert_error(
        client.put(
            "/api/admin/egress-policy", json={"expected_revision": 1, "rules": []}
        ),
        409,
        "conflict",
    )
    with workbench.app.state.sessions() as session:
        assert (
            session.get(
                ClusterCredential, (workbench.users["admin"].id, clusters.granted.id)
            )
            is None
        )
        saved = session.get(Run, run["id"])
        assert saved.status == "cancelled" and saved.credential is None










def test_default_one_shot_is_session_bound_consumed_and_snapshot_survives(
    workbench, clusters
):
    client = workbench.client
    login(client, "auditor")
    import_personal(workbench, clusters.granted)
    view = client.get("/api/clusters").json()[0]
    assert view["status"] == "authorized" and view["storage_mode"] == "run_only"
    with workbench.app.state.sessions() as session:
        credential = session.get(
            ClusterCredential, (workbench.users["auditor"].id, clusters.granted.id)
        )
        assert credential.session_hash == digest(client.cookies.get(api.COOKIE))
        expiry = aware(credential.expires_at)
    response = client.post(
        "/api/runs", json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]}
    )
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]
    with workbench.app.state.sessions() as session:
        assert (
            session.get(
                ClusterCredential, (workbench.users["auditor"].id, clusters.granted.id)
            )
            is None
        )
        run = session.get(Run, run_id)
        assert aware(run.credential_expires_at) == expiry
        snapshot = workbench.app.state.vault.decrypt(run.credential, f"run:{run_id}")
        assert snapshot["expires_at"] == expiry.isoformat()
    assert client.get("/api/clusters").json()[0]["status"] == "authorization_required"
    assert_error(
        client.post(
            "/api/runs",
            json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]},
        ),
        409,
        "authorization_required",
    )
    assert client.post("/api/logout").status_code == 200
    with workbench.app.state.sessions() as session:
        assert session.get(Run, run_id).credential is not None


@pytest.mark.parametrize("storage_mode,persists", [(None, False), ("persistent", True)])
def test_logout_cleans_only_unused_one_shot_credentials(
    workbench, clusters, storage_mode, persists
):
    client = workbench.client
    login(client, "auditor")
    import_personal(workbench, clusters.granted, storage_mode)
    assert client.post("/api/logout").status_code == 200
    with workbench.app.state.sessions() as session:
        credential = session.get(
            ClusterCredential, (workbench.users["auditor"].id, clusters.granted.id)
        )
        assert (credential is not None) == persists
        if persists:
            assert (
                credential.storage_mode == "persistent"
                and credential.session_hash is None
            )
    login(client, "auditor")
    assert client.get("/api/clusters").json()[0]["status"] == (
        "authorized" if persists else "authorization_required"
    )


def test_run_only_rejects_different_session_even_same_user(workbench, clusters):
    client = workbench.client
    login(client, "auditor")
    import_personal(workbench, clusters.granted)
    token = secrets.token_urlsafe(48)
    with workbench.app.state.sessions.begin() as session:
        session.add(
            WebSession(
                token_hash=digest(token),
                user_id=workbench.users["auditor"].id,
                csrf_token="test-csrf",
                expires_at=now() + timedelta(hours=1),
            )
        )
    with TestClient(
        workbench.app, headers={"Origin": ORIGIN, "x-csrf-token": "test-csrf"}
    ) as other:
        other.cookies.set(api.COOKIE, token)
        assert (
            other.get("/api/clusters").json()[0]["status"] == "authorization_required"
        )
        assert_error(
            other.post(
                "/api/runs",
                json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]},
            ),
            409,
            "authorization_required",
        )


@pytest.mark.parametrize(
    "field",
    ["policy_revision", "auth_generation", "cluster_generation"],
)
def test_stale_credentials_and_legacy_revision_zero_never_authorize(
    workbench, clusters, field
):
    client = workbench.client
    login(client, "auditor")
    store_credential(workbench, clusters.granted, "auditor")
    with workbench.app.state.sessions.begin() as session:
        credential = session.get(
            ClusterCredential, (workbench.users["auditor"].id, clusters.granted.id)
        )
        setattr(credential, field, 0 if field.endswith("revision") else 1)
    assert client.get("/api/clusters").json()[0]["status"] == "authorization_required"
    for path, payload in (
        (f"/api/clusters/{clusters.granted.id}/preflight", {"namespaces": ["demo"]}),
        ("/api/runs", {"cluster_id": clusters.granted.id, "namespaces": ["demo"]}),
    ):
        assert_error(client.post(path, json=payload), 409, "authorization_required")
    workbench.http_factory.assert_not_called()


def test_personal_revoke_does_not_touch_other_users_or_require_admin_reauth(
    workbench, clusters
):
    client = workbench.client
    login(client, "auditor")
    store_credential(workbench, clusters.granted, "auditor")
    store_credential(workbench, clusters.granted, "other-auditor")
    run = client.post(
        "/api/runs", json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]}
    ).json()
    response = client.delete(f"/api/clusters/{clusters.granted.id}/authorization")
    assert response.status_code == 200, response.text
    with workbench.app.state.sessions() as session:
        own = workbench.users["auditor"].id
        assert session.get(ClusterCredential, (own, clusters.granted.id)) is None
        assert (
            session.get(AuthorizationBinding, (own, clusters.granted.id)).generation
            == 1
        )
        assert session.get(Cluster, clusters.granted.id).auth_generation == 0
        assert (
            session.get(
                ClusterCredential,
                (workbench.users["other-auditor"].id, clusters.granted.id),
            )
            is not None
        )
        assert session.get(Run, run["id"]).status == "cancelled"
    login(client, "viewer")
    assert_error(
        client.delete(f"/api/clusters/{clusters.granted.id}/authorization"),
        403,
        "forbidden",
    )
