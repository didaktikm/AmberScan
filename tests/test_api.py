"""Offline HTTP integration tests with real persistence, sessions, and encryption."""

import base64
import json
import secrets
import socket
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from workbench import api, configuration, scanners
from workbench.config import Settings
from workbench.db import (
    AuditEvent,
    AuthorizationBinding,
    Base,
    Cluster,
    ClusterCredential,
    ClusterGrant,
    Finding,
    IntegrationPolicy,
    LoginAttempt,
    Observation,
    Run,
    User,
    WebSession,
    now,
    uid,
)
from workbench.migrations import init_database
from workbench.security import password_hash
from workbench.services import digest

ORIGIN = "http://testserver"
PASSWORD = "synthetic integration password"
KUBECONFIG_TOKEN = "synthetic-imported-credential-must-be-discarded"
SERVER = "https://10.23.0.10:6443"
FIXTURES = Path(__file__).parent / "fixtures" / "scanners"
REPORTS = [
    ("trivy", "trivy-image.json", 1),
    ("kube-bench", "kube-bench.json", 2),
    ("kubescape", "kubescape-resources.json", 1),
]


@pytest.fixture(scope="module")
def hashed_password():
    return password_hash(PASSWORD)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Allow TestClient's local event loop, but never DNS or outbound sockets."""
    for target, name in (
        (socket, "getaddrinfo"),
        (socket, "create_connection"),
        (socket.socket, "connect"),
        (socket.socket, "connect_ex"),
    ):
        monkeypatch.setattr(
            target, name, Mock(side_effect=AssertionError("Unexpected network access"))
        )


@pytest.fixture
def workbench(monkeypatch, tmp_path, hashed_password):
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        master_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        public_origin=ORIGIN,
        secure_cookie=False,
        allowed_hosts=["10.23.0.10"],
        allowed_cidrs=["10.23.0.0/24"],
        web_dist_dir=str(tmp_path / "not-built"),
    )
    http = Mock(spec=configuration.PolicyHTTP)
    http.get_json.side_effect = AssertionError("Unexpected HTTP request")
    http.post_form.side_effect = AssertionError("Unexpected HTTP request")
    http.validate_endpoint.return_value = ["10.23.0.10"]
    http_factory = Mock(return_value=http)
    monkeypatch.setattr(api, "policy_http", http_factory)
    app = api.create_app(settings)
    init_database(app.state.engine)
    users = {
        name: User(username=name, password_hash=hashed_password, role=role)
        for name, role in (
            ("admin", "administrator"),
            ("auditor", "auditor"),
            ("other-auditor", "auditor"),
            ("lead", "security_lead"),
            ("viewer", "viewer"),
        )
    }
    with app.state.sessions() as session:
        session.add_all(users.values())
        session.merge(
            IntegrationPolicy(
                id=1,
                revision=1,
                rules=[
                    {
                        "id": "kube",
                        "purpose": "kubernetes",
                        "host": "10.23.0.10",
                        "port": 6443,
                        "cidrs": ["10.23.0.0/24"],
                    },
                ],
            )
        )
        session.commit()
    try:
        with TestClient(app, headers={"Origin": ORIGIN}) as client:
            yield SimpleNamespace(
                app=app,
                client=client,
                users=users,
                http=http,
                http_factory=http_factory,
            )
    finally:
        app.state.engine.dispose()


@pytest.fixture
def clusters(workbench):
    rows = [
        Cluster(
            id=uid(),
            name=name,
            context="test-context",
            server=SERVER,
            auth_type="kubeconfig",
            namespaces=["demo", "other"],
        )
        for name in ("granted-cluster", "hidden-cluster")
    ]
    with workbench.app.state.sessions() as session:
        session.add_all(rows)
        session.flush()
        for username in ("auditor", "other-auditor", "lead", "viewer"):
            session.add(
                ClusterGrant(
                    user_id=workbench.users[username].id, cluster_id=rows[0].id
                )
            )
        session.commit()
    return SimpleNamespace(granted=rows[0], hidden=rows[1])


@pytest.fixture
def kubeconfig():
    # JSON is also valid YAML; no user kubeconfig or credential files are read.
    return json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "test-context",
            "clusters": [{"name": "test", "cluster": {"server": SERVER}}],
            "users": [{"name": "test-user", "user": {"token": KUBECONFIG_TOKEN}}],
            "contexts": [
                {
                    "name": "test-context",
                    "context": {"cluster": "test", "user": "test-user"},
                }
            ],
        }
    )


def login(client, username="admin"):
    response = client.post(
        "/api/login", json={"username": username, "password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    client.headers["x-csrf-token"] = response.json()["csrf_token"]
    return response


def assert_error(response, status, code):
    assert response.status_code == status, response.text
    assert response.json()["detail"]["code"] == code


def store_credential(workbench, cluster, username="admin", seconds=600):
    user = workbench.users[username]
    token = f"synthetic.{username}.id-token"
    encrypted = workbench.app.state.vault.encrypt(
        {"version": 1, "kind": "token", "token": token}, f"credential:{user.id}:{cluster.id}"
    )
    with workbench.app.state.sessions() as session:
        binding = session.get(AuthorizationBinding, (user.id, cluster.id))
        if binding is None:
            binding = AuthorizationBinding(
                user_id=user.id, cluster_id=cluster.id, generation=0
            )
            session.add(binding)
        session.merge(
            ClusterCredential(
                user_id=user.id,
                cluster_id=cluster.id,
                encrypted=encrypted,
                expires_at=now() + timedelta(seconds=seconds),
                policy_revision=session.get(IntegrationPolicy, 1).revision,
                auth_generation=binding.generation,
                cluster_generation=session.get(Cluster, cluster.id).auth_generation,
                storage_mode="persistent",
                session_hash=None,
            )
        )
        session.commit()
    return token


def import_report(client, cluster, scanner="trivy", filename="trivy-image.json"):
    response = client.post(
        "/api/imports",
        json={
            "cluster_id": cluster.id,
            "scanner": scanner,
            "report": json.loads((FIXTURES / filename).read_text()),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()




def test_startup_health_routes_and_missing_schema(workbench):
    client = workbench.client
    live = client.get("/api/health/live")
    assert live.status_code == 200
    assert live.json()["status"] == "ok"
    assert live.headers["cache-control"] == "no-store"
    assert live.headers["x-content-type-options"] == "nosniff"
    assert live.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in live.headers["content-security-policy"]
    assert client.get("/api/health/ready").json() == {"status": "ready"}
    assert_error(client.get("/api/session"), 401, "unauthenticated")
    assert_error(client.get("/api/does-not-exist"), 404, "not_found")
    assert client.get("/").status_code == 503
    assert client.get("/").json()["status"] == "frontend_not_built"
    assert client.get("/openapi.json").status_code == 404
    Base.metadata.drop_all(workbench.app.state.engine)
    assert_error(client.get("/api/health/ready"), 503, "storage_error")
    assert client.get("/api/health/live").status_code == 200


def test_runtime_refuses_legacy_marker_without_mutation(workbench):
    from sqlalchemy import text

    with workbench.app.state.engine.begin() as connection:
        connection.execute(text("UPDATE workbench_schema SET version='0.1.0'"))
    assert_error(
        workbench.client.get("/api/health/ready"), 503, "schema_upgrade_required"
    )
    response = workbench.client.post(
        "/api/login", json={"username": "admin", "password": PASSWORD}
    )
    assert_error(response, 503, "schema_upgrade_required")
    assert workbench.client.get("/api/health/live").status_code == 200


def test_login_session_logout_persist_and_revoke_session(workbench):
    client = workbench.client
    response = login(client)
    body = response.json()
    assert body["user"] == {
        "id": workbench.users["admin"].id,
        "username": "admin",
        "role": "administrator",
    }
    assert len(body["csrf_token"]) == 64
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie
    assert "; secure" not in cookie
    token = client.cookies.get(api.COOKIE)
    assert token and client.get("/api/session").json() == body
    with workbench.app.state.sessions() as session:
        saved = session.get(WebSession, digest(token))
        assert saved.user_id == workbench.users["admin"].id
        assert saved.token_hash != token
        assert saved.csrf_token == body["csrf_token"]
        assert session.get(LoginAttempt, digest("testclient")).count == 1
    response = client.post("/api/logout")
    assert response.status_code == 200
    assert response.json() == {"status": "logged_out"}
    assert api.COOKIE not in client.cookies
    assert_error(client.get("/api/session"), 401, "unauthenticated")
    with workbench.app.state.sessions() as session:
        assert session.get(WebSession, digest(token)) is None
        assert set(session.scalars(select(AuditEvent.action))) == {"schema_upgraded", "login", "logout"}


def test_session_rotation_expiry_and_deactivated_user(workbench):
    client = workbench.client
    login(client)
    old_token = client.cookies.get(api.COOKIE)
    login(client)
    new_token = client.cookies.get(api.COOKIE)
    assert new_token != old_token
    assert_error(
        client.get("/api/session", headers={"Cookie": f"{api.COOKIE}={old_token}"}),
        401,
        "unauthenticated",
    )
    with workbench.app.state.sessions() as session:
        assert session.get(WebSession, digest(old_token)) is None
        session.get(WebSession, digest(new_token)).expires_at = now() - timedelta(
            seconds=1
        )
        session.commit()
    assert_error(client.get("/api/session"), 401, "unauthenticated")
    login(client)
    with workbench.app.state.sessions() as session:
        session.get(User, workbench.users["admin"].id).active = False
        session.commit()
    assert_error(client.get("/api/session"), 401, "unauthenticated")
    assert_error(
        client.post("/api/login", json={"username": "admin", "password": PASSWORD}),
        401,
        "unauthenticated",
    )


def test_csrf_rejects_missing_and_wrong_token_without_logging_out(workbench):
    client = workbench.client
    csrf = login(client).json()["csrf_token"]
    del client.headers["x-csrf-token"]
    assert_error(client.post("/api/logout"), 403, "csrf")
    assert_error(
        client.post("/api/logout", headers={"x-csrf-token": "wrong-token"}), 403, "csrf"
    )
    assert client.get("/api/session").status_code == 200
    assert client.post("/api/logout", headers={"x-csrf-token": csrf}).status_code == 200


def test_origin_fetch_site_and_host_boundaries(workbench):
    client = workbench.client
    payload = {"username": "admin", "password": PASSWORD}
    for headers in (
        {"Origin": "https://attacker.example.test"},
        {"Origin": "null"},
        {"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"},
    ):
        assert_error(
            client.post("/api/login", json=payload, headers=headers), 403, "csrf"
        )
    with workbench.app.state.sessions() as session:
        assert session.scalar(select(func.count(WebSession.token_hash))) == 0
        assert session.scalar(select(func.count(LoginAttempt.key))) == 0
    assert login(client).status_code == 200
    assert (
        client.get(
            "/api/session", headers={"Host": "attacker.example.test"}
        ).status_code
        == 400
    )


def test_validation_and_request_limits_do_not_echo_secrets(workbench):
    client = workbench.client
    response = client.post(
        "/api/login",
        json={
            "username": "admin",
            "password": PASSWORD,
            "unexpected": KUBECONFIG_TOKEN,
        },
    )
    assert_error(response, 422, "invalid_input")
    assert PASSWORD not in response.text and KUBECONFIG_TOKEN not in response.text
    oversized = client.post(
        "/api/login",
        content=b"x" * (workbench.app.state.settings.max_body_bytes + 1),
        headers={"Content-Type": "application/json"},
    )
    assert_error(oversized, 413, "too_large")
    login(client)
    for namespaces in (["demo", "demo"], ["../secret"], [], ["UPPERCASE"]):
        assert_error(
            client.post(
                "/api/runs", json={"cluster_id": uid(), "namespaces": namespaces}
            ),
            422,
            "invalid_input",
        )


def test_failed_login_locks_account_and_recovers_after_expiry(workbench):
    client = workbench.client
    for _ in range(5):
        assert_error(
            client.post("/api/login", json={"username": "admin", "password": "wrong"}),
            401,
            "unauthenticated",
        )
    assert_error(
        client.post("/api/login", json={"username": "admin", "password": PASSWORD}),
        429,
        "rate_limited",
    )
    with workbench.app.state.sessions() as session:
        user = session.get(User, workbench.users["admin"].id)
        assert user.locked_until is not None and user.failed_logins == 0
        user.locked_until = now() - timedelta(seconds=1)
        session.commit()
    login(client)
    with workbench.app.state.sessions() as session:
        user = session.get(User, workbench.users["admin"].id)
        assert user.locked_until is None and user.failed_logins == 0


def test_peer_login_limit_and_window_reset(workbench):
    client = workbench.client
    with workbench.app.state.sessions() as session:
        session.add(
            LoginAttempt(key=digest("testclient"), count=29, window_start=now())
        )
        session.commit()
    assert_error(
        client.post("/api/login", json={"username": "unknown", "password": "wrong"}),
        401,
        "unauthenticated",
    )
    assert_error(
        client.post("/api/login", json={"username": "admin", "password": PASSWORD}),
        429,
        "rate_limited",
    )
    with workbench.app.state.sessions() as session:
        attempt = session.get(LoginAttempt, digest("testclient"))
        assert attempt.count == 30
        attempt.window_start = now() - timedelta(minutes=6)
        session.commit()
    login(client)
    with workbench.app.state.sessions() as session:
        assert session.get(LoginAttempt, digest("testclient")).count == 1


def test_cluster_creation_defaults_and_encrypted_kubeconfig_credential(
    workbench, kubeconfig
):
    client = workbench.client
    login(client)
    inspection = client.post("/api/kubeconfig/inspect", json={"content": kubeconfig})
    assert inspection.status_code == 200, inspection.text
    context = inspection.json()["contexts"][0]
    assert context["context"] == "test-context" and context["auth_type"] == "token"
    assert "ca_data" not in context and KUBECONFIG_TOKEN not in inspection.text
    response = client.post(
        "/api/cluster-drafts",
        json={
            "name": "Created via HTTP",
            "connection": {"kind": "kubeconfig", "context": "test-context", "content": kubeconfig},
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["id"] and body["created_at"]
    assert body["environment"] == "test"
    assert body["status"] == "authorized"
    assert body["credential_expires_at"] is not None
    assert body["lifecycle"] == "draft" and body["namespaces"] == []
    assert body["access_revision"] == 0 and body["draft_expires_at"]
    assert client.get("/api/clusters").json() == []
    assert client.get("/api/cluster-drafts").json() == [body]
    with workbench.app.state.sessions() as session:
        cluster = session.get(Cluster, body["id"])
        assert cluster.server == SERVER and cluster.namespaces == []
        assert cluster.draft_owner_id == workbench.users["admin"].id
        assert session.scalar(select(func.count(ClusterCredential.user_id))) == 1
        created = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "cluster_draft_created")
        )
        assert created.target == cluster.id
        assert KUBECONFIG_TOKEN not in json.dumps(created.detail)
    workbench.http_factory.assert_not_called()
    workbench.http.validate_endpoint.assert_not_called()
    workbench.http.get_json.assert_not_called()


def test_capabilities_publish_the_confirmed_actions(workbench):
    login(workbench.client)
    features = workbench.client.get("/api/capabilities").json()["features"]
    available = [item["id"] for item in features if item["status"] == "available"]
    assert available == [
        "read_only",
        "imports",
        "live_scanners",
        "scheduled",
        "extended",
        "operator",
        "runtime",
        "continuous",
        "remediate",
    ]
    assert [item["id"] for item in features if item["status"] == "not_implemented"] == ["team_sso"]


def test_viewer_read_only_and_administrator_only_routes(
    workbench, clusters, kubeconfig
):
    client = workbench.client
    login(client)
    run = import_report(client, clusters.granted)
    finding_id = run["findings"][0]["id"]
    login(client, "viewer")
    for path in (
        "/api/capabilities",
        "/api/overview",
        "/api/clusters",
        "/api/runs",
        "/api/findings",
    ):
        assert client.get(path).status_code == 200
    for method, path, payload in (
        ("POST", f"/api/clusters/{clusters.granted.id}/credential", {"content": kubeconfig, "context": "test-context", "expected_access_revision": 0}),
        (
            "POST",
            f"/api/clusters/{clusters.granted.id}/preflight",
            {"namespaces": ["demo"]},
        ),
        (
            "POST",
            "/api/runs",
            {"cluster_id": clusters.granted.id, "namespaces": ["demo"]},
        ),
        (
            "POST",
            "/api/imports",
            {"cluster_id": clusters.granted.id, "scanner": "trivy", "report": {}},
        ),
        ("POST", f"/api/runs/{run['id']}/cancel", None),
        ("PATCH", f"/api/findings/{finding_id}", {"disposition": "confirmed"}),
        ("GET", f"/api/runs/{run['id']}/report", None),
    ):
        assert_error(client.request(method, path, json=payload), 403, "forbidden")
    for username in ("viewer", "auditor", "lead"):
        if username != "viewer":
            login(client, username)
        assert_error(client.get("/api/audit"), 403, "forbidden")
        assert_error(
            client.post("/api/kubeconfig/inspect", json={"content": kubeconfig}),
            403,
            "forbidden",
        )
        assert_error(
            client.delete(f"/api/clusters/{clusters.granted.id}/credential"),
            403,
            "forbidden",
        )
    workbench.http_factory.assert_not_called()


def test_cluster_grants_isolate_lists_details_mutations_and_reports(
    workbench, clusters
):
    client = workbench.client
    login(client)
    visible = import_report(client, clusters.granted)
    hidden = import_report(client, clusters.hidden)
    login(client, "auditor")
    assert [row["id"] for row in client.get("/api/clusters").json()] == [
        clusters.granted.id
    ]
    assert [row["id"] for row in client.get("/api/runs").json()] == [visible["id"]]
    assert [row["cluster_id"] for row in client.get("/api/findings").json()] == [
        clusters.granted.id
    ]
    overview = client.get("/api/overview").json()
    assert (overview["clusters"], overview["runs"], overview["findings"]) == (1, 1, 1)
    for method, path, payload in (
        ("GET", f"/api/runs/{hidden['id']}", None),
        ("GET", f"/api/runs/{hidden['id']}/report", None),
        ("GET", f"/api/findings?cluster_id={clusters.hidden.id}", None),
        ("POST", f"/api/clusters/{clusters.hidden.id}/authorize", None),
        (
            "POST",
            f"/api/clusters/{clusters.hidden.id}/preflight",
            {"namespaces": ["demo"]},
        ),
        (
            "POST",
            "/api/runs",
            {"cluster_id": clusters.hidden.id, "namespaces": ["demo"]},
        ),
        (
            "POST",
            "/api/imports",
            {"cluster_id": clusters.hidden.id, "scanner": "trivy", "report": {}},
        ),
        ("POST", f"/api/runs/{hidden['id']}/cancel", None),
        (
            "PATCH",
            f"/api/findings/{hidden['findings'][0]['id']}",
            {"disposition": "confirmed"},
        ),
    ):
        assert_error(client.request(method, path, json=payload), 404, "not_found")


def test_app_session_and_other_users_credentials_do_not_authorize_scans(
    workbench, clusters
):
    client = workbench.client
    store_credential(workbench, clusters.granted, "admin")
    login(client, "auditor")
    assert client.get("/api/clusters").json()[0]["status"] == "authorization_required"
    assert_error(
        client.post(
            f"/api/clusters/{clusters.granted.id}/preflight",
            json={"namespaces": ["demo"]},
        ),
        409,
        "authorization_required",
    )
    assert_error(
        client.post(
            "/api/runs",
            json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]},
        ),
        409,
        "authorization_required",
    )
    workbench.http_factory.assert_not_called()
    with workbench.app.state.sessions() as session:
        assert session.scalar(select(func.count(Run.id))) == 0


def test_enqueue_scope_credential_snapshot_conflict_and_cancel(workbench, clusters):
    client = workbench.client
    admin_token = store_credential(workbench, clusters.granted, "admin")
    auditor_token = store_credential(workbench, clusters.granted, "auditor")
    login(client, "auditor")
    assert_error(
        client.post(
            "/api/runs",
            json={"cluster_id": clusters.granted.id, "namespaces": ["outside"]},
        ),
        403,
        "forbidden",
    )
    payload = {"cluster_id": clusters.granted.id, "namespaces": ["demo"]}
    response = client.post("/api/runs", json=payload)
    assert response.status_code == 201, response.text
    run = response.json()
    assert (run["status"], run["stage"], run["source"]) == ("queued", "prepare", "api")
    assert run["scope"] == {
        "namespaces": ["demo"],
        "max_objects": 1000,
        "timeout_seconds": 300,
        "inventory_version": 1,
    }
    assert run["coverage"] == [] and run["limitations"] == [] and run["versions"] == {}
    assert run["cancel_requested"] is False
    with workbench.app.state.sessions() as session:
        saved = session.get(Run, run["id"])
        assert saved.actor_id == workbench.users["auditor"].id
        assert (
            auditor_token not in saved.credential
            and admin_token not in saved.credential
        )
        snapshot = workbench.app.state.vault.decrypt(
            saved.credential, f"run:{saved.id}"
        )
        assert snapshot == {
            "server": SERVER,
            "ca_data": None,
            "auth_type": "kubeconfig",
            "auth": {"version": 1, "kind": "token", "token": auditor_token},
            "expires_at": saved.credential_expires_at.replace(
                tzinfo=now().tzinfo
            ).isoformat(),
            "policy_revision": 1,
            "auth_generation": 0,
            "cluster_generation": 0,
            "scope": run["scope"],
        }
    details = client.get(f"/api/runs/{run['id']}")
    assert details.status_code == 200 and details.json()["findings"] == []
    assert auditor_token not in details.text and admin_token not in details.text
    assert "credential" not in details.json()
    assert_error(client.post("/api/runs", json=payload), 409, "conflict")
    cancelled = client.post(f"/api/runs/{run['id']}/cancel")
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    assert (
        cancelled.json()["finished_at"] and cancelled.json()["cancel_requested"] is True
    )
    with workbench.app.state.sessions() as session:
        assert session.get(Run, run["id"]).credential is None
    workbench.http_factory.assert_not_called()


def test_expired_and_nearly_expired_credentials_cannot_enqueue(workbench, clusters):
    client = workbench.client
    login(client, "auditor")
    for seconds in (-1, 20):
        store_credential(workbench, clusters.granted, "auditor", seconds=seconds)
        assert_error(
            client.post(
                "/api/runs",
                json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]},
            ),
            409,
            "authorization_required",
        )
    store_credential(workbench, clusters.granted, "auditor", seconds=-1)
    assert_error(
        client.post(
            f"/api/clusters/{clusters.granted.id}/preflight",
            json={"namespaces": ["demo"]},
        ),
        409,
        "authorization_required",
    )
    workbench.http_factory.assert_not_called()


def test_preflight_uses_only_scoped_gets_and_current_users_token(workbench, clusters):
    client = workbench.client
    token = store_credential(workbench, clusters.granted, "auditor")
    login(client, "auditor")

    def resource_page(url, headers):
        assert headers["Authorization"] == f"Bearer {token}"
        parsed = urlsplit(url)
        assert parsed.hostname == "10.23.0.10" and "/namespaces/demo/" in parsed.path
        assert parsed.query == "limit=1"
        resource = next(
            item
            for item in scanners.RESOURCES
            if item.plural == parsed.path.rsplit("/", 1)[-1]
        )
        return {
            "kind": resource.kind + "List",
            "apiVersion": resource.api,
            "metadata": {"resourceVersion": "1"},
            "items": [],
        }

    workbench.http.get_json.side_effect = resource_page
    response = client.post(
        f"/api/clusters/{clusters.granted.id}/preflight", json={"namespaces": ["demo"]}
    )
    assert response.status_code == 200, response.text
    assert {item["status"] for item in response.json()["coverage"]} == {"completed"}
    assert workbench.http.get_json.call_count == len(scanners.RESOURCES)
    workbench.http.post_form.assert_not_called()
    assert token not in response.text
    with workbench.app.state.sessions() as session:
        assert session.scalar(select(func.count(Run.id))) == 0
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "preflight")
        )
        assert event.detail == {"namespaces": ["demo"]}




def test_revoke_clears_cluster_credentials_and_queued_snapshot(
    workbench, clusters
):
    client = workbench.client
    login(client)
    for username in ("admin", "auditor"):
        store_credential(workbench, clusters.granted, username)
    store_credential(workbench, clusters.hidden, "admin")
    response = client.post(
        "/api/runs", json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]}
    )
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]
    assert (
        client.post("/api/admin/reauth", json={"password": PASSWORD}).status_code == 200
    )
    response = client.delete(f"/api/clusters/{clusters.granted.id}/credential")
    assert response.status_code == 200
    assert response.json()["status"] == "authorization_required"
    with workbench.app.state.sessions() as session:
        for username in ("admin", "auditor"):
            assert (
                session.get(
                    ClusterCredential,
                    (workbench.users[username].id, clusters.granted.id),
                )
                is None
            )
        assert (
            session.get(
                ClusterCredential, (workbench.users["admin"].id, clusters.hidden.id)
            )
            is not None
        )
        run = session.get(Run, run_id)
        assert (
            run.status == "cancelled"
            and run.cancel_requested
            and run.credential is None
        )
        assert run.finished_at is not None


@pytest.mark.parametrize("scanner,filename,finding_count", REPORTS)
def test_import_fixtures_and_export_all_formats(
    workbench, clusters, scanner, filename, finding_count
):
    client = workbench.client
    login(client, "auditor")
    run = import_report(client, clusters.granted, scanner, filename)
    assert run["status"] == "partial" and run["stage"] == "cleanup"
    assert run["source"] == f"import:{scanner}"
    assert run["scope"] == {"namespaces": [], "verified": False}
    assert run["started_at"] and run["finished_at"] and run["created_at"]
    assert run["limitations"] and len(run["findings"]) == finding_count
    assert any(
        item["check"] == "import:provenance" and item["status"] == "not_checked"
        for item in run["coverage"]
    )
    assert len(client.get("/api/findings").json()) == finding_count
    details = client.get(f"/api/runs/{run['id']}")
    assert details.status_code == 200 and details.json() == run
    for format_name, media_type, extension in (
        ("json", "application/json", "json"),
        ("markdown", "text/markdown", "md"),
        ("html", "text/html", "html"),
    ):
        response = client.get(
            f"/api/runs/{run['id']}/report", params={"format": format_name}
        )
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith(media_type)
        assert (
            response.headers["content-disposition"]
            == f'attachment; filename="amberdata-{run["id"]}.{extension}"'
        )
        assert "amberdata.run.v1" in response.text
        assert "fixture-" not in response.text and "<script" not in response.text
        assert "<img" not in response.text and "credential" not in response.text
        if format_name == "json":
            assert response.json()["findings"] == run["findings"]
            assert response.json()["scope"]["verified"] is False
        elif format_name == "html":
            assert "Content-Security-Policy" in response.text
            assert "default-src 'none'" in response.text
    with workbench.app.state.sessions() as session:
        assert session.scalar(select(func.count(Run.id))) == 1
        assert session.scalar(select(func.count(Finding.id))) == finding_count
        assert (
            session.scalar(select(func.count(Observation.finding_id))) == finding_count
        )
        assert session.get(Run, run["id"]).credential is None
        events = list(
            session.scalars(
                select(AuditEvent).where(AuditEvent.action == "report_exported")
            )
        )
        assert {event.detail["format"] for event in events} == {
            "json",
            "markdown",
            "html",
        }
    workbench.http_factory.assert_not_called()


def test_reimports_deduplicate_findings_and_enforce_review_roles(workbench, clusters):
    client = workbench.client
    login(client, "auditor")
    first = import_report(client, clusters.granted)
    second = import_report(client, clusters.granted)
    finding_id = first["findings"][0]["id"]
    assert second["findings"][0]["id"] == finding_id and first["id"] != second["id"]
    assert_error(
        client.patch(
            f"/api/findings/{finding_id}", json={"disposition": "accepted_risk"}
        ),
        403,
        "forbidden",
    )
    confirmed = client.patch(
        f"/api/findings/{finding_id}", json={"disposition": "confirmed"}
    )
    assert (
        confirmed.status_code == 200 and confirmed.json()["disposition"] == "confirmed"
    )
    login(client, "lead")
    accepted = client.patch(
        f"/api/findings/{finding_id}", json={"disposition": "accepted_risk"}
    )
    assert (
        accepted.status_code == 200
        and accepted.json()["disposition"] == "accepted_risk"
    )
    historical = client.get(f"/api/runs/{first['id']}/report").json()
    assert historical["findings"][0]["disposition"] == "accepted_risk"
    with workbench.app.state.sessions() as session:
        assert session.scalar(select(func.count(Finding.id))) == 1
        assert session.scalar(select(func.count(Observation.finding_id))) == 2
        assert session.get(Finding, finding_id).latest_run_id == second["id"]


def test_invalid_imports_do_not_create_runs_or_leak_report_input(workbench, clusters):
    client = workbench.client
    login(client, "auditor")
    for scanner, report, status, code in (
        ("unknown", {"secret": KUBECONFIG_TOKEN}, 422, "invalid_input"),
        (
            "trivy",
            {"Results": [], "secret": KUBECONFIG_TOKEN},
            400,
            "unsupported_report_schema",
        ),
        ("kubescape", {"results": {}, "resources": []}, 400, "malformed_report"),
    ):
        response = client.post(
            "/api/imports",
            json={
                "cluster_id": clusters.granted.id,
                "scanner": scanner,
                "report": report,
            },
        )
        assert_error(response, status, code)
        assert KUBECONFIG_TOKEN not in response.text
    with workbench.app.state.sessions() as session:
        assert session.scalar(select(func.count(Run.id))) == 0
        assert session.scalar(select(func.count(Finding.id))) == 0
        assert (
            session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.action == "report_imported"
                )
            )
            == 0
        )
    workbench.http_factory.assert_not_called()
