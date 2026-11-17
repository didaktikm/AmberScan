"""Namespace onboarding against synthetic persistence/HTTP; never a live cluster."""

import json
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from sqlalchemy import event, select
from sqlalchemy.dialects import postgresql
from test_api import (
    KUBECONFIG_TOKEN,
    SERVER,
    assert_error,
    login,
    store_credential,
)
from test_api import clusters as clusters
from test_api import hashed_password as hashed_password
from test_api import kubeconfig as kubeconfig
from test_api import no_network as no_network
from test_api import workbench as workbench
from test_api_configuration import import_personal, mutate_access, reauth

from workbench import api, connections, scanners
from workbench.db import (
    AuthorizationBinding,
    Cluster,
    ClusterCredential,
    Run,
    User,
    WebSession,
    aware,
    now,
)
from workbench.domain import DomainError
from workbench.services import digest


def draft_payload(**changes):
    return {
        "name": "Synthetic draft",
        "environment": "test",
        "auth_type": "kubeconfig",
        "connection": {"kind": "kubeconfig", "context": "test-context", "content": json.dumps({"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "c", "cluster": {"server": SERVER}}], "users": [{"name": "u", "user": {"token": KUBECONFIG_TOKEN}}], "contexts": [{"name": "test-context", "context": {"cluster": "c", "user": "u"}}]})},
        **changes,
    }


def make_draft(workbench, payload=None):
    response = workbench.client.post("/api/cluster-drafts", json=payload or draft_payload())
    assert response.status_code == 201, response.text
    return SimpleNamespace(**response.json())


def namespace_page(names, cursor="", revision="10"):
    return {
        "kind": "NamespaceList", "apiVersion": "v1",
        "metadata": {"resourceVersion": revision, "continue": cursor},
        "items": [
            {"metadata": {"name": name, "annotations": {"token": "must-not-project"}}, "status": {"phase": "Active"}}
            for name in names
        ],
    }


def resource_page(url, headers=None):
    parsed = urlsplit(url)
    assert parsed.query == "limit=1"
    resource = next(resource for resource in scanners.RESOURCES if resource.plural == parsed.path.rsplit("/", 1)[-1])
    return {"kind": resource.kind + "List", "apiVersion": resource.api, "metadata": {"resourceVersion": "1"}, "items": []}


def finalize(workbench, draft, **changes):
    return workbench.client.post(
        f"/api/cluster-drafts/{draft.id}/finalize",
        json={"namespaces": ["chosen"], "expected_access_revision": draft.access_revision, **changes},
    )


def test_draft_creation_is_offline_private_and_not_authority(workbench, kubeconfig):
    client = workbench.client
    login(client)
    config = json.loads(kubeconfig)
    config["contexts"][0]["context"]["namespace"] = "hint-only"
    draft = make_draft(workbench, draft_payload(connection={"kind": "kubeconfig", "content": json.dumps(config), "context": "test-context"}))
    assert draft.namespace_hint == "hint-only"
    assert draft.namespaces == [] and draft.lifecycle == "draft"
    assert draft.status == "authorized" and draft.access_revision == 0
    assert client.get("/api/clusters").json() == []
    assert client.get("/api/overview").json()["clusters"] == 0
    view = client.get(f"/api/cluster-drafts/{draft.id}")
    assert view.status_code == 200
    assert KUBECONFIG_TOKEN not in view.text and "content" not in view.json()
    with workbench.app.state.sessions() as session:
        saved = session.get(Cluster, draft.id)
        assert saved.draft_owner_id == workbench.users["admin"].id
        assert now() + timedelta(hours=23) < aware(saved.draft_expires_at) <= now() + timedelta(hours=24)
        assert len(list(session.scalars(select(ClusterCredential)))) == 1
    for path, payload in (
        ("/api/runs", {"cluster_id": draft.id, "namespaces": ["hint-only"]}),
        ("/api/imports", {"cluster_id": draft.id, "scanner": "trivy", "report": {}}),
    ):
        assert_error(client.post(path, json=payload), 404, "not_found")
    workbench.http_factory.assert_not_called()


@pytest.mark.parametrize("username", ["auditor", "viewer", "lead", "other-auditor"])
def test_draft_owner_privacy_includes_other_administrators(workbench, username):
    client = workbench.client
    login(client)
    draft = make_draft(workbench)
    with workbench.app.state.sessions.begin() as session:
        session.get(User, workbench.users[username].id).role = "administrator"
    login(client, username)
    assert client.get("/api/cluster-drafts").json() == []
    assert client.get("/api/clusters").json() == []
    for method, path, payload in (
        ("GET", f"/api/cluster-drafts/{draft.id}", None),
        ("DELETE", f"/api/cluster-drafts/{draft.id}", None),
        ("POST", f"/api/clusters/{draft.id}/authorize", {}),
        ("POST", f"/api/clusters/{draft.id}/namespaces/discover", {}),
        ("POST", f"/api/clusters/{draft.id}/preflight", {"namespaces": ["chosen"]}),
        ("DELETE", f"/api/clusters/{draft.id}/authorization", None),
        ("POST", f"/api/cluster-drafts/{draft.id}/finalize", {"namespaces": ["chosen"], "expected_access_revision": 0}),
    ):
        assert_error(client.request(method, path, json=payload), 404, "not_found")
    with workbench.app.state.sessions() as session:
        assert session.get(AuthorizationBinding, (workbench.users[username].id, draft.id)) is None
    workbench.http_factory.assert_not_called()


def test_same_endpoint_requires_a_different_name(workbench):
    client = workbench.client
    login(client)
    draft = make_draft(workbench)
    with workbench.app.state.sessions.begin() as session:
        saved = session.get(Cluster, draft.id)
        saved.lifecycle = "ready"
        saved.namespaces = ["chosen"]
        saved.draft_owner_id = None
        saved.draft_expires_at = None
    duplicate = client.post("/api/cluster-drafts", json=draft_payload(name="Synthetic draft"))
    assert_error(duplicate, 400, "cluster_duplicate")
    assert "Synthetic draft" in duplicate.json()["detail"]["message"]
    same_name = client.post("/api/cluster-drafts", json=draft_payload(name="Synthetic draft", accept_alias=True))
    assert_error(same_name, 400, "cluster_duplicate")
    alias = make_draft(workbench, draft_payload(name="Второй контур", accept_alias=True))
    assert alias.name == "Второй контур" and alias.lifecycle == "draft"
    workbench.http_factory.assert_not_called()


@pytest.mark.parametrize("username", ["auditor", "viewer", "lead"])
def test_non_admin_cannot_create_drafts(workbench, username):
    login(workbench.client, username)
    assert_error(workbench.client.post("/api/cluster-drafts", json=draft_payload()), 403, "forbidden")
    assert_error(workbench.client.get("/api/cluster-drafts"), 403, "forbidden")
    workbench.http_factory.assert_not_called()


def test_abort_and_expiry_cascade_credentials_and_states(workbench):
    client = workbench.client
    login(client)
    draft = make_draft(workbench)
    store_credential(workbench, draft)
    assert client.delete(f"/api/cluster-drafts/{draft.id}").json() == {"status": "discarded"}
    with workbench.app.state.sessions() as session:
        assert session.get(Cluster, draft.id) is None
        assert session.get(ClusterCredential, (workbench.users["admin"].id, draft.id)) is None
    expired = make_draft(workbench)
    store_credential(workbench, expired)
    with workbench.app.state.sessions.begin() as session:
        session.get(Cluster, expired.id).draft_expires_at = now() - timedelta(seconds=1)
    assert_error(client.get(f"/api/cluster-drafts/{expired.id}"), 404, "not_found")
    assert_error(client.post(f"/api/clusters/{expired.id}/authorize"), 404, "not_found")
    assert client.get("/api/cluster-drafts").json() == []
    with workbench.app.state.sessions() as session:
        assert session.get(Cluster, expired.id) is None


def test_owned_draft_limit_cleanup_never_deletes_ready_rows(workbench):
    client = workbench.client
    login(client)
    drafts = [make_draft(workbench) for _ in range(connections.MAX_OWNED_DRAFTS)]
    assert_error(client.post("/api/cluster-drafts", json=draft_payload()), 429, "rate_limited")
    with workbench.app.state.sessions.begin() as session:
        expired = session.get(Cluster, drafts[0].id)
        expired.draft_expires_at = now() - timedelta(seconds=1)
        ready = session.get(Cluster, drafts[1].id)
        ready.lifecycle = "ready"
        ready.draft_expires_at = now() - timedelta(seconds=1)
    make_draft(workbench)
    with workbench.app.state.sessions.begin() as session:
        assert connections.cleanup_expired_drafts(session) == 0
        assert session.get(Cluster, drafts[0].id) is None
        assert session.get(Cluster, drafts[1].id).lifecycle == "ready"


@pytest.mark.parametrize("changes", [
    {"namespaces": ["default"]}, {"cluster_scope": True}, {"profile": "full"},
    {"connection": {"kind": "manual", "context": "x", "server": SERVER, "token": "secret"}},
    {"connection": {"kind": "manual", "context": "x", "server": SERVER, "insecure_skip_tls_verify": True}},
])
def test_draft_strict_models_reject_implicit_scope_or_credentials(workbench, changes):
    login(workbench.client)
    response = workbench.client.post("/api/cluster-drafts", json=draft_payload(**changes))
    assert_error(response, 422, "invalid_input")
    assert "secret" not in response.text
    workbench.http_factory.assert_not_called()


@pytest.mark.parametrize("server", ["http://10.23.0.10", SERVER + "/%2e%2e/", SERVER + "/../", SERVER + "?token=secret", "https://user:secret@host"])
def test_manual_metadata_invalid_endpoint_never_uses_network(workbench, server):
    login(workbench.client)
    response = workbench.client.post("/api/cluster-drafts", json=draft_payload(connection={"kind": "manual", "context": "x", "server": server}))
    assert response.status_code == 422
    assert "secret" not in response.text
    workbench.http_factory.assert_not_called()




def client_draft(workbench, draft):
    return workbench.client.get(f"/api/cluster-drafts/{draft.id}").json()




def test_draft_is_user_bound_but_run_only_token_session_bound(workbench):
    client = workbench.client
    login(client)
    draft = make_draft(workbench)
    client.post("/api/logout")
    login(client)
    assert client_draft(workbench, draft)["status"] == "authorization_required"
    assert_error(client.post(f"/api/clusters/{draft.id}/namespaces/discover", json={}), 409, "authorization_required")


def test_discovery_is_names_only_uses_own_token_and_never_saves_allowlist(workbench):
    client = workbench.client
    login(client)
    draft = make_draft(workbench)
    token = store_credential(workbench, draft)
    requests = []

    def page(url, headers):
        requests.append(url)
        assert headers["Authorization"] == f"Bearer {token}"
        assert url == SERVER + "/api/v1/namespaces?limit=200"
        return namespace_page(["work", "kube-system"])

    workbench.http.get_json.side_effect = page
    response = client.post(f"/api/clusters/{draft.id}/namespaces/discover", json={})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "status": "complete", "complete": True, "limitation": None, "namespace_hint": None, "continuation": None,
        "items": [{"name": "kube-system", "system": True, "phase": "Active"}, {"name": "work", "system": False, "phase": "Active"}],
    }
    assert len(requests) == 1 and "must-not-project" not in response.text
    assert client_draft(workbench, draft)["namespaces"] == []


@pytest.mark.parametrize("username,expected", [("admin", ["demo", "outside"]), ("auditor", ["demo"]), ("lead", ["demo"])])
def test_ready_discovery_filters_nonadmin_results_to_saved_allowlist(workbench, clusters, username, expected):
    login(workbench.client, username)
    store_credential(workbench, clusters.granted, username)
    with workbench.app.state.sessions.begin() as session:
        session.get(Cluster, clusters.granted.id).context_namespace_hint = "private-team"
    workbench.http.get_json.side_effect = lambda *_args, **_kwargs: namespace_page(["outside", "demo"])
    response = workbench.client.post(f"/api/clusters/{clusters.granted.id}/namespaces/discover", json={})
    assert response.status_code == 200, response.text
    assert [item["name"] for item in response.json()["items"]] == expected
    expected_hint = "private-team" if username == "admin" else None
    assert response.json()["namespace_hint"] == expected_hint
    rows = workbench.client.get("/api/clusters").json()
    assert next(row for row in rows if row["id"] == clusters.granted.id)["namespace_hint"] == expected_hint
    if username != "admin":
        assert "private-team" not in workbench.client.get("/api/clusters").text
    with workbench.app.state.sessions.begin() as session:
        session.get(Cluster, clusters.granted.id).context_namespace_hint = "demo"
    rows = workbench.client.get("/api/clusters").json()
    assert next(row for row in rows if row["id"] == clusters.granted.id)["namespace_hint"] == "demo"


@pytest.mark.parametrize("kind", ["discover", "preflight"])
def test_kubernetes_401_is_conflict_not_application_logout(workbench, clusters, kind):
    login(workbench.client, "auditor")
    store_credential(workbench, clusters.granted, "auditor")
    workbench.http.get_json.side_effect = DomainError("untrusted upstream token secret", "http_401")
    route = "namespaces/discover" if kind == "discover" else "preflight"
    response = workbench.client.post(f"/api/clusters/{clusters.granted.id}/{route}", json={} if kind == "discover" else {"namespaces": ["demo"]})
    assert_error(response, 409, "kubernetes_authentication_required")
    assert "secret" not in response.text
    assert workbench.client.get("/api/session").status_code == 200
    assert workbench.http.get_json.call_count == 1


def test_discovery_forbidden_offers_manual_selection(workbench):
    login(workbench.client)
    draft = make_draft(workbench)
    store_credential(workbench, draft)
    workbench.http.get_json.side_effect = DomainError("private upstream", "http_403")
    result = workbench.client.post(f"/api/clusters/{draft.id}/namespaces/discover", json={})
    assert result.status_code == 200 and result.json()["status"] == "forbidden"
    assert result.json()["items"] == [] and result.json()["complete"] is False
    workbench.http.get_json.side_effect = resource_page
    response = finalize(workbench, draft)
    assert response.status_code == 200, response.text
    assert response.json()["cluster"]["namespaces"] == ["chosen"]


@pytest.mark.parametrize("mutation", ["policy", "personal", "global", "disabled", "logout", "grant", "role", "replacement", "scope"])
@pytest.mark.parametrize("kind", ["discover", "preflight"])
def test_every_get_stops_after_authorization_changes(workbench, clusters, mutation, kind):
    login(workbench.client, "auditor")
    store_credential(workbench, clusters.granted, "auditor")

    def changed(url, headers):
        if mutation == "replacement":
            store_credential(workbench, clusters.granted, "auditor")
        elif mutation == "scope":
            with workbench.app.state.sessions.begin() as session:
                session.get(Cluster, clusters.granted.id).namespaces = ["other"]
        else:
            mutate_access(workbench, clusters.granted, mutation)
        return namespace_page(["demo"], cursor="next") if kind == "discover" else resource_page(url, headers)

    workbench.http.get_json.side_effect = changed
    path = "namespaces/discover" if kind == "discover" else "preflight"
    response = workbench.client.post(f"/api/clusters/{clusters.granted.id}/{path}", json={} if kind == "discover" else {"namespaces": ["demo"]})
    assert response.status_code in {401, 403, 404, 409}, response.text
    assert workbench.http.get_json.call_count == 1
    if mutation == "replacement":
        with workbench.app.state.sessions() as session:
            assert session.get(ClusterCredential, (workbench.users["auditor"].id, clusters.granted.id)) is not None


@pytest.mark.parametrize("kind", ["discover", "preflight"])
def test_final_publication_rechecks_exact_credential_even_after_last_get(workbench, clusters, kind):
    login(workbench.client, "auditor")
    store_credential(workbench, clusters.granted, "auditor")
    count = 0

    def page(url, headers):
        nonlocal count
        count += 1
        if kind == "discover" or count == len(scanners.RESOURCES):
            store_credential(workbench, clusters.granted, "auditor")
        return namespace_page(["demo"]) if kind == "discover" else resource_page(url, headers)

    workbench.http.get_json.side_effect = page
    path = "namespaces/discover" if kind == "discover" else "preflight"
    response = workbench.client.post(f"/api/clusters/{clusters.granted.id}/{path}", json={} if kind == "discover" else {"namespaces": ["demo"]})
    assert_error(response, 409, "authorization_required")


def test_each_get_rebuilds_policy_and_releases_transaction(workbench, clusters, monkeypatch):
    login(workbench.client)
    store_credential(workbench, clusters.granted)
    real = api.preflight

    def preflight(connection, scope, http):
        def page(url, headers):
            assert not http.session.in_transaction()
            return resource_page(url, headers)
        workbench.http.get_json.side_effect = page
        return real(connection, scope, http)

    monkeypatch.setattr(api, "preflight", preflight)
    response = workbench.client.post(f"/api/clusters/{clusters.granted.id}/preflight", json={"namespaces": ["demo"]})
    assert response.status_code == 200, response.text
    assert workbench.http_factory.call_count == len(scanners.RESOURCES)


def test_finalize_reprobes_selected_only_preserves_exact_own_one_shot(workbench):
    login(workbench.client)
    draft = make_draft(workbench)
    store_credential(workbench, draft, "auditor")  # Defensive cleanup of a corrupt foreign draft credential.
    with workbench.app.state.sessions() as session:
        credential = session.get(ClusterCredential, (workbench.users["admin"].id, draft.id))
        encrypted, expiry, session_hash = credential.encrypted, aware(credential.expires_at), credential.session_hash
    workbench.http.get_json.side_effect = resource_page
    response = finalize(workbench, draft)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["cluster"]["lifecycle"] == "ready" and result["cluster"]["access_revision"] == 1
    assert result["cluster"]["draft_expires_at"] is None
    assert result["cluster"]["status"] == "authorized" and result["cluster"]["storage_mode"] == "run_only"
    assert len(result["coverage"]) == len(scanners.RESOURCES)
    assert all("/namespaces/chosen/" in call.args[0] for call in workbench.http.get_json.call_args_list)
    with workbench.app.state.sessions() as session:
        saved = session.get(Cluster, draft.id)
        assert saved.draft_owner_id is None and saved.namespaces == ["chosen"]
        credential = session.get(ClusterCredential, (workbench.users["admin"].id, draft.id))
        assert (credential.encrypted, aware(credential.expires_at), credential.session_hash) == (encrypted, expiry, session_hash)
        assert credential.cluster_generation == 1
        assert session.get(ClusterCredential, (workbench.users["auditor"].id, draft.id)) is None
    assert workbench.client.get("/api/cluster-drafts").json() == []
    assert_error(finalize(workbench, draft), 404, "not_found")
    queued = workbench.client.post("/api/runs", json={"cluster_id": draft.id, "namespaces": ["chosen"]})
    assert queued.status_code == 201
    with workbench.app.state.sessions() as session:
        run = session.get(Run, queued.json()["id"])
        snapshot = workbench.app.state.vault.decrypt(run.credential, f"run:{run.id}")
        assert snapshot["scope"] == run.scope
        assert run.scope["inventory_version"] == 1


@pytest.mark.parametrize("code", ["http_403", "http_401", "http_tls", "http_transport", "http_timeout", "http_404", "http_405", "endpoint_denied", "http_invalid_json"])
def test_finalize_never_accepts_all_failed_or_fatal_coverage(workbench, code):
    login(workbench.client)
    draft = make_draft(workbench)
    store_credential(workbench, draft)
    workbench.http.get_json.side_effect = DomainError("never-return-this-token", code)
    response = finalize(workbench, draft, accept_partial=True)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == ("kubernetes_authentication_required" if code == "http_401" else "preflight_failed")
    assert "never-return-this-token" not in response.text
    assert client_draft(workbench, draft)["lifecycle"] == "draft"


def test_partial_requires_explicit_ack_and_is_recomputed_each_time(workbench):
    login(workbench.client)
    draft = make_draft(workbench)
    store_credential(workbench, draft)

    def partial(url, headers):
        if "/pods?" in url:
            raise DomainError("private", "http_403")
        return resource_page(url, headers)

    workbench.http.get_json.side_effect = partial
    assert_error(finalize(workbench, draft), 409, "preflight_partial")
    assert workbench.http.get_json.call_count == len(scanners.RESOURCES)
    assert finalize(workbench, draft, accept_partial=True).status_code == 200
    assert workbench.http.get_json.call_count == 2 * len(scanners.RESOURCES)


def test_success_then_fatal_cannot_be_acknowledged(workbench):
    login(workbench.client)
    draft = make_draft(workbench)
    store_credential(workbench, draft)

    def partial(url, headers):
        if "/pods?" in url:
            raise DomainError("private", "http_tls")
        return resource_page(url, headers)

    workbench.http.get_json.side_effect = partial
    assert_error(finalize(workbench, draft, accept_partial=True), 409, "preflight_failed")


@pytest.mark.parametrize("mutation", ["replacement", "abort", "expire", "scope", "generation"])
def test_finalize_rechecks_before_any_commit(workbench, mutation):
    login(workbench.client)
    draft = make_draft(workbench)
    store_credential(workbench, draft)
    count = 0

    def page(url, headers):
        nonlocal count
        count += 1
        if count == len(scanners.RESOURCES):
            if mutation == "replacement":
                store_credential(workbench, draft)
            else:
                with workbench.app.state.sessions.begin() as session:
                    saved = session.get(Cluster, draft.id)
                    if mutation == "abort":
                        session.delete(saved)
                    elif mutation == "expire":
                        saved.draft_expires_at = now() - timedelta(seconds=1)
                    elif mutation == "scope":
                        saved.namespaces = ["outside"]
                    else:
                        saved.auth_generation += 1
        return resource_page(url, headers)

    workbench.http.get_json.side_effect = page
    response = finalize(workbench, draft)
    assert response.status_code in {404, 409}, response.text
    with workbench.app.state.sessions() as session:
        saved = session.get(Cluster, draft.id)
        assert saved is None or saved.lifecycle == "draft"




def test_scope_edit_requires_recent_admin_and_does_not_mutate_preflight(workbench, clusters):
    client = workbench.client
    login(client, "auditor")
    store_credential(workbench, clusters.granted, "auditor")
    route = f"/api/clusters/{clusters.granted.id}/scope"
    assert_error(client.post(route + "/preflight", json={"namespaces": ["expansion"]}), 403, "forbidden")
    login(client)
    store_credential(workbench, clusters.granted)
    assert_error(client.post(route + "/preflight", json={"namespaces": ["expansion"]}), 403, "reauthentication_required")
    workbench.http_factory.assert_not_called()
    reauth(client)
    workbench.http.get_json.side_effect = resource_page
    assert_error(client.post(f"/api/clusters/{clusters.granted.id}/preflight", json={"namespaces": ["expansion"]}), 403, "forbidden")
    response = client.post(route + "/preflight", json={"namespaces": ["expansion"]})
    assert response.status_code == 200, response.text
    with workbench.app.state.sessions() as session:
        assert session.get(Cluster, clusters.granted.id).namespaces == ["demo", "other"]
    assert all("/namespaces/expansion/" in call.args[0] for call in workbench.http.get_json.call_args_list)


def test_scope_update_cas_invalidates_jobs_all_credentials_and_states(workbench, clusters):
    client = workbench.client
    login(client)
    store_credential(workbench, clusters.granted)
    store_credential(workbench, clusters.granted, "auditor")
    run = client.post("/api/runs", json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]}).json()
    reauth(client)
    workbench.http.get_json.side_effect = resource_page
    route = f"/api/clusters/{clusters.granted.id}/scope"
    response = client.patch(route, json={"namespaces": ["expansion"], "expected_access_revision": 0})
    assert response.status_code == 200, response.text
    assert response.json()["cluster"]["namespaces"] == ["expansion"]
    assert response.json()["cluster"]["access_revision"] == 1
    assert response.json()["cluster"]["status"] == "authorization_required"
    with workbench.app.state.sessions() as session:
        assert list(session.scalars(select(ClusterCredential).where(ClusterCredential.cluster_id == clusters.granted.id))) == []
        saved = session.get(Run, run["id"])
        assert saved.status == "cancelled" and saved.credential is None
    calls = workbench.http.get_json.call_count
    assert_error(client.patch(route, json={"namespaces": ["demo"], "expected_access_revision": 0}), 409, "conflict")
    assert workbench.http.get_json.call_count == calls


def test_scope_noop_preserves_credentials_generation_and_jobs(workbench, clusters):
    client = workbench.client
    login(client)
    store_credential(workbench, clusters.granted)
    run = client.post("/api/runs", json={"cluster_id": clusters.granted.id, "namespaces": ["demo"]}).json()
    reauth(client)
    workbench.http.get_json.side_effect = resource_page
    response = client.patch(f"/api/clusters/{clusters.granted.id}/scope", json={"namespaces": ["other", "demo"], "expected_access_revision": 0})
    assert response.status_code == 200, response.text
    assert response.json()["cluster"]["status"] == "authorized"
    assert response.json()["cluster"]["access_revision"] == 0
    with workbench.app.state.sessions() as session:
        assert session.get(Run, run["id"]).status == "queued"
        assert session.get(Cluster, clusters.granted.id).namespaces == ["demo", "other"]


def test_scope_edit_rechecks_recent_reauth_between_gets(workbench, clusters):
    login(workbench.client)
    store_credential(workbench, clusters.granted)
    reauth(workbench.client)

    def page(url, headers):
        with workbench.app.state.sessions.begin() as session:
            session.get(WebSession, digest(workbench.client.cookies.get(api.COOKIE))).reauthenticated_at = now() - timedelta(minutes=6)
        return resource_page(url, headers)

    workbench.http.get_json.side_effect = page
    response = workbench.client.patch(f"/api/clusters/{clusters.granted.id}/scope", json={"namespaces": ["expansion"], "expected_access_revision": 0})
    assert_error(response, 403, "reauthentication_required")
    assert workbench.http.get_json.call_count == 1


@pytest.mark.parametrize("kind", ["discover", "preflight"])
def test_stale_401_does_not_override_or_revoke_replaced_credential(workbench, clusters, kind):
    login(workbench.client, "auditor")
    store_credential(workbench, clusters.granted, "auditor")
    replacement = []

    def rejected(_url, headers):
        store_credential(workbench, clusters.granted, "auditor")
        with workbench.app.state.sessions() as session:
            replacement.append(session.get(ClusterCredential, (workbench.users["auditor"].id, clusters.granted.id)).encrypted)
        raise DomainError("untrusted token", "http_401")

    workbench.http.get_json.side_effect = rejected
    path = "namespaces/discover" if kind == "discover" else "preflight"
    response = workbench.client.post(f"/api/clusters/{clusters.granted.id}/{path}", json={} if kind == "discover" else {"namespaces": ["demo"]})
    assert_error(response, 409, "authorization_required")
    assert workbench.http.get_json.call_count == 1
    assert workbench.client.get("/api/session").status_code == 200
    with workbench.app.state.sessions() as session:
        assert session.get(ClusterCredential, (workbench.users["auditor"].id, clusters.granted.id)).encrypted == replacement[0]


@pytest.mark.parametrize("coverage", [[], [{"check": [], "code": "allowed", "status": "completed"}], [{"check": "chosen/pods", "code": "allowed", "status": "completed"}]])
def test_finalize_rejects_incomplete_or_malformed_coverage(workbench, monkeypatch, coverage):
    login(workbench.client)
    draft = make_draft(workbench)
    store_credential(workbench, draft)
    monkeypatch.setattr(api, "preflight", lambda *_args: coverage)
    assert_error(finalize(workbench, draft, accept_partial=True), 409, "preflight_failed")
    assert client_draft(workbench, draft)["lifecycle"] == "draft"


def test_cleanup_rechecks_lifecycle_even_if_selected_draft_was_finalized(workbench, monkeypatch):
    login(workbench.client)
    draft = make_draft(workbench)
    with workbench.app.state.sessions.begin() as session:
        saved = session.get(Cluster, draft.id)
        saved.draft_expires_at = now() - timedelta(seconds=1)
        session.flush()
        original_scalars = session.scalars

        def scalars(statement, *args, **kwargs):
            if statement.is_delete:
                saved.lifecycle, saved.draft_owner_id, saved.draft_expires_at = "ready", None, None
                session.flush()
            return original_scalars(statement, *args, **kwargs)

        monkeypatch.setattr(session, "scalars", scalars)
        assert connections.cleanup_expired_drafts(session) == 0
    with workbench.app.state.sessions() as session:
        assert session.get(Cluster, draft.id).lifecycle == "ready"


@pytest.mark.parametrize("operation", ["probe", "credential", "login", "draft"])
def test_identity_fences_allow_postgres_foreign_key_key_share(workbench, clusters, operation):
    """Identity fences cannot block policy-held run/binding/credential FK inserts."""
    login(workbench.client)
    store_credential(workbench, clusters.granted)
    statements = []

    def capture(state):
        if state.is_select:
            sql = str(state.statement.compile(dialect=postgresql.dialect()))
            if ("FROM users " in sql or "FROM sessions " in sql) and " FOR " in sql:
                statements.append(sql)

    session_class = workbench.app.state.sessions.class_
    event.listen(session_class, "do_orm_execute", capture)
    try:
        if operation == "probe":
            workbench.http.get_json.side_effect = resource_page
            result = workbench.client.post(f"/api/clusters/{clusters.granted.id}/preflight", json={"namespaces": ["demo"]})
            assert result.status_code == 200, result.text
        elif operation == "credential":
            import_personal(workbench, clusters.granted)
        elif operation == "login":
            login(workbench.client)
        elif operation == "draft":
            make_draft(workbench)
    finally:
        event.remove(session_class, "do_orm_execute", capture)
    assert any("FROM users " in sql for sql in statements)
    if operation not in {"login", "draft"}:
        assert any("FROM sessions " in sql for sql in statements)
    assert all(sql.endswith("FOR NO KEY UPDATE") for sql in statements)
