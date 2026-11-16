"""Names-only discovery and strict scope tests using synthetic, local transports."""

import copy
import json
import socket
import ssl
from unittest.mock import Mock
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from workbench import namespaces, scanners, security
from workbench.domain import DomainError
from workbench.namespaces import (
    INVENTORY_VERSION,
    discover_namespaces,
    validate_inventory_url,
    validate_namespaces,
    validate_run_scope,
)

CONNECTION = {
    "server": "https://cluster.example.test:6443/proxy/cluster",
    "auth_type": "kubeconfig",
    "auth": {"version": 1, "kind": "token", "token": "synthetic.identity.token"},
}
SCOPE = {
    "namespaces": ["demo"],
    "max_objects": 1000,
    "timeout_seconds": 300,
    "inventory_version": 1,
}
CANARY = "private-response-or-token-not-for-output"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", Mock(side_effect=AssertionError("Unexpected DNS"))
    )
    monkeypatch.setattr(
        socket, "socket", Mock(side_effect=AssertionError("Unexpected socket"))
    )


def namespace(name, **extra):
    return {"metadata": {"name": name}, **extra}


def page(items=None, cursor="", revision="123"):
    return {
        "apiVersion": "v1",
        "kind": "NamespaceList",
        "metadata": {"resourceVersion": revision, "continue": cursor},
        "items": items or [],
    }


class FakeHTTP:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get_json(self, url, headers=None):
        self.calls.append((url, headers))
        response = self.responses.pop(0)
        if callable(response):
            response = response(url)
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        "demo",
        ("demo",),
        [""],
        ["*"],
        ["ALL"],
        ["a.b"],
        ["a/b"],
        ["a%2fb"],
        ["a b"],
        ["a\n"],
        ["-a"],
        ["a-"],
        ["a" * 64],
        ["а"],
        [1],
        [True],
        [{}],
        ["demo", "demo"],
        [f"ns-{i}" for i in range(101)],
    ],
)
def test_namespaces_reject_invalid_or_implicit_scope(value):
    with pytest.raises(DomainError):
        validate_namespaces(value)


def test_namespace_selection_returns_copy_without_sorting_or_truncation():
    original = ["z", "a" * 63, "1"]
    result = validate_namespaces(original)
    assert result == original and result is not original
    assert len(validate_namespaces([f"ns-{i}" for i in range(100)])) == 100


def test_run_scope_requires_current_version_and_is_independent_copy():
    original = copy.deepcopy(SCOPE)
    result = validate_run_scope(original, ["other", "demo"])
    assert result == original and INVENTORY_VERSION == 1
    result["namespaces"].append("other")
    assert original == SCOPE


@pytest.mark.parametrize("missing", SCOPE)
def test_run_scope_rejects_each_missing_sealed_field(missing):
    scope = {key: value for key, value in SCOPE.items() if key != missing}
    with pytest.raises(DomainError) as error:
        validate_run_scope(scope, ["demo"])
    assert error.value.code == "invalid_scope"


@pytest.mark.parametrize(
    "change",
    [
        {"inventory_version": True},
        {"inventory_version": 2},
        {"inventory_version": "1"},
        {"max_objects": True},
        {"max_objects": 0},
        {"max_objects": 10001},
        {"timeout_seconds": 0},
        {"timeout_seconds": 601},
        {"timeout_seconds": 1.0},
        {"namespaces": ["other"]},
        {"namespaces": ["*"]},
        {"namespaces": []},
        {"cluster_scope": True},
        {"profile": "b2"},
        {"resources": ["secrets"]},
    ],
)
def test_worker_scope_rejects_unknown_fields_invalid_limits_and_expansion(change):
    with pytest.raises(DomainError) as error:
        validate_run_scope({**SCOPE, **change}, ["demo"])
    assert error.value.code == "invalid_scope"


@pytest.mark.parametrize("allowed", [None, [], ["*"], ["demo", "demo"]])
def test_run_scope_fails_closed_for_invalid_current_allowlist(allowed):
    with pytest.raises(DomainError) as error:
        validate_run_scope(SCOPE, allowed)
    assert error.value.code == "invalid_scope"


@pytest.mark.parametrize("limit", [1, 200, 500])
def test_inventory_url_allows_exact_nine_namespaced_resources_and_encoded_cursors(
    limit,
):
    assert len(scanners.RESOURCES) == 9
    for resource in scanners.RESOURCES:
        for ns in ("demo", "payments"):
            url = (
                CONNECTION["server"]
                + resource.path(ns)
                + "?"
                + urlencode(
                    {"limit": limit, "continue": "opaque&watch=true/../../secrets?x=+"}
                )
            )
            assert (
                validate_inventory_url(
                    url, CONNECTION["server"] + "/", ["demo", "payments"]
                )
                is None
            )


@pytest.mark.parametrize(
    "suffix",
    [
        "/api/v1/namespaces?limit=1",
        "/api/v1/pods?limit=1",
        "/version?limit=1",
        "/apis/rbac.authorization.k8s.io/v1/clusterroles?limit=1",
        "/api/v1/namespaces/other/pods?limit=1",
        "/api/v1/namespaces/demo/secrets?limit=1",
        "/api/v1/namespaces/demo/configmaps?limit=1",
        "/api/v1/namespaces/demo/pods/name?limit=1",
        "/api/v1/namespaces/demo/pods/name/log?limit=1",
        "/api/v1/namespaces/demo/pods/name/exec?limit=1",
        "/api/v1/namespaces/demo/pods/?limit=1",
        "/api/v1/namespaces/demo//pods?limit=1",
        "/api/v1/namespaces/demo/../other/pods?limit=1",
        "/api/v1/namespaces/demo/%2e%2e/pods?limit=1",
        "/api/v1/namespaces/demo%2fother/pods?limit=1",
        "/api/v1/namespaces/%64emo/pods?limit=1",
        "/api/v1/namespaces/demo/pods",
        "/api/v1/namespaces/demo/pods?",
        "/api/v1/namespaces/demo/pods?continue=x",
        "/api/v1/namespaces/demo/pods?limit=0",
        "/api/v1/namespaces/demo/pods?limit=501",
        "/api/v1/namespaces/demo/pods?limit=01",
        "/api/v1/namespaces/demo/pods?limit=-1",
        "/api/v1/namespaces/demo/pods?limit=1&limit=2",
        "/api/v1/namespaces/demo/pods?limit=1&watch=true",
        "/api/v1/namespaces/demo/pods?limit=1&labelSelector=a",
        "/api/v1/namespaces/demo/pods?%6cimit=1",
        "/api/v1/namespaces/demo/pods?limit=1&continue=",
        "/api/v1/namespaces/demo/pods?limit=1&continue=a&continue=b",
        "/api/v1/namespaces/demo/pods?limit=1&continue=%0A",
        "/api/v1/namespaces/demo/pods?limit=1&continue=%ff",
        "/api/v1/namespaces/demo/pods?limit=1&continue=%ZZ",
        "/api/v1/namespaces/demo/pods?limit=1#x",
        "/api/v1/namespaces/demo/pods?limit=1&continue=" + "a" * 4097,
    ],
)
def test_inventory_url_denies_path_tricks_unsupported_endpoints_and_query_expansion(
    suffix,
):
    with pytest.raises(DomainError) as error:
        validate_inventory_url(
            CONNECTION["server"] + suffix, CONNECTION["server"], ["demo"]
        )
    assert error.value.code == "scope_denied"


@pytest.mark.parametrize(
    "base",
    [
        "http://cluster.example.test:6443/proxy/cluster",
        "https://other.example.test:6443/proxy/cluster",
        "https://cluster.example.test/proxy/cluster",
        "https://cluster.example.test:6443/other",
        "https://cluster.example.test:6443/proxy/cluster-suffix",
        "https://cluster.example.test:6443/proxy",
        "https://cluster.example.test:6443",
        "https://user@cluster.example.test:6443/proxy/cluster",
    ],
)
def test_inventory_url_denies_origin_port_or_base_path_changes(base):
    with pytest.raises(DomainError) as error:
        validate_inventory_url(
            base + "/api/v1/namespaces/demo/pods?limit=1",
            CONNECTION["server"],
            ["demo"],
        )
    assert error.value.code == "scope_denied"


def test_discovery_projects_names_only_and_never_probes_resources():
    first = namespace(
        "kube-system",
        status={"phase": "Active", "reason": CANARY},
        spec={"finalizers": [CANARY]},
    )
    first["metadata"].update(
        annotations={"token": CANARY}, labels={"a": CANARY}, uid=CANARY
    )
    http = FakeHTTP(
        page([first, namespace("demo")], cursor="opaque&limit=999/../../secrets"),
        page(
            [
                namespace("default"),
                namespace("kube-public", status={"phase": "Terminating"}),
            ]
        ),
    )
    result = discover_namespaces(CONNECTION, http)
    assert result == {
        "status": "complete",
        "complete": True,
        "limitation": None,
        "continuation": None,
        "items": [
            {"name": "default", "system": False},
            {"name": "demo", "system": False},
            {"name": "kube-public", "system": True, "phase": "Terminating"},
            {"name": "kube-system", "system": True, "phase": "Active"},
        ],
    }
    assert len(http.calls) == 2
    for url, headers in http.calls:
        parsed = urlsplit(url)
        assert parsed.path == "/proxy/cluster/api/v1/namespaces"
        assert parse_qs(parsed.query)["limit"] == ["200"]
        assert headers["Authorization"] == "Bearer " + CONNECTION["auth"]["token"]
    assert parse_qs(urlsplit(http.calls[1][0]).query)["continue"] == [
        "opaque&limit=999/../../secrets"
    ]
    assert CANARY not in json.dumps(result)
    assert CONNECTION["auth"]["token"] not in json.dumps(result)
    assert "opaque" not in json.dumps(result)


def test_discovery_empty_success_is_distinct_from_forbidden():
    result = discover_namespaces(CONNECTION, FakeHTTP(page()))
    assert result == {
        "status": "complete",
        "complete": True,
        "limitation": None,
        "continuation": None,
        "items": [],
    }


@pytest.mark.parametrize("after_page", [False, True])
def test_discovery_forbidden_returns_empty_manual_fallback_without_partial_authority(
    after_page,
):
    responses = [page([namespace("demo")], cursor="next")] if after_page else []
    http = FakeHTTP(*responses, DomainError(CANARY, "http_403"))
    result = discover_namespaces(CONNECTION, http)
    assert result["status"] == "forbidden" and not result["complete"]
    assert result["items"] == [] and "manually" in result["limitation"]
    assert CANARY not in json.dumps(result)


@pytest.mark.parametrize(
    "code,expected",
    [
        ("http_401", "kubernetes_authentication_required"),
        ("http_410", "namespace_snapshot_expired"),
        ("http_tls", "http_tls"),
        ("http_dns", "http_dns"),
        ("http_transport", "http_transport"),
        ("http_timeout", "http_timeout"),
        ("endpoint_denied", "endpoint_denied"),
        ("http_invalid_json", "http_invalid_json"),
        ("http_response_too_large", "http_response_too_large"),
        ("http_redirect_denied", "http_redirect_denied"),
        ("http_404", "http_404"),
        ("http_500", "http_500"),
    ],
)
def test_discovery_fatal_remote_errors_are_typed_sanitized_and_never_empty_success(
    code, expected
):
    http = FakeHTTP(page([namespace("demo")], cursor="next"), DomainError(CANARY, code))
    with pytest.raises(DomainError) as error:
        discover_namespaces(CONNECTION, http)
    assert error.value.code == expected and CANARY not in str(error.value)
    assert len(http.calls) == 2


@pytest.mark.parametrize(
    "code",
    [
        "session_expired",
        "authorization_required",
        "credential_revoked",
        "scope_denied",
        "scope_changed",
        "invalid_scope",
        "forbidden",
        "kubernetes_authentication_required",
    ],
)
def test_discovery_local_fences_propagate_without_more_requests(code):
    failure = DomainError("The local authorization fence changed.", code)
    http = FakeHTTP(failure)
    with pytest.raises(DomainError) as error:
        discover_namespaces(CONNECTION, http)
    assert error.value is failure and len(http.calls) == 1


@pytest.mark.parametrize(
    "failure,code",
    [
        (TimeoutError(CANARY), "http_timeout"),
        (ssl.SSLError(CANARY), "http_tls"),
        (OSError(CANARY), "http_transport"),
    ],
)
def test_discovery_sanitizes_unwrapped_transport_failures(failure, code):
    with pytest.raises(DomainError) as error:
        discover_namespaces(CONNECTION, FakeHTTP(failure))
    assert error.value.code == code and CANARY not in str(error.value)


@pytest.mark.parametrize(
    "response",
    [
        {},
        [],
        {"kind": "Status", "message": CANARY},
        page([{}]),
        page([namespace("*")]),
        page([namespace("A")]),
        page([namespace("a" * 64)]),
        page([namespace("demo", kind="Pod")]),
        page([namespace("demo", apiVersion="v2")]),
        page([namespace("demo", status={"phase": CANARY})]),
        page([namespace("demo", status=None)]),
        page([{"metadata": {"name": "demo", "namespace": "other"}}]),
        page([{"metadata": {"name": "demo", "resourceVersion": ""}}]),
        page([namespace("demo"), namespace("demo")]),
        page([namespace(f"ns-{i}") for i in range(201)]),
        page(revision=""),
        page(revision=1),
        page(revision="1\n"),
        page(revision="a" * 257),
        page(cursor="a" * 4097),
        page(cursor="a\0"),
        page(cursor="Ω"),
        {"apiVersion": "v1", "kind": "NamespaceList", "items": [], "metadata": {}},
        {
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "items": [],
            "metadata": {"resourceVersion": "1", "remainingItemCount": True},
        },
        {
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "items": [],
            "metadata": {"resourceVersion": "1", "remainingItemCount": 1},
        },
    ],
)
def test_discovery_malformed_lists_fail_closed_without_raw_response(response):
    with pytest.raises(DomainError) as error:
        discover_namespaces(CONNECTION, FakeHTTP(response))
    assert error.value.code == "invalid_namespace_discovery"
    assert CANARY not in str(error.value)


@pytest.mark.parametrize(
    "second", [page(cursor="next"), page(revision="changed"), page([namespace("demo")])]
)
def test_discovery_rejects_repeated_cursor_changed_snapshot_and_duplicate_names(second):
    http = FakeHTTP(page([namespace("demo")], cursor="next"), second)
    with pytest.raises(DomainError) as error:
        discover_namespaces(CONNECTION, http)
    assert error.value.code == "invalid_namespace_discovery"
    assert len(http.calls) == 2


@pytest.mark.parametrize("remaining", [False, True])
def test_discovery_maximum_1000_names_five_pages_and_explicit_partial(remaining):
    responses = [
        page(
            [namespace(f"ns-{p}-{i}") for i in range(200)],
            cursor=f"cursor-{p}" if p < 4 or remaining else "",
        )
        for p in range(5)
    ]
    http = FakeHTTP(*responses)
    result = discover_namespaces(CONNECTION, http)
    assert len(http.calls) == 5 and len(result["items"]) == 1000
    assert result["complete"] is not remaining
    assert result["status"] == ("partial" if remaining else "complete")
    assert bool(result["limitation"]) is remaining


def test_discovery_empty_pages_cannot_bypass_page_budget():
    http = FakeHTTP(*(page(cursor=f"cursor-{p}") for p in range(5)))
    result = discover_namespaces(CONNECTION, http)
    assert result["status"] == "partial" and result["items"] == []
    assert not result["complete"] and len(http.calls) == 5


def test_discovery_deadline_is_shared_with_fresh_pinned_clients_and_stops_requests(
    monkeypatch,
):
    now = [0.0]
    monkeypatch.setattr(namespaces.time, "monotonic", lambda: now[0])

    def first(_url):
        assert security._REQUEST_DEADLINE.get() == 30
        now[0] = 30
        return page([namespace("demo")], cursor="more")

    http = FakeHTTP(first)
    result = discover_namespaces(CONNECTION, http)
    assert result["status"] == "partial" and not result["complete"]
    assert result["items"] == [{"name": "demo", "system": False}]
    assert "deadline" in result["limitation"] and len(http.calls) == 1
    assert security._REQUEST_DEADLINE.get() is None


def test_discovery_rejects_missing_credentials_before_get():
    http = FakeHTTP()
    with pytest.raises(DomainError) as error:
        discover_namespaces({"server": CONNECTION["server"], "auth_type": "kubeconfig"}, http)
    assert error.value.code == "credential_required" and not http.calls
