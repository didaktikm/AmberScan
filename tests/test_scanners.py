"""Offline contract/security tests; no scanner binaries or cluster calls are used."""

from __future__ import annotations

import copy
import json
from dataclasses import asdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from workbench import scanners
from workbench.domain import DomainError

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"
CONNECTION = {
    "server": "https://cluster.example.test:6443",
    "auth_type": "kubeconfig",
    "auth": {"version": 1, "kind": "token", "token": "fixture.identity.token"},
}
SCOPE = {"namespaces": ["demo"]}


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def page(resource, items=None, cursor="", revision="1"):
    return {
        "kind": resource.kind + "List",
        "apiVersion": resource.api,
        "metadata": {"continue": cursor, "resourceVersion": revision},
        "items": items or [],
    }


class FakeHTTP:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def get_json(self, url, headers=None):
        self.calls.append((url, headers))
        parsed = urlsplit(url)
        plural = parsed.path.rsplit("/", 1)[-1]
        resource = next(
            resource for resource in scanners.RESOURCES if resource.plural == plural
        )
        response = self.responses.get(plural, page(resource))
        if callable(response):
            response = response(url)
        elif isinstance(response, list):
            response = response.pop(0)
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)


def records(result):
    return {entry["check"]: entry for entry in result.coverage}


def serialized(result):
    return json.dumps(asdict(result))


def scan(http=None, scope=None, cancelled=lambda: False):
    return scanners.scan_inventory(
        CONNECTION, scope or SCOPE, http or FakeHTTP(), cancelled
    )


def test_trivy_normalization_preserves_only_relevant_identifiers():
    result = scanners.parse_report("trivy", fixture("trivy-image.json"))
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["severity"] == "high"
    assert finding["vulnerability_id"] == "CVE-2025-12345"
    assert finding["package"] == {
        "name": "@example/parser",
        "installed_version": "1.2.3",
        "fixed_version": "1.2.4",
    }
    assert finding["image_digest"] == "sha256:" + "a" * 64
    assert finding["evidence"]["image_config_digest"] == "sha256:" + "b" * 64
    assert finding["evidence"]["layer_digest"] == "sha256:" + "c" * 64
    assert finding["location"] == "usr/lib/node_modules/parser/package.json"
    assert finding["evidence"]["provenance_verified"] is False
    assert result.versions["trivy"] == "not_provided"
    output = serialized(result)
    for forbidden in (
        "fixture-private-value",
        "fixture-description-token",
        "fixture-password",
        "<script",
        "PrimaryURL",
        "ImageConfig",
    ):
        assert forbidden not in output
    assert records(result)["import:trivy"]["status"] == "completed"
    assert records(result)["import:provenance"]["status"] == "not_checked"


def test_trivy_config_image_id_is_not_manifest_digest():
    data = fixture("trivy-image.json")
    data["ArtifactName"] = "api:latest"
    data["Metadata"]["RepoDigests"] = []
    finding = scanners.parse_report("trivy", data).findings[0]
    assert "image_digest" not in finding
    assert finding["evidence"]["image_config_digest"] == "sha256:" + "b" * 64


@pytest.mark.parametrize(
    "field,value",
    [
        ("PkgName", "<img src=x onerror=alert(1)>"),
        ("PkgName", "password=do-not-keep-any-fragment"),
        ("PkgPath", "Bearer do-not-keep-any-fragment"),
        ("InstalledVersion", "secret=do-not-keep-any-fragment"),
        ("FixedVersion", "a" * 5000),
        ("PkgName", "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0.c2lnbmF0dXJl"),
    ],
)
def test_report_allowlist_redacts_whole_unsafe_values(field, value):
    data = fixture("trivy-image.json")
    data["Results"][0]["Vulnerabilities"][0][field] = value
    output = serialized(scanners.parse_report("trivy", data))
    assert "[redacted]" in output
    assert value not in output
    assert "do-not-keep-any-fragment" not in output
    assert "<img" not in output


@pytest.mark.parametrize(
    "scanner,file",
    [("kube-bench", "kube-bench.json"), ("kubescape", "kubescape-resources.json")],
)
def test_benchmark_imports_do_not_emit_scanner_text_or_embedded_objects(scanner, file):
    result = scanners.parse_report(scanner, fixture(file))
    output = serialized(result)
    assert "fixture-" not in output
    assert "<script" not in output and "<img" not in output
    assert records(result)[f"import:{scanner}"]["status"] == "not_checked"
    assert records(result)["import:provenance"]["status"] == "not_checked"
    assert all(f["evidence"]["source"] == "imported_report" for f in result.findings)


def test_kube_bench_preserves_benchmark_not_fabricated_scanner_version():
    result = scanners.parse_report("kube-bench", fixture("kube-bench.json"))
    assert result.versions["kube-bench"] == "not_provided"
    assert result.versions["benchmark_versions"] == ["cis-1.8"]
    assert len(result.findings) == 2
    assert result.findings[0]["rule_id"] == "kube-bench:1.1.1"
    assert result.findings[0]["evidence"]["reported_status"] == "FAIL"
    assert result.findings[0]["location"] == "CIS/cis-1.8/1.1.1"
    assert result.findings[1]["confidence"] == "low"


def test_kubescape_preserves_resource_provenance_without_raw_manifest():
    result = scanners.parse_report("kubescape", fixture("kubescape-resources.json"))
    assert result.versions["kubescape"] == "3.0.1"
    finding = result.findings[0]
    assert finding["namespace"] == "demo"
    assert finding["resource_kind"] == "Deployment"
    assert finding["resource_name"] == "api"
    assert finding["resource_uid"] == "11111111-2222-3333-4444-555555555555"
    assert finding["location"] == "apps/v1/Deployment/demo/api"
    assert finding["rule_id"] == "kubescape:C-0001"


@pytest.mark.parametrize(
    "scanner,data,code",
    [
        ("unknown", {}, "unsupported_scanner"),
        ("trivy", {"Results": []}, "unsupported_report_schema"),
        (
            "trivy",
            {"SchemaVersion": 1, "ArtifactType": "container_image"},
            "unsupported_report_schema",
        ),
        (
            "trivy",
            {"SchemaVersion": 2, "ArtifactType": "filesystem"},
            "unsupported_report_schema",
        ),
        (
            "trivy",
            {
                "SchemaVersion": 2,
                "ArtifactType": "container_image",
                "ArtifactName": "x",
                "Results": {},
            },
            "malformed_report",
        ),
        ("kube-bench", {"totals": {}}, "unsupported_report_schema"),
        ("kube-bench", {"Controls": {}}, "malformed_report"),
        ("kubescape", {"summary": {"controls": []}}, "unsupported_report_schema"),
        ("kubescape", {"frameworks": []}, "unsupported_report_schema"),
        ("kubescape", {"results": {}, "resources": []}, "malformed_report"),
        ("trivy", [], "malformed_report"),
    ],
)
def test_unknown_or_invalid_report_roots_fail_closed(scanner, data, code):
    with pytest.raises(DomainError) as exc:
        scanners.parse_report(scanner, data)
    assert exc.value.code == code


@pytest.mark.parametrize(
    "scanner,file",
    [
        ("trivy", "trivy-image.json"),
        ("kube-bench", "kube-bench.json"),
        ("kubescape", "kubescape-resources.json"),
    ],
)
def test_malformed_rows_preserve_valid_findings_but_never_completed(scanner, file):
    data = fixture(file)
    if scanner == "trivy":
        data["Results"][0]["Vulnerabilities"].append(
            {"VulnerabilityID": "CVE-1", "Severity": "HIGH"}
        )
    elif scanner == "kube-bench":
        data["Controls"][0]["tests"][0]["results"].append(
            {"test_number": "1.1.99", "status": "UNEXPECTED"}
        )
    else:
        data["results"][0]["controls"].append(
            {"controlID": "C-9999", "status": "failed"}
        )
    result = scanners.parse_report(scanner, data)
    assert result.findings
    assert records(result)[f"import:{scanner}"]["status"] == "error"
    assert any("incomplete" in text for text in result.limitations)


@pytest.mark.parametrize(
    "scanner,data",
    [
        (
            "trivy",
            {
                "SchemaVersion": 2,
                "ArtifactType": "container_image",
                "ArtifactName": "api",
                "Results": [
                    {
                        "Class": "os-pkgs",
                        "Target": "alpine",
                        "Type": "alpine",
                        "Vulnerabilities": [{"Severity": "HIGH"}],
                    }
                ],
            },
        ),
        (
            "kube-bench",
            {
                "Controls": [
                    {
                        "tests": [
                            {"results": [{"test_number": "1.1.1", "status": "INVALID"}]}
                        ]
                    }
                ]
            },
        ),
        (
            "kubescape",
            {
                "resources": [],
                "results": [
                    {
                        "resourceID": "apps/v1/Deployment/demo/api",
                        "controls": [{"controlID": "C-0001", "status": "failed"}],
                    }
                ],
            },
        ),
    ],
)
def test_entirely_malformed_reports_raise_instead_of_empty_success(scanner, data):
    with pytest.raises(DomainError, match="no valid supported") as exc:
        scanners.parse_report(scanner, data)
    assert exc.value.code == "malformed_report"


def test_report_findings_limit_is_visible(monkeypatch):
    monkeypatch.setattr(scanners, "MAX_FINDINGS", 1)
    data = fixture("trivy-image.json")
    other = copy.deepcopy(data["Results"][0]["Vulnerabilities"][0])
    other["VulnerabilityID"] = "CVE-2025-99999"
    data["Results"][0]["Vulnerabilities"].append(other)
    result = scanners.parse_report("trivy", data)
    assert len(result.findings) == 1
    assert records(result)["import:trivy"]["status"] == "error"
    assert "1 findings omitted" in records(result)["import:trivy"]["detail"]


@pytest.mark.parametrize(
    "data,code",
    [
        ({"x": "x" * (scanners.MAX_REPORT_BYTES + 1)}, "report_too_large"),
        ({"x": [0] * (scanners.MAX_JSON_NODES + 1)}, "report_too_large"),
        ({"x": float("nan")}, "malformed_report"),
        ({"x": b"bytes"}, "malformed_report"),
        ({1: "numeric key"}, "malformed_report"),
        ({"x": "\ud800"}, "malformed_report"),
    ],
)
def test_json_size_and_type_limits(data, code):
    with pytest.raises(DomainError) as exc:
        scanners.parse_report("trivy", data)
    assert exc.value.code == code


def test_cyclic_and_deep_input_are_rejected():
    data = {}
    data["self"] = data
    with pytest.raises(DomainError) as exc:
        scanners.parse_report("trivy", data)
    assert exc.value.code == "malformed_report"
    data = {}
    child = data
    for _ in range(scanners.MAX_JSON_DEPTH + 1):
        child["child"] = {}
        child = child["child"]
    with pytest.raises(DomainError) as exc:
        scanners.parse_report("trivy", data)
    assert exc.value.code == "report_too_large"


def test_preflight_probes_all_explicit_resources_using_only_get_limit_one():
    http = FakeHTTP()
    coverage = scanners.preflight(
        CONNECTION, {"namespaces": ["demo", "payments"]}, http
    )
    assert len(http.calls) == 18
    assert len(coverage) == 18
    assert all(item["status"] == "completed" for item in coverage)
    assert all(
        item["code"] == "allowed" and item["verb"] == "list" for item in coverage
    )
    assert (
        coverage[0]["namespace"] == "demo" and coverage[0]["resource"] == "deployments"
    )
    assert coverage[0]["group"] == "apps" and coverage[3]["group"] == ""
    assert all("not security scan coverage" in item["detail"] for item in coverage)
    for url, headers in http.calls:
        parsed = urlsplit(url)
        assert parsed.netloc == "cluster.example.test:6443"
        assert parse_qs(parsed.query) == {"limit": ["1"]}
        assert (
            "/namespaces/demo/" in parsed.path or "/namespaces/payments/" in parsed.path
        )
        assert headers == {
            "Authorization": "Bearer fixture.identity.token",
            "Accept": "application/json",
        }
        assert all(
            part not in parsed.path
            for part in (
                "secrets",
                "configmaps",
                "/logs",
                "/exec",
                "selfsubjectaccessreviews",
            )
        )


@pytest.mark.parametrize(
    "namespaces",
    [
        None,
        [],
        ["*"],
        ["demo", "demo"],
        ["demo/../../secrets"],
        ["DEMO"],
        ["a" * 64],
        [1],
        ["test"] * 101,
        "demo",
    ],
)
def test_scope_is_explicit_validated_and_bounded(namespaces):
    http = FakeHTTP()
    with pytest.raises(DomainError):
        scan(http, {"namespaces": namespaces})
    assert not http.calls


@pytest.mark.parametrize(
    "key,value",
    [
        ("max_objects", 0),
        ("max_objects", 10001),
        ("max_objects", True),
        ("timeout_seconds", 0),
        ("timeout_seconds", 601),
        ("timeout_seconds", float("inf")),
        ("timeout_seconds", True),
    ],
)
def test_numeric_scope_limits_fail_before_network(key, value):
    http = FakeHTTP()
    with pytest.raises(DomainError):
        scan(http, {**SCOPE, key: value})
    assert not http.calls


@pytest.mark.parametrize(
    "server",
    [
        "http://cluster.test",
        "https://user:secret@cluster.test",
        "https://cluster.test?token=secret",
        "https://cluster.test/#fragment",
        "https://cluster.test/../api",
        "https://cluster.test/%2fapi",
        "https://cluster.test\n",
    ],
)
def test_connection_rejects_unsafe_url_before_network(server):
    http = FakeHTTP()
    with pytest.raises(DomainError) as exc:
        scanners.preflight({**CONNECTION, "server": server}, SCOPE, http)
    assert exc.value.code == "endpoint_denied"
    assert not http.calls


@pytest.mark.parametrize(
    "token", [None, "", "token\r\nX-Secret: injected", "x" * 16385]
)
def test_connection_rejects_header_injection_and_missing_token(token):
    with pytest.raises(DomainError) as exc:
        scanners.preflight({**CONNECTION, "auth": {"version": 1, "kind": "token", "token": token}}, SCOPE, FakeHTTP())
    assert exc.value.code == "credential_invalid"


@pytest.mark.parametrize(
    "code,status,halted",
    [
        ("http_401", "denied", True),
        ("http_403", "denied", False),
        ("http_404", "unsupported", False),
        ("http_410", "error", False),
        ("http_429", "error", True),
        ("http_timeout", "error", True),
        ("http_transport", "error", True),
        ("http_tls", "error", True),
        ("http_dns", "error", True),
        ("http_invalid_json", "error", False),
        ("http_response_too_large", "error", True),
        ("http_redirect_denied", "error", True),
        ("endpoint_denied", "denied", True),
        ("http_500", "error", False),
    ],
)
@pytest.mark.parametrize("is_preflight", [True, False])
def test_http_error_codes_are_sanitized_and_coverage_is_explicit(
    code, status, halted, is_preflight
):
    http = FakeHTTP(
        {
            "deployments": DomainError(
                "Bearer fixture-secret <script>unsafe</script>", code
            )
        }
    )
    result = (
        scanners.preflight(CONNECTION, SCOPE, http)
        if is_preflight
        else scan(http).coverage
    )
    assert result[0]["check"] == "demo/deployments"
    assert result[0]["status"] == status
    if is_preflight:
        assert result[0]["code"] == code
        assert result[1]["code"] == ("not_checked" if halted else "allowed")
    assert len(http.calls) == (1 if halted else 9)
    assert result[1]["status"] == ("not_checked" if halted else "completed")
    assert "fixture-secret" not in json.dumps(result)
    assert "<script>" not in json.dumps(result)


def test_builtin_projection_drops_env_and_all_arbitrary_workload_text():
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    obj = fixture("pod-malicious.json")
    original = copy.deepcopy(obj)
    result = scan(FakeHTTP({"pods": page(pods, [obj])}))
    assert obj == original
    assert {finding["rule_id"] for finding in result.findings} == {
        "builtin:privileged",
        "builtin:host-namespaces",
        "builtin:root-user",
        "builtin:privilege-escalation",
    }
    output = serialized(result)
    assert "fixture-" not in output
    for field in (
        "annotations",
        "env",
        "command",
        "volumeMounts",
        "imagePullSecrets",
        "seLinuxOptions",
        "sysctls",
        "<script",
    ):
        assert field not in output
    privileged = next(
        f for f in result.findings if f["rule_id"] == "builtin:privileged"
    )
    assert privileged["image_digest"] == "sha256:" + "a" * 64
    assert privileged["evidence"]["container"]["securityContext"] == {
        "privileged": True,
        "allowPrivilegeEscalation": True,
    }
    assert records(result)["demo/pods"]["status"] == "completed"
    assert all(
        records(result)[f"cli:{name}"]["status"] == "not_checked"
        for name in scanners.SCANNERS
    )


def test_absent_security_settings_are_low_confidence_not_claimed_exploits():
    obj = fixture("pod-malicious.json")
    obj["spec"] = {"containers": [{"name": "api", "image": "api:latest"}]}
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    result = scan(FakeHTTP({"pods": page(pods, [obj])}))
    assert {f["rule_id"] for f in result.findings} == {
        "builtin:nonroot-unset",
        "builtin:privilege-escalation",
    }
    assert all(f["confidence"] == "low" for f in result.findings)
    assert all(f["severity"] == "low" for f in result.findings)
    assert "does not prove root execution" in result.findings[0]["recommendation"]
    assert "not evidence of a successful" in result.findings[1]["recommendation"]


def test_pod_nonroot_inheritance_and_container_override():
    obj = fixture("pod-malicious.json")
    obj["spec"] = {
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000},
        "containers": [
            {"name": "api", "securityContext": {"allowPrivilegeEscalation": False}}
        ],
        "initContainers": [
            {
                "name": "init",
                "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False},
            }
        ],
        "ephemeralContainers": [
            {
                "name": "debug",
                "securityContext": {
                    "privileged": True,
                    "allowPrivilegeEscalation": False,
                },
            }
        ],
    }
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    result = scan(FakeHTTP({"pods": page(pods, [obj])}))
    assert {f["rule_id"] for f in result.findings} == {
        "builtin:root-user",
        "builtin:privileged",
    }
    assert any("initContainers[0]" in f["location"] for f in result.findings)
    assert any("ephemeralContainers[0]" in f["location"] for f in result.findings)


def test_controller_templates_are_checked():
    deployment = scanners.RESOURCES[0]
    pod = fixture("pod-malicious.json")
    obj = {"metadata": pod["metadata"], "spec": {"template": {"spec": pod["spec"]}}}
    result = scan(FakeHTTP({"deployments": page(deployment, [obj])}))
    assert result.findings
    assert all(f["resource_kind"] == "Deployment" for f in result.findings)
    assert all(f["location"].startswith("spec.template.spec") for f in result.findings)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda obj: obj["metadata"].update(namespace="other"),
        lambda obj: obj["metadata"].update(name="<script>unsafe</script>"),
        lambda obj: obj["metadata"].pop("uid"),
        lambda obj: obj["spec"]["containers"][0]["securityContext"].update(
            privileged="true"
        ),
        lambda obj: obj["spec"]["securityContext"].update(runAsUser=False),
        lambda obj: obj["spec"].update(containers="invalid"),
        lambda obj: obj.update(spec={}),
    ],
)
def test_malformed_objects_never_produce_complete_resource_coverage(mutation):
    obj = fixture("pod-malicious.json")
    mutation(obj)
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    result = scan(FakeHTTP({"pods": page(pods, [obj])}))
    assert not result.findings
    assert records(result)["demo/pods"]["status"] == "error"


def test_windows_workloads_explicitly_unsupported_not_linux_false_positives():
    obj = fixture("pod-malicious.json")
    obj["spec"]["os"] = {"name": "windows"}
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    result = scan(FakeHTTP({"pods": page(pods, [obj])}))
    assert not result.findings
    assert records(result)["builtin:windows"]["status"] == "unsupported"


def test_pagination_encodes_opaque_cursor_and_keeps_same_resource_path():
    resource = scanners.RESOURCES[0]
    http = FakeHTTP(
        {
            "deployments": [
                page(resource, cursor="opaque&limit=999/../../secrets?token=fixture"),
                page(resource),
            ]
        }
    )
    result = scan(http)
    first, second = [urlsplit(url) for url, _ in http.calls[:2]]
    assert first.path == second.path
    assert parse_qs(second.query) == {
        "limit": ["100"],
        "continue": ["opaque&limit=999/../../secrets?token=fixture"],
    }
    assert records(result)["demo/deployments"]["status"] == "completed"
    assert "opaque" not in serialized(result)


def test_pagination_loop_and_snapshot_change_are_incomplete():
    resource = scanners.RESOURCES[0]
    for responses in (
        [page(resource, cursor="same"), page(resource, cursor="same")],
        [page(resource, cursor="next"), page(resource, revision="changed")],
    ):
        http = FakeHTTP({"deployments": responses})
        result = scan(http)
        assert records(result)["demo/deployments"]["status"] == "error"
        assert len(http.calls) == 10


def test_empty_pages_cannot_bypass_page_limit(monkeypatch):
    monkeypatch.setattr(scanners, "MAX_PAGES_PER_RESOURCE", 2)
    resource = scanners.RESOURCES[0]
    http = FakeHTTP(
        {"deployments": [page(resource, cursor="one"), page(resource, cursor="two")]}
    )
    result = scan(http)
    assert records(result)["demo/deployments"]["status"] == "error"
    assert len(http.calls) == 10


def test_global_page_limit_reports_unattempted_resources(monkeypatch):
    monkeypatch.setattr(scanners, "MAX_TOTAL_PAGES", 1)
    http = FakeHTTP()
    result = scan(http)
    assert len(http.calls) == 1
    assert records(result)["demo/deployments"]["status"] == "completed"
    assert records(result)["demo/statefulsets"]["status"] == "not_checked"


def test_object_limit_does_not_silently_complete_paginated_list():
    pod = fixture("pod-malicious.json")
    resource = scanners.RESOURCES[0]
    obj = {"metadata": pod["metadata"], "spec": {"template": {"spec": pod["spec"]}}}
    http = FakeHTTP({"deployments": page(resource, [obj], cursor="more")})
    result = scan(http, {**SCOPE, "max_objects": 1})
    assert len(http.calls) == 1
    assert parse_qs(urlsplit(http.calls[0][0]).query)["limit"] == ["1"]
    assert records(result)["demo/deployments"]["status"] == "error"
    assert records(result)["demo/statefulsets"]["status"] == "not_checked"
    assert result.findings


def test_duplicate_objects_are_rejected_and_partial_result_preserved():
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    obj = fixture("pod-malicious.json")
    result = scan(
        FakeHTTP({"pods": [page(pods, [obj], cursor="two"), page(pods, [obj])]})
    )
    assert len(result.findings) == 4
    assert records(result)["demo/pods"]["status"] == "error"


def test_overlarge_api_pages_and_wrong_shapes_are_rejected():
    resource = scanners.RESOURCES[0]
    for response in (
        {"items": []},
        page(resource, [{}, {}]),
        {"kind": "Status", "code": 403},
    ):
        http = FakeHTTP({"deployments": response})
        result = scan(http, {**SCOPE, "max_objects": 1})
        assert records(result)["demo/deployments"]["status"] == "error"


def test_builtin_finding_cap_is_explicit(monkeypatch):
    monkeypatch.setattr(scanners, "MAX_FINDINGS", 1)
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    result = scan(FakeHTTP({"pods": page(pods, [fixture("pod-malicious.json")])}))
    assert len(result.findings) == 1
    assert records(result)["builtin:output-limit"]["status"] == "error"


def test_cancel_before_scan_never_touches_network():
    http = FakeHTTP()
    with pytest.raises(DomainError) as exc:
        scan(http, cancelled=lambda: True)
    assert exc.value.code == "cancelled"
    assert not http.calls


def test_cancel_during_request_drops_result_and_stops():
    http = FakeHTTP()
    with pytest.raises(DomainError) as exc:
        scan(http, cancelled=lambda: bool(http.calls))
    assert exc.value.code == "cancelled"
    assert len(http.calls) == 1


def test_http_cancel_error_is_preserved_without_exception_message():
    with pytest.raises(DomainError) as exc:
        scan(
            FakeHTTP(
                {"deployments": DomainError("Bearer fixture-private", "cancelled")}
            )
        )
    assert exc.value.code == "cancelled"
    assert "fixture-private" not in str(exc.value)


@pytest.mark.parametrize("is_preflight", [False, True])
def test_deadline_after_inflight_request_marks_partial_without_more_calls(
    monkeypatch, is_preflight
):
    now = [0]
    monkeypatch.setattr(scanners.time, "monotonic", lambda: now[0])
    resource = scanners.RESOURCES[0]

    def expire(_url):
        now[0] = 2
        return page(resource)

    http = FakeHTTP({"deployments": expire})
    scope = {**SCOPE, "timeout_seconds": 1}
    result = (
        scanners.preflight(CONNECTION, scope, http)
        if is_preflight
        else scan(http, scope).coverage
    )
    assert result[0]["status"] == "error"
    assert result[1]["status"] == "not_checked"
    assert len(http.calls) == 1


def test_safe_argv_is_literal_and_never_executes(tmp_path):
    target = tmp_path / "must-not-exist"
    argument = f"api:tag; touch {target} $(touch {target})"
    argv = scanners.subprocess_argv("/opt/pinned/trivy", ["image", argument])
    assert argv == ("/opt/pinned/trivy", "image", argument)
    assert not target.exists()
    with pytest.raises(DomainError) as exc:
        scanners.run_cli("trivy")
    assert exc.value.code == "scanner_unavailable"


@pytest.mark.parametrize(
    "executable,arguments",
    [
        ("trivy", []),
        ("/opt/../bin/trivy", []),
        ("/opt/trivy", "image api"),
        ("/opt/trivy", ["secret\x00"]),
        ("/opt/trivy", ["x"] * 65),
        ("/opt/trivy", [1]),
    ],
)
def test_argv_rejects_invalid_or_shell_string_input(executable, arguments):
    with pytest.raises(DomainError) as exc:
        scanners.subprocess_argv(executable, arguments)
    assert exc.value.code == "invalid_cli_arguments"


@pytest.mark.parametrize(
    "scanner,data",
    [
        (
            "trivy",
            {
                "SchemaVersion": 2,
                "ArtifactType": "container_image",
                "ArtifactName": "api",
                "Results": [],
            },
        ),
        ("kube-bench", {"Controls": []}),
        ("kubescape", {"resources": [], "results": []}),
    ],
)
def test_empty_report_shapes_do_not_establish_completed_coverage(scanner, data):
    result = scanners.parse_report(scanner, data)
    assert not result.findings
    assert records(result)[f"import:{scanner}"]["status"] == "not_checked"


def test_known_trivy_clean_target_is_not_a_synthetic_finding():
    data = fixture("trivy-image.json")
    data["Results"][0]["Vulnerabilities"] = []
    result = scanners.parse_report("trivy", data)
    assert not result.findings
    assert records(result)["import:trivy"]["status"] == "completed"
    assert records(result)["import:provenance"]["status"] == "not_checked"


def test_trivy_explicit_version_is_preserved_but_not_attested():
    data = fixture("trivy-image.json")
    data["Trivy"] = {"Version": "0.58.2"}
    result = scanners.parse_report("trivy", data)
    assert result.versions["trivy"] == "0.58.2"
    assert result.versions["origin"] == "imported"


@pytest.mark.parametrize(
    "malformed",
    [
        {"Class": []},
        {"Class": "os-pkgs", "Target": None},
        {
            "Class": "os-pkgs",
            "Target": "alpine",
            "Type": "alpine",
            "Vulnerabilities": {},
        },
    ],
)
def test_trivy_malformed_target_fields_produce_domain_result_not_typeerror(malformed):
    data = fixture("trivy-image.json")
    data["Results"].append(malformed)
    result = scanners.parse_report("trivy", data)
    assert result.findings
    assert records(result)["import:trivy"]["status"] == "error"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data["Metadata"].update(RepoDigests=["invalid-digest"]),
        lambda data: data["Metadata"].update(ImageID="bad-config-digest"),
        lambda data: data.update(Trivy={"Version": []}),
        lambda data: data.update(Errors=["Bearer private-output"]),
    ],
)
def test_trivy_metadata_errors_never_report_completed(mutation):
    data = fixture("trivy-image.json")
    mutation(data)
    result = scanners.parse_report("trivy", data)
    assert records(result)["import:trivy"]["status"] == "error"
    assert "private-output" not in serialized(result)


def test_trivy_other_scanner_results_are_explicitly_not_supported():
    data = fixture("trivy-image.json")
    data["Results"][0]["Secrets"] = [{"Match": "private-secret-match"}]
    result = scanners.parse_report("trivy", data)
    assert records(result)["import:trivy"]["status"] == "not_checked"
    assert "private-secret-match" not in serialized(result)


@pytest.mark.parametrize(
    "value",
    [
        "user:private-password@registry.example/api",
        "https://host/path?token=private-password",
        "AKIAABCDEFGHIJKLMNOP",
    ],
)
def test_secret_like_allowed_fields_redact_entire_values(value):
    data = fixture("trivy-image.json")
    data["ArtifactName"] = value
    result = scanners.parse_report("trivy", data)
    assert result.findings[0]["resource_name"] == "[redacted]"
    assert "private-password" not in serialized(result)


def test_kube_bench_nested_empty_sections_are_not_completed():
    data = fixture("kube-bench.json")
    data["Controls"][0]["tests"].append({"section": "1.2", "results": []})
    result = scanners.parse_report("kube-bench", data)
    assert records(result)["import:kube-bench"]["status"] == "error"


def test_kubescape_error_or_malformed_resource_is_incomplete():
    data = fixture("kubescape-resources.json")
    data["resources"].append({"resourceID": "invalid/resource/id"})
    data["errors"] = ["Bearer private-output"]
    result = scanners.parse_report("kubescape", data)
    assert records(result)["import:kubescape"]["status"] == "error"
    assert "private-output" not in serialized(result)


def test_untrusted_inventory_object_size_is_bounded(monkeypatch):
    monkeypatch.setattr(scanners, "MAX_REPORT_BYTES", 512)
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    result = scan(FakeHTTP({"pods": page(pods, [fixture("pod-malicious.json")])}))
    assert records(result)["demo/pods"]["status"] == "error"
    assert not result.findings


def test_preflight_invalid_list_is_error_not_access_success():
    http = FakeHTTP({"pods": {"kind": "Status", "message": "private-output"}})
    coverage = scanners.preflight(CONNECTION, SCOPE, http)
    item = next(item for item in coverage if item["check"] == "demo/pods")
    assert item["status"] == "error"
    assert "private-output" not in json.dumps(coverage)


def test_cancellation_checked_inside_object_loop():
    obj = fixture("pod-malicious.json")
    pods = next(r for r in scanners.RESOURCES if r.plural == "pods")
    counter = [0]

    def cancelled():
        counter[0] += 1
        return counter[0] >= 13

    http = FakeHTTP({"pods": page(pods, [obj])})
    with pytest.raises(DomainError) as exc:
        scan(http, cancelled=cancelled)
    assert exc.value.code == "cancelled"
    assert len(http.calls) == 4


def test_kube_bench_secret_pattern_in_identifier_is_not_retained():
    data = fixture("kube-bench.json")
    data["Controls"][0]["tests"][0]["results"][0]["test_number"] = (
        "AKIAABCDEFGHIJKLMNOP"
    )
    result = scanners.parse_report("kube-bench", data)
    assert "AKIAABCDEFGHIJKLMNOP" not in serialized(result)
    assert result.findings[0]["evidence"]["test_number"] == "[redacted]"


@pytest.mark.parametrize("is_preflight", [True, False])
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
        "http_request_invalid",
    ],
)
@pytest.mark.parametrize("resource", ["deployments", "serviceaccounts"])
def test_local_security_fences_propagate_even_on_final_get(
    is_preflight, code, resource
):
    failure = DomainError("The current local authorization fence changed.", code)
    http = FakeHTTP({resource: failure})
    with pytest.raises(DomainError) as error:
        if is_preflight:
            scanners.preflight(CONNECTION, SCOPE, http)
        else:
            scan(http)
    assert error.value is failure
    assert len(http.calls) == (1 if resource == "deployments" else 9)


@pytest.mark.parametrize(
    "change",
    [
        {"inventory_version": 2},
        {"inventory_version": True},
        {"cluster_scope": True},
        {"profile": "b2"},
        {"unknown": 1},
    ],
)
@pytest.mark.parametrize("is_preflight", [True, False])
def test_standalone_scope_defaults_do_not_allow_new_fields_or_wrong_version(
    change, is_preflight
):
    http = FakeHTTP()
    with pytest.raises(DomainError) as error:
        if is_preflight:
            scanners.preflight(CONNECTION, {**SCOPE, **change}, http)
        else:
            scan(http, {**SCOPE, **change})
    assert error.value.code == "invalid_scope" and not http.calls


def test_preflight_rejects_out_of_scope_item_in_valid_list():
    resource = scanners.RESOURCES[0]
    obj = {"metadata": {"name": "api", "uid": "fixture-uid", "namespace": "other"}}
    http = FakeHTTP({"deployments": page(resource, [obj])})
    result = scanners.preflight(CONNECTION, SCOPE, http)
    assert result[0]["code"] == "invalid_inventory" and result[0]["status"] == "error"


@pytest.mark.parametrize("plural", ["roles", "rolebindings"])
def test_rbac_names_with_colons_are_valid_inventory(plural):
    resource = next(item for item in scanners.RESOURCES if item.plural == plural)
    obj = {
        "kind": resource.kind,
        "apiVersion": resource.api,
        "metadata": {
            "name": "system:controller:deployment-controller",
            "uid": "fixture-uid",
            "namespace": "demo",
        },
    }
    response = page(resource, [obj])
    probe = scanners.preflight(CONNECTION, SCOPE, FakeHTTP({plural: response}))
    assert next(item for item in probe if item["resource"] == plural)["code"] == "allowed"
    inventory = scan(FakeHTTP({plural: response}))
    assert records(inventory)[f"demo/{plural}"]["status"] == "completed"


@pytest.mark.parametrize("name", ["system:controller/invalid", "system:controller invalid"])
def test_rbac_names_must_remain_bounded_path_segments(name):
    resource = next(item for item in scanners.RESOURCES if item.plural == "roles")
    response = page(
        resource,
        [{"metadata": {"name": name, "uid": "fixture-uid", "namespace": "demo"}}],
    )
    probe = scanners.preflight(CONNECTION, SCOPE, FakeHTTP({"roles": response}))
    assert next(item for item in probe if item["resource"] == "roles")["code"] == "invalid_inventory"


def test_preflight_cancellation_is_terminal_and_sanitized():
    http = FakeHTTP({"deployments": DomainError("Bearer private", "cancelled")})
    with pytest.raises(DomainError) as error:
        scanners.preflight(CONNECTION, SCOPE, http)
    assert error.value.code == "cancelled" and "private" not in str(error.value)
    assert len(http.calls) == 1


def test_list_without_resource_version_does_not_claim_snapshot_completeness():
    resource = scanners.RESOURCES[0]
    response = page(resource)
    response["metadata"].pop("resourceVersion")
    result = scan(FakeHTTP({"deployments": response}))
    assert records(result)["demo/deployments"]["status"] == "error"
