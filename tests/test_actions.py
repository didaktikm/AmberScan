"""Confirmed actions: pinned scanners, a disposable probe, and narrow patches."""

import json
import stat
from pathlib import Path

import pytest

from workbench.actions import (
    apply_remediation,
    operator_manifests,
    probe_pod,
    remediation_patch,
    run_extended,
    run_live_scanners,
    scanner_arguments,
    validate_action_url,
)
from workbench.config import Settings
from workbench.domain import DomainError, ScanResult

SERVER = "https://10.23.0.10:6443"
FIXTURE = Path(__file__).parent / "fixtures" / "scanners" / "trivy-image.json"


def test_action_urls_reject_secrets_exec_and_privileged_escape():
    with pytest.raises(DomainError):
        validate_action_url(SERVER + "/api/v1/namespaces/demo/secrets", SERVER, ["demo"], "GET")
    with pytest.raises(DomainError):
        validate_action_url(SERVER + "/api/v1/namespaces/demo/pods/amberscan-probe-abcd1234/exec", SERVER, ["demo"], "POST")
    validate_action_url(SERVER + "/api/v1/nodes?limit=50", SERVER, ["demo"], "GET")
    validate_action_url(SERVER + "/api/v1/namespaces/demo/pods/amberscan-probe-abcd1234", SERVER, ["demo"], "DELETE")


def test_probe_and_operator_cannot_be_privileged():
    pod = probe_pod("demo", "amberscan-probe-abcd1234")
    context = pod["spec"]["containers"][0]["securityContext"]
    assert context["capabilities"]["drop"] == ["ALL"]
    assert context["allowPrivilegeEscalation"] is False
    assert pod["spec"]["automountServiceAccountToken"] is False
    manifests = operator_manifests("demo", "registry.example/amberscan:1.2.3")
    role = next(item for item in manifests if item["kind"] == "Role")
    verbs = {verb for rule in role["rules"] for verb in rule["verbs"]}
    resources = {resource for rule in role["rules"] for resource in rule["resources"]}
    assert verbs <= {"get", "list", "watch"}
    assert "secrets" not in resources
    deployment = next(item for item in manifests if item["kind"] == "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["securityContext"]["privileged"] is False
    assert "hostPath" not in json.dumps(deployment)


def test_operator_process_source_has_no_write_method():
    source = Path(__file__).parents[1].joinpath("src/workbench/operator.py").read_text(encoding="utf-8")
    for method in ("POST", "PATCH", "DELETE", "PUT"):
        assert method not in source


def test_remediation_is_limited_to_one_controller_setting():
    patch = remediation_patch(
        {
            "rule_id": "builtin:privileged",
            "resource_kind": "Deployment",
            "evidence": {"container": {"name": "app", "type": "containers"}},
        }
    )
    assert patch["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] is False
    with pytest.raises(DomainError):
        remediation_patch({"rule_id": "builtin:privileged", "resource_kind": "Pod", "evidence": {"container": {"name": "app", "type": "containers"}}})


def test_extended_check_deletes_the_probe(monkeypatch):
    monkeypatch.setattr("workbench.actions.secrets.token_hex", lambda _n: "abcd1234")
    calls = []

    class HTTP:
        def get_action(self, url, headers=None):
            calls.append(("GET", url))
            if url.endswith("/nodes?limit=50"):
                return {"items": [{"spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}
            if url.endswith("/networkpolicies?limit=50"):
                return {"items": []}
            return {"metadata": {"name": "amberscan-probe-abcd1234"}, "status": {"phase": "Running", "podIP": "10.9.9.9"}}

        def post_json(self, url, data, headers=None):
            calls.append(("POST", url))
            assert data["spec"]["containers"][0]["securityContext"].get("privileged") is not True
            return data

        def delete_json(self, url, headers=None):
            calls.append(("DELETE", url))
            return {"status": "Success"}

    result = run_extended({"server": SERVER}, {"namespaces": ["demo"]}, HTTP())
    assert [call[0] for call in calls] == ["GET", "GET", "POST", "GET", "DELETE"]
    assert "10.9.9.9" not in json.dumps(result.coverage)


def test_pinned_trivy_runs_without_downloading_or_leaking_the_token(tmp_path):
    binary = tmp_path / "trivy"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        f"print(open({str(FIXTURE)!r}, encoding='utf-8').read())\n",
        encoding="utf-8",
    )
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        master_key="c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2Vj",
        trivy_path=str(binary),
    )
    result = run_live_scanners(
        {"server": SERVER, "ca_data": "YQ==", "auth": {"kind": "token", "token": "synthetic-token-value"}},
        {"namespaces": ["demo"]},
        settings,
    )
    rendered = json.dumps({"findings": result.findings, "coverage": result.coverage}, ensure_ascii=False)
    assert "synthetic-token-value" not in rendered
    assert result.findings
    assert not any(row["check"] == "cli:trivy" and row["status"] in {"error", "not_checked"} for row in result.coverage)
    assert "--disable-node-collector" in scanner_arguments("trivy", "/tmp/kubeconfig", ["demo"])
    missing = Settings(database_url="sqlite+pysqlite:///:memory:", master_key="c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2Vj")
    skipped = run_live_scanners(
        {"server": SERVER, "ca_data": "YQ==", "auth": {"kind": "token", "token": "synthetic-token-value"}},
        {"namespaces": ["demo"]},
        missing,
    )
    assert any(row["check"] == "cli:trivy" and row["status"] == "not_checked" for row in skipped.coverage)


def test_apply_remediation_patches_only_after_the_uid_matches():
    finding = {
        "rule_id": "builtin:privilege-escalation",
        "resource_kind": "Deployment",
        "resource_name": "api",
        "namespace": "demo",
        "resource_uid": "uid-1",
        "evidence": {"container": {"name": "api", "type": "containers"}},
    }
    seen = {}

    class HTTP:
        def get_action(self, url, headers=None):
            seen["get"] = url
            return {"metadata": {"uid": "uid-1"}}

        def patch_json(self, url, data, headers=None):
            seen["patch"] = data
            return data

    result = apply_remediation({"server": SERVER}, HTTP(), finding)
    assert seen["patch"]["spec"]["template"]["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"] is False
    assert result.coverage[-1]["status"] == "completed"


def test_default_perform_remains_inventory(monkeypatch):
    monkeypatch.setattr("workbench.actions.scan_inventory", lambda *args: ScanResult(coverage=[{"check": "inventory", "status": "completed", "detail": "ok"}]))
    from workbench.actions import perform

    result = perform("schedule:periodic", {"server": SERVER}, {"namespaces": ["demo"]}, object(), Settings(database_url="sqlite+pysqlite:///:memory:", master_key="c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2Vj"))
    assert result.coverage[0]["check"] == "inventory"
