"""Bounded, read-only Kubernetes inventory and conservative offline report imports.

No scanner executable is launched by this module. Untrusted descriptions, command
output, workload environment variables, annotations and embedded manifests are never
projected into findings. Imported observations are not proof of cluster provenance.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Protocol
from urllib.parse import urlencode

from .domain import DomainError, ScanResult
from .namespaces import INVENTORY_VERSION, validate_inventory_url, validate_run_scope
from .security import _cluster_endpoint, connection_headers


class ReadOnlyHTTP(Protocol):
    def get_json(self, url: str, headers: dict | None = None) -> dict: ...


MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_JSON_NODES = 100_000
MAX_JSON_DEPTH = 32
MAX_FINDINGS = 2000
MAX_OBJECTS = 10_000
MAX_NAMESPACES = 100
PAGE_SIZE = 100
MAX_PAGES_PER_RESOURCE = 100
MAX_TOTAL_PAGES = 1000
MAX_CONTAINERS = 100
BUILTIN_VERSION = "0.1.0"
SCANNERS = ("trivy", "kube-bench", "kubescape")

_DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
_DNS_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?\Z")
_RBAC_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9.:]{0,251}[a-z0-9])?\Z")
_DIGEST = re.compile(r"sha256:[a-fA-F0-9]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_@/][A-Za-z0-9_@.+:/~%(),=^*| -]{0,199}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:*/(),=^| -]{0,127}\Z")
_VULN_ID = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{0,127}\Z")
_BENCH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_UID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SECRET_MARKERS = re.compile(
    r"(?i)(?:bearer\s|-----BEGIN|(?:password|passwd|secret|token|credential|api[-_]?key)"
    r"\s*[:=]|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
    r"AKIA[A-Z0-9]{16}|[a-z]+://|^[^/@\s:]+:[^/@\s]+@)"
)
_REDACTED = "[redacted]"


@dataclass(frozen=True)
class _Resource:
    plural: str
    kind: str
    api: str
    workload: bool = False

    def path(self, namespace: str) -> str:
        prefix = "/api/v1" if self.api == "v1" else f"/apis/{self.api}"
        return f"{prefix}/namespaces/{namespace}/{self.plural}"


RESOURCES = (
    _Resource("deployments", "Deployment", "apps/v1", True),
    _Resource("statefulsets", "StatefulSet", "apps/v1", True),
    _Resource("daemonsets", "DaemonSet", "apps/v1", True),
    _Resource("pods", "Pod", "v1", True),
    _Resource("services", "Service", "v1"),
    _Resource("networkpolicies", "NetworkPolicy", "networking.k8s.io/v1"),
    _Resource("roles", "Role", "rbac.authorization.k8s.io/v1"),
    _Resource("rolebindings", "RoleBinding", "rbac.authorization.k8s.io/v1"),
    _Resource("serviceaccounts", "ServiceAccount", "v1"),
)


def _coverage(check: str, status: str, detail: str) -> dict:
    return {"check": check, "status": status, "detail": detail}


def _safe(value: Any, pattern: re.Pattern = _IDENTIFIER, default: str = "") -> str:
    """Project identifiers, never arbitrary scanner prose; do not retain fragments."""
    if value is None or value == "":
        return default
    if not isinstance(value, str):
        return _REDACTED
    if (
        len(value) > 200
        or _SECRET_MARKERS.search(value)
        or not pattern.fullmatch(value)
    ):
        return _REDACTED
    return value


def _digest(value: Any) -> str | None:
    if isinstance(value, str) and _DIGEST.fullmatch(value):
        return value.lower()
    return None


def _bounded_json(value: Any, *, malformed: str = "malformed_report") -> None:
    """Bound an already-decoded JSON tree, including malicious direct Python callers."""
    stack = [(value, 0)]
    seen: set[int] = set()
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise DomainError(
                "JSON structure exceeds the supported limits.", "report_too_large"
            )
        if isinstance(item, (dict, list)):
            if id(item) in seen:
                raise DomainError(
                    "JSON contains a repeated or cyclic container.", malformed
                )
            seen.add(id(item))
            size += 2 + len(item) * 2
            if len(item) + len(stack) + nodes > MAX_JSON_NODES:
                raise DomainError(
                    "JSON structure exceeds the supported limits.", "report_too_large"
                )
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise DomainError(
                            "JSON object keys must be strings.", malformed
                        )
                    stack.append((key, depth + 1))
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > MAX_REPORT_BYTES:
                raise DomainError(
                    "JSON exceeds the supported byte limit.", "report_too_large"
                )
            try:
                size += len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
            except UnicodeError:
                raise DomainError("JSON contains invalid Unicode.", malformed) from None
        elif item is None or isinstance(item, bool):
            size += 5
        elif isinstance(item, int) and item.bit_length() <= 64:
            size += 20
        elif isinstance(item, float) and math.isfinite(item):
            size += 24
        else:
            raise DomainError("JSON contains an unsupported value.", malformed)
        if size > MAX_REPORT_BYTES:
            raise DomainError(
                "JSON exceeds the supported byte limit.", "report_too_large"
            )


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    scanner: str,
    evidence: dict,
    recommendation: str,
    *,
    namespace: str = "",
    resource_kind: str = "",
    resource_name: str = "",
    resource_uid: str = "",
    category: str = "configuration",
    confidence: str = "medium",
    **optional: Any,
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "namespace": namespace,
        "resource_kind": resource_kind,
        "resource_name": resource_name,
        "resource_uid": resource_uid,
        "category": category,
        "scanner": scanner,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
        **{key: value for key, value in optional.items() if value is not None},
    }


@dataclass
class _Import:
    scanner: str
    result: ScanResult
    valid: int = 0
    malformed: int = 0
    unsupported: int = 0
    skipped: int = 0
    omitted: int = 0

    def add(self, finding: dict) -> None:
        if len(self.result.findings) < MAX_FINDINGS:
            self.result.findings.append(finding)
        else:
            self.omitted += 1

    def finish(self) -> ScanResult:
        if self.malformed and not self.valid:
            raise DomainError(
                "The report contains no valid supported entries.", "malformed_report"
            )
        incomplete = (
            self.malformed
            or self.omitted
            or self.skipped
            or self.unsupported
            or not self.valid
        )
        self.result.coverage.append(
            _coverage(
                f"import:{self.scanner}",
                "error"
                if self.malformed or self.omitted
                else "not_checked"
                if incomplete
                else "completed",
                f"Normalized {self.valid} supported entries; {self.malformed} malformed, "
                f"{self.unsupported} unsupported, {self.skipped} unevaluated and "
                f"{self.omitted} findings omitted by the output cap. This is report parsing, not a live scan.",
            )
        )
        self.result.coverage.append(
            _coverage(
                "import:provenance",
                "not_checked",
                "Cluster scope, image identity, scanner execution and claimed versions are unverified.",
            )
        )
        if incomplete:
            self.result.limitations.append(
                "The imported report is incomplete; coverage is not established."
            )
        return self.result


def _import_evidence(**fields: Any) -> dict:
    return {"source": "imported_report", "provenance_verified": False, **fields}


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid supported report entry")


def _optional_string(item: dict, key: str) -> str | None:
    value = item.get(key)
    _require(value is None or isinstance(value, str))
    return value


def _severity(value: Any) -> str:
    _require(isinstance(value, str))
    severity = value.lower()
    _require(severity in {"critical", "high", "medium", "low", "info", "unknown"})
    return severity


def _parse_trivy(data: dict, state: _Import) -> None:
    if (
        type(data.get("SchemaVersion")) is not int
        or data["SchemaVersion"] != 2
        or data.get("ArtifactType") != "container_image"
    ):
        raise DomainError(
            "Only Trivy schema 2 container-image JSON is supported.",
            "unsupported_report_schema",
        )
    if not isinstance(data.get("Results"), list) or not isinstance(
        data.get("ArtifactName"), str
    ):
        raise DomainError(
            "The Trivy report structure is malformed.", "malformed_report"
        )
    metadata = data.get("Metadata", {})
    if not isinstance(metadata, dict):
        raise DomainError(
            "The Trivy metadata structure is malformed.", "malformed_report"
        )
    digests = metadata.get("RepoDigests", [])
    if not isinstance(digests, list) or any(not isinstance(d, str) for d in digests):
        raise DomainError(
            "The Trivy digest structure is malformed.", "malformed_report"
        )
    manifest_digests = sorted(
        {d for value in digests if (d := _digest(value.rsplit("@", 1)[-1]))}
    )
    if any(not _digest(value.rsplit("@", 1)[-1]) for value in digests):
        state.malformed += 1
    artifact_digest = _digest(data["ArtifactName"].rsplit("@", 1)[-1])
    if artifact_digest and artifact_digest not in manifest_digests:
        manifest_digests.append(artifact_digest)
    if len(manifest_digests) > 16:
        state.malformed += 1
    # Config ImageID is NOT a manifest digest; retain it under its actual meaning.
    config_digest = _digest(metadata.get("ImageID"))
    if metadata.get("ImageID") and not config_digest:
        state.malformed += 1
    version = data.get("Trivy", {})
    if not isinstance(version, dict) or (
        "Version" in version and not isinstance(version["Version"], str)
    ):
        state.malformed += 1
        version = {}
    state.result.versions.update(
        {
            "trivy": _safe(version.get("Version"), _VERSION, "not_provided"),
            "report_schema": "2",
        }
    )
    if data.get("Errors") or data.get("Error"):
        state.malformed += 1
    for target in data["Results"]:
        if not isinstance(target, dict):
            state.malformed += 1
            continue
        if target.get("Class") not in ("os-pkgs", "lang-pkgs"):
            if isinstance(target.get("Class"), str):
                state.unsupported += 1
            else:
                state.malformed += 1
            continue
        if not isinstance(target.get("Type"), str) or not isinstance(
            target.get("Target"), str
        ):
            state.malformed += 1
            continue
        # A recognized target can additionally contain checks outside this adapter.
        if any(
            target.get(key)
            for key in ("Secrets", "Misconfigurations", "Licenses", "CustomResources")
        ):
            state.unsupported += 1
        vulnerabilities = target.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            state.malformed += 1
            continue
        if target.get("Errors") or target.get("Error"):
            state.malformed += 1
        if not vulnerabilities:
            state.valid += 1
        for vulnerability in vulnerabilities:
            try:
                _require(isinstance(vulnerability, dict))
                for field in ("VulnerabilityID", "PkgName", "InstalledVersion"):
                    _require(
                        isinstance(vulnerability.get(field), str)
                        and bool(vulnerability[field])
                    )
                severity = _severity(vulnerability.get("Severity"))
                fixed = _optional_string(vulnerability, "FixedVersion")
                path = _optional_string(vulnerability, "PkgPath")
                layer = vulnerability.get("Layer", {})
                _require(isinstance(layer, dict))
                vuln_id = _safe(vulnerability["VulnerabilityID"], _VULN_ID)
                evidence = _import_evidence(
                    reported_severity=severity,
                    result_class=target["Class"],
                    package_type=_safe(target["Type"], _BENCH_ID),
                    manifest_digests=manifest_digests[:16],
                )
                if config_digest:
                    evidence["image_config_digest"] = config_digest
                if layer_digest := _digest(layer.get("Digest")):
                    evidence["layer_digest"] = layer_digest
                state.add(
                    _finding(
                        f"trivy:{vuln_id}",
                        "Reported image package vulnerability",
                        severity,
                        "trivy",
                        evidence,
                        "Verify the affected image digest and package; review trusted advisory and fixed-version guidance.",
                        resource_kind="Image",
                        resource_name=_safe(data["ArtifactName"]),
                        category="image_vulnerability",
                        vulnerability_id=vuln_id,
                        image_digest=manifest_digests[0]
                        if len(manifest_digests) == 1
                        else None,
                        package={
                            "name": _safe(vulnerability["PkgName"]),
                            "installed_version": _safe(
                                vulnerability["InstalledVersion"], _VERSION
                            ),
                            "fixed_version": _safe(fixed, _VERSION),
                        },
                        location=_safe(path or target["Target"]),
                    )
                )
                state.valid += 1
            except (ValueError, TypeError):
                state.malformed += 1


def _parse_kube_bench(data: dict, state: _Import) -> None:
    if "Controls" not in data:
        raise DomainError(
            "Only kube-bench Controls JSON is supported.", "unsupported_report_schema"
        )
    if not isinstance(data["Controls"], list):
        raise DomainError(
            "The kube-bench report structure is malformed.", "malformed_report"
        )
    state.result.versions["kube-bench"] = "not_provided"
    state.result.versions["report_schema"] = "Controls/tests/results"
    if data.get("error") or data.get("errors"):
        state.malformed += 1
    benchmark_versions: set[str] = set()
    for control in data["Controls"]:
        if not isinstance(control, dict) or not isinstance(control.get("tests"), list):
            state.malformed += 1
            continue
        if (
            not isinstance(control.get("id"), str)
            or not _BENCH_ID.fullmatch(control["id"])
            or ("version" in control and not isinstance(control["version"], str))
            or not control["tests"]
        ):
            state.malformed += 1
            continue
        control_id = _safe(control["id"], _BENCH_ID)
        benchmark = _safe(control.get("version"), _VERSION, "not_provided")
        benchmark_versions.add(benchmark)
        node_type = control.get("node_type")
        safe_node_type = (
            node_type
            if node_type
            in (
                "master",
                "node",
                "controlplane",
                "worker",
                "etcd",
                "policies",
                "managedservices",
            )
            else "unspecified"
        )
        for test in control["tests"]:
            if (
                not isinstance(test, dict)
                or not isinstance(test.get("results"), list)
                or not test["results"]
                or not isinstance(test.get("section"), str)
                or not _BENCH_ID.fullmatch(test["section"])
            ):
                state.malformed += 1
                continue
            for check in test["results"]:
                try:
                    _require(isinstance(check, dict))
                    number = check.get("test_number")
                    _require(
                        isinstance(number, str) and bool(_BENCH_ID.fullmatch(number))
                    )
                    number = _safe(number, _BENCH_ID)
                    status = check.get("status")
                    _require(status in ("PASS", "FAIL", "WARN", "INFO"))
                    state.valid += 1
                    if status == "PASS":
                        continue
                    if status in ("WARN", "INFO"):
                        state.skipped += 1
                    state.add(
                        _finding(
                            f"kube-bench:{number}",
                            "CIS benchmark check reported failed"
                            if status == "FAIL"
                            else "CIS benchmark check requires review",
                            "medium" if status == "FAIL" else "info",
                            "kube-bench",
                            _import_evidence(
                                test_number=number,
                                reported_status=status,
                                benchmark_version=benchmark,
                                control_id=control_id,
                                section=_safe(test.get("section"), _BENCH_ID),
                                node_type=safe_node_type,
                            ),
                            "Review the identified CIS control in trusted benchmark documentation; confirm applicability and actual node configuration.",
                            resource_kind="Node",
                            category="benchmark",
                            confidence="medium" if status == "FAIL" else "low",
                            location=f"CIS/{benchmark}/{number}",
                        )
                    )
                except (ValueError, TypeError):
                    state.malformed += 1
    if len(benchmark_versions) > 32:
        state.malformed += 1
    state.result.versions["benchmark_versions"] = sorted(benchmark_versions)[:32]


def _kubescape_location(resource_id: Any) -> dict:
    _require(isinstance(resource_id, str) and len(resource_id) <= 600)
    parts = resource_id.split("/")
    # Group/version/kind/namespace/name; an empty group starts with '/'.
    _require(len(parts) == 5)
    group, version, kind, namespace, name = parts
    _require(not group or bool(_DNS_NAME.fullmatch(group)))
    _require(bool(re.fullmatch(r"v[0-9]+(?:(?:alpha|beta)[0-9]+)?", version)))
    _require(bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,62}", kind)))
    _require(not namespace or bool(_DNS_LABEL.fullmatch(namespace)))
    _require(bool(_DNS_NAME.fullmatch(name)))
    return {
        "namespace": namespace,
        "resource_kind": kind,
        "resource_name": name,
        "location": resource_id,
    }


def _parse_kubescape(data: dict, state: _Import) -> None:
    # A resource-results posture report, not arbitrary JSON or summary-only output.
    if "results" not in data or "resources" not in data:
        raise DomainError(
            "Only Kubescape resource-results JSON is supported.",
            "unsupported_report_schema",
        )
    if not isinstance(data["results"], list) or not isinstance(data["resources"], list):
        raise DomainError(
            "The Kubescape report structure is malformed.", "malformed_report"
        )
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        raise DomainError(
            "The Kubescape metadata structure is malformed.", "malformed_report"
        )
    if "toolVersion" in metadata and not isinstance(metadata["toolVersion"], str):
        state.malformed += 1
    if data.get("error") or data.get("errors"):
        state.malformed += 1
    state.result.versions.update(
        {
            "kubescape": _safe(metadata.get("toolVersion"), _VERSION, "not_provided"),
            "report_schema": "resource-results",
        }
    )
    uids: dict[str, str] = {}
    seen_results: set[str] = set()
    for resource in data["resources"]:
        if not isinstance(resource, dict) or not isinstance(
            resource.get("resourceID"), str
        ):
            state.malformed += 1
            continue
        try:
            _kubescape_location(resource["resourceID"])
            _require(resource["resourceID"] not in uids)
        except (ValueError, TypeError):
            state.malformed += 1
            continue
        obj = resource.get("object", {})
        if isinstance(obj, dict) and isinstance(obj.get("metadata", {}), dict):
            # Never retain the embedded manifest, even if it is a Secret.
            uids[resource["resourceID"]] = _safe(
                obj.get("metadata", {}).get("uid"), _UID
            )
        else:
            state.malformed += 1
    for entry in data["results"]:
        try:
            _require(isinstance(entry, dict))
            location = _kubescape_location(entry.get("resourceID"))
            _require(entry["resourceID"] not in seen_results)
            seen_results.add(entry["resourceID"])
            controls = entry.get("controls")
            _require(isinstance(controls, list) and bool(controls))
        except (ValueError, TypeError):
            state.malformed += 1
            continue
        for control in controls:
            try:
                _require(isinstance(control, dict))
                control_id = control.get("controlID")
                _require(
                    isinstance(control_id, str)
                    and bool(re.fullmatch(r"C-[0-9]{4,6}", control_id))
                )
                status_object = control.get("status")
                _require(isinstance(status_object, dict))
                status = status_object.get("status")
                _require(status in ("passed", "failed", "skipped", "error"))
                severity = _severity(control.get("severity", "unknown"))
                if "rules" in control:
                    _require(
                        isinstance(control["rules"], list)
                        and all(isinstance(rule, dict) for rule in control["rules"])
                    )
                state.valid += 1
                if status in ("skipped", "error"):
                    state.skipped += 1
                    continue
                if status == "passed":
                    continue
                state.add(
                    _finding(
                        f"kubescape:{control_id}",
                        "Kubescape control reported failed",
                        severity,
                        "kubescape",
                        _import_evidence(control_id=control_id, reported_status=status),
                        "Review the named Kubescape control and resource configuration in a trusted rule reference; confirm applicability.",
                        **location,
                        resource_uid=uids.get(entry["resourceID"], ""),
                        category="posture",
                    )
                )
            except (ValueError, TypeError):
                state.malformed += 1


def parse_report(scanner: str, data: dict) -> ScanResult:
    """Normalize a known offline report, fail unknown roots, mark partial rows explicitly."""
    if scanner not in SCANNERS:
        raise DomainError(
            "The scanner report type is unsupported.", "unsupported_scanner"
        )
    if not isinstance(data, dict):
        raise DomainError("A scanner report must be a JSON object.", "malformed_report")
    _bounded_json(data)
    result = ScanResult(
        versions={"origin": "imported"},
        limitations=[
            "Imported reports are untrusted observations; cluster scope, execution, image identity and versions are not verified.",
            "Only allowlisted identifiers and structured evidence are retained. Free-text descriptions, commands, output and embedded manifests are omitted.",
            "A reported configuration weakness or vulnerability does not establish exploitability or remediation status.",
        ],
    )
    state = _Import(scanner, result)
    {
        "trivy": _parse_trivy,
        "kube-bench": _parse_kube_bench,
        "kubescape": _parse_kubescape,
    }[scanner](data, state)
    return state.finish()


@dataclass(frozen=True)
class _Scope:
    namespaces: tuple[str, ...]
    max_objects: int
    timeout_seconds: int


def _scope(scope: dict) -> _Scope:
    if not isinstance(scope, dict):
        raise DomainError("Explicit namespace scope is required.")
    # Standalone callers may retain historical defaults; persisted worker/API scopes
    # use validate_run_scope directly and must contain every versioned field.
    validated = validate_run_scope(
        {
            "max_objects": 1000,
            "timeout_seconds": 300,
            "inventory_version": INVENTORY_VERSION,
            **scope,
        },
        scope.get("namespaces"),
    )
    return _Scope(
        tuple(validated["namespaces"]),
        validated["max_objects"],
        validated["timeout_seconds"],
    )


def _connection(connection: dict) -> tuple[str, dict]:
    if not isinstance(connection, dict):
        raise DomainError("A cluster connection is required.")
    server = _cluster_endpoint(connection.get("server"))
    return server.rstrip("/"), connection_headers(connection)


class _DeadlineReached(Exception):
    pass


class _BadInventory(Exception):
    pass


@dataclass
class _Budget:
    deadline: float
    cancelled: Callable[[], bool]

    def check(self) -> None:
        if self.cancelled():
            raise DomainError("The scan was cancelled.", "cancelled")
        if time.monotonic() >= self.deadline:
            raise _DeadlineReached


def _http_failure(error: DomainError) -> tuple[str, str, bool]:
    # Do not copy HTTP exception prose. Crucially, a local authorization/session/
    # scope fence is NOT a recoverable remote failure, even on the final GET.
    if error.code == "cancelled":
        raise DomainError("The scan was cancelled.", "cancelled") from None
    mapping = {
        "http_401": ("denied", "Cluster authentication was rejected (HTTP 401).", True),
        "http_403": ("denied", "Read access was denied (HTTP 403).", False),
        "http_404": (
            "unsupported",
            "The requested resource endpoint is unavailable (HTTP 404).",
            False,
        ),
        "http_405": (
            "unsupported",
            "The endpoint does not support the required GET operation.",
            False,
        ),
        "http_410": (
            "error",
            "The list snapshot expired; collection is incomplete (HTTP 410).",
            False,
        ),
        "http_429": (
            "error",
            "The API rate limit was reached; no automatic retry was attempted.",
            True,
        ),
        "http_timeout": (
            "error",
            "The API request timed out; collection is incomplete.",
            True,
        ),
        "http_transport": (
            "error",
            "The API connection failed; collection is incomplete.",
            True,
        ),
        "http_tls": ("error", "The API TLS verification or negotiation failed.", True),
        "http_dns": ("error", "The API endpoint could not be resolved.", True),
        "http_invalid_json": ("error", "The API returned invalid JSON.", False),
        "http_response_too_large": (
            "error",
            "The API response exceeded the permitted size.",
            True,
        ),
        "http_redirect_denied": ("error", "An API redirect was rejected.", True),
        "endpoint_denied": (
            "denied",
            "The cluster endpoint was rejected by egress policy.",
            True,
        ),
    }
    if error.code in mapping:
        return mapping[error.code]
    if isinstance(error.code, str) and re.fullmatch(r"http_[1-5][0-9]{2}", error.code):
        return "error", "The API request failed; collection is incomplete.", False
    raise error


def _list_page(
    data: dict, resource: _Resource, limit: int
) -> tuple[list, str, str | None]:
    try:
        _bounded_json(data, malformed="invalid_inventory")
    except DomainError:
        raise _BadInventory from None
    if (
        not isinstance(data, dict)
        or data.get("kind") != resource.kind + "List"
        or data.get("apiVersion") != resource.api
        or not isinstance(data.get("items"), list)
        or not isinstance(data.get("metadata"), dict)
        or len(data["items"]) > limit
    ):
        raise _BadInventory
    meta = data["metadata"]
    cursor = meta.get("continue", "")
    revision = meta.get("resourceVersion")
    remaining = meta.get("remainingItemCount")
    if (
        not isinstance(cursor, str)
        or len(cursor) > 4096
        or any(ord(c) < 32 or ord(c) >= 127 for c in cursor)
        or not isinstance(revision, str)
        or not revision
        or len(revision) > 256
        or any(ord(c) <= 32 or ord(c) >= 127 for c in revision)
        or (remaining is not None and (type(remaining) is not int or remaining < 0))
        or (not cursor and remaining)
    ):
        raise _BadInventory
    return data["items"], cursor, revision


def preflight(connection: dict, scope: dict, http: ReadOnlyHTTP) -> list[dict]:
    """GET-only list probes; local security fences always propagate to the caller."""
    selected = _scope(scope)
    server, headers = _connection(connection)
    budget = _Budget(time.monotonic() + selected.timeout_seconds, lambda: False)
    coverage: list[dict] = []
    halted = False
    for namespace in selected.namespaces:
        for resource in RESOURCES:
            if halted:
                status, code, detail = (
                    "not_checked",
                    "not_checked",
                    "Probe not attempted after an authentication, connection or time-limit failure.",
                )
            else:
                try:
                    budget.check()
                    url = server + resource.path(namespace) + "?limit=1"
                    validate_inventory_url(url, server, list(selected.namespaces))
                    data = http.get_json(url, headers=headers)
                    budget.check()
                    items, _, _ = _list_page(data, resource, 1)
                    for obj in items:
                        _object_identity(obj, namespace, resource)
                    status, code, detail = (
                        "completed",
                        "allowed",
                        "GET list probe allowed; this is not security scan coverage.",
                    )
                except _DeadlineReached:
                    status, code, detail = (
                        "error",
                        "http_timeout",
                        "The preflight deadline was reached.",
                    )
                    halted = True
                except _BadInventory:
                    status, code, detail = (
                        "error",
                        "invalid_inventory",
                        "The API returned a malformed or oversized resource list.",
                    )
                except DomainError as error:
                    status, detail, halted = _http_failure(error)
                    code = error.code
            coverage.append(
                {
                    **_coverage(f"{namespace}/{resource.plural}", status, detail),
                    "code": code,
                    "namespace": namespace,
                    "resource": resource.plural,
                    "group": ""
                    if resource.api == "v1"
                    else resource.api.rsplit("/", 1)[0],
                    "verb": "list",
                }
            )
    return coverage


def _object_identity(obj: Any, namespace: str, resource: _Resource) -> dict:
    if not isinstance(obj, dict) or not isinstance(obj.get("metadata"), dict):
        raise _BadInventory
    meta = obj["metadata"]
    name, uid = meta.get("name"), meta.get("uid")
    name_pattern = _RBAC_NAME if resource.kind in ("Role", "RoleBinding") else _DNS_NAME
    if (
        meta.get("namespace") != namespace
        or not isinstance(name, str)
        or not name_pattern.fullmatch(name)
        or not isinstance(uid, str)
        or not _UID.fullmatch(uid)
        or obj.get("kind", resource.kind) != resource.kind
        or obj.get("apiVersion", resource.api) != resource.api
    ):
        raise _BadInventory
    return {
        "namespace": namespace,
        "resource_kind": resource.kind,
        "resource_name": name,
        "resource_uid": _safe(uid, _UID),
    }


def _security_context(value: Any) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _BadInventory
    projected = {}
    for field in ("privileged", "allowPrivilegeEscalation", "runAsNonRoot"):
        if field in value:
            if type(value[field]) is not bool:
                raise _BadInventory
            projected[field] = value[field]
    if "runAsUser" in value:
        if (
            type(value["runAsUser"]) is not int
            or not 0 <= value["runAsUser"] <= 2**31 - 1
        ):
            raise _BadInventory
        projected["runAsUser"] = value["runAsUser"]
    return projected


def _workload_findings(
    obj: dict, resource: _Resource, identity: dict
) -> tuple[list[dict], bool]:
    try:
        spec = (
            obj["spec"] if resource.kind == "Pod" else obj["spec"]["template"]["spec"]
        )
    except (KeyError, TypeError):
        raise _BadInventory from None
    if not isinstance(spec, dict):
        raise _BadInventory
    os_value = spec.get("os", {})
    if not isinstance(os_value, dict) or os_value.get("name", "linux") not in (
        "linux",
        "windows",
    ):
        raise _BadInventory
    if os_value.get("name") == "windows":
        return [], True
    prefix = "spec" if resource.kind == "Pod" else "spec.template.spec"
    pod_context = _security_context(spec.get("securityContext"))
    host_fields = {}
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if field in spec and type(spec[field]) is not bool:
            raise _BadInventory
        if spec.get(field) is True:
            host_fields[field] = True
    containers = []
    for group in ("containers", "initContainers", "ephemeralContainers"):
        values = spec.get(group, [])
        if not isinstance(values, list) or (group == "containers" and not values):
            raise _BadInventory
        for index, container in enumerate(values):
            if (
                not isinstance(container, dict)
                or not isinstance(container.get("name"), str)
                or not _DNS_LABEL.fullmatch(container["name"])
            ):
                raise _BadInventory
            context = _security_context(container.get("securityContext"))
            image = container.get("image", "")
            if not isinstance(image, str):
                raise _BadInventory
            containers.append(
                (
                    group,
                    index,
                    container["name"],
                    context,
                    _digest(image.rsplit("@", 1)[-1]),
                )
            )
            if len(containers) > MAX_CONTAINERS:
                raise _BadInventory
    findings = []
    if host_fields:
        findings.append(
            _finding(
                "builtin:host-namespaces",
                "Host namespace sharing is enabled",
                "high",
                "builtin",
                {"source": "kubernetes_api", "pod_security": host_fields},
                "Review whether host namespace access is required; disable unnecessary sharing. This setting alone does not establish exploitation.",
                **identity,
                confidence="high",
                location=prefix,
            )
        )
    for group, index, name, context, digest in containers:
        location = f"{prefix}.{group}[{index}].securityContext"
        evidence = {
            "source": "kubernetes_api",
            "container": {"name": name, "type": group, "securityContext": context},
            "pod_security_context": pod_context,
        }
        common: dict[str, Any] = {
            **identity,
            "location": location,
            "image_digest": digest,
        }
        if context.get("privileged") is True:
            findings.append(
                _finding(
                    "builtin:privileged",
                    "Privileged container mode is configured",
                    "high",
                    "builtin",
                    evidence,
                    "Remove privileged mode unless explicitly justified; use only required capabilities. Actual admission and runtime behavior were not tested.",
                    **common,
                    confidence="high",
                )
            )
        run_as_user = context.get("runAsUser", pod_context.get("runAsUser"))
        nonroot = context.get("runAsNonRoot", pod_context.get("runAsNonRoot"))
        if run_as_user == 0:
            findings.append(
                _finding(
                    "builtin:root-user",
                    "UID 0 is explicitly selected",
                    "medium",
                    "builtin",
                    evidence,
                    "Select a supported non-root UID and enforce runAsNonRoot. This observation is configuration, not proof a process is running as root.",
                    **common,
                    confidence="high",
                )
            )
        elif run_as_user is None and nonroot is not True:
            findings.append(
                _finding(
                    "builtin:nonroot-unset",
                    "Non-root execution is not enforced in the workload configuration",
                    "low",
                    "builtin",
                    evidence,
                    "Consider runAsNonRoot or a non-root UID. Image defaults, admission controls and runtime identity were not inspected; an absent setting does not prove root execution.",
                    **common,
                    confidence="low",
                )
            )
        if context.get("allowPrivilegeEscalation") is not False:
            explicit = context.get("allowPrivilegeEscalation") is True
            findings.append(
                _finding(
                    "builtin:privilege-escalation",
                    "Privilege escalation prevention is not enabled in the container configuration",
                    "medium" if explicit else "low",
                    "builtin",
                    evidence,
                    "Consider allowPrivilegeEscalation=false where compatible. Missing configuration is not evidence of a successful privilege escalation.",
                    **common,
                    confidence="high" if explicit else "low",
                )
            )
    return findings, False


def scan_inventory(
    connection: dict, scope: dict, http: ReadOnlyHTTP, cancelled: Callable[[], bool]
) -> ScanResult:
    """Collect bounded explicit-namespace GET lists; retain only projected findings."""
    selected = _scope(scope)
    server, headers = _connection(connection)
    if not callable(cancelled):
        raise DomainError("A cancellation callback is required.")
    budget = _Budget(time.monotonic() + selected.timeout_seconds, cancelled)
    result = ScanResult(
        versions={"builtin": BUILTIN_VERSION},
        limitations=[
            "Built-in checks examine selected Linux workload security fields only; they are not Kubescape, CIS compliance or a complete security assessment.",
            "Secrets, ConfigMaps, logs, exec, node resources and cluster-scoped RBAC are never requested. Service, network-policy and namespaced RBAC inventories are not policy analyses.",
            "Missing workload settings are configuration observations, not proof of root execution or exploitability; image defaults and admission/runtime behavior were not verified.",
            "Cancellation and the overall deadline are cooperative; an in-flight GET is bounded by the PinnedHTTP request timeout.",
        ],
    )
    count = pages = 0
    halted = False
    omitted = windows = 0
    for namespace in selected.namespaces:
        for resource in RESOURCES:
            # Cancellation has priority even when a resource cap has been reached.
            if cancelled():
                raise DomainError("The scan was cancelled.", "cancelled")
            check = f"{namespace}/{resource.plural}"
            if halted or count >= selected.max_objects or pages >= MAX_TOTAL_PAGES:
                result.coverage.append(
                    _coverage(
                        check,
                        "not_checked",
                        "Collection was not attempted after an authentication, transport, time, object or page limit.",
                    )
                )
                continue
            cursor = ""
            seen_cursors: set[str] = set()
            seen_objects: set[str] = set()
            resource_pages = collected = malformed = 0
            snapshot: str | None = None
            status, detail = "completed", ""
            try:
                while True:
                    budget.check()
                    if (
                        count >= selected.max_objects
                        or pages >= MAX_TOTAL_PAGES
                        or resource_pages >= MAX_PAGES_PER_RESOURCE
                    ):
                        status, detail = (
                            "error",
                            "A collection cap was reached before this resource list completed.",
                        )
                        break
                    limit = min(PAGE_SIZE, selected.max_objects - count)
                    query = {"limit": str(limit)}
                    if cursor:
                        query["continue"] = cursor
                    pages += 1
                    resource_pages += 1
                    url = server + resource.path(namespace) + "?" + urlencode(query)
                    validate_inventory_url(url, server, list(selected.namespaces))
                    data = http.get_json(url, headers=headers)
                    budget.check()
                    items, next_cursor, revision = _list_page(data, resource, limit)
                    if resource_pages > 1 and snapshot != revision:
                        raise _BadInventory
                    snapshot = revision
                    for obj in items:
                        budget.check()
                        count += 1
                        try:
                            identity = _object_identity(obj, namespace, resource)
                            uid = identity["resource_uid"]
                            if uid in seen_objects:
                                raise _BadInventory
                            seen_objects.add(uid)
                            if resource.workload:
                                observations, unsupported_os = _workload_findings(
                                    obj, resource, identity
                                )
                                windows += int(unsupported_os)
                                for finding in observations:
                                    if len(result.findings) < MAX_FINDINGS:
                                        result.findings.append(finding)
                                    else:
                                        omitted += 1
                            collected += 1
                        except _BadInventory:
                            malformed += 1
                    if not next_cursor:
                        break
                    if next_cursor in seen_cursors:
                        status, detail = (
                            "error",
                            "The API repeated a continuation token; this resource list is incomplete.",
                        )
                        break
                    seen_cursors.add(next_cursor)
                    cursor = next_cursor
            except _DeadlineReached:
                status, detail, halted = (
                    "error",
                    "The collection deadline was reached; this resource list is incomplete.",
                    True,
                )
            except _BadInventory:
                status, detail = (
                    "error",
                    "The API returned a malformed, oversized or inconsistent resource list.",
                )
            except DomainError as error:
                if error.code == "cancelled":
                    raise DomainError("The scan was cancelled.", "cancelled") from None
                status, detail, halted = _http_failure(error)
            if malformed:
                status = "error"
                detail = f"{malformed} malformed, duplicate or out-of-scope objects were rejected; coverage is incomplete."
            if not detail:
                detail = f"Read {collected} objects in {resource_pages} GET page(s). "
                detail += (
                    "Limited workload configuration checks only."
                    if resource.workload
                    else "Inventory only; no built-in policy assessment."
                )
            result.coverage.append(_coverage(check, status, detail))
    if cancelled():
        raise DomainError("The scan was cancelled.", "cancelled")
    if omitted:
        result.coverage.append(
            _coverage(
                "builtin:output-limit",
                "error",
                f"The finding cap was reached; {omitted} additional observations were omitted.",
            )
        )
    if windows:
        result.coverage.append(
            _coverage(
                "builtin:windows",
                "unsupported",
                f"Linux security checks were not applied to {windows} Windows workloads.",
            )
        )
    for scanner in SCANNERS:
        result.coverage.append(
            _coverage(
                f"cli:{scanner}",
                "not_checked",
                "Live CLI adapter unavailable pending pinned-binary and default-behavior verification; no scanner was executed.",
            )
        )
    if any(
        entry["status"] != "completed"
        for entry in result.coverage
        if not entry["check"].startswith("cli:")
    ):
        result.limitations.append(
            "Inventory or built-in observations are incomplete; uncollected resources must not be treated as compliant."
        )
    return result


def subprocess_argv(executable: str, arguments: Sequence[str]) -> tuple[str, ...]:
    """Prepare literal argv only, never a shell command and never execute it.

    A future adapter must verify a pinned executable, use fixed scanner-specific
    options, control environment/network/filesystem and cap subprocess output.
    This helper does not make any scanner available or attest its defaults.
    """
    if (
        not isinstance(executable, str)
        or not executable.startswith("/")
        or ".." in PurePosixPath(executable).parts
        or len(executable) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in executable)
        or isinstance(arguments, (str, bytes))
        or not isinstance(arguments, (tuple, list))
        or len(arguments) > 64
    ):
        raise DomainError(
            "A bounded argument vector and an absolute executable path are required.",
            "invalid_cli_arguments",
        )
    if any(
        not isinstance(arg, str)
        or len(arg) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in arg)
        for arg in arguments
    ):
        raise DomainError(
            "The CLI argument vector contains an invalid argument.",
            "invalid_cli_arguments",
        )
    return (executable, *arguments)


def run_cli(scanner: str) -> ScanResult:
    """Explicitly unavailable; no PATH lookup, download or subprocess fallback."""
    if scanner not in SCANNERS:
        raise DomainError("The scanner is unsupported.", "unsupported_scanner")
    raise DomainError(
        "Live scanner execution is unavailable pending pinned-binary and default-behavior verification.",
        "scanner_unavailable",
    )
