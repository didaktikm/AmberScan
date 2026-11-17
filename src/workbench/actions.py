"""Confirmed capabilities that go beyond a one-off read-only inventory.

Live scanners run only from pinned absolute paths and are not downloaded.
Cluster writes happen only for an already confirmed run source, and only
against the fixed objects this module builds.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

import yaml
from sqlalchemy import func, select

from workbench.config import Settings
from workbench.db import (
    AuditEvent,
    Cluster,
    ClusterCredential,
    Finding,
    Run,
    User,
    audit,
    uid,
)
from workbench.domain import DomainError, ScanResult
from workbench.namespaces import INVENTORY_VERSION, validate_namespaces
from workbench.scanners import parse_report, scan_inventory
from workbench.services import (
    ACTIVE_STATES,
    AUTH_FIELDS,
    credential_for,
    lock_authorization,
)

WRITE_SOURCES = frozenset({"extended", "operator", "remediate"})
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
OPERATOR_NAME = "amberscan-operator"
REMEDIABLE_RULES = frozenset(
    {
        "builtin:privileged",
        "builtin:privilege-escalation",
        "builtin:root-user",
        "builtin:host-namespaces",
    }
)
CONTROLLER_KINDS = {"Deployment": "deployments", "StatefulSet": "statefulsets", "DaemonSet": "daemonsets"}
_PROBE = re.compile(r"amberscan-probe-[0-9a-f]{8}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
_OUTPUT_LIMIT = 2_000_000
_SCAN_TIMEOUT = 180


def _coverage(check: str, status: str, detail: str) -> dict:
    return {"check": check, "status": status, "detail": detail}


def _server(connection: dict) -> str:
    server = connection.get("server")
    if not isinstance(server, str) or not server.startswith("https://"):
        raise DomainError("Адрес API недействителен", "invalid_scope")
    return server.rstrip("/")


def validate_action_url(url, server, namespaces, method: str) -> None:
    """Allow only the fixed read and confirmed-write URLs these actions use."""
    try:
        base = _server({"server": server})
        names = set(validate_namespaces(list(namespaces)))
        if not isinstance(url, str) or not url.startswith(base + "/") or method not in {"GET", "POST", "DELETE", "PATCH"}:
            raise ValueError
        path = url[len(base):]
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)
        allowed = set()
        for name in names:
            allowed.add(f"/api/v1/namespaces/{name}/pods")
            allowed.add(f"/apis/networking.k8s.io/v1/namespaces/{name}/networkpolicies")
            allowed.add(f"/api/v1/namespaces/{name}/serviceaccounts")
            allowed.add(f"/apis/rbac.authorization.k8s.io/v1/namespaces/{name}/roles")
            allowed.add(f"/apis/rbac.authorization.k8s.io/v1/namespaces/{name}/rolebindings")
            allowed.add(f"/apis/apps/v1/namespaces/{name}/deployments")
            for plural in CONTROLLER_KINDS.values():
                allowed.add(f"/apis/apps/v1/namespaces/{name}/{plural}/{OPERATOR_NAME}")
        if path == "/api/v1/nodes" and method == "GET" and query == "limit=50":
            return
        if path in {f"/apis/networking.k8s.io/v1/namespaces/{name}/networkpolicies" for name in names} and method == "GET" and query == "limit=50":
            return
        if method in {"POST", "DELETE", "PATCH", "GET"} and query:
            raise ValueError
        if path in allowed and method == "POST" and path.endswith(("/serviceaccounts", "/roles", "/rolebindings", "/deployments", "/pods")):
            return
        for name in names:
            prefix = f"/api/v1/namespaces/{name}/pods/"
            if path.startswith(prefix) and method in {"GET", "DELETE"} and _PROBE.fullmatch(path[len(prefix):]):
                return
            for plural in CONTROLLER_KINDS.values():
                marker = f"/apis/apps/v1/namespaces/{name}/{plural}/"
                if path.startswith(marker) and method in {"GET", "PATCH"}:
                    resource = path[len(marker):]
                    if _LABEL.fullmatch(resource):
                        return
        raise ValueError
    except (ValueError, TypeError, DomainError):
        raise DomainError("Запрос вне подтверждённого действия", "scope_denied") from None


def _reject_enabled(value, field: str) -> None:
    if isinstance(value, dict) and value.get(field) is True:
        raise DomainError("Объект действия включает запрещённый режим", "invalid_input")
    if isinstance(value, dict):
        for item in value.values():
            _reject_enabled(item, field)
    elif isinstance(value, list):
        for item in value:
            _reject_enabled(item, field)


def assert_safe_write(method: str, url: str, body) -> None:
    if method == "POST" and url.rstrip("/").endswith("/pods"):
        if not isinstance(body, dict) or not _PROBE.fullmatch(str(body.get("metadata", {}).get("name", ""))):
            raise DomainError("Временный под имеет недопустимое имя", "invalid_input")
        spec = body.get("spec") if isinstance(body.get("spec"), dict) else {}
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(field) is True:
                raise DomainError("Временный под не может использовать пространство узла", "invalid_input")
        containers = spec.get("containers")
        if not isinstance(containers, list) or len(containers) != 1:
            raise DomainError("Временный под должен содержать один контейнер", "invalid_input")
        context = containers[0].get("securityContext") if isinstance(containers[0], dict) else {}
        if not isinstance(context, dict) or context.get("privileged") is True or context.get("allowPrivilegeEscalation") is not False:
            raise DomainError("Временный под не может быть привилегированным", "invalid_input")
        if context.get("capabilities", {}).get("drop") != ["ALL"]:
            raise DomainError("Временный под должен сбросить capabilities", "invalid_input")
    if method == "POST" and url.rstrip("/").endswith("/deployments"):
        if not isinstance(body, dict) or body.get("metadata", {}).get("name") != OPERATOR_NAME:
            raise DomainError("Имя оператора зафиксировано", "invalid_input")
        _reject_enabled(body, "privileged")
        _reject_enabled(body, "hostNetwork")
        _reject_enabled(body, "hostPID")
        _reject_enabled(body, "hostIPC")
    if method == "PATCH" and isinstance(body, dict):
        _reject_enabled(body, "privileged")
        _reject_enabled(body, "hostNetwork")
        _reject_enabled(body, "hostPID")
        _reject_enabled(body, "hostIPC")


def probe_pod(namespace: str, name: str) -> dict:
    if not _LABEL.fullmatch(namespace) or not _PROBE.fullmatch(name):
        raise DomainError("Имя временного пода недопустимо", "invalid_input")
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace, "labels": {"app.kubernetes.io/name": "amberscan-probe"}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [
                {
                    "name": "probe",
                    "image": "registry.k8s.io/pause:3.10",
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                    },
                    "resources": {"limits": {"cpu": "50m", "memory": "32Mi"}, "requests": {"cpu": "10m", "memory": "16Mi"}},
                }
            ],
        },
    }


def operator_manifests(namespace: str, image: str) -> list[dict]:
    if not _LABEL.fullmatch(namespace) or namespace in SYSTEM_NAMESPACES:
        raise DomainError("Оператор не ставится в системное пространство имён", "invalid_input")
    if not image or image.endswith(":latest") or (":" not in image and "@" not in image):
        raise DomainError("Нужен образ с явным тегом, не latest", "configuration_required")
    meta = {"name": OPERATOR_NAME, "namespace": namespace, "labels": {"app.kubernetes.io/name": OPERATOR_NAME}}
    return [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta},
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": meta,
            "rules": [
                {"apiGroups": [""], "resources": ["pods", "services", "serviceaccounts"], "verbs": ["get", "list", "watch"]},
                {"apiGroups": ["apps"], "resources": ["deployments", "statefulsets", "daemonsets"], "verbs": ["get", "list", "watch"]},
                {"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"], "verbs": ["get", "list", "watch"]},
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": meta,
            "subjects": [{"kind": "ServiceAccount", "name": OPERATOR_NAME, "namespace": namespace}],
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": OPERATOR_NAME},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": meta,
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app.kubernetes.io/name": OPERATOR_NAME}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": OPERATOR_NAME}},
                    "spec": {
                        "serviceAccountName": OPERATOR_NAME,
                        "automountServiceAccountToken": True,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [
                            {
                                "name": "operator",
                                "image": image,
                                "command": ["python", "-m", "workbench.operator"],
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                    "runAsNonRoot": True,
                                    "runAsUser": 65534,
                                    "privileged": False,
                                },
                                "resources": {"limits": {"cpu": "200m", "memory": "256Mi"}, "requests": {"cpu": "20m", "memory": "64Mi"}},
                            }
                        ],
                    },
                },
            },
        },
    ]


def remediation_patch(finding: dict) -> dict:
    rule = finding.get("rule_id")
    kind = finding.get("resource_kind")
    if rule not in REMEDIABLE_RULES or kind not in CONTROLLER_KINDS:
        raise DomainError("Для этой находки нет безопасной автоправки", "unsupported")
    if rule == "builtin:host-namespaces":
        return {"spec": {"template": {"spec": {"hostNetwork": False, "hostPID": False, "hostIPC": False}}}}
    container = (finding.get("evidence") or {}).get("container") or {}
    name = container.get("name")
    group = container.get("type") or "containers"
    if not isinstance(name, str) or not _LABEL.fullmatch(name) or group not in {"containers", "initContainers", "ephemeralContainers"}:
        raise DomainError("Контейнер находки не определён", "unsupported")
    context = {"allowPrivilegeEscalation": False}
    if rule == "builtin:privileged":
        context["privileged"] = False
    elif rule == "builtin:root-user":
        context["runAsNonRoot"] = True
        context["runAsUser"] = 65534
    return {"spec": {"template": {"spec": {group: [{"name": name, "securityContext": context}]}}}}


def _paths(settings: Settings) -> dict[str, str | None]:
    return {"trivy": settings.trivy_path, "kubescape": settings.kubescape_path}


def scanner_arguments(scanner: str, kubeconfig: str, namespaces: list[str]) -> list[str]:
    names = validate_namespaces(list(namespaces))
    joined = ",".join(names)
    if scanner == "trivy":
        return ["k8s", "--disable-node-collector", "--quiet", "--format", "json", "--timeout", "3m", "--kubeconfig", kubeconfig, "--include-namespaces", joined]
    if scanner == "kubescape":
        return ["scan", "framework", "nsa", "--format", "json", "--kubeconfig", kubeconfig, "--include-namespaces", joined, "--logger", "error"]
    raise DomainError("Этот сканер не запускается из консоли", "unsupported_scanner")


def materialize_kubeconfig(connection: dict, directory: Path) -> Path:
    auth = connection.get("auth")
    if not isinstance(auth, dict):
        raise DomainError("Нет личной авторизации для сканера", "authorization_required")
    user: dict[str, str] = {}
    if auth.get("kind") == "token" and isinstance(auth.get("token"), str):
        user["token"] = auth["token"]
    elif auth.get("kind") == "client_certificate":
        cert = directory / "client.crt"
        key = directory / "client.key"
        cert.write_text(str(auth.get("certificate_pem", "")), encoding="utf-8")
        key.write_text(str(auth.get("private_key_pem", "")), encoding="utf-8")
        cert.chmod(0o600)
        key.chmod(0o600)
        user["client-certificate"] = str(cert)
        user["client-key"] = str(key)
    else:
        raise DomainError("Сканеру нужен токен или клиентский сертификат", "credential_invalid")
    document = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "cluster", "cluster": {"server": _server(connection), "certificate-authority-data": connection.get("ca_data") or ""}}],
        "users": [{"name": "user", "user": user}],
        "contexts": [{"name": "workbench", "context": {"cluster": "cluster", "user": "user"}}],
        "current-context": "workbench",
    }
    path = directory / "kubeconfig"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    path.chmod(0o600)
    return path


def _run_binary(executable: str, arguments: list[str], directory: Path) -> dict:
    candidate = Path(executable)
    if not candidate.is_absolute() or ".." in candidate.parts or candidate.is_symlink() or not candidate.is_file():
        raise DomainError("Закреплённый файл сканера не найден", "scanner_unavailable")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(directory), "TMPDIR": str(directory), "LANG": "C"}
    process = subprocess.Popen(
        [str(candidate), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=directory,
        env=env,
    )
    try:
        stdout, _stderr = process.communicate(timeout=_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise DomainError("Сканер остановлен по таймауту", "timeout") from None
    if len(stdout) > _OUTPUT_LIMIT:
        raise DomainError("Ответ сканера слишком большой", "invalid_input")
    try:
        data = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise DomainError("Сканер не вернул поддерживаемый JSON", "malformed_report") from None
    if not isinstance(data, dict):
        raise DomainError("Сканер не вернул поддерживаемый JSON", "malformed_report")
    return data


def run_live_scanners(connection: dict, scope: dict, settings: Settings) -> ScanResult:
    result = ScanResult(
        versions={"origin": "live_scanner", "provenance_verified": False},
        limitations=["Живой запуск не устанавливает сборщик узлов и не скачивает бинарники."],
    )
    namespaces = list(scope["namespaces"])
    paths = _paths(settings)
    with tempfile.TemporaryDirectory(prefix="workbench-scanner-") as raw:
        directory = Path(raw)
        os.chmod(directory, 0o700)
        kubeconfig = materialize_kubeconfig(connection, directory)
        for scanner in ("trivy", "kubescape"):
            configured = paths[scanner]
            if not configured:
                result.coverage.append(_coverage(f"cli:{scanner}", "not_checked", "Закреплённый файл сканера не задан. Скачивание не выполняется."))
                continue
            try:
                data = _run_binary(configured, scanner_arguments(scanner, str(kubeconfig), namespaces), directory)
                parsed = parse_report(scanner, data)
            except DomainError as exc:
                result.coverage.append(_coverage(f"cli:{scanner}", "error", exc.message))
                continue
            result.findings.extend(parsed.findings)
            result.coverage.extend(parsed.coverage or [_coverage(f"cli:{scanner}", "completed", "Отчёт сканера разобран.")])
            result.limitations.extend(parsed.limitations)
        result.coverage.append(_coverage("cli:kube-bench", "not_checked", "Проверка узла входит в расширенное действие и здесь не запускается."))
    return result


def _items(payload) -> list:
    items = payload.get("items") if isinstance(payload, dict) else None
    return items if isinstance(items, list) else []


def run_extended(connection: dict, scope: dict, http) -> ScanResult:
    server = _server(connection)
    namespaces = [name for name in scope["namespaces"] if name not in SYSTEM_NAMESPACES]
    result = ScanResult(versions={"origin": "extended"}, limitations=["Временный под удаляется после проверки. Адрес пода не сохраняется."])
    try:
        nodes = http.get_action(f"{server}/api/v1/nodes?limit=50")
        ready = 0
        blocked = 0
        for item in _items(nodes):
            if not isinstance(item, dict):
                continue
            spec = item.get("spec") if isinstance(item.get("spec"), dict) else {}
            if spec.get("unschedulable") is True:
                blocked += 1
            conditions = item.get("status", {}).get("conditions", []) if isinstance(item.get("status"), dict) else []
            if any(isinstance(row, dict) and row.get("type") == "Ready" and row.get("status") == "True" for row in conditions):
                ready += 1
        result.coverage.append(_coverage("extended:nodes", "completed", f"Прочитаны узлы: готовы {ready}, недоступны для планирования {blocked}. Адреса узлов не сохранены."))
    except DomainError as exc:
        result.coverage.append(_coverage("extended:nodes", "error", exc.message))
    if not namespaces:
        result.coverage.append(_coverage("extended:probe", "not_checked", "Временный под не создаётся в системном пространстве имён."))
        return result
    namespace = namespaces[0]
    try:
        policies = http.get_action(f"{server}/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies?limit=50")
        result.coverage.append(_coverage("extended:network", "completed", f"Прочитано сетевых политик: {len(_items(policies))}."))
    except DomainError as exc:
        result.coverage.append(_coverage("extended:network", "error", exc.message))
    name = "amberscan-probe-" + secrets.token_hex(4)
    created = False
    try:
        body = probe_pod(namespace, name)
        http.post_json(f"{server}/api/v1/namespaces/{namespace}/pods", body)
        created = True
        viewed = http.get_action(f"{server}/api/v1/namespaces/{namespace}/pods/{name}")
        phase = viewed.get("status", {}).get("phase") if isinstance(viewed.get("status"), dict) else None
        addressed = bool(isinstance(viewed.get("status"), dict) and viewed["status"].get("podIP"))
        result.coverage.append(_coverage("extended:probe", "completed", f"Временный под создан, фаза {phase or 'неизвестна'}, адрес {'назначен' if addressed else 'не назначен'}."))
    except DomainError as exc:
        result.coverage.append(_coverage("extended:probe", "error", exc.message))
    finally:
        if created:
            try:
                http.delete_json(f"{server}/api/v1/namespaces/{namespace}/pods/{name}")
                result.coverage.append(_coverage("extended:cleanup", "completed", "Временный под удалён."))
            except DomainError:
                result.limitations.append("Временный под не удалён автоматически. Удалите объект amberscan-probe в выбранном пространстве имён.")
    return result


def _post_collection(kind: str) -> str:
    return {
        "ServiceAccount": "/api/v1/namespaces/{namespace}/serviceaccounts",
        "Role": "/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles",
        "RoleBinding": "/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/rolebindings",
        "Deployment": "/apis/apps/v1/namespaces/{namespace}/deployments",
    }[kind]


def install_operator(connection: dict, scope: dict, http, image: str | None) -> ScanResult:
    result = ScanResult(versions={"origin": "operator"}, limitations=["Оператор только читает API. Секреты и команды ему не разрешены."])
    if not image:
        result.coverage.append(_coverage("operator:image", "error", "Образ оператора не задан."))
        return result
    namespaces = [name for name in scope["namespaces"] if name not in SYSTEM_NAMESPACES]
    if not namespaces:
        result.coverage.append(_coverage("operator:namespace", "error", "В области нет пространства имён вне системных."))
        return result
    namespace = namespaces[0]
    server = _server(connection)
    for manifest in operator_manifests(namespace, image):
        path = _post_collection(manifest["kind"]).format(namespace=namespace)
        try:
            http.post_json(server + path, manifest)
            result.coverage.append(_coverage(f"operator:{manifest['kind']}", "completed", "Объект создан."))
        except DomainError as exc:
            if exc.code == "http_409":
                result.coverage.append(_coverage(f"operator:{manifest['kind']}", "completed", "Объект уже существует и не заменяется."))
            else:
                result.coverage.append(_coverage(f"operator:{manifest['kind']}", "error", exc.message))
    return result


def apply_remediation(connection: dict, http, finding: dict | None) -> ScanResult:
    result = ScanResult(versions={"origin": "remediate"}, limitations=["Исправляется только шаблон контроллера из одной встроенной находки."])
    if not finding:
        result.coverage.append(_coverage("remediate:finding", "error", "Находка не найдена."))
        return result
    try:
        patch = remediation_patch(finding)
    except DomainError as exc:
        result.coverage.append(_coverage("remediate:patch", "error", exc.message))
        return result
    namespace = finding.get("namespace")
    name = finding.get("resource_name")
    kind = finding.get("resource_kind")
    if not isinstance(namespace, str) or not isinstance(name, str) or kind not in CONTROLLER_KINDS:
        result.coverage.append(_coverage("remediate:target", "error", "Цель исправления недопустима."))
        return result
    server = _server(connection)
    url = f"{server}/apis/apps/v1/namespaces/{namespace}/{CONTROLLER_KINDS[kind]}/{name}"
    try:
        current = http.get_action(url)
        uid_value = current.get("metadata", {}).get("uid") if isinstance(current.get("metadata"), dict) else None
        if uid_value != finding.get("resource_uid"):
            raise DomainError("Объект изменился с момента находки", "conflict")
        http.patch_json(url, patch)
        result.coverage.append(_coverage("remediate:apply", "completed", "Шаблон контроллера обновлён."))
    except DomainError as exc:
        result.coverage.append(_coverage("remediate:apply", "error", exc.message))
    return result


def perform(source: str, connection: dict, scope: dict, http, settings: Settings, finding: dict | None = None) -> ScanResult:
    if source == "scanners":
        return run_live_scanners(connection, scope, settings)
    if source == "extended":
        return run_extended(connection, scope, http)
    if source == "operator":
        return install_operator(connection, scope, http, settings.operator_image)
    if source == "remediate":
        return apply_remediation(connection, http, finding)
    return scan_inventory(connection, scope, http, lambda: False)


def queue_confirmed_action(session, vault, settings: Settings, user: User, cluster: Cluster, action: str, finding_id: str | None = None) -> dict:
    """Queue a confirmed action. Mutating work runs later in the worker, not here."""
    if action not in {"live_scanner", "extended", "operator", "remediate"}:
        raise DomainError("Недопустимое действие", "invalid_input")
    if user.role not in {"administrator", "auditor", "security_lead"}:
        raise DomainError("Недостаточно прав приложения", "forbidden")
    if action == "operator" and not settings.operator_image:
        raise DomainError("Образ оператора не задан", "configuration_required")
    finding = None
    if action == "remediate":
        if not finding_id:
            raise DomainError("Выберите одну находку", "invalid_input")
        finding = session.get(Finding, finding_id)
        if finding is None or finding.cluster_id != cluster.id:
            raise DomainError("Находка не найдена", "not_found")
        remediation_patch(finding.data)
    cluster, _, _ = lock_authorization(session, cluster.id, user.id)
    if cluster.lifecycle != "ready":
        raise DomainError("Объект не найден", "not_found")
    if session.scalar(select(func.count(Run.id)).where(Run.cluster_id == cluster.id, Run.status.in_(ACTIVE_STATES))):
        raise DomainError("Для кластера уже есть активный запуск", "conflict")
    scope = {
        "namespaces": list(cluster.namespaces),
        "max_objects": 1000,
        "timeout_seconds": 300,
        "inventory_version": INVENTORY_VERSION,
    }
    credential = session.get(ClusterCredential, (user.id, cluster.id))
    if credential is None:
        raise DomainError("Требуется повторная личная авторизация", "authorization_required")
    connection = credential_for(session, vault, cluster, user, 30)
    source = {"live_scanner": "scanners", "extended": "extended", "operator": "operator", "remediate": "remediate"}[action]
    run_id = uid()
    sealed = {**connection, "scope": scope}
    session.add(
        Run(
            id=run_id,
            cluster_id=cluster.id,
            actor_id=user.id,
            scope=scope,
            credential=vault.encrypt(sealed, f"run:{run_id}"),
            credential_expires_at=credential.expires_at,
            source=source,
            **{key: sealed[key] for key in AUTH_FIELDS},
        )
    )
    if finding is not None:
        audit(session, user.username, "remediate_target", run_id, finding_id=finding.id)
    changes_cluster = action in {"extended", "operator", "remediate"}
    audit(session, user.username, "action_queued", run_id, requested=action, confirmed=True, changes_cluster=changes_cluster)
    detail = {
        "live_scanner": "Запуск сканеров поставлен в очередь. Кластер этим запуском не изменяется.",
        "extended": "Расширенная проверка поставлена в очередь. После подтверждения будет создан и удалён временный под.",
        "operator": "Установка оператора поставлена в очередь. В кластере появятся только фиксированные объекты чтения.",
        "remediate": "Исправление поставлено в очередь и изменит шаблон одного контроллера.",
    }[action]
    return {"status": "queued", "action": action, "run_id": run_id, "cluster_changed": False, "changes_cluster": changes_cluster, "detail": detail}


def load_remediation_target(session, run_id: str) -> dict | None:
    event = session.scalar(select(AuditEvent).where(AuditEvent.action == "remediate_target", AuditEvent.target == run_id))
    if event is None or not isinstance(event.detail, dict):
        return None
    finding = session.get(Finding, event.detail.get("finding_id"))
    if finding is None:
        return None
    return dict(finding.data)
