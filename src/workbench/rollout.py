"""Read-only rollout: 30-day credentials, local retention, explicit schedules.

Nothing in this module opens a Kubernetes connection or sends a write.
Cluster-changing actions are recorded and refused.
"""

import re
from datetime import timedelta

from sqlalchemy import delete, func, select

from workbench.db import (
    AuditEvent,
    Cluster,
    ClusterCredential,
    Finding,
    Observation,
    Run,
    User,
    audit,
    aware,
    now,
    uid,
)
from workbench.domain import DomainError, ScanResult
from workbench.namespaces import INVENTORY_VERSION, validate_run_scope
from workbench.services import (
    ACTIVE_STATES,
    AUTH_FIELDS,
    SCAN_ROLES,
    credential_for,
    credential_valid,
    lock_authorization,
    save_result,
)

REUSABLE_MODES = frozenset({"persistent", "days_30"})
TERMINAL_RUNS = frozenset({"completed", "partial", "failed", "cancelled", "interrupted"})
SCHEDULE_ACTION = "read_only_schedule"
PROTECTED_ACTIONS = frozenset({"live_scanner", "extended", "operator", "remediate"})
PERIODIC_INTERVAL = timedelta(hours=24)
WATCH_INTERVAL = timedelta(hours=6)
RUNTIME_SOURCES = frozenset({"falco", "tetragon"})
_RULE = re.compile(r"[A-Za-z0-9_.:-]{1,80}")
_NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PRIORITY = {
    "emergency": "high",
    "alert": "high",
    "critical": "high",
    "error": "high",
    "warning": "medium",
    "notice": "medium",
    "info": "low",
    "debug": "low",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def storage_deadline(storage_mode: str, *, session_expires_at, source_expires_at):
    """Explicit retention of a personal credential. Never extends an existing row."""
    if storage_mode not in {"run_only", "persistent", "days_30"}:
        raise DomainError("Недопустимый режим хранения", "invalid_input")
    current = now()
    expiry = current + {
        "run_only": timedelta(hours=1),
        "persistent": timedelta(hours=24),
        "days_30": timedelta(days=30),
    }[storage_mode]
    if storage_mode == "run_only":
        expiry = min(expiry, aware(session_expires_at))
    if source_expires_at is not None:
        expiry = min(expiry, aware(source_expires_at))
    if expiry <= current:
        raise DomainError(
            "Срок личной авторизации истёк; импортируйте kubeconfig снова",
            "authorization_required",
        )
    return expiry


def reusable_credential(credential) -> bool:
    return bool(
        credential
        and credential.storage_mode in REUSABLE_MODES
        and credential.session_hash is None
    )


def retention_cutoff(retention_days: int):
    """Never delete fresher than 90 days, even if configuration asks for less."""
    days = retention_days if retention_days >= 90 else 90
    return now() - timedelta(days=days)


def purge_expired_results(session, *, retention_days: int = 90) -> int:
    """Delete local run results only. Audit, credentials and the cluster stay."""
    cutoff = retention_cutoff(retention_days)
    runs = list(
        session.scalars(
            select(Run).where(
                Run.finished_at.is_not(None),
                Run.finished_at < cutoff,
                Run.status.in_(TERMINAL_RUNS),
            )
        )
    )
    removed = 0
    for run in runs:
        findings = list(
            session.scalars(select(Finding).where(Finding.latest_run_id == run.id))
        )
        if any(aware(finding.last_seen) >= cutoff for finding in findings):
            continue
        finding_ids = [finding.id for finding in findings]
        if finding_ids:
            session.execute(delete(Observation).where(Observation.finding_id.in_(finding_ids)))
            session.execute(delete(Finding).where(Finding.id.in_(finding_ids)))
        session.execute(delete(Observation).where(Observation.run_id == run.id))
        session.delete(run)
        removed += 1
    return removed


def _namespaces(cluster: Cluster) -> list[str]:
    names = list(cluster.namespaces or [])
    if not names or not set(names) <= set(cluster.namespaces or []):
        raise DomainError("Сохранённая область пуста", "invalid_scope")
    return names


def record_schedule(session, user: User, cluster: Cluster, kind: str) -> dict:
    """Opt in to repeating the saved scope. Does not contact the cluster."""
    if user.role not in SCAN_ROLES:
        raise DomainError("Недостаточно прав приложения", "forbidden")
    if kind not in {"periodic", "watch", "off"}:
        raise DomainError("Недопустимый вид расписания", "invalid_input")
    if cluster.lifecycle != "ready":
        raise DomainError("Объект не найден", "not_found")
    namespaces: list[str] = []
    if kind != "off":
        namespaces = _namespaces(cluster)
        credential = session.get(ClusterCredential, (user.id, cluster.id))
        if (
            not credential_valid(session, cluster, user, credential, minimum_seconds=60)
            or not credential
            or credential.storage_mode != "days_30"
        ):
            raise DomainError(
                "Для расписания сохраните личную авторизацию на 30 дней.",
                "credential_required",
            )
    audit(
        session,
        user.username,
        SCHEDULE_ACTION,
        cluster.id,
        enabled=kind != "off",
        kind=kind if kind != "off" else "off",
        namespaces=namespaces,
        user_id=user.id,
        confirmed=True,
    )
    return {"enabled": kind != "off", "kind": kind, "namespaces": namespaces, "cluster_changed": False}


def latest_schedules(session) -> list[AuditEvent]:
    latest: dict[str, AuditEvent] = {}
    events = session.scalars(
        select(AuditEvent)
        .where(AuditEvent.action == SCHEDULE_ACTION)
        .order_by(AuditEvent.created_at, AuditEvent.id)
    )
    for event in events:
        latest[event.target] = event
    return [event for event in latest.values() if event.detail.get("enabled") is True]


def enqueue_due_schedules(session, vault, settings) -> int:
    """Queue a GET-only inventory run. One-shot credentials are never consumed."""
    queued = 0
    active_total = session.scalar(select(func.count(Run.id)).where(Run.status.in_(ACTIVE_STATES))) or 0
    for event in latest_schedules(session):
        if active_total >= settings.max_queued_runs:
            break
        detail = event.detail if isinstance(event.detail, dict) else {}
        kind = detail.get("kind")
        user_id = detail.get("user_id")
        if kind not in {"periodic", "watch"} or not isinstance(user_id, str):
            continue
        interval = PERIODIC_INTERVAL if kind == "periodic" else WATCH_INTERVAL
        try:
            user = session.get(User, user_id)
            if not user or not user.active or user.role not in SCAN_ROLES:
                continue
            cluster, _, _ = lock_authorization(session, event.target, user.id)
            if cluster.lifecycle != "ready":
                continue
            names = detail.get("namespaces")
            if not isinstance(names, list) or not names or not set(names) <= set(cluster.namespaces or []):
                continue
            credential = session.get(ClusterCredential, (user.id, cluster.id))
            if not credential or credential.storage_mode != "days_30":
                continue
            if not credential_valid(session, cluster, user, credential, minimum_seconds=60):
                continue
            recent = session.scalar(
                select(Run.created_at)
                .where(Run.cluster_id == cluster.id)
                .order_by(Run.created_at.desc())
                .limit(1)
            )
            if recent is not None and aware(recent) + interval > now():
                continue
            if session.scalar(
                select(func.count(Run.id)).where(
                    Run.cluster_id == cluster.id, Run.status.in_(ACTIVE_STATES)
                )
            ):
                continue
            scope = validate_run_scope(
                {
                    "namespaces": list(names),
                    "max_objects": 1000,
                    "timeout_seconds": 300,
                    "inventory_version": INVENTORY_VERSION,
                },
                cluster.namespaces,
            )
            connection = credential_for(session, vault, cluster, user, 60)
            run_id = uid()
            sealed = {**connection, "scope": {**scope, "namespaces": list(scope["namespaces"])}}
            session.add(
                Run(
                    id=run_id,
                    cluster_id=cluster.id,
                    actor_id=user.id,
                    scope=scope,
                    credential=vault.encrypt(sealed, f"run:{run_id}"),
                    credential_expires_at=credential.expires_at,
                    source=f"schedule:{kind}",
                    **{key: sealed[key] for key in AUTH_FIELDS},
                )
            )
            audit(session, "worker", "schedule_queued", run_id, cluster_id=cluster.id, kind=kind)
            queued += 1
            active_total += 1
        except DomainError:
            continue
    return queued


def refuse_cluster_change(session, user: User, cluster: Cluster, action: str) -> dict:
    """Record an explicit confirmation and do not send it to the cluster."""
    if action not in PROTECTED_ACTIONS:
        raise DomainError("Недопустимое действие", "invalid_input")
    if user.role not in SCAN_ROLES:
        raise DomainError("Недостаточно прав приложения", "forbidden")
    audit(
        session,
        user.username,
        "cluster_change_refused",
        cluster.id,
        requested=action,
        confirmed=True,
        cluster_changed=False,
    )
    return {
        "status": "not_applied",
        "action": action,
        "cluster_changed": False,
        "detail": "Подтверждение записано. Кластер не изменён: запрос не отправлен.",
    }


def parse_runtime_report(source: str, data: dict) -> ScanResult:
    """Keep rule, priority and namespace. Drop command lines, output and manifests."""
    if source not in RUNTIME_SOURCES:
        raise DomainError("Этот источник среды выполнения не поддерживается.", "unsupported_scanner")
    if not isinstance(data, dict) or set(data) != {"events"} or not isinstance(data.get("events"), list):
        raise DomainError(
            "Отчёт среды выполнения может содержать только список events.",
            "malformed_report",
        )
    events = data["events"]
    if not events or len(events) > 100:
        raise DomainError("В отчёте должно быть от 1 до 100 событий.", "malformed_report")
    result = ScanResult(
        versions={"origin": "imported", "runtime": source, "provenance_verified": False},
        limitations=[
            "Импорт не подтверждает, что события получены из этого кластера.",
            "Текст команд, вывод и манифесты не сохраняются.",
            "Агент Falco или Tetragon этим импортом не устанавливается.",
        ],
        coverage=[
            {
                "check": "runtime:provenance",
                "status": "not_checked",
                "detail": "Происхождение импорта не проверено.",
            }
        ],
    )
    allowed = {"rule", "priority", "namespace"}
    for event in events:
        if not isinstance(event, dict) or set(event) - allowed or "rule" not in event:
            raise DomainError(
                "В событии допускаются только rule, priority и namespace.",
                "malformed_report",
            )
        rule = event["rule"]
        if not isinstance(rule, str) or not _RULE.fullmatch(rule):
            raise DomainError("Идентификатор правила недопустим.", "malformed_report")
        priority = event.get("priority")
        severity = "unknown"
        if priority is not None:
            if not isinstance(priority, str) or priority.casefold() not in _PRIORITY:
                raise DomainError("Недопустимый priority.", "malformed_report")
            severity = _PRIORITY[priority.casefold()]
        namespace = event.get("namespace") or ""
        if namespace and not _NAMESPACE.fullmatch(namespace):
            raise DomainError("Недопустимое пространство имён в событии.", "malformed_report")
        evidence = {}
        if isinstance(priority, str):
            evidence["priority"] = priority.casefold()
        result.findings.append(
            {
                "title": "Событие среды выполнения",
                "rule_id": rule,
                "scanner": source,
                "severity": severity,
                "confidence": "low",
                "namespace": namespace,
                "category": "runtime",
                "recommendation": "Сверьте идентификатор правила с журналом среды выполнения. Импорт не доказывает источник.",
                "evidence": evidence,
            }
        )
    return result
