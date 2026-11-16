"""Authorization, observations, and presentation independent of HTTP."""

import hashlib
import json
from datetime import timedelta

from sqlalchemy import select

from workbench.configuration import lock_policy
from workbench.db import (
    AuthorizationBinding,
    Cluster,
    ClusterCredential,
    ClusterGrant,
    Finding,
    IntegrationPolicy,
    Observation,
    Run,
    User,
    aware,
    iso,
    now,
)
from workbench.domain import DomainError, ScanResult
from workbench.security import connection_headers

SCAN_ROLES = {"administrator", "auditor", "security_lead"}
REVIEW_ROLES = {"administrator", "security_lead"}
ACTIVE_STATES = {"queued", "running"}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def permitted_cluster(session, user: User, cluster_id: str) -> Cluster:
    cluster = session.get(Cluster, cluster_id)
    grant = user.role == "administrator" or session.get(ClusterGrant, (user.id, cluster_id))
    if not cluster or cluster.lifecycle != "ready" or not grant or not user.active:
        raise DomainError("Объект не найден", "not_found")
    return cluster


def clusters_for(session, user: User) -> list[Cluster]:
    query = select(Cluster).where(Cluster.lifecycle == "ready").order_by(Cluster.created_at.desc())
    if user.role != "administrator":
        query = query.join(ClusterGrant).where(ClusterGrant.user_id == user.id)
    return list(session.scalars(query))


AUTH_FIELDS = ("policy_revision", "auth_generation", "cluster_generation")


def lock_authorization(session, cluster_id: str, user_id: str, *, create_binding: bool = False) -> tuple:
    """Canonical policy -> cluster -> binding lock order.

    An absent policy is initialized deny-all, never imported from Settings. A binding
    survives revocation, including an already-consumed run snapshot.
    Callers release locks before outbound I/O and reacquire/recheck afterwards.
    """
    policy = lock_policy(session)
    cluster = session.scalar(select(Cluster).where(Cluster.id == cluster_id).with_for_update().execution_options(populate_existing=True))
    if not cluster:
        raise DomainError("Объект не найден", "not_found")
    if not policy or policy.revision <= 0 or cluster.auth_type != "kubeconfig":
        raise DomainError("Администратор должен настроить сетевую политику", "configuration_required")
    binding = session.scalar(select(AuthorizationBinding).where(AuthorizationBinding.user_id == user_id, AuthorizationBinding.cluster_id == cluster_id).with_for_update().execution_options(populate_existing=True))
    if binding is None:
        if not create_binding:
            raise DomainError("Требуется повторная личная авторизация", "authorization_required")
        binding = AuthorizationBinding(user_id=user_id, cluster_id=cluster_id, generation=0)
        session.add(binding)
        session.flush()
    return cluster, policy, binding


def authorization_values(cluster, policy, binding) -> dict:
    if cluster.auth_type != "kubeconfig":
        raise DomainError("Настройки авторизации недействительны", "configuration_required")
    return {
        "policy_revision": policy.revision,
        "auth_generation": binding.generation,
        "cluster_generation": cluster.auth_generation,
    }


def authorization_current(session, cluster: Cluster, user_id: str, record) -> bool:
    """Pure DB check shared by credentials and immutable run leases."""
    policy = session.get(IntegrationPolicy, 1)
    binding = session.get(AuthorizationBinding, (user_id, cluster.id))
    if not policy or policy.revision <= 0 or cluster.auth_type != "kubeconfig" or not binding:
        return False
    current = authorization_values(cluster, policy, binding)
    return all(getattr(record, field) == value for field, value in current.items())


def credential_valid(session, cluster, user, credential, session_hash=None, minimum_seconds=0) -> bool:
    return bool(
        credential
        and user.active
        and user.role in SCAN_ROLES
        and aware(credential.expires_at) > now() + timedelta(seconds=minimum_seconds)
        and (
            (credential.storage_mode in {"persistent", "days_30"} and credential.session_hash is None)
            or (credential.storage_mode == "run_only" and session_hash is not None and credential.session_hash == session_hash)
        )
        and authorization_current(session, cluster, user.id, credential)
    )


def cluster_view(session, cluster: Cluster, user: User, session_hash: str | None = None) -> dict:
    credential = session.get(ClusterCredential, (user.id, cluster.id))
    valid = credential_valid(session, cluster, user, credential, session_hash)
    return {
        "id": cluster.id,
        "name": cluster.name,
        "environment": cluster.environment,
        "context": cluster.context,
        "server": cluster.server,
        "auth_type": cluster.auth_type,
        "namespaces": cluster.namespaces,
        "lifecycle": cluster.lifecycle,
        "access_revision": cluster.auth_generation,
        "namespace_hint": cluster.context_namespace_hint if user.role == "administrator" or cluster.context_namespace_hint in cluster.namespaces else None,
        "draft_expires_at": iso(cluster.draft_expires_at),
        "status": "authorized" if valid else "authorization_required",
        "created_at": iso(cluster.created_at),
        "credential_expires_at": iso(credential.expires_at) if valid else None,
        "storage_mode": credential.storage_mode if valid else None,
    }


def credential_for(session, vault, cluster: Cluster, user: User, minimum_seconds: int = 0, *, session_hash: str | None = None) -> dict:
    credential = session.get(ClusterCredential, (user.id, cluster.id))
    if not credential_valid(session, cluster, user, credential, session_hash, minimum_seconds):
        raise DomainError("Требуется повторная личная авторизация", "authorization_required")
    data = vault.decrypt(credential.encrypted, f"credential:{user.id}:{cluster.id}")
    connection = {
        "server": cluster.server,
        "ca_data": cluster.ca_data,
        "auth_type": cluster.auth_type,
        "auth": data,
        "expires_at": iso(credential.expires_at),
        **{field: getattr(credential, field) for field in AUTH_FIELDS},
    }
    connection_headers(connection)  # Fail closed before sealing malformed credentials.
    return connection


def run_view(session, run: Run, details: bool = False) -> dict:
    cluster = session.get(Cluster, run.cluster_id)
    result = {
        "id": run.id,
        "cluster_id": run.cluster_id,
        "cluster_name": cluster.name if cluster else "",
        "status": run.status,
        "stage": run.stage,
        "scope": run.scope,
        "created_at": iso(run.created_at),
        "started_at": iso(run.started_at),
        "finished_at": iso(run.finished_at),
        "error": run.error,
        "cancel_requested": run.cancel_requested,
        "coverage": run.coverage,
        "limitations": run.limitations,
        "versions": run.versions,
        "source": run.source,
    }
    if details:
        rows = session.execute(
            select(Observation, Finding)
            .join(Finding, Observation.finding_id == Finding.id)
            .where(Observation.run_id == run.id)
        )
        result["findings"] = [
            {
                **observation.data,
                "id": finding.id,
                "run_id": run.id,
                "cluster_id": run.cluster_id,
                "disposition": finding.disposition,
                "first_seen": iso(finding.first_seen),
                "last_seen": iso(finding.last_seen),
            }
            for observation, finding in rows
        ]
    return result


def finding_view(session, finding: Finding) -> dict:
    cluster = session.get(Cluster, finding.cluster_id)
    return {
        **finding.data,
        "id": finding.id,
        "cluster_id": finding.cluster_id,
        "cluster_name": cluster.name if cluster else "",
        "run_id": finding.latest_run_id,
        "first_seen": iso(finding.first_seen),
        "last_seen": iso(finding.last_seen),
        "disposition": finding.disposition,
    }


def fingerprint(cluster_id: str, data: dict, source: str) -> str:
    package = data.get("package", {})
    package_identity = (
        [package.get("name"), package.get("installed_version")]
        if isinstance(package, dict)
        else package
    )
    identity = [
        cluster_id,
        source,
        data.get("scanner"),
        data.get("rule_id"),
        data.get("vulnerability_id"),
        data.get("namespace"),
        data.get("resource_kind"),
        data.get("resource_uid") or data.get("resource_name"),
        data.get("image_digest"),
        package_identity,
        data.get("location"),
    ]
    return digest(json.dumps(identity, sort_keys=True, ensure_ascii=True))


def save_result(session, run: Run, result: ScanResult) -> None:
    seen: set[str] = set()
    for data in result.findings:
        key = fingerprint(run.cluster_id, data, run.source)
        if key in seen:
            continue
        seen.add(key)
        finding = session.scalar(select(Finding).where(Finding.fingerprint == key))
        if finding is None:
            finding = Finding(
                cluster_id=run.cluster_id,
                fingerprint=key,
                data=data,
                latest_run_id=run.id,
            )
            session.add(finding)
            session.flush()
        else:
            finding.last_seen = now()
            finding.latest_run_id = run.id
            finding.data = data
        session.add(Observation(run_id=run.id, finding_id=finding.id, data=data))
    run.coverage = result.coverage
    run.limitations = result.limitations
    run.versions = result.versions
    run.status = (
        "completed"
        if result.coverage
        and all(item.get("status") == "completed" for item in result.coverage)
        and not result.limitations
        else "partial"
    )
    run.stage = "cleanup"
    run.finished_at = now()
    run.credential = None
    run.lease_until = None
