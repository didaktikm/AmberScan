"""Administrator-owned integration configuration, revisions and outbound policy.

Passive reads and saves are offline. Only explicit probes and transport methods
perform DNS/HTTPS. Legacy file settings never silently override database state.
"""

import copy
import ipaddress
import re

from sqlalchemy import delete, select

from workbench.config import Settings
from workbench.db import (
    AuthorizationBinding,
    Cluster,
    ClusterCredential,
    IntegrationPolicy,
    Run,
    audit,
    now,
)
from workbench.domain import DomainError
from workbench.security import (
    PinnedHTTP,
    Vault,
    _canonical_host,
    _https_parts,
    _intrinsically_denied,
    validate_endpoint,
)

PURPOSES = {"kubernetes", "registry", "database"}

def _invalid(message: str = "Проверьте поля настройки") -> DomainError:
    return DomainError(message, "invalid_input")


def _label(value, maximum: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not value and not empty):
        raise _invalid()
    if value != value.strip() or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise _invalid()
    return value


def _slug(value) -> str:
    value = _label(value, 100)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", value):
        raise _invalid("ID должен содержать только буквы, цифры, дефис и подчёркивание")
    return value


def _expected(payload: dict, revision: int) -> None:
    if type(payload.get("expected_revision")) is not int:
        raise _invalid("Укажите expected_revision")
    if payload["expected_revision"] != revision:
        raise DomainError(
            "Настройка уже изменена. Обновите данные и повторите действие", "conflict"
        )


def lock_policy(session) -> IntegrationPolicy:
    """Create the singleton atomically; lock it before cluster/auth rows."""
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise DomainError("Unsupported configuration storage", "configuration_required")
    session.execute(
        insert(IntegrationPolicy)
        .values(id=1, revision=0, rules=[], legacy_imported=False, updated_at=now())
        .on_conflict_do_nothing(index_elements=["id"])
    )
    return session.scalar(
        select(IntegrationPolicy)
        .where(IntegrationPolicy.id == 1)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def policy_view(session) -> dict:
    policy = session.get(IntegrationPolicy, 1)
    return {
        "revision": policy.revision if policy else 0,
        "rules": copy.deepcopy(policy.rules) if policy else [],
        "legacy_imported": policy.legacy_imported if policy else False,
    }


def validate_rules(rules: object, *, allowed_purposes: set[str] | None = None) -> list[dict]:
    """Only pure syntax checks here; runtime validates every resolved address."""
    if not isinstance(rules, list) or len(rules) > 128:
        raise _invalid("Допускается не более 128 правил egress")
    normalized, ids, endpoints = [], set(), set()
    try:
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {
                "id",
                "purpose",
                "host",
                "port",
                "cidrs",
            }:
                raise _invalid(
                    "Правило должно содержать id, purpose, host, port, cidrs"
                )
            identifier = _slug(rule["id"])
            purpose = rule["purpose"]
            if (
                purpose not in (PURPOSES if allowed_purposes is None else allowed_purposes)
                or type(rule["port"]) is not int
                or not 1 <= rule["port"] <= 65535
            ):
                raise _invalid()
            host = _canonical_host(rule["host"])
            if (
                host == "localhost"
                or host.endswith(".localhost")
                or host in {"metadata.google.internal", "metadata.goog"}
            ):
                raise _invalid("Служебное назначение запрещено")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and _intrinsically_denied(address):
                raise _invalid("Служебное назначение запрещено")
            if not isinstance(rule["cidrs"], list) or not 1 <= len(rule["cidrs"]) <= 64:
                raise _invalid("Укажите от 1 до 64 явных CIDR")
            networks = []
            for raw in rule["cidrs"]:
                if not isinstance(raw, str) or "/" not in raw:
                    raise _invalid("Требуется явный CIDR")
                network = ipaddress.ip_network(raw, strict=True)
                if _intrinsically_denied(network.network_address):
                    raise _invalid("CIDR содержит недопустимое сетевое назначение")
                networks.append(str(network))
            if len(networks) != len(set(networks)):
                raise _invalid("Повторяющиеся CIDR")
            endpoint = (purpose, host, rule["port"])
            if identifier in ids or endpoint in endpoints:
                raise _invalid("Повторяющиеся ID или назначения egress")
            ids.add(identifier)
            endpoints.add(endpoint)
            normalized.append(
                {
                    "id": identifier,
                    "purpose": purpose,
                    "host": host,
                    "port": rule["port"],
                    "cidrs": sorted(networks),
                }
            )
    except (ValueError, TypeError, UnicodeError, KeyError):
        raise _invalid("Недопустимый hostname, порт или CIDR") from None
    return normalized


def _apply_ceiling(rules: list[dict], ceiling: list[dict] | None) -> None:
    if ceiling is None:
        return
    ceiling = validate_rules(ceiling)
    for rule in rules:
        matches = [
            bound
            for bound in ceiling
            if all(bound[key] == rule[key] for key in ("purpose", "host", "port"))
        ]
        networks = [
            ipaddress.ip_network(cidr) for bound in matches for cidr in bound["cidrs"]
        ]
        for cidr in rule["cidrs"]:
            network = ipaddress.ip_network(cidr)
            if not any(
                network.version == bound.version
                and network.prefixlen >= bound.prefixlen
                and int(network.network_address) >= int(bound.network_address)
                and int(network.broadcast_address) <= int(bound.broadcast_address)
                for bound in networks
            ):
                raise DomainError(
                    "Правило выходит за ограничения deployment egress_ceiling",
                    "forbidden",
                )


def invalidate_access(
    session,
    cluster_id: str | None = None,
    user_id: str | None = None,
    reason: str = "Настройки доступа изменены",
) -> None:
    """Callers lock policy first. Revoke generations survive token removal."""
    query = select(Cluster).order_by(Cluster.id)
    if cluster_id:
        query = query.where(Cluster.id == cluster_id)
    clusters = list(
        session.scalars(
            query.with_for_update().execution_options(populate_existing=True)
        )
    )
    for cluster in clusters:
        if user_id:
            binding = session.scalar(
                select(AuthorizationBinding)
                .where(
                    AuthorizationBinding.cluster_id == cluster.id,
                    AuthorizationBinding.user_id == user_id,
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if not binding:
                binding = AuthorizationBinding(
                    cluster_id=cluster.id, user_id=user_id, generation=0
                )
                session.add(binding)
            binding.generation += 1
        else:
            cluster.auth_generation += 1
        credentials = delete(ClusterCredential).where(
            ClusterCredential.cluster_id == cluster.id
        )
        runs = select(Run).where(
            Run.cluster_id == cluster.id, Run.status.in_(["queued", "running"])
        )
        if user_id:
            credentials = credentials.where(ClusterCredential.user_id == user_id)
            runs = runs.where(Run.actor_id == user_id)
        session.execute(credentials)
        for run in session.scalars(
            runs.order_by(Run.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ):
            run.cancel_requested, run.credential = True, None
            if run.status == "queued":
                run.status, run.stage, run.finished_at = "cancelled", "cleanup", now()
                run.error = reason


def save_policy(session, payload: dict, settings: Settings, actor: str) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"expected_revision", "rules"}:
        raise _invalid()
    rules = validate_rules(payload["rules"])
    _apply_ceiling(rules, settings.egress_ceiling)
    policy = lock_policy(session)
    _expected(payload, policy.revision)
    invalidate_access(session)
    policy.rules, policy.revision, policy.updated_at = rules, policy.revision + 1, now()
    session.flush()
    audit(
        session,
        actor,
        "egress_policy_saved",
        "integration_policy",
        revision=policy.revision,
        rules=len(rules),
    )
    return policy_view(session)


class PolicyHTTP:
    """Enforce host/port/purpose-specific CIDRs on every request, not their union."""

    def __init__(
        self,
        rules: list[dict],
        purpose: str,
        ca_data: str | None = None,
        *,
        client_identity: dict | None = None,
    ):
        if purpose not in PURPOSES:
            raise DomainError("Неизвестное назначение исходящего подключения", "configuration_required")
        if client_identity is not None and purpose != "kubernetes":
            raise DomainError(
                "Клиентские сертификаты допускаются только для Kubernetes.",
                "credential_invalid",
            )
        self.client_identity = copy.deepcopy(client_identity)
        self.rules = [
            rule for rule in validate_rules(rules) if rule["purpose"] == purpose
        ]
        self.ca_data = ca_data
        self.allowed_hosts = tuple(sorted({rule["host"] for rule in self.rules}))
        self.allowed_cidrs = tuple(
            sorted({cidr for rule in self.rules for cidr in rule["cidrs"]})
        )

    def _transport(self, url: str, *, allow_query: bool = False):
        _, host, port = _https_parts(url, allow_query=allow_query)
        matches = [
            rule for rule in self.rules if rule["host"] == host and rule["port"] == port
        ]
        if len(matches) != 1:
            raise DomainError(
                "Назначение или порт не разрешены для этой интеграции",
                "endpoint_denied",
            )
        rule = matches[0]
        options = (
            {"client_identity": self.client_identity}
            if self.client_identity is not None
            else {}
        )
        return PinnedHTTP(rule["cidrs"], [host], self.ca_data, **options), rule

    def validate_endpoint(self, url: str) -> list[str]:
        _, rule = self._transport(url)
        return validate_endpoint(url, rule["cidrs"], [rule["host"]])

    def get_json(self, url: str, headers=None) -> dict:
        transport, _ = self._transport(url, allow_query=True)
        return transport.get_json(url, headers=headers)

    def post_form(self, url: str, data: dict, headers=None) -> dict:
        transport, _ = self._transport(url)
        return transport.post_form(url, data, headers=headers)

    def post_json(self, url: str, data: dict, headers=None) -> dict:
        transport, _ = self._transport(url)
        return transport.post_json(url, data, headers=headers)


def policy_http(
    session,
    settings: Settings,
    purpose: str,
    ca_data: str | None = None,
    *,
    client_identity: dict | None = None,
) -> PolicyHTTP:
    rules = policy_view(session)["rules"]
    _apply_ceiling(rules, settings.egress_ceiling)
    options = (
        {"client_identity": client_identity} if client_identity is not None else {}
    )
    return PolicyHTTP(rules, purpose, ca_data, **options)


def import_legacy_configuration(
    session, settings: Settings, vault: Vault, apply: bool = False
) -> dict:
    """Explicit one-time import; existing database settings are never merged silently."""
    policy = policy_view(session)
    preview = {
        "allowed_hosts": len(settings.allowed_hosts),
        "already_imported": policy["legacy_imported"],
        "applied": False,
        "warning": "Проверьте адреса и порты перед применением. Старые учётные данные требуют повторной авторизации.",
    }
    if not apply:
        return preview
    current_policy = lock_policy(session)
    if current_policy.legacy_imported:
        preview["already_imported"] = True
        return preview
    if current_policy.revision != 0:
        raise DomainError(
            "Настройки в базе уже существуют; автоматическое объединение запрещено",
            "conflict",
        )
    allowed = {_canonical_host(host) for host in settings.allowed_hosts}
    destinations = set()
    for cluster in session.scalars(select(Cluster)):
        _, host, port = _https_parts(cluster.server)
        if host not in allowed:
            raise _invalid("Прежний адрес API отсутствует в явном списке разрешённых узлов")
        destinations.add(("kubernetes", host, port))
    rules = [
        {
            "id": f"legacy-{index + 1}",
            "purpose": purpose,
            "host": host,
            "port": port,
            "cidrs": list(settings.allowed_cidrs),
        }
        for index, (purpose, host, port) in enumerate(sorted(destinations))
    ]
    save_policy(
        session, {"expected_revision": 0, "rules": rules}, settings, "offline-admin"
    )
    session.get(IntegrationPolicy, 1).legacy_imported = True
    audit(
        session,
        "offline-admin",
        "legacy_configuration_imported",
        "integration_policy",
    )
    preview["applied"] = True
    return preview
