"""Private connection drafts and short-lived, exact-credential probe fences."""

import json
import re
from datetime import datetime, timedelta
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import delete, func, select

from workbench.admin_routes import REAUTH_WINDOW
from workbench.db import (
    Cluster,
    ClusterCredential,
    User,
    WebSession,
    audit,
    aware,
    iso,
    now,
    uid,
)
from workbench.domain import DomainError
from workbench.namespaces import validate_inventory_url, validate_namespaces
from workbench.scanners import RESOURCES
from workbench.security import (
    connection_headers,
    connection_tls,
    extract_kubeconfig_credentials,
    validate_connection_metadata,
)
from workbench.services import (
    AUTH_FIELDS,
    SCAN_ROLES,
    authorization_values,
    credential_for,
    digest,
    lock_authorization,
    permitted_cluster,
)

DRAFT_TTL = timedelta(hours=24)
MAX_OWNED_DRAFTS = 10


def cleanup_expired_drafts(session, cutoff=None) -> int:
    """Delete expired drafts atomically; never delete a concurrently finalized row.

    No policy locks or commit: worker recovery can call this inside its transaction.
    Credentials and bindings disappear through FK cascades.
    """
    cutoff = cutoff or now()
    ids = list(session.scalars(
        select(Cluster.id)
        .where(Cluster.lifecycle == "draft", Cluster.draft_expires_at <= cutoff)
        .order_by(Cluster.id)
        .limit(100)
        .with_for_update(skip_locked=True)
    ))
    if not ids:
        return 0
    deleted = session.scalars(
        delete(Cluster)
        .where(Cluster.id.in_(ids), Cluster.lifecycle == "draft", Cluster.draft_expires_at <= cutoff)
        .returning(Cluster.id)
        .execution_options(synchronize_session=False)
    )
    return len(list(deleted))


def owned_draft(session, user, cluster_id: str) -> Cluster:
    cluster = session.get(Cluster, cluster_id)
    if (
        not cluster
        or cluster.lifecycle != "draft"
        or not user.active
        or user.role != "administrator"
        or cluster.draft_owner_id != user.id
        or cluster.draft_expires_at is None
        or aware(cluster.draft_expires_at) <= now()
    ):
        raise DomainError("Объект не найден", "not_found")
    return cluster


def permitted_connection(session, user, cluster_id: str) -> Cluster:
    """Ordinary cluster permission plus an explicit owner-only draft exception."""
    cluster = session.get(Cluster, cluster_id)
    if cluster is not None and cluster.lifecycle == "draft":
        return owned_draft(session, user, cluster_id)
    return permitted_cluster(session, user, cluster_id)


def create_draft(session, user, *, name, environment, connection, auth_type="kubeconfig", extracted=None) -> Cluster:
    if user.role != "administrator" or not user.active:
        raise DomainError("Недостаточно прав приложения", "forbidden")
    if auth_type != "kubeconfig" or connection["kind"] != "kubeconfig":
        raise DomainError("Требуется kubeconfig со встроенным токеном или клиентским сертификатом", "invalid_input")
    extracted = extracted or extract_kubeconfig_credentials(connection["content"], connection["context"])
    metadata = extracted["metadata"]
    # Pure metadata validation: never DNS, kubeconfig commands, tokens or HTTP here.
    validate_connection_metadata(metadata["server"], metadata.get("ca_data"))
    owner = session.scalar(select(User).where(User.id == user.id).with_for_update(key_share=True).execution_options(populate_existing=True))
    if owner is None or not owner.active or owner.role != "administrator":
        raise DomainError("Недостаточно прав приложения", "forbidden")
    cleanup_expired_drafts(session)
    count = session.scalar(select(func.count(Cluster.id)).where(Cluster.lifecycle == "draft", Cluster.draft_owner_id == user.id, Cluster.draft_expires_at > now()))
    if count >= MAX_OWNED_DRAFTS:
        raise DomainError("Удалите или завершите существующие черновики", "rate_limited")
    cluster = Cluster(
        id=uid(), name=name, environment=environment, context=connection["context"],
        server=metadata["server"], ca_data=metadata.get("ca_data"),
        auth_type=auth_type, namespaces=[], lifecycle="draft",
        draft_owner_id=user.id, draft_expires_at=now() + DRAFT_TTL,
        context_namespace_hint=metadata.get("namespace_hint"),
    )
    session.add(cluster)
    audit(session, user.username, "cluster_draft_created", cluster.id)
    session.flush()
    return cluster


def store_kubeconfig_credential(session, vault, user, web_session, cluster, extracted, storage_mode, revisions):
    """Store selected normalized auth only; caller owns locks and atomic commit."""
    if storage_mode not in {"run_only", "persistent"}:
        raise DomainError("Недопустимый режим хранения", "invalid_input")
    expiry = now() + timedelta(hours=1 if storage_mode == "run_only" else 24)
    if storage_mode == "run_only":
        expiry = min(expiry, aware(web_session.expires_at))
    if extracted["source_expires_at"] is not None:
        expiry = min(expiry, aware(extracted["source_expires_at"]))
    if expiry <= now():
        raise DomainError("Срок личной авторизации истёк; импортируйте kubeconfig снова", "authorization_required")
    connection_headers({"auth_type": "kubeconfig", "auth": extracted["auth"]})
    session.add(ClusterCredential(
        user_id=user.id, cluster_id=cluster.id,
        encrypted=vault.encrypt(extracted["auth"], f"credential:{user.id}:{cluster.id}"),
        expires_at=expiry, storage_mode=storage_mode,
        session_hash=web_session.token_hash if storage_mode == "run_only" else None,
        **revisions,
    ))
    session.flush()


def _credential_fingerprint(credential) -> str:
    # Ciphertext changes even for same-token replacement; all credential metadata
    # participates so expiry/storage/session edits cannot inherit a completed probe.
    return digest(json.dumps({
        "encrypted": credential.encrypted,
        "expires_at": iso(credential.expires_at),
        "storage_mode": credential.storage_mode,
        "session_hash": credential.session_hash,
        **{field: getattr(credential, field) for field in AUTH_FIELDS},
    }, sort_keys=True))


def _cluster_fingerprint(cluster) -> tuple:
    return (
        cluster.lifecycle, cluster.draft_owner_id, iso(cluster.draft_expires_at),
        cluster.server, cluster.ca_data, cluster.auth_type,
        tuple(cluster.namespaces), cluster.context,
    )


class ConnectionProbe:
    """Fence every GET and publication without holding a DB lock over network I/O.

    Each request reconstructs policy from current DB state and uses only the exact
    personal credential initially verified. A new token, even at unchanged access
    revisions, invalidates this attempt rather than silently changing identities.
    """

    def __init__(
        self, session, settings, vault, policy_factory, *, user_id, session_hash,
        cluster_id, namespaces=None, discovery=False, draft_only=False,
        scope_edit=False, expected_revision=None,
    ):
        self.session, self.settings, self.vault = session, settings, vault
        self.policy_factory = policy_factory
        self.user_id, self.session_hash, self.cluster_id = user_id, session_hash, cluster_id
        self.namespaces = validate_namespaces(namespaces) if namespaces is not None else None
        self.discovery, self.draft_only, self.scope_edit = discovery, draft_only, scope_edit
        self.expected_revision = expected_revision
        self._captured = False
        user, cluster, credential, connection, revisions = self._current()
        self.role = user.role
        self.cluster_stamp = _cluster_fingerprint(cluster)
        self.credential_stamp = _credential_fingerprint(credential)
        self.revisions = revisions
        self.connection = connection
        self._captured = True
        session.commit()

    def _current(self):
        session = self.session
        session.expire_all()
        # NO KEY UPDATE permits FK KEY SHARE from canonical-policy-locked run and
        # credential inserts, while still fencing concurrent account/session mutation.
        user = session.scalar(select(User).where(User.id == self.user_id).with_for_update(key_share=True).execution_options(populate_existing=True))
        web_session = session.scalar(select(WebSession).where(WebSession.token_hash == self.session_hash).with_for_update(key_share=True).execution_options(populate_existing=True))
        if not user or not user.active or not web_session or web_session.user_id != self.user_id or aware(web_session.expires_at) <= now():
            raise DomainError("Сессия истекла", "unauthenticated")
        if user.role not in SCAN_ROLES:
            raise DomainError("Недостаточно прав приложения", "forbidden")
        cluster = permitted_connection(session, user, self.cluster_id)
        if self.draft_only:
            owned_draft(session, user, self.cluster_id)
        if self.scope_edit:
            permitted_cluster(session, user, self.cluster_id)
            if user.role != "administrator":
                raise DomainError("Недостаточно прав приложения", "forbidden")
            if web_session.reauthenticated_at is None or aware(web_session.reauthenticated_at) + REAUTH_WINDOW <= now():
                raise DomainError("Подтвердите пароль администратора", "reauthentication_required")
        cluster, policy, binding = lock_authorization(session, self.cluster_id, self.user_id)
        # Re-evaluate owner/expiry/subset on the locked, freshly loaded row.
        permitted_connection(session, user, self.cluster_id)
        if self.draft_only:
            owned_draft(session, user, self.cluster_id)
        if self.scope_edit:
            permitted_cluster(session, user, self.cluster_id)
        if self.expected_revision is not None and cluster.auth_generation != self.expected_revision:
            raise DomainError("Доступ уже изменён; обновите данные", "conflict")
        if self.namespaces is not None and cluster.lifecycle == "ready" and not self.scope_edit and not set(self.namespaces) <= set(cluster.namespaces):
            raise DomainError("Пространство имён вне разрешённой области", "forbidden")
        credential = session.scalar(select(ClusterCredential).where(ClusterCredential.user_id == self.user_id, ClusterCredential.cluster_id == self.cluster_id).with_for_update().execution_options(populate_existing=True))
        connection = credential_for(session, self.vault, cluster, user, session_hash=self.session_hash)
        revisions = authorization_values(cluster, policy, binding)
        if self._captured and (
            user.role != self.role
            or _cluster_fingerprint(cluster) != self.cluster_stamp
            or revisions != self.revisions
            or _credential_fingerprint(credential) != self.credential_stamp
        ):
            raise DomainError("Доступ или личная авторизация изменились; повторите проверку", "authorization_required")
        return user, cluster, credential, connection, revisions

    def check(self):
        """Return locked current rows for final publication/CAS; caller commits."""
        user, cluster, credential, _, _ = self._current()
        return user, cluster, credential

    def _continuation_binding(self):
        return {
            "user": self.user_id, "session": self.session_hash, "cluster": self.cluster_id,
            "credential": self.credential_stamp,
            "configuration": digest(json.dumps(self.cluster_stamp)),
            "role": self.role, "revisions": self.revisions,
        }

    def read_continuation(self, token):
        try:
            data = self.vault.decrypt(token, "namespace-discovery:v1")
            if data.get("binding") != self._continuation_binding():
                raise ValueError
            expiry = datetime.fromisoformat(data["expires_at"])
            if aware(expiry) <= now():
                raise DomainError("Снимок списка пространств имён истёк; обновите список", "namespace_snapshot_expired")
            return data
        except (KeyError, TypeError, ValueError):
            raise DomainError("Продолжение списка недействительно; обновите список", "invalid_namespace_continuation") from None
        except DomainError as error:
            if error.code == "namespace_snapshot_expired":
                raise
            raise DomainError("Продолжение списка недействительно; обновите список", "invalid_namespace_continuation") from None

    def seal_continuation(self, cursor, snapshot, expires_at=None):
        expiry = expires_at or iso(min(now() + timedelta(minutes=5), datetime.fromisoformat(self.connection["expires_at"])))
        return self.vault.encrypt({
            "binding": self._continuation_binding(), "cursor": cursor,
            "snapshot": snapshot, "expires_at": expiry,
        }, "namespace-discovery:v1")

    def get_json(self, url: str, headers=None) -> dict:
        _, cluster, _, connection, _ = self._current()
        if self.discovery:
            try:
                parsed = urlsplit(url)
                pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2, errors="strict")
                params = dict(pairs)
                cursor = params.get("continue")
                if (
                    url.split("?", 1)[0] != connection["server"].rstrip("/") + "/api/v1/namespaces"
                    or parsed.fragment or len(params) != len(pairs)
                    or params.get("limit") != "200"
                    or any(field.split("=", 1)[0] not in {"limit", "continue"} for field in parsed.query.split("&"))
                    or re.search(r"%(?![A-Fa-f0-9]{2})", parsed.query)
                    or (cursor is not None and (not 1 <= len(cursor) <= 4096 or any(not 32 <= ord(char) < 127 for char in cursor)))
                ):
                    raise ValueError
            except (ValueError, UnicodeError):
                raise DomainError("Недопустимый запрос списка пространств имён", "scope_denied") from None
        else:
            validate_inventory_url(url, connection["server"], self.namespaces)
        identity = connection_tls(connection)
        options = {"client_identity": identity} if identity is not None else {}
        http = self.policy_factory(self.session, self.settings, "kubernetes", cluster.ca_data, **options)
        self.session.commit()
        # Ignore caller-supplied authorization headers. No transaction spans I/O.
        try:
            result = http.get_json(url, headers=connection_headers(connection))
        except DomainError:
            # A late HTTP rejection must not supersede a local revoke/replacement.
            self.check()
            self.session.commit()
            raise
        self.check()
        self.session.commit()
        return result


def require_preflight_success(coverage, namespaces, *, accept_partial: bool) -> None:
    """Only complete success or explicitly acknowledged 403 gaps may save scope."""
    expected = {f"{namespace}/{resource.plural}" for namespace in namespaces for resource in RESOURCES}
    if (
        not isinstance(coverage, list) or len(coverage) != len(expected)
        or any(not isinstance(row, dict) or not isinstance(row.get("check"), str) for row in coverage)
        or {row.get("check") for row in coverage} != expected
    ):
        raise DomainError("Проверка доступа не подтвердила выбранную область", "preflight_failed")
    if any(row.get("code") == "http_401" for row in coverage):
        raise DomainError("Kubernetes отклонил личную авторизацию; авторизуйтесь снова", "kubernetes_authentication_required")
    if any(
        not ((row.get("code") == "allowed" and row.get("status") == "completed") or (row.get("code") == "http_403" and row.get("status") == "denied"))
        for row in coverage
    ) or not any(row.get("code") == "allowed" for row in coverage):
        raise DomainError("Проверка доступа не подтвердила выбранную область", "preflight_failed")
    if any(row.get("code") == "http_403" for row in coverage) and not accept_partial:
        raise DomainError("Подтвердите сохранение области с отказами RBAC (403)", "preflight_partial")
