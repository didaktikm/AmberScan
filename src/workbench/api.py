"""Same-origin HTTP API; scanners never execute in request handlers."""

import hmac
import json
import re
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from workbench import __version__
from workbench.admin_routes import (
    install_admin_routes,
    reauthenticated_until,
    require_recent_reauth,
)
from workbench.config import Settings
from workbench.configuration import (
    invalidate_access,
    lock_policy,
    policy_http,
    policy_view,
)
from workbench.connections import (
    ConnectionProbe,
    cleanup_expired_drafts,
    create_draft,
    owned_draft,
    permitted_connection,
    require_preflight_success,
    store_kubeconfig_credential,
)
from workbench.db import (
    AuditEvent,
    Cluster,
    ClusterCredential,
    Finding,
    LoginAttempt,
    Run,
    User,
    WebSession,
    Worker,
    audit,
    aware,
    database,
    iso,
    now,
    uid,
)
from workbench.domain import DomainError
from workbench.migrations import require_runtime_schema
from workbench.namespaces import (
    INVENTORY_VERSION,
    discover_namespaces,
    validate_run_scope,
)
from workbench.reports import render_report
from workbench.rollout import parse_runtime_report, record_schedule, refuse_cluster_change
from workbench.scanners import parse_report, preflight
from workbench.security import (
    Vault,
    extract_kubeconfig_credentials,
    inspect_kubeconfig,
    password_hash,
    password_verify,
)
from workbench.services import (
    ACTIVE_STATES,
    AUTH_FIELDS,
    REVIEW_ROLES,
    SCAN_ROLES,
    authorization_values,
    cluster_view,
    clusters_for,
    credential_for,
    digest,
    finding_view,
    lock_authorization,
    permitted_cluster,
    run_view,
    save_result,
)

COOKIE = "workbench_session"


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class Login(Input):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class KubeconfigInput(Input):
    content: str = Field(min_length=1, max_length=262144)


class Scope(Input):
    namespaces: list[str] = Field(min_length=1, max_length=100)

    @field_validator("namespaces")
    @classmethod
    def namespace_names(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", v) for v in values):
            raise ValueError("Namespaces must be explicit DNS labels")
        if len(set(values)) != len(values):
            raise ValueError("Duplicate namespaces")
        return values


class KubeconfigConnection(Input):
    kind: Literal["kubeconfig"]
    content: str = Field(min_length=1, max_length=262144)
    context: str = Field(min_length=1, max_length=250)


class DraftInput(Input):
    name: str = Field(min_length=1, max_length=120)
    environment: str = Field(default="test", min_length=1, max_length=50)
    auth_type: Literal["kubeconfig"] = "kubeconfig"
    storage_mode: Literal["run_only", "persistent", "days_30"] = "run_only"
    connection: KubeconfigConnection


class CredentialInput(KubeconfigInput):
    context: str = Field(min_length=1, max_length=250)
    storage_mode: Literal["run_only", "persistent", "days_30"] = "run_only"
    expected_access_revision: int = Field(ge=0, strict=True)


class DiscoveryInput(Input):
    continuation: str | None = Field(default=None, min_length=1, max_length=16384)


class SaveScopeInput(Scope):
    expected_access_revision: int = Field(ge=0, strict=True)
    accept_partial: bool = Field(default=False, strict=True)


class RunInput(Scope):
    cluster_id: str = Field(max_length=36)
    timeout_seconds: int = Field(default=300, ge=10, le=600)


class ImportInput(Input):
    cluster_id: str = Field(max_length=36)
    scanner: Literal["trivy", "kube-bench", "kubescape"]
    report: dict


class ScheduleInput(Input):
    kind: Literal["periodic", "watch", "off"]
    confirm: Literal[True]


class ProtectedActionInput(Input):
    action: Literal["live_scanner", "extended", "operator", "remediate"]
    confirm: Literal[True]


class RuntimeImportInput(Input):
    cluster_id: str = Field(max_length=36)
    source: Literal["falco", "tetragon"]
    report: dict


class DispositionInput(Input):
    disposition: Literal["open", "confirmed", "accepted_risk", "false_positive"]


class BoundaryMiddleware:
    """Bound even chunked request bodies and add headers without logging inputs."""

    def __init__(self, app, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        if scope["method"] in {"POST", "PATCH", "DELETE", "PUT"}:
            origin = headers.get(b"origin")
            if origin and origin.decode("latin-1") != self.settings.public_origin:
                response = JSONResponse({"detail": {"code": "csrf", "message": "Источник запроса отклонён"}}, 403)
                await response(scope, receive, send)
                return
            if headers.get(b"sec-fetch-site") == b"cross-site":
                response = JSONResponse({"detail": {"code": "csrf", "message": "Межсайтовый запрос отклонён"}}, 403)
                await response(scope, receive, send)
                return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.settings.max_body_bytes:
                response = JSONResponse({"detail": {"code": "too_large", "message": "Запрос превышает 1 МиБ"}}, 413)
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        consumed = False

        async def bounded_receive():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        async def secure_send(message):
            if message["type"] == "http.response.start":
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"),
                ]
                if scope["path"].startswith("/api"):
                    extra.append((b"cache-control", b"no-store"))
                if self.settings.secure_cookie:
                    extra.append((b"strict-transport-security", b"max-age=31536000"))
                message["headers"] = list(message.get("headers", [])) + extra
            await send(message)

        await self.app(scope, bounded_receive, secure_send)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    vault = Vault(settings.master_key)
    engine, sessions = database(settings.database_url)
    app = FastAPI(title="AmberData Workbench", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessions = sessions
    app.state.vault = vault
    app.state.dummy_hash = password_hash(secrets.token_urlsafe(32))
    app.add_middleware(BoundaryMiddleware, settings=settings)
    hostname = urlsplit(settings.public_origin).hostname
    if not hostname:
        raise DomainError("Invalid public origin", "configuration_required")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[hostname])

    @app.exception_handler(DomainError)
    async def domain_error(_request: Request, exc: DomainError):
        status = {"not_found": 404, "forbidden": 403, "unauthenticated": 401, "csrf": 403, "rate_limited": 429, "conflict": 409, "configuration_required": 409, "authorization_required": 409, "kubernetes_authentication_required": 409, "preflight_failed": 409, "preflight_partial": 409, "reauthentication_required": 403, "reauthentication_failed": 403, "schema_upgrade_required": 503}.get(exc.code, 400)
        return JSONResponse({"detail": {"code": exc.code, "message": exc.message}}, status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError):
        # Pydantic errors include input values: never return passwords/kubeconfig/tokens.
        return JSONResponse({"detail": {"code": "invalid_input", "message": "Проверьте поля запроса и допустимые размеры"}}, 422)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(_request: Request, _exc: SQLAlchemyError):
        return JSONResponse({"detail": {"code": "storage_error", "message": "Хранилище временно недоступно"}}, 503)

    def db():
        with sessions() as session:
            require_runtime_schema(session)
            yield session

    def identity(request: Request, session=Depends(db)) -> User:
        token = request.cookies.get(COOKIE, "")
        if not token or len(token) > 128:
            raise DomainError("Войдите в приложение", "unauthenticated")
        web_session = session.get(WebSession, digest(token))
        if not web_session or aware(web_session.expires_at) <= now():
            raise DomainError("Сессия истекла", "unauthenticated")
        user = session.get(User, web_session.user_id)
        if not user or not user.active:
            raise DomainError("Войдите в приложение", "unauthenticated")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            csrf = request.headers.get("x-csrf-token", "")
            if not hmac.compare_digest(csrf, web_session.csrf_token):
                raise DomainError("Проверка CSRF не пройдена", "csrf")
        request.state.web_session = web_session
        return user

    CurrentUser = Annotated[User, Depends(identity)]

    def role(user: User, allowed: set[str]) -> None:
        if user.role not in allowed:
            raise DomainError("Недостаточно прав приложения", "forbidden")

    def scope_for(cluster: Cluster, namespaces: list[str], timeout_seconds: int = 300) -> dict:
        if cluster.lifecycle != "ready":
            raise DomainError("Объект не найден", "not_found")
        if not set(namespaces) <= set(cluster.namespaces):
            raise DomainError("Пространство имён вне разрешённой области", "forbidden")
        return validate_run_scope({"namespaces": namespaces, "max_objects": 1000, "timeout_seconds": timeout_seconds, "inventory_version": INVENTORY_VERSION}, cluster.namespaces)

    def session_view(user: User, web_session: WebSession) -> dict:
        return {"user": {"id": user.id, "username": user.username, "role": user.role}, "csrf_token": web_session.csrf_token, "reauthenticated_until": reauthenticated_until(web_session)}

    def recheck_identity(session, user_id: str, session_hash: str) -> User:
        """A logout, grant removal or account change during outbound I/O is final."""
        # PostgreSQL NO KEY UPDATE fences role/logout changes but permits FK KEY
        # SHARE from enqueue/credential inserts which already hold canonical policy locks.
        user = session.scalar(select(User).where(User.id == user_id).with_for_update(key_share=True).execution_options(populate_existing=True))
        web_session = session.scalar(select(WebSession).where(WebSession.token_hash == session_hash).with_for_update(key_share=True).execution_options(populate_existing=True))
        if not user or not user.active or not web_session or web_session.user_id != user_id or aware(web_session.expires_at) <= now():
            raise DomainError("Сессия истекла", "unauthenticated")
        role(user, SCAN_ROLES)
        return user

    install_admin_routes(app, settings, vault, db, identity)

    def get_run(session, user: User, run_id: str) -> Run:
        run = session.get(Run, run_id)
        if not run:
            raise DomainError("Запуск не найден", "not_found")
        permitted_cluster(session, user, run.cluster_id)
        return run

    @app.get("/api/health/live")
    def live():
        return {"status": "ok", "version": __version__}

    @app.get("/api/health/ready")
    def ready(session=Depends(db)):
        session.execute(text("SELECT 1"))
        session.scalar(select(func.count(User.id)))
        return {"status": "ready"}

    @app.post("/api/login")
    def login(payload: Login, request: Request, response: Response, session=Depends(db)):
        peer = request.client.host if request.client else "unknown"
        key = digest(peer)
        attempt = session.scalar(select(LoginAttempt).where(LoginAttempt.key == key).with_for_update())
        if attempt is None:
            attempt = LoginAttempt(key=key, count=0, window_start=now())
            session.add(attempt)
        if aware(attempt.window_start) < now() - timedelta(minutes=5):
            attempt.count, attempt.window_start = 0, now()
        if attempt.count >= 30:
            raise DomainError("Слишком много попыток входа. Повторите позже", "rate_limited")
        attempt.count += 1
        user = session.scalar(select(User).where(User.username == payload.username).with_for_update(key_share=True))
        if user and user.locked_until and aware(user.locked_until) > now():
            session.commit()
            raise DomainError("Слишком много попыток входа. Повторите позже", "rate_limited")
        valid = password_verify(payload.password, user.password_hash if user else app.state.dummy_hash)
        if not user or not user.active or not valid:
            if user:
                user.failed_logins += 1
                if user.failed_logins >= 5:
                    user.locked_until = now() + timedelta(minutes=5)
                    user.failed_logins = 0
            audit(session, "anonymous", "login_failed", "session")
            session.commit()
            raise DomainError("Неверные данные для входа", "unauthenticated")
        user.failed_logins, user.locked_until = 0, None
        session.execute(delete(WebSession).where(WebSession.user_id == user.id))
        token = secrets.token_urlsafe(48)
        web_session = WebSession(token_hash=digest(token), user_id=user.id, csrf_token=secrets.token_hex(32), expires_at=now() + timedelta(seconds=settings.session_seconds))
        session.add(web_session)
        audit(session, user.username, "login", user.id)
        session.commit()
        response.set_cookie(COOKIE, token, max_age=settings.session_seconds, httponly=True, secure=settings.secure_cookie, samesite="lax", path="/")
        return session_view(user, web_session)

    @app.get("/api/session")
    def current_session(request: Request, user: CurrentUser):
        return session_view(user, request.state.web_session)

    @app.post("/api/logout")
    def logout(request: Request, response: Response, user: CurrentUser, session=Depends(db)):
        session.delete(request.state.web_session)
        audit(session, user.username, "logout", user.id)
        session.commit()
        response.delete_cookie(COOKIE, path="/", httponly=True, secure=settings.secure_cookie, samesite="lax")
        return {"status": "logged_out"}

    @app.get("/api/capabilities")
    def capabilities(user: CurrentUser, session=Depends(db)):
        rules = policy_view(session)["rules"]
        kubernetes_setup_required = not any(rule["purpose"] == "kubernetes" for rule in rules)
        return {
            "version": __version__,
            "features": [
                {"id": "read_only", "title": "Разовый аудит только на чтение", "status": "available", "detail": "Kubernetes API: ограниченные встроенные проверки. Это не полный контрольный профиль."},
                {"id": "imports", "title": "Импорт отчётов", "status": "available", "detail": "Trivy, kube-bench и Kubescape. Происхождение и область импорта не подтверждаются."},
                {"id": "live_scanners", "title": "Запуск Kubescape и Trivy", "status": "not_implemented", "detail": "Бинарники не запускаются и не скачиваются. Подтверждение не начинает проверку."},
                {"id": "scheduled", "title": "Периодический аудит", "status": "available", "detail": "Явное расписание только на чтение по сохранённой области: раз в сутки или не чаще чем раз в 6 часов. Нужна авторизация на 30 дней. Результаты старше 90 дней удаляются из приложения, не из кластера."},
                {"id": "extended", "title": "Расширенные проверки", "status": "not_implemented", "detail": "Создание подов, проверки узлов и сетевые тесты не отправляются в кластер даже после подтверждения."},
                {"id": "operator", "title": "Контроль из кластера", "status": "not_implemented", "detail": "Установка оператора не выполняется даже после подтверждения."},
                {"id": "runtime", "title": "Наблюдение за средой выполнения", "status": "available", "detail": "Явный импорт JSON Falco и Tetragon. Агент не устанавливается, происхождение не подтверждается."},
                {"id": "team_sso", "title": "Единый вход в приложение", "status": "not_implemented", "detail": "Отложено до финальной версии. Пилот использует локальные учётные записи."},
            ],
            "setup_required": kubernetes_setup_required,
            "kubernetes_setup_required": kubernetes_setup_required,
            "limits": {"request_bytes": settings.max_body_bytes, "objects_per_run": 1000, "run_timeout_seconds": 600, "list_rows": 500},
        }

    @app.get("/api/overview")
    def overview(user: CurrentUser, session=Depends(db)):
        ids = [cluster.id for cluster in clusters_for(session, user)]
        runs = list(session.scalars(select(Run).where(Run.cluster_id.in_(ids))))
        workers = list(session.scalars(select(Worker)))
        return {
            "clusters": len(ids),
            "runs": len(runs),
            "findings": session.scalar(select(func.count(Finding.id)).where(Finding.cluster_id.in_(ids))),
            "coverage_gaps": sum(sum(item.get("status") != "completed" for item in run.coverage) for run in runs),
            "workers": [{"id": worker.id, "status": worker.status if aware(worker.heartbeat_at) > now() - timedelta(seconds=60) else "offline", "heartbeat_at": iso(worker.heartbeat_at)} for worker in workers],
        }

    @app.get("/api/clusters")
    def list_clusters(request: Request, user: CurrentUser, session=Depends(db)):
        return [cluster_view(session, item, user, request.state.web_session.token_hash) for item in clusters_for(session, user)]

    @app.post("/api/kubeconfig/inspect")
    def inspect(payload: KubeconfigInput, user: CurrentUser):
        role(user, {"administrator"})
        contexts = inspect_kubeconfig(payload.content)
        return {"contexts": [{key: value for key, value in item.items() if key != "ca_data"} for item in contexts]}

    def save_draft(payload: DraftInput, request: Request, user: User, session):
        role(user, {"administrator"})
        extracted = extract_kubeconfig_credentials(payload.connection.content, payload.connection.context)
        user = recheck_identity(session, user.id, request.state.web_session.token_hash)
        # Acquire policy before inserting the cluster/binding FK rows.
        lock_policy(session)
        cluster = create_draft(session, user, name=payload.name, environment=payload.environment, connection=payload.connection.model_dump(), auth_type=payload.auth_type, extracted=extracted)
        cluster, policy, binding = lock_authorization(session, cluster.id, user.id, create_binding=True)
        store_kubeconfig_credential(session, vault, user, request.state.web_session, cluster, extracted, payload.storage_mode, authorization_values(cluster, policy, binding))
        audit(session, user.username, "kubeconfig_authorized", cluster.id, storage_mode=payload.storage_mode)
        session.commit()
        return cluster_view(session, cluster, user, request.state.web_session.token_hash)

    @app.post("/api/cluster-drafts", status_code=201)
    def add_draft(payload: DraftInput, request: Request, user: CurrentUser, session=Depends(db)):
        return save_draft(payload, request, user, session)

    @app.get("/api/cluster-drafts")
    def list_drafts(request: Request, user: CurrentUser, session=Depends(db)):
        role(user, {"administrator"})
        cleanup_expired_drafts(session)
        rows = list(session.scalars(select(Cluster).where(Cluster.lifecycle == "draft", Cluster.draft_owner_id == user.id, Cluster.draft_expires_at > now()).order_by(Cluster.created_at.desc())))
        session.commit()
        return [cluster_view(session, item, user, request.state.web_session.token_hash) for item in rows]

    @app.get("/api/cluster-drafts/{cluster_id}")
    def get_draft(cluster_id: str, request: Request, user: CurrentUser, session=Depends(db)):
        return cluster_view(session, owned_draft(session, user, cluster_id), user, request.state.web_session.token_hash)

    @app.delete("/api/cluster-drafts/{cluster_id}")
    def discard_draft(cluster_id: str, user: CurrentUser, session=Depends(db)):
        owned_draft(session, user, cluster_id)
        # Conditional DML rechecks lifecycle/owner after waiting for a concurrent CAS.
        deleted = session.scalar(delete(Cluster).where(Cluster.id == cluster_id, Cluster.lifecycle == "draft", Cluster.draft_owner_id == user.id, Cluster.draft_expires_at > now()).returning(Cluster.id).execution_options(synchronize_session=False))
        if deleted is None:
            raise DomainError("Объект не найден", "not_found")
        audit(session, user.username, "cluster_draft_discarded", cluster_id)
        session.commit()
        return {"status": "discarded"}

    @app.post("/api/clusters/{cluster_id}/credential")
    def import_credential(cluster_id: str, payload: CredentialInput, request: Request, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        permitted_connection(session, user, cluster_id)
        extracted = extract_kubeconfig_credentials(payload.content, payload.context)
        user = recheck_identity(session, user.id, request.state.web_session.token_hash)
        cluster, policy, binding = lock_authorization(session, cluster_id, user.id, create_binding=True)
        permitted_connection(session, user, cluster_id)
        if cluster.auth_generation != payload.expected_access_revision:
            raise DomainError("Доступ уже изменён; обновите данные", "conflict")
        metadata = extracted["metadata"]
        if (metadata["server"], metadata.get("ca_data"), metadata["context"]) != (cluster.server, cluster.ca_data, cluster.context):
            raise DomainError("Адрес API, центр сертификации и контекст должны совпадать с сохранённым подключением", "connection_mismatch")
        invalidate_access(session, cluster_id=cluster.id, user_id=user.id, reason="Личная авторизация заменена")
        session.flush()
        store_kubeconfig_credential(session, vault, user, request.state.web_session, cluster, extracted, payload.storage_mode, authorization_values(cluster, policy, binding))
        audit(session, user.username, "kubeconfig_authorized", cluster.id, storage_mode=payload.storage_mode)
        result = cluster_view(session, cluster, user, request.state.web_session.token_hash)
        session.commit()
        return result

    def revoke_authorization(cluster_id, user, session, *, personal):
        cluster = permitted_connection(session, user, cluster_id)
        # Revocation must work even for a deny-all policy.
        lock_policy(session)
        session.scalar(select(Cluster).where(Cluster.id == cluster_id).with_for_update().execution_options(populate_existing=True))
        cluster = permitted_connection(session, user, cluster_id)
        invalidate_access(session, cluster_id=cluster.id, user_id=user.id if personal else None, reason="Авторизация отозвана")
        audit(session, user.username, "personal_authorization_removed" if personal else "credentials_removed", cluster.id)
        session.commit()
        return {"status": "authorization_required", "detail": "Локальные учётные данные удалены. Это не отзывает учётные данные в Kubernetes; активный запрос может завершиться до отмены."}

    @app.delete("/api/clusters/{cluster_id}/authorization")
    def revoke_personal(cluster_id: str, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        return revoke_authorization(cluster_id, user, session, personal=True)

    @app.delete("/api/clusters/{cluster_id}/credential")
    def revoke(cluster_id: str, request: Request, user: CurrentUser, session=Depends(db)):
        require_recent_reauth(request, user)
        return revoke_authorization(cluster_id, user, session, personal=False)

    def connection_probe(cluster_id, request, user, session, **options):
        role(user, SCAN_ROLES)
        return ConnectionProbe(session, settings, vault, policy_http, user_id=user.id, session_hash=request.state.web_session.token_hash, cluster_id=cluster_id, **options)

    def probe_coverage(probe):
        return preflight(probe.connection, {"namespaces": probe.namespaces, "max_objects": 1000, "timeout_seconds": 30, "inventory_version": INVENTORY_VERSION}, probe)

    def check_kubernetes_authentication(coverage):
        if any(row.get("code") == "http_401" for row in coverage):
            # Do not revoke a potentially replaced credential or the application session.
            raise DomainError("Kubernetes отклонил личную авторизацию; авторизуйтесь снова", "kubernetes_authentication_required")

    @app.post("/api/clusters/{cluster_id}/namespaces/discover")
    def namespaces_discover(cluster_id: str, request: Request, user: CurrentUser, payload: DiscoveryInput | None = None, session=Depends(db)):
        probe = connection_probe(cluster_id, request, user, session, discovery=True)
        continuation = probe.read_continuation(payload.continuation) if payload and payload.continuation else None
        result = discover_namespaces(probe.connection, probe, continuation=continuation, seal_continuation=probe.seal_continuation)
        user, cluster, _ = probe.check()
        if cluster.lifecycle == "ready" and user.role != "administrator":
            result = {**result, "items": [item for item in result["items"] if item["name"] in cluster.namespaces]}
        hint = cluster.context_namespace_hint
        if cluster.lifecycle == "ready" and user.role != "administrator" and hint not in cluster.namespaces:
            hint = None
        audit(session, user.username, "namespaces_discovered", cluster_id, status=result["status"])
        session.commit()
        return {**result, "namespace_hint": hint}

    @app.post("/api/clusters/{cluster_id}/preflight")
    def cluster_preflight(cluster_id: str, payload: Scope, request: Request, user: CurrentUser, session=Depends(db)):
        probe = connection_probe(cluster_id, request, user, session, namespaces=payload.namespaces)
        coverage = probe_coverage(probe)
        user, _, _ = probe.check()
        check_kubernetes_authentication(coverage)
        audit(session, user.username, "preflight", cluster_id, namespaces=payload.namespaces)
        session.commit()
        return {"coverage": coverage}

    @app.post("/api/cluster-drafts/{cluster_id}/finalize")
    def finalize_draft(cluster_id: str, payload: SaveScopeInput, request: Request, user: CurrentUser, session=Depends(db)):
        probe = connection_probe(cluster_id, request, user, session, namespaces=payload.namespaces, draft_only=True, expected_revision=payload.expected_access_revision)
        coverage = probe_coverage(probe)
        user, cluster, credential = probe.check()
        require_preflight_success(coverage, payload.namespaces, accept_partial=payload.accept_partial)
        generation = cluster.auth_generation + 1
        updated = session.scalar(update(Cluster).where(Cluster.id == cluster_id, Cluster.lifecycle == "draft", Cluster.draft_owner_id == user.id, Cluster.draft_expires_at > now(), Cluster.auth_generation == payload.expected_access_revision).values(lifecycle="ready", namespaces=list(payload.namespaces), auth_generation=generation, draft_owner_id=None, draft_expires_at=None).returning(Cluster.id).execution_options(synchronize_session=False))
        if updated is None:
            raise DomainError("Черновик уже изменён; обновите данные", "conflict")
        # Preserve exactly the validated personal credential, not any concurrent flow.
        session.execute(delete(ClusterCredential).where(ClusterCredential.cluster_id == cluster_id, ClusterCredential.user_id != user.id))
        credential.cluster_generation = generation
        session.flush()
        session.refresh(cluster)
        audit(session, user.username, "cluster_draft_finalized", cluster_id, namespaces=payload.namespaces, accept_partial=payload.accept_partial)
        result = cluster_view(session, cluster, user, request.state.web_session.token_hash)
        session.commit()
        return {"cluster": result, "coverage": coverage}

    @app.post("/api/clusters/{cluster_id}/scope/preflight")
    def scope_preflight(cluster_id: str, payload: Scope, request: Request, user: CurrentUser, session=Depends(db)):
        require_recent_reauth(request, user)
        probe = connection_probe(cluster_id, request, user, session, namespaces=payload.namespaces, scope_edit=True)
        coverage = probe_coverage(probe)
        user, _, _ = probe.check()
        check_kubernetes_authentication(coverage)
        audit(session, user.username, "scope_preflight", cluster_id, namespaces=payload.namespaces)
        session.commit()
        return {"coverage": coverage}

    @app.patch("/api/clusters/{cluster_id}/scope")
    def save_scope(cluster_id: str, payload: SaveScopeInput, request: Request, user: CurrentUser, session=Depends(db)):
        require_recent_reauth(request, user)
        probe = connection_probe(cluster_id, request, user, session, namespaces=payload.namespaces, scope_edit=True, expected_revision=payload.expected_access_revision)
        coverage = probe_coverage(probe)
        user, cluster, _ = probe.check()
        require_preflight_success(coverage, payload.namespaces, accept_partial=payload.accept_partial)
        if set(cluster.namespaces) != set(payload.namespaces):
            updated = session.scalar(update(Cluster).where(Cluster.id == cluster_id, Cluster.lifecycle == "ready", Cluster.auth_generation == payload.expected_access_revision).values(namespaces=list(payload.namespaces)).returning(Cluster.id).execution_options(synchronize_session=False))
            if updated is None:
                raise DomainError("Доступ уже изменён; обновите данные", "conflict")
            # Canonical locks are held by probe.check; invalidate credentials and work.
            invalidate_access(session, cluster_id=cluster_id, reason="Область namespaces изменена")
            session.flush()
            session.refresh(cluster)
            audit(session, user.username, "cluster_scope_changed", cluster_id, namespaces=payload.namespaces, accept_partial=payload.accept_partial)
        result = cluster_view(session, cluster, user, request.state.web_session.token_hash)
        session.commit()
        return {"cluster": result, "coverage": coverage}

    @app.post("/api/runs", status_code=201)
    def enqueue(payload: RunInput, request: Request, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        permitted_cluster(session, user, payload.cluster_id)
        # Canonical locks serialize one-shot consumption, config changes, and revocation.
        cluster, _, _ = lock_authorization(session, payload.cluster_id, user.id)
        scope = scope_for(cluster, payload.namespaces, payload.timeout_seconds)
        credential = session.scalar(select(ClusterCredential).where(ClusterCredential.user_id == user.id, ClusterCredential.cluster_id == cluster.id).with_for_update().execution_options(populate_existing=True))
        connection = credential_for(session, vault, cluster, user, 30, session_hash=request.state.web_session.token_hash)
        assert credential is not None  # credential_for rejects missing/expired/stale rows.
        active = session.scalar(select(func.count(Run.id)).where(Run.cluster_id == cluster.id, Run.status.in_(ACTIVE_STATES)))
        if active:
            raise DomainError("Для кластера уже есть активный запуск", "conflict")
        if session.scalar(select(func.count(Run.id)).where(Run.status.in_(ACTIVE_STATES))) >= settings.max_queued_runs:
            raise DomainError("Очередь заполнена", "rate_limited")
        run_id = uid()
        connection = {**connection, "scope": {**scope, "namespaces": list(scope["namespaces"])}}
        run = Run(id=run_id, cluster_id=cluster.id, actor_id=user.id, scope=scope, credential=vault.encrypt(connection, f"run:{run_id}"), credential_expires_at=credential.expires_at, **{key: connection[key] for key in AUTH_FIELDS})
        session.add(run)
        if credential.storage_mode == "run_only":
            session.delete(credential)
        audit(session, user.username, "run_queued", run.id, namespaces=payload.namespaces)
        session.commit()
        return run_view(session, run)

    @app.get("/api/runs")
    def list_runs(user: CurrentUser, session=Depends(db), offset: int = 0):
        if offset < 0:
            raise DomainError("Некорректное смещение списка")
        ids = [cluster.id for cluster in clusters_for(session, user)]
        rows = session.scalars(select(Run).where(Run.cluster_id.in_(ids)).order_by(Run.created_at.desc()).offset(offset).limit(500))
        return [run_view(session, run) for run in rows]

    @app.get("/api/runs/{run_id}")
    def get_run_details(run_id: str, user: CurrentUser, session=Depends(db)):
        return run_view(session, get_run(session, user, run_id), details=True)

    @app.post("/api/runs/{run_id}/cancel")
    def cancel(run_id: str, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        run = get_run(session, user, run_id)
        if run.status in ACTIVE_STATES:
            run.cancel_requested = True
            if run.status == "queued":
                run.status, run.stage, run.finished_at, run.credential = "cancelled", "cleanup", now(), None
            audit(session, user.username, "cancel_requested", run.id)
            session.commit()
        return run_view(session, run)

    @app.post("/api/imports", status_code=201)
    def import_report(payload: ImportInput, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        cluster = permitted_cluster(session, user, payload.cluster_id)
        # Pure bounded parsing. No filesystem paths, subprocesses or report-provided URLs.
        result = parse_report(payload.scanner, payload.report)
        session.execute(select(Cluster.id).where(Cluster.id == cluster.id).with_for_update())
        run = Run(id=uid(), cluster_id=cluster.id, actor_id=user.id, status="running", stage="normalize", scope={"namespaces": [], "verified": False}, source=f"import:{payload.scanner}", started_at=now())
        session.add(run)
        session.flush()
        save_result(session, run, result)
        audit(session, user.username, "report_imported", run.id, scanner=payload.scanner)
        session.commit()
        return run_view(session, run, details=True)

    @app.post("/api/clusters/{cluster_id}/schedule")
    def set_schedule(cluster_id: str, payload: ScheduleInput, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        cluster = permitted_cluster(session, user, cluster_id)
        result = record_schedule(session, user, cluster, payload.kind)
        session.commit()
        return result

    @app.post("/api/clusters/{cluster_id}/protected-action")
    def protected_action(cluster_id: str, payload: ProtectedActionInput, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        cluster = permitted_cluster(session, user, cluster_id)
        result = refuse_cluster_change(session, user, cluster, payload.action)
        session.commit()
        return result

    @app.post("/api/runtime-imports", status_code=201)
    def import_runtime(payload: RuntimeImportInput, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        cluster = permitted_cluster(session, user, payload.cluster_id)
        result = parse_runtime_report(payload.source, payload.report)
        session.execute(select(Cluster.id).where(Cluster.id == cluster.id).with_for_update())
        run = Run(id=uid(), cluster_id=cluster.id, actor_id=user.id, status="running", stage="normalize", scope={"namespaces": [], "verified": False}, source=f"import:{payload.source}", started_at=now())
        session.add(run)
        session.flush()
        save_result(session, run, result)
        audit(session, user.username, "runtime_imported", run.id, source=payload.source)
        session.commit()
        return run_view(session, run, details=True)

    @app.get("/api/findings")
    def list_findings(user: CurrentUser, session=Depends(db), cluster_id: str | None = None, severity: str | None = None, q: str = "", offset: int = 0):
        if offset < 0 or len(q) > 200:
            raise DomainError("Некорректный фильтр")
        ids = [cluster.id for cluster in clusters_for(session, user)]
        if cluster_id:
            permitted_cluster(session, user, cluster_id)
            ids = [cluster_id]
        query = select(Finding).where(Finding.cluster_id.in_(ids))
        if severity:
            query = query.where(Finding.data["severity"].as_string() == severity)
        # Search on bounded presentation data rather than SQL string interpolation.
        rows = list(session.scalars(query.order_by(Finding.last_seen.desc())))
        if q:
            rows = [row for row in rows if q.casefold() in json.dumps(row.data, ensure_ascii=False).casefold()]
        return [finding_view(session, row) for row in rows[offset:offset + 500]]

    @app.patch("/api/findings/{finding_id}")
    def disposition(finding_id: str, payload: DispositionInput, user: CurrentUser, session=Depends(db)):
        role(user, SCAN_ROLES)
        finding = session.get(Finding, finding_id)
        if not finding:
            raise DomainError("Находка не найдена", "not_found")
        permitted_cluster(session, user, finding.cluster_id)
        if user.role not in REVIEW_ROLES and payload.disposition != "confirmed":
            raise DomainError("Требуется роль руководителя ИБ", "forbidden")
        finding.disposition = payload.disposition
        audit(session, user.username, "finding_disposition", finding.id, disposition=payload.disposition)
        session.commit()
        return finding_view(session, finding)

    @app.get("/api/runs/{run_id}/report")
    def report(run_id: str, user: CurrentUser, format: Literal["json", "markdown", "html"] = "json", session=Depends(db)):
        role(user, SCAN_ROLES)
        run = get_run(session, user, run_id)
        content, media_type, extension = render_report(run_view(session, run, details=True), format)
        audit(session, user.username, "report_exported", run.id, format=format)
        session.commit()
        return Response(content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="amberdata-{run.id}.{extension}"'})

    @app.get("/api/audit")
    def audit_list(user: CurrentUser, session=Depends(db), offset: int = 0):
        role(user, {"administrator"})
        if offset < 0:
            raise DomainError("Некорректное смещение списка")
        rows = session.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).offset(offset).limit(500))
        return [{"id": row.id, "created_at": iso(row.created_at), "actor": row.actor, "action": row.action, "target": row.target, "detail": row.detail} for row in rows]

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    def missing_api(path: str):
        raise DomainError("API не найден", "not_found")

    dist = Path(settings.web_dist_dir)
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="web")
    else:
        @app.get("/")
        def build_required():
            return JSONResponse({"status": "frontend_not_built", "detail": "Build frontend with bun run build"}, 503)
    return app
