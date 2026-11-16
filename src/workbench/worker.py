"""Durable PostgreSQL queue with fenced ownership and bounded child lifetime."""

import multiprocessing
import os
import signal
import tempfile
import time
from datetime import datetime, timedelta

from sqlalchemy import delete, select

from workbench.config import Settings
from workbench.configuration import policy_http
from workbench.connections import cleanup_expired_drafts
from workbench.db import (
    ClusterCredential,
    Run,
    User,
    WebSession,
    Worker,
    audit,
    aware,
    database,
    now,
    uid,
)
from workbench.domain import DomainError
from workbench.migrations import require_runtime_schema
from workbench.namespaces import validate_inventory_url, validate_run_scope
from workbench.scanners import scan_inventory
from workbench.security import Vault, connection_headers, connection_tls
from workbench.services import (
    AUTH_FIELDS,
    SCAN_ROLES,
    authorization_current,
    lock_authorization,
    permitted_cluster,
    save_result,
)


def authorized_run(session, run_id: str, worker_id: str) -> Run:
    """Fence ownership and authorization without consulting a consumed credential row."""
    run = session.get(Run, run_id)
    if not run:
        raise DomainError("Lease lost", "interrupted")
    try:
        cluster, _, _ = lock_authorization(session, run.cluster_id, run.actor_id)
    except DomainError as exc:
        if exc.code in {"configuration_required", "not_found"}:
            raise DomainError("Authorization changed", "authorization_required") from None
        raise
    run = session.scalar(select(Run).where(Run.id == run_id).with_for_update().execution_options(populate_existing=True))
    if not run or run.status != "running" or run.worker_id != worker_id or not run.lease_until or aware(run.lease_until) <= now():
        raise DomainError("Lease lost", "interrupted")
    if run.cancel_requested or not run.credential:
        raise DomainError("Cancelled", "cancelled")
    user = session.get(User, run.actor_id, populate_existing=True)
    if not user or not user.active or user.role not in SCAN_ROLES:
        raise DomainError("Permission revoked", "forbidden")
    try:
        permitted_cluster(session, user, run.cluster_id)
    except DomainError:
        raise DomainError("Permission revoked", "forbidden") from None
    if not run.credential_expires_at or aware(run.credential_expires_at) <= now() or not authorization_current(session, cluster, user.id, run):
        raise DomainError("Login required", "authorization_required")
    if cluster.lifecycle != "ready":
        raise DomainError("Connection is not ready", "scope_changed")
    validate_run_scope(run.scope, cluster.namespaces)
    return run


def run_connection(vault, run) -> dict:
    connection = vault.decrypt(run.credential, f"run:{run.id}")
    try:
        expiry = aware(datetime.fromisoformat(connection["expires_at"]))
        if expiry != aware(run.credential_expires_at) or expiry <= now() or any(connection[field] != getattr(run, field) for field in AUTH_FIELDS):
            raise ValueError("Snapshot mismatch")
        if connection.get("scope") != run.scope:
            raise ValueError("Scope snapshot mismatch")
        validate_run_scope(connection["scope"], connection["scope"]["namespaces"])
        if connection.get("auth_type") != "kubeconfig" or "auth" not in connection or set(connection) - {"server", "ca_data", "auth_type", "auth", "expires_at", "scope", *AUTH_FIELDS}:
            raise ValueError("Invalid imported credential")
        connection_headers(connection)
    except (KeyError, TypeError, ValueError):
        raise DomainError("Invalid credential snapshot", "authorization_required") from None
    return connection


class RunHTTP:
    """Fence every GET to the authenticated snapshot's endpoint and selected scope."""

    def __init__(self, sessions, settings, run_id, worker_id):
        self.sessions, self.settings = sessions, settings
        self.run_id, self.worker_id = run_id, worker_id
        self.vault = Vault(settings.master_key)

    def get_json(self, url, headers=None):
        with self.sessions() as session:
            require_runtime_schema(session)
            run = authorized_run(session, self.run_id, self.worker_id)
            connection = run_connection(self.vault, run)
            validate_inventory_url(url, connection["server"], run.scope["namespaces"])
            cluster = permitted_cluster(session, session.get(User, run.actor_id), run.cluster_id)
            if connection.get("auth_type") != cluster.auth_type:
                raise DomainError("Authentication mode changed", "authorization_required")
            client_identity = connection_tls(connection)
            options = {"client_identity": client_identity} if client_identity is not None else {}
            http = policy_http(session, self.settings, "kubernetes", connection.get("ca_data"), **options)
            session.commit()  # Never hold database locks over network I/O.
        # Never forward caller-selected identity or headers to another destination.
        result = http.get_json(url, headers=connection_headers(connection))
        with self.sessions() as session:
            require_runtime_schema(session)
            current = authorized_run(session, self.run_id, self.worker_id)
            if run_connection(self.vault, current) != connection:
                raise DomainError("Run snapshot changed", "scope_changed")
        return result


def collect(connection: dict, scope: dict, settings: Settings, run_id: str, worker_id: str, output) -> None:
    """Pass credentials in memory; mTLS loading uses immediately unlinked TLS files."""
    engine = None
    try:
        engine, sessions = database(settings.database_url)
        http = RunHTTP(sessions, settings, run_id, worker_id)
        result = scan_inventory(connection, scope, http, lambda: False)
        output.send(("ok", result))
    except DomainError as exc:
        output.send(("error", exc.code))
    except Exception:
        output.send(("error", "scanner_failed"))
    finally:
        if engine is not None:
            engine.dispose()
        output.close()


def cleanup_expired_authorizations(session) -> None:
    """Use a separate transaction: never hold run/cluster locks while deleting auth."""
    cutoff = now()
    session.execute(delete(WebSession).where(WebSession.expires_at < cutoff))
    session.execute(delete(ClusterCredential).where(ClusterCredential.expires_at < cutoff))


def recover(session) -> int:
    """Recover run leases only; authorization cleanup must commit before run locks."""
    rows = list(session.scalars(select(Run).where(Run.status == "running", Run.lease_until < now()).with_for_update(skip_locked=True)))
    for run in rows:
        run.status, run.stage = "interrupted", "cleanup"
        run.error = "Worker lease истёк. Запуск не повторяется автоматически."
        run.finished_at, run.credential, run.lease_until = now(), None, None
        audit(session, "worker", "run_interrupted", run.id)
    return len(rows)


def claim(session, worker_id: str, lease_seconds: int) -> str | None:
    run = session.scalar(select(Run).where(Run.status == "queued").order_by(Run.created_at).with_for_update(skip_locked=True).limit(1))
    if not run:
        return None
    run.status, run.stage = "running", "preflight"
    run.worker_id, run.started_at = worker_id, now()
    run.lease_until = now() + timedelta(seconds=lease_seconds)
    audit(session, "worker", "run_claimed", run.id)
    return run.id


class Runner:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.engine, self.sessions = database(settings.database_url)
        self.vault = Vault(settings.master_key)
        self.id = f"worker-{uid()}"
        self.stopping = False

    def pulse(self, session, status: str) -> None:
        session.merge(Worker(id=self.id, heartbeat_at=now(), status=status))

    def stop(self, *_args):
        self.stopping = True

    def finish_error(self, run_id: str, code: str) -> None:
        messages = {
            "cancelled": "Запуск отменён; процесс сборщика остановлен, credentials очищены.",
            "timeout": "Превышен лимит времени; процесс сборщика остановлен.",
            "authorization_required": "Требуется повторная авторизация подключения: импортируйте kubeconfig.",
            "kubernetes_authentication_required": "Kubernetes отклонил credentials; авторизуйте подключение повторно.",
            "http_401": "Kubernetes отклонил credentials; авторизуйте подключение повторно.",
            "forbidden": "Полномочия пользователя изменились; запуск остановлен.",
            "scope_changed": "Область подключения изменилась; запуск остановлен.",
            "invalid_scope": "Область запуска недействительна; сбор данных не выполняется.",
            "scope_denied": "Запрос за пределами области запуска отклонён.",
            "interrupted": "Worker остановлен; запуск не завершён.",
        }
        with self.sessions.begin() as session:
            run = session.scalar(select(Run).where(Run.id == run_id).with_for_update())
            if run and run.worker_id == self.id and run.status == "running":
                run.status = "cancelled" if code == "cancelled" else "interrupted" if code == "interrupted" else "failed"
                run.stage, run.error = "cleanup", messages.get(code, "Сбор данных завершился ошибкой; результаты не считаются успешными.")
                run.finished_at, run.credential, run.lease_until = now(), None, None
                audit(session, self.id, "run_stopped", run.id, code=code)

    def execute(self, run_id: str) -> None:
        process = None
        receiver = None
        try:
            with self.sessions() as session:
                run = authorized_run(session, run_id, self.id)
                connection = run_connection(self.vault, run)
                scope = dict(run.scope)
                assert run.credential_expires_at is not None  # authorized_run checked it.
                expiry = aware(run.credential_expires_at)
                session.commit()
            context = multiprocessing.get_context("spawn")
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(target=collect, args=(connection, scope, self.settings, run_id, self.id, sender), daemon=True)
            process.start()
            sender.close()
            del connection
            deadline = time.monotonic() + scope["timeout_seconds"]
            next_heartbeat = 0.0
            while True:
                if self.stopping:
                    raise DomainError("Stopped", "interrupted")
                if time.monotonic() >= deadline:
                    raise DomainError("Timeout", "timeout")
                if now() >= expiry:
                    raise DomainError("Token expired", "authorization_required")
                if time.monotonic() >= next_heartbeat:
                    with self.sessions.begin() as session:
                        run = authorized_run(session, run_id, self.id)
                        run.stage, run.lease_until = "execute", now() + timedelta(seconds=self.settings.lease_seconds)
                        self.pulse(session, "busy")
                    next_heartbeat = time.monotonic() + 1
                if receiver.poll(0.1):
                    try:
                        status, result = receiver.recv()
                    except EOFError:
                        raise DomainError("Collector exited", "scanner_failed") from None
                    if status != "ok":
                        raise DomainError("Collector error", result)
                    process.join(timeout=2)
                    with self.sessions.begin() as session:
                        run = authorized_run(session, run_id, self.id)
                        run_connection(self.vault, run)
                        save_result(session, run, result)
                        audit(session, self.id, "run_finished", run.id, status=run.status)
                    break
                if not process.is_alive():
                    raise DomainError("Collector exited", "scanner_failed")
        except DomainError as exc:
            self.finish_error(run_id, exc.code)
        except Exception:
            self.finish_error(run_id, "scanner_failed")
        finally:
            if process and process.is_alive():
                process.terminate()
                process.join(timeout=2)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=2)
            if receiver:
                receiver.close()

    def tick(self) -> bool:
        # Cleanup touches cascading auth rows. Commit it before taking run locks,
        # otherwise a concurrent scope revoke can wait on credentials we wait for.
        with self.sessions.begin() as session:
            require_runtime_schema(session)
            cleanup_expired_drafts(session)
        with self.sessions.begin() as session:
            require_runtime_schema(session)
            cleanup_expired_authorizations(session)
        with self.sessions.begin() as session:
            require_runtime_schema(session)
            recover(session)
            self.pulse(session, "idle")
            run_id = claim(session, self.id, self.settings.lease_seconds)
        if run_id:
            self.execute(run_id)
            return True
        return False

    def serve(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        # Worker scratch is private; the TLS loader owns its separate short-lived files.
        with tempfile.TemporaryDirectory(prefix="workbench-", dir=os.environ.get("TMPDIR")):
            while not self.stopping:
                try:
                    if not self.tick():
                        time.sleep(1)
                except Exception:
                    # Never log database connection strings or exception payloads.
                    print("worker: storage unavailable; retrying", flush=True)
                    time.sleep(3)
            with self.sessions.begin() as session:
                self.pulse(session, "stopped")
        self.engine.dispose()


def main() -> None:
    Runner(Settings.from_env()).serve()


if __name__ == "__main__":
    main()
