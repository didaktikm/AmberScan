"""Relational persistence shared by API and workers."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def uid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def iso(value: datetime | None) -> str | None:
    return aware(value).isoformat() if value else None


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class WebSession(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    reauthenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IntegrationPolicy(Base):
    __tablename__ = "integration_policy"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    rules: Mapped[list] = mapped_column(JSON, default=list)
    legacy_imported: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Cluster(Base):
    __tablename__ = "clusters"
    __table_args__ = (
        CheckConstraint(
            "auth_type = 'kubeconfig'",
            name="ck_clusters_auth_type",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    environment: Mapped[str] = mapped_column(String(50), default="test")
    context: Mapped[str] = mapped_column(String(250))
    server: Mapped[str] = mapped_column(Text)
    ca_data: Mapped[str | None] = mapped_column(Text)
    auth_type: Mapped[str] = mapped_column(
        String(20), default="kubeconfig", server_default="kubeconfig"
    )
    namespaces: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    auth_generation: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    lifecycle: Mapped[str] = mapped_column(
        String(20), default="ready", server_default="ready"
    )
    draft_owner_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE")
    )
    draft_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    context_namespace_hint: Mapped[str | None] = mapped_column(String(63))


class AuthorizationBinding(Base):
    __tablename__ = "authorization_bindings"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    cluster_id: Mapped[str] = mapped_column(
        ForeignKey("clusters.id", ondelete="CASCADE"), primary_key=True
    )
    generation: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class ClusterCredential(Base):
    __tablename__ = "cluster_credentials"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    cluster_id: Mapped[str] = mapped_column(
        ForeignKey("clusters.id", ondelete="CASCADE"), primary_key=True
    )
    encrypted: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    policy_revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    auth_generation: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    cluster_generation: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    storage_mode: Mapped[str] = mapped_column(
        String(20), default="persistent", server_default="persistent"
    )
    session_hash: Mapped[str | None] = mapped_column(
        ForeignKey("sessions.token_hash", ondelete="CASCADE")
    )


class ClusterGrant(Base):
    __tablename__ = "cluster_grants"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    cluster_id: Mapped[str] = mapped_column(
        ForeignKey("clusters.id", ondelete="CASCADE"), primary_key=True
    )


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    cluster_id: Mapped[str] = mapped_column(ForeignKey("clusters.id"), index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), index=True, default="queued")
    stage: Mapped[str] = mapped_column(String(32), default="prepare")
    scope: Mapped[dict] = mapped_column(JSON)
    credential: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    worker_id: Mapped[str | None] = mapped_column(String(100))
    lease_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    coverage: Mapped[list] = mapped_column(JSON, default=list)
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    versions: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(32), default="api")
    policy_revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    auth_generation: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    cluster_generation: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    credential_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    cluster_id: Mapped[str] = mapped_column(ForeignKey("clusters.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    disposition: Mapped[str] = mapped_column(String(30), default="open")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    latest_run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    data: Mapped[dict] = mapped_column(JSON)


class Observation(Base):
    __tablename__ = "observations"
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    data: Mapped[dict] = mapped_column(JSON)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, index=True
    )
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(100))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Worker(Base):
    __tablename__ = "workers"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    status: Mapped[str] = mapped_column(String(20), default="idle")


def database(url: str):
    options: dict = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            options["poolclass"] = StaticPool
    engine = create_engine(url, **options)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

    return engine, sessionmaker(engine, expire_on_commit=False)


def audit(session, actor: str, action: str, target: str, **detail) -> None:
    session.add(AuditEvent(actor=actor, action=action, target=target, detail=detail))
