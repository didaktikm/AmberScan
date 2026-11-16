"""Frozen 0.1.0 schema, captured before B1 model changes.

Do not import the application's mutable Base here. This literal metadata is both
our initial Alembic revision and the allowlist for adopting an old schema marker.
Python-side ORM defaults were not database defaults in 0.1.0.
"""

import sqlalchemy as sa


def metadata() -> sa.MetaData:
    schema = sa.MetaData()
    sa.Table(
        "users",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(100), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("active", sa.Boolean, nullable=False),
        sa.Column("failed_logins", sa.Integer, nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
    )
    sa.Table(
        "login_attempts",
        schema,
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("count", sa.Integer, nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
    )
    sa.Table(
        "sessions",
        schema,
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    sa.Table(
        "clusters",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("environment", sa.String(50), nullable=False),
        sa.Column("context", sa.String(250), nullable=False),
        sa.Column("server", sa.Text, nullable=False),
        sa.Column("ca_data", sa.Text),
        sa.Column("oidc_provider_id", sa.String(100), nullable=False),
        sa.Column("namespaces", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    sa.Table(
        "cluster_credentials",
        schema,
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "cluster_id",
            sa.String(36),
            sa.ForeignKey("clusters.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("encrypted", sa.Text, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    sa.Table(
        "cluster_grants",
        schema,
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "cluster_id",
            sa.String(36),
            sa.ForeignKey("clusters.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    sa.Table(
        "oidc_transactions",
        schema,
        sa.Column("state_hash", sa.String(64), primary_key=True),
        sa.Column(
            "session_hash",
            sa.String(64),
            sa.ForeignKey("sessions.token_hash", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "cluster_id",
            sa.String(36),
            sa.ForeignKey("clusters.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("encrypted", sa.Text, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    sa.Table(
        "runs",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "cluster_id",
            sa.String(36),
            sa.ForeignKey("clusters.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, index=True),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("scope", sa.JSON, nullable=False),
        sa.Column("credential", sa.Text),
        sa.Column("cancel_requested", sa.Boolean, nullable=False),
        sa.Column("worker_id", sa.String(100)),
        sa.Column("lease_until", sa.DateTime(timezone=True), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text),
        sa.Column("coverage", sa.JSON, nullable=False),
        sa.Column("limitations", sa.JSON, nullable=False),
        sa.Column("versions", sa.JSON, nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
    )
    sa.Table(
        "findings",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "cluster_id",
            sa.String(36),
            sa.ForeignKey("clusters.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("disposition", sa.String(30), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "latest_run_id", sa.String(36), sa.ForeignKey("runs.id"), nullable=False
        ),
        sa.Column("data", sa.JSON, nullable=False),
    )
    sa.Table(
        "observations",
        schema,
        sa.Column(
            "run_id",
            sa.String(36),
            sa.ForeignKey("runs.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("data", sa.JSON, nullable=False),
    )
    sa.Table(
        "audit_events",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("actor", sa.String(100), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("target", sa.String(100), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False),
    )
    sa.Table(
        "workers",
        schema,
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
    )
    # The original init-db used raw SQL PRIMARY KEY without NOT NULL. SQLite
    # reflects that nullable; PostgreSQL implicitly makes a primary key NOT NULL.
    sa.Table(
        "workbench_schema",
        schema,
        sa.Column("version", sa.String(32), primary_key=True, nullable=True),
    )
    return schema
