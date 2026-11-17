"""Frozen 0.5.0 kubeconfig-only schema; never imports mutable application models."""

import sqlalchemy as sa

from workbench.alembic.schema_v04 import metadata as previous_metadata

AUTH_TYPE_CHECK = "auth_type = 'kubeconfig'"


def metadata() -> sa.MetaData:
    previous = previous_metadata()
    schema = sa.MetaData()
    replaced = {"clusters", "cluster_credentials", "runs"}
    removed = {"oidc_providers", "oidc_transactions"}
    for name, table in previous.tables.items():
        if name not in replaced | removed:
            table.to_metadata(schema)
    sa.Table(
        "clusters",
        schema,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("environment", sa.String(50), nullable=False),
        sa.Column("context", sa.String(250), nullable=False),
        sa.Column("server", sa.Text, nullable=False),
        sa.Column("ca_data", sa.Text),
        sa.Column("namespaces", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("auth_generation", sa.Integer, nullable=False, server_default="0"),
        sa.Column("lifecycle", sa.String(20), nullable=False, server_default="ready"),
        sa.Column(
            "draft_owner_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
        ),
        sa.Column("draft_expires_at", sa.DateTime(timezone=True), index=True),
        sa.Column("context_namespace_hint", sa.String(63)),
        sa.Column(
            "auth_type", sa.String(20), nullable=False, server_default="kubeconfig"
        ),
        sa.CheckConstraint(AUTH_TYPE_CHECK, name="ck_clusters_auth_type"),
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
        sa.Column("policy_revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column("auth_generation", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cluster_generation", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "storage_mode", sa.String(20), nullable=False, server_default="persistent"
        ),
        sa.Column(
            "session_hash",
            sa.String(64),
            sa.ForeignKey("sessions.token_hash", ondelete="CASCADE"),
        ),
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
        sa.Column("policy_revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column("auth_generation", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cluster_generation", sa.Integer, nullable=False, server_default="0"),
        sa.Column("credential_expires_at", sa.DateTime(timezone=True)),
    )
    return schema
