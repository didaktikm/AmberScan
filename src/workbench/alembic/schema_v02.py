"""Frozen B1 additions; independent of the current application's ORM models."""

import sqlalchemy as sa

from workbench.alembic.schema_v01 import metadata as baseline_metadata

REVISION_COLUMNS = (
    "provider_revision",
    "policy_revision",
    "auth_generation",
    "cluster_generation",
)


def metadata() -> sa.MetaData:
    schema = baseline_metadata()
    schema.tables["sessions"].append_column(
        sa.Column("reauthenticated_at", sa.DateTime(timezone=True))
    )
    schema.tables["clusters"].append_column(
        sa.Column("auth_generation", sa.Integer, nullable=False, server_default="0")
    )
    for name in ("cluster_credentials", "oidc_transactions", "runs"):
        for column in REVISION_COLUMNS:
            schema.tables[name].append_column(
                sa.Column(column, sa.Integer, nullable=False, server_default="0")
            )
    schema.tables["cluster_credentials"].append_column(
        sa.Column(
            "storage_mode", sa.String(20), nullable=False, server_default="persistent"
        )
    )
    schema.tables["cluster_credentials"].append_column(
        sa.Column(
            "session_hash",
            sa.String(64),
            sa.ForeignKey("sessions.token_hash", ondelete="CASCADE"),
        )
    )
    schema.tables["oidc_transactions"].append_column(
        sa.Column(
            "storage_mode", sa.String(20), nullable=False, server_default="run_only"
        )
    )
    schema.tables["runs"].append_column(
        sa.Column("credential_expires_at", sa.DateTime(timezone=True))
    )
    sa.Table(
        "integration_policy",
        schema,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("revision", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rules", sa.JSON, nullable=False),
        sa.Column(
            "legacy_imported", sa.Boolean, nullable=False, server_default="false"
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    sa.Table(
        "oidc_providers",
        schema,
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("config", sa.JSON, nullable=False),
        sa.Column("encrypted_secret", sa.Text),
        sa.Column("verification", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    sa.Table(
        "authorization_bindings",
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
        sa.Column("generation", sa.Integer, nullable=False, server_default="0"),
    )
    sa.Table(
        "alembic_version",
        schema,
        sa.Column("version_num", sa.String(32), primary_key=True),
    )
    return schema
