"""Frozen 0.3.0 namespace onboarding schema; never import mutable ORM models."""

import sqlalchemy as sa

from workbench.alembic.schema_v02 import metadata as b1_metadata


def metadata() -> sa.MetaData:
    schema = b1_metadata()
    clusters = schema.tables["clusters"]
    clusters.append_column(
        sa.Column("lifecycle", sa.String(20), nullable=False, server_default="ready")
    )
    clusters.append_column(
        sa.Column(
            "draft_owner_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
        )
    )
    clusters.append_column(
        sa.Column("draft_expires_at", sa.DateTime(timezone=True), index=True)
    )
    clusters.append_column(sa.Column("context_namespace_hint", sa.String(63)))
    return schema
