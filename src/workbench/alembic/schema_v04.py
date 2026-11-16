"""Frozen 0.4.0 kubeconfig authentication schema; independent of mutable models."""

import sqlalchemy as sa

from workbench.alembic.schema_v03 import metadata as namespace_metadata

AUTH_PROVIDER_CHECK = (
    "(auth_type = 'oidc' AND oidc_provider_id IS NOT NULL) OR "
    "(auth_type = 'kubeconfig' AND oidc_provider_id IS NULL)"
)


def metadata() -> sa.MetaData:
    schema = namespace_metadata()
    clusters = schema.tables["clusters"]
    clusters.c.oidc_provider_id.nullable = True
    clusters.append_column(
        sa.Column("auth_type", sa.String(20), nullable=False, server_default="oidc")
    )
    clusters.append_constraint(
        sa.CheckConstraint(AUTH_PROVIDER_CHECK, name="ck_clusters_auth_provider")
    )
    return schema
