"""Explicit namespace onboarding and conservative legacy authorization cleanup."""

import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

from workbench.alembic.schema_v03 import metadata
from workbench.domain import DomainError

revision = "0003_namespace_selection"
down_revision = "0002_b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    schema = metadata()
    op.add_column(
        "clusters",
        sa.Column("lifecycle", sa.String(20), nullable=False, server_default="ready"),
    )
    if connection.dialect.name == "sqlite":
        # SQLite supports a nullable inline REFERENCES column. Rebuilding this
        # referenced parent table would cascade-delete auth/ACLs or fail on history.
        # Do not disable foreign keys or use batch table recreation here.
        connection.exec_driver_sql(
            "ALTER TABLE clusters ADD COLUMN draft_owner_id VARCHAR(36) "
            "REFERENCES users (id) ON DELETE CASCADE"
        )
    else:
        op.add_column(
            "clusters",
            sa.Column(
                "draft_owner_id",
                sa.String(36),
                sa.ForeignKey(
                    "users.id", name="fk_clusters_draft_owner", ondelete="CASCADE"
                ),
            ),
        )
    op.add_column("clusters", sa.Column("draft_expires_at", sa.DateTime(timezone=True)))
    op.create_index("ix_clusters_draft_expires_at", "clusters", ["draft_expires_at"])
    op.add_column("clusters", sa.Column("context_namespace_hint", sa.String(63)))

    timestamp = datetime.now(UTC)
    runs = schema.tables["runs"]
    for old_status, terminal in (("queued", "cancelled"), ("running", "interrupted")):
        connection.execute(
            runs.update()
            .where(runs.c.status == old_status)
            .values(
                status=terminal,
                stage="cleanup",
                cancel_requested=True,
                finished_at=timestamp,
                worker_id=None,
                lease_until=None,
                credential_expires_at=None,
                error="Stopped for namespace selection upgrade; authorize again before a new run.",
            )
        )
    # Historical scopes, results, token expiry and worker attribution stay intact.
    # Remove stale lease ownership if present, and all token snapshots even on
    # already terminal runs. A finished run's worker with no lease is just history.
    connection.execute(
        runs.update()
        .where(runs.c.lease_until.is_not(None))
        .values(lease_until=None, worker_id=None)
    )
    connection.execute(
        runs.update().where(runs.c.credential.is_not(None)).values(credential=None)
    )
    connection.execute(schema.tables["cluster_credentials"].delete())
    connection.execute(schema.tables["oidc_transactions"].delete())
    clusters = schema.tables["clusters"]
    connection.execute(
        clusters.update().values(auth_generation=clusters.c.auth_generation + 1)
    )
    bindings = schema.tables["authorization_bindings"]
    connection.execute(bindings.update().values(generation=bindings.c.generation + 1))
    connection.execute(
        schema.tables["audit_events"]
        .insert()
        .values(
            id=str(uuid.uuid4()),
            created_at=timestamp,
            actor="offline-admin",
            action="schema_upgraded",
            target="0.3.0",
            detail={"from": "0.2.0", "authorization_invalidated": True},
        )
    )
    connection.execute(sa.text("UPDATE workbench_schema SET version='0.3.0'"))


def downgrade() -> None:
    raise DomainError(
        "Namespace authorization invalidation is irreversible; restore a verified backup into an empty database."
    )
