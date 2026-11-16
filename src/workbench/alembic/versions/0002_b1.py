"""B1 configuration revisions and explicit legacy authorization invalidation."""

import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from workbench.alembic.schema_v02 import REVISION_COLUMNS, metadata
from workbench.domain import DomainError

revision = "0002_b1"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    schema = metadata()
    # The guarded upgrade holds the advisory lock and verifies the exact old
    # structure before Alembic adopts it. No ORM or network is used here.
    for name in ("integration_policy", "oidc_providers", "authorization_bindings"):
        schema.tables[name].create(connection, checkfirst=False)
    op.add_column(
        "sessions", sa.Column("reauthenticated_at", sa.DateTime(timezone=True))
    )
    op.add_column(
        "clusters",
        sa.Column("auth_generation", sa.Integer, nullable=False, server_default="0"),
    )
    for name in ("cluster_credentials", "oidc_transactions", "runs"):
        for column in REVISION_COLUMNS:
            op.add_column(
                name, sa.Column(column, sa.Integer, nullable=False, server_default="0")
            )
    # SQLite cannot ADD CONSTRAINT; its empty auth table is recreated with
    # Alembic batch operations after credentials are explicitly invalidated.
    connection.execute(sa.text("DELETE FROM cluster_credentials"))
    connection.execute(sa.text("DELETE FROM oidc_transactions"))
    with op.batch_alter_table("cluster_credentials") as batch:
        batch.add_column(
            sa.Column(
                "storage_mode",
                sa.String(20),
                nullable=False,
                server_default="persistent",
            )
        )
        batch.add_column(sa.Column("session_hash", sa.String(64), nullable=True))
        batch.create_foreign_key(
            "fk_cluster_credentials_session",
            "sessions",
            ["session_hash"],
            ["token_hash"],
            ondelete="CASCADE",
        )
    op.add_column(
        "oidc_transactions",
        sa.Column(
            "storage_mode", sa.String(20), nullable=False, server_default="run_only"
        ),
    )
    op.add_column(
        "runs", sa.Column("credential_expires_at", sa.DateTime(timezone=True))
    )
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
                credential=None,
                lease_until=None,
                worker_id=None,
                finished_at=timestamp,
                error="Stopped for B1 upgrade; authorize again before a new run.",
            )
        )
    # No completed observations or findings are changed; stale token snapshots
    # must not survive merely because their run had already reached a terminal state.
    connection.execute(
        runs.update().where(runs.c.credential.is_not(None)).values(credential=None)
    )
    connection.execute(
        schema.tables["integration_policy"]
        .insert()
        .values(
            id=1,
            revision=0,
            rules=[],
            legacy_imported=False,
            updated_at=timestamp,
        )
    )
    connection.execute(
        schema.tables["audit_events"]
        .insert()
        .values(
            id=str(uuid.uuid4()),
            created_at=timestamp,
            actor="offline-admin",
            action="schema_upgraded",
            target="0.2.0",
            detail={"from": "0.1.0", "authorization_invalidated": True},
        )
    )
    connection.execute(sa.text("UPDATE workbench_schema SET version='0.2.0'"))


def downgrade() -> None:
    raise DomainError(
        "B1 authorization invalidation is irreversible; restore a verified backup into an empty database."
    )
