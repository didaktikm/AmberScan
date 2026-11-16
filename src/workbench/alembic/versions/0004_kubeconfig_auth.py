"""Personal kubeconfig authentication; explicitly invalidate prior authorization."""

import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

from workbench.alembic.schema_v03 import metadata as previous_metadata
from workbench.alembic.schema_v04 import AUTH_PROVIDER_CHECK, metadata
from workbench.domain import DomainError

revision = "0004_kubeconfig_auth"
down_revision = "0003_namespace_selection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        if connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 0:
            raise DomainError(
                "SQLite parent rebuild requires the guarded offline migration entrypoint."
            )
        # Frozen copy avoids SQLite's loss of inline FK options on reflection.
        # The entrypoint disables FK actions BEFORE BEGIN and checks every FK
        # before committing; DROP/rename cannot cascade into grants or history.
        with op.batch_alter_table(
            "clusters",
            recreate="always",
            copy_from=previous_metadata().tables["clusters"],
        ) as batch:
            batch.alter_column(
                "oidc_provider_id", existing_type=sa.String(100), nullable=True
            )
            batch.add_column(
                sa.Column(
                    "auth_type", sa.String(20), nullable=False, server_default="oidc"
                )
            )
            batch.create_check_constraint(
                "ck_clusters_auth_provider", AUTH_PROVIDER_CHECK
            )
        op.create_index(
            "ix_clusters_draft_expires_at", "clusters", ["draft_expires_at"]
        )
    else:
        op.alter_column(
            "clusters", "oidc_provider_id", existing_type=sa.String(100), nullable=True
        )
        op.add_column(
            "clusters",
            sa.Column(
                "auth_type", sa.String(20), nullable=False, server_default="oidc"
            ),
        )
        op.create_check_constraint(
            "ck_clusters_auth_provider", "clusters", AUTH_PROVIDER_CHECK
        )

    schema = metadata()
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
                error="Stopped for kubeconfig authentication upgrade; authorize again before a new run.",
            )
        )
    # Terminal history retains scopes/results/timestamps and worker attribution
    # unless it still owned a lease. Every encrypted run snapshot is removed.
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
            target="0.4.0",
            detail={"from": "0.3.0", "authorization_invalidated": True},
        )
    )
    connection.execute(sa.text("UPDATE workbench_schema SET version='0.4.0'"))


def downgrade() -> None:
    raise DomainError(
        "Kubeconfig authorization invalidation is irreversible; restore a verified backup into an empty database."
    )
