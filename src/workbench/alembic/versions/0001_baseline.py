"""Literal 0.1.0 baseline, created only in an empty database."""

import sqlalchemy as sa
from alembic import op
from workbench.alembic.schema_v01 import metadata
from workbench.domain import DomainError

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if set(sa.inspect(connection).get_table_names()) - {"alembic_version"}:
        raise DomainError("Baseline creation requires an empty database.")
    schema = metadata()
    for table in schema.sorted_tables:
        table.create(connection, checkfirst=False)
    connection.execute(
        schema.tables["workbench_schema"].insert().values(version="0.1.0")
    )


def downgrade() -> None:
    raise DomainError(
        "Destructive downgrade is not supported; restore a verified backup into an empty database."
    )
