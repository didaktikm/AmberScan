"""Migrations only run through the guarded administration entrypoints."""

from alembic import context

from workbench.domain import DomainError

connection = context.config.attributes.get("connection")
if connection is None or not context.config.attributes.get("workbench_guarded"):
    raise DomainError(
        "Use workbench.admin init-db or upgrade; direct Alembic execution is disabled."
    )
context.configure(connection=connection, transactional_ddl=True, compare_type=True)
with context.begin_transaction():
    context.run_migrations()
