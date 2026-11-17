"""Guarded, transactional Alembic entrypoints; never infer a version from tables."""

import re
from contextlib import contextmanager
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from workbench.alembic.schema_v01 import metadata as baseline_metadata
from workbench.alembic.schema_v02 import metadata as b1_metadata
from workbench.alembic.schema_v03 import metadata as namespace_metadata
from workbench.alembic.schema_v04 import metadata as kubeconfig_metadata
from workbench.alembic.schema_v05 import metadata as current_metadata
from workbench.domain import DomainError

BASELINE_VERSION = "0.1.0"
B1_VERSION = "0.2.0"
NAMESPACE_VERSION = "0.3.0"
KUBECONFIG_VERSION = "0.4.0"
SCHEMA_VERSION = "0.5.0"
BASELINE_REVISION = "0001_baseline"
B1_REVISION = "0002_b1"
NAMESPACE_REVISION = "0003_namespace_selection"
KUBECONFIG_REVISION = "0004_kubeconfig_auth"
HEAD_REVISION = "0005_remove_oidc"
VERSION_REVISIONS = {
    BASELINE_VERSION: BASELINE_REVISION,
    B1_VERSION: B1_REVISION,
    NAMESPACE_VERSION: NAMESPACE_REVISION,
    KUBECONFIG_VERSION: KUBECONFIG_REVISION,
    SCHEMA_VERSION: HEAD_REVISION,
}
SUPPORTED_VERSIONS = tuple(VERSION_REVISIONS)
ADVISORY_LOCK = 716203104


def require_runtime_schema(connection) -> None:
    """Cheap fail-closed runtime gate; full structural validation belongs to admin."""
    version = (
        connection.execute(sa.text("SELECT version FROM workbench_schema"))
        .scalars()
        .all()
    )
    if version != [SCHEMA_VERSION]:
        raise DomainError(
            "Требуется явное обновление схемы БД; остановите API/воркеры и используйте offline upgrade",
            "schema_upgrade_required",
        )
    revision = (
        connection.execute(sa.text("SELECT version_num FROM alembic_version"))
        .scalars()
        .all()
    )
    if revision != [HEAD_REVISION]:
        raise DomainError(
            "Версия миграций БД не соответствует приложению", "schema_upgrade_required"
        )


def _refuse(
    message: str = "Unsupported schema structure; no changes made.",
) -> DomainError:
    return DomainError(message, "schema_unsupported")


def _default(value) -> str | None:
    if value is None:
        return None
    # PostgreSQL reflection casts string defaults; SQLite does not. Strip only
    # syntactic quotes/casts, never lowercase or truncate the literal itself.
    raw = str(value).strip()
    literal = re.fullmatch(
        r"'((?:[^']|'')*)'(?:::(?:character varying|text|boolean|integer))?", raw
    )
    return literal.group(1).replace("''", "'") if literal else raw


def _type(value, dialect) -> str:
    return value.compile(dialect=dialect).upper()


def _sqlite_draft_owner_options(connection) -> dict:
    """SQLAlchemy omits inline FK options; accept only our literal ADD COLUMN form."""
    sql = connection.execute(
        sa.text("SELECT sql FROM sqlite_master WHERE type='table' AND name='clusters'")
    ).scalar_one()
    # Reject appended DEFERRABLE/INITIALLY clauses rather than inferring missing
    # reflection options. Table-level FKs are reflected normally and skip this.
    if not re.search(
        r",\s*draft_owner_id VARCHAR\(36\) REFERENCES users \(id\) "
        r"ON DELETE CASCADE\s*(?=,|\))",
        sql,
    ):
        return {}
    constraints = connection.exec_driver_sql(
        'PRAGMA foreign_key_list("clusters")'
    ).all()
    if len(constraints) != 1 or tuple(constraints[0][2:7]) != (
        "users",
        "draft_owner_id",
        "id",
        "NO ACTION",
        "CASCADE",
    ):
        return {}
    return {"ondelete": "CASCADE"}


def _verify_tables(connection, schema: sa.MetaData) -> None:
    inspector = sa.inspect(connection)
    if set(inspector.get_table_names()) != set(schema.tables):
        raise _refuse()
    if inspector.get_view_names():
        raise _refuse()
    if (
        connection.dialect.name == "sqlite"
        and connection.execute(
            sa.text("SELECT count(*) FROM sqlite_master WHERE type='trigger'")
        ).scalar_one()
    ):
        raise _refuse()
    if connection.dialect.name == "postgresql":
        if inspector.default_schema_name != "public":
            raise _refuse("Workbench requires its dedicated public schema.")
        # A marker is not permission to adopt a database containing unrelated objects.
        extra = connection.execute(
            sa.text("""
            SELECT EXISTS (
                SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname NOT IN ('public', 'information_schema')
                  AND n.nspname NOT LIKE 'pg_%' AND c.relkind IN ('r','p','v','m','S','f')
                UNION ALL
                SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg_%'
                UNION ALL
                SELECT 1 FROM pg_trigger WHERE NOT tgisinternal
                UNION ALL
                SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND (c.relrowsecurity OR c.relforcerowsecurity OR c.relkind IN ('p','f'))
                UNION ALL
                SELECT 1 FROM pg_rules WHERE schemaname='public'
            )
        """)
        ).scalar_one()
        if extra or inspector.get_materialized_view_names():
            raise _refuse()
        sequences = set(inspector.get_sequence_names())
        expected_sequences = (
            {"integration_policy_id_seq"}
            if "integration_policy" in schema.tables
            else set()
        )
        if sequences != expected_sequences:
            raise _refuse()
    for name, table in schema.tables.items():
        columns = {column["name"]: column for column in inspector.get_columns(name)}
        if set(columns) != set(table.columns.keys()):
            raise _refuse()
        for expected in table.columns:
            actual = columns[expected.name]
            nullable = expected.nullable
            if expected.primary_key and connection.dialect.name == "postgresql":
                nullable = False
            if actual["nullable"] != nullable or _type(
                actual["type"], connection.dialect
            ) != _type(expected.type, connection.dialect):
                raise _refuse()
            default = actual.get("default")
            serial = (
                name == "integration_policy"
                and expected.name == "id"
                and connection.dialect.name == "postgresql"
            )
            if serial:
                if not default or not default.startswith(
                    "nextval('integration_policy_id_seq'"
                ):
                    raise _refuse()
            elif _default(default) != _default(
                expected.server_default.arg
                if expected.server_default is not None
                else None
            ):
                raise _refuse()
        pk = inspector.get_pk_constraint(name).get("constrained_columns") or []
        if pk != [column.name for column in table.primary_key]:
            raise _refuse()
        actual_unique = {
            tuple(item["column_names"])
            for item in inspector.get_unique_constraints(name)
        }
        expected_unique = {
            tuple(column.name for column in item.columns)
            for item in table.constraints
            if isinstance(item, sa.UniqueConstraint)
        }
        if actual_unique != expected_unique:
            raise _refuse()
        expected_checks = {
            (constraint.name, str(constraint.sqltext))
            for constraint in table.constraints
            if isinstance(constraint, sa.CheckConstraint)
        }
        actual_checks = inspector.get_check_constraints(name)
        if connection.dialect.name == "postgresql" and expected_checks:
            # PostgreSQL deparses our expression with casts and SQL precedence.
            # Accept only this exact parse output, not arbitrary CHECKs, stripped
            # parentheses, or a permissive substring match.
            if connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_constraint c "
                    "JOIN pg_class t ON t.oid=c.conrelid "
                    "JOIN pg_namespace n ON n.oid=t.relnamespace "
                    "WHERE n.nspname='public' AND t.relname=:table "
                    "AND c.contype='c' AND (NOT c.convalidated OR c.connoinherit)"
                ),
                {"table": name},
            ).scalar_one():
                raise _refuse()
            postgres_checks = {
                "ck_clusters_auth_type": "auth_type::text = 'kubeconfig'::text",
                "ck_clusters_auth_provider": (
                    "auth_type::text = 'oidc'::text AND oidc_provider_id IS NOT NULL OR "
                    "auth_type::text = 'kubeconfig'::text AND oidc_provider_id IS NULL"
                ),
            }
            expected_checks = {
                (key, postgres_checks[key]) for key, _ in expected_checks
            }
            # Version-specific frozen checks only.
        if (
            len(actual_checks) != len(expected_checks)
            or {
                (constraint["name"], constraint["sqltext"])
                for constraint in actual_checks
            }
            != expected_checks
        ):
            raise _refuse()
        expected_fk = set()
        for constraint in table.foreign_key_constraints:
            expected_fk.add(
                (
                    tuple(column.name for column in constraint.columns),
                    tuple(element.column.name for element in constraint.elements),
                    constraint.referred_table.name,
                    constraint.ondelete or "NO ACTION",
                    constraint.onupdate or "NO ACTION",
                    bool(constraint.deferrable),
                    constraint.initially or "IMMEDIATE",
                )
            )
        actual_fk = set()
        for constraint in inspector.get_foreign_keys(name):
            if constraint.get("referred_schema") not in (None, "public"):
                raise _refuse()
            options = constraint.get("options", {})
            if (
                connection.dialect.name == "sqlite"
                and name == "clusters"
                and constraint["constrained_columns"] == ["draft_owner_id"]
                and not options
            ):
                options = _sqlite_draft_owner_options(connection)
            actual_fk.add(
                (
                    tuple(constraint["constrained_columns"]),
                    tuple(constraint["referred_columns"]),
                    constraint["referred_table"],
                    options.get("ondelete", "NO ACTION"),
                    options.get("onupdate", "NO ACTION"),
                    bool(options.get("deferrable")),
                    options.get("initially", "IMMEDIATE"),
                )
            )
        if actual_fk != expected_fk:
            raise _refuse()
        indexes = [
            index
            for index in inspector.get_indexes(name)
            if not index.get("duplicates_constraint")
        ]
        actual_indexes = {
            (index["name"], tuple(index["column_names"]), bool(index["unique"]))
            for index in indexes
        }
        expected_indexes = {
            (
                index.name,
                tuple(column.name for column in index.columns),
                bool(index.unique),
            )
            for index in table.indexes
        }
        if actual_indexes != expected_indexes:
            raise _refuse()
        for index in indexes:
            options = index.get("dialect_options", {})
            if (
                options.get("postgresql_where") is not None
                or options.get("sqlite_where") is not None
                or options.get("postgresql_using", "btree") != "btree"
                or options.get("postgresql_include")
                or index.get("expressions")
                or index.get("column_sorting")
            ):
                raise _refuse()


def assert_empty_database(connection) -> None:
    inspector = sa.inspect(connection)
    if inspector.get_table_names() or inspector.get_view_names():
        raise _refuse("Database is not empty; refusing changes.")
    if connection.dialect.name == "postgresql":
        if inspector.default_schema_name != "public":
            raise _refuse("Workbench requires its dedicated public schema.")
        occupied = connection.execute(
            sa.text("""
            SELECT EXISTS (
                SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg_%'
                  AND c.relkind IN ('r','p','v','m','S','f')
                UNION ALL
                SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg_%'
            )
        """)
        ).scalar_one()
        if occupied:
            raise _refuse("Database is not empty; refusing changes.")


def schema_metadata(version: str) -> sa.MetaData:
    """Return only a frozen supported schema, never the mutable current models."""
    factories = {
        BASELINE_VERSION: baseline_metadata,
        B1_VERSION: b1_metadata,
        NAMESPACE_VERSION: namespace_metadata,
        KUBECONFIG_VERSION: kubeconfig_metadata,
        SCHEMA_VERSION: current_metadata,
    }
    factory = factories.get(version)
    if factory is None:
        raise _refuse(
            "Unsupported schema version; restore or use an explicit migration."
        )
    return factory()


def schema_status(connection) -> str:
    tables = set(sa.inspect(connection).get_table_names())
    if not tables:
        assert_empty_database(connection)
        return "empty"
    if "workbench_schema" not in tables:
        raise _refuse(
            "Database is not empty and has no Workbench schema marker. Refusing changes."
        )
    # Inspect the marker before selecting anything from a possibly foreign table.
    marker = sa.inspect(connection).get_columns("workbench_schema")
    if (
        len(marker) != 1
        or marker[0]["name"] != "version"
        or _type(marker[0]["type"], connection.dialect) != "VARCHAR(32)"
    ):
        raise _refuse()
    versions = (
        connection.execute(sa.text("SELECT version FROM workbench_schema"))
        .scalars()
        .all()
    )
    if len(versions) != 1 or versions[0] not in SUPPORTED_VERSIONS:
        raise _refuse(
            "Unsupported schema version; restore or use an explicit migration."
        )
    version = versions[0]
    _verify_tables(connection, schema_metadata(version))
    if version != BASELINE_VERSION:
        expected_revision = VERSION_REVISIONS[version]
        revisions = (
            connection.execute(sa.text("SELECT version_num FROM alembic_version"))
            .scalars()
            .all()
        )
        if revisions != [expected_revision]:
            raise _refuse()
    return version


def verify_schema(connection) -> str:
    version = schema_status(connection)
    if version == "empty":
        raise _refuse("Database is empty; run init-db or restore explicitly.")
    return version


def require_latest(connection) -> None:
    if verify_schema(connection) != SCHEMA_VERSION:
        raise _refuse(
            "Schema upgrade required; stop API/workers and use the offline upgrade command."
        )


def require_offline(connection) -> None:
    """Best-effort stop check; the operator must also prevent new connections."""
    if connection.dialect.name == "postgresql":
        others = connection.execute(
            sa.text("""
            SELECT count(*) FROM pg_stat_activity
            WHERE datname=current_database() AND pid<>pg_backend_pid()
              AND backend_type='client backend'
        """)
        ).scalar_one()
        if others:
            raise DomainError(
                "Stop API, workers and other database clients before this operation.",
                "maintenance_required",
            )


@contextmanager
def guarded_transaction(engine, *, sqlite_rebuild: bool = False):
    with engine.connect() as connection:
        rebuild = sqlite_rebuild and connection.dialect.name == "sqlite"
        if rebuild:
            # Must precede BEGIN: disabling inside a transaction is a silent no-op.
            # This connection is exclusively held through validation and commit.
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
        try:
            with connection.begin():
                if connection.dialect.name == "postgresql":
                    acquired = connection.execute(
                        sa.text("SELECT pg_try_advisory_xact_lock(:key)"),
                        {"key": ADVISORY_LOCK},
                    ).scalar_one()
                    if not acquired:
                        raise DomainError(
                            "Another database administration operation is active.",
                            "maintenance_required",
                        )
                    connection.execute(sa.text("SET LOCAL lock_timeout='5s'"))
                elif connection.dialect.name == "sqlite":
                    # pysqlite otherwise delays BEGIN until DML and can auto-commit DDL.
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                else:
                    raise _refuse(
                        "Only PostgreSQL (and isolated SQLite tests) are supported."
                    )
                yield connection
                if (
                    rebuild
                    and connection.exec_driver_sql("PRAGMA foreign_key_check").all()
                ):
                    raise _refuse(
                        "Foreign key validation failed; migration rolled back."
                    )
        finally:
            if rebuild:
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
                connection.commit()
                if connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 1:
                    connection.invalidate()
                    raise _refuse("Could not restore SQLite foreign key enforcement.")


def _config(connection) -> Config:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).with_name("alembic")))
    config.attributes.update(connection=connection, workbench_guarded=True)
    return config


def init_database(engine) -> None:
    """Create latest schema only when empty; never implicitly upgrade an old DB."""
    with guarded_transaction(engine, sqlite_rebuild=True) as connection:
        version = schema_status(connection)
        if version == SCHEMA_VERSION:
            return
        if version != "empty":
            raise _refuse(
                "Schema upgrade required; use upgrade with backup and offline confirmations."
            )
        command.upgrade(_config(connection), HEAD_REVISION)
        require_latest(connection)


def upgrade_database(
    engine,
    *,
    apply: bool = False,
    backup_confirmed: bool = False,
    offline_confirmed: bool = False,
) -> dict:
    """Preview by default; adopt a verified 0.1 baseline or upgrade a verified revision."""
    with guarded_transaction(engine, sqlite_rebuild=apply) as connection:
        version = verify_schema(connection)
        preview = {
            "from_version": version,
            "to_version": SCHEMA_VERSION,
            "applied": False,
            "changes_required": version != SCHEMA_VERSION,
        }
        if version == SCHEMA_VERSION:
            return preview
        preview["invalidate"] = {
            name: connection.execute(
                sa.text(f"SELECT count(*) FROM {name}")
            ).scalar_one()
            for name in ("cluster_credentials", "oidc_transactions")
        }
        preview["runs"] = {
            status: connection.execute(
                sa.text("SELECT count(*) FROM runs WHERE status=:status"),
                {"status": status},
            ).scalar_one()
            for status in ("queued", "running")
        }
        preview["clear_run_credentials"] = connection.execute(
            sa.text("SELECT count(*) FROM runs WHERE credential IS NOT NULL")
        ).scalar_one()
        preview["clear_run_leases"] = connection.execute(
            sa.text("SELECT count(*) FROM runs WHERE lease_until IS NOT NULL")
        ).scalar_one()
        preview["preserved"] = [
            "users",
            "sessions",
            "clusters",
            "cluster_grants",
            "findings",
            "observations",
            "run history",
            "audit history",
        ]
        if version != BASELINE_VERSION:
            preview["preserved"].extend(
                ["integration_policy (non-OIDC rules only)", "authorization_bindings"]
            )
        preview["removed"] = [
            "oidc_providers",
            "oidc_transactions",
            "provider references",
        ]
        preview["requirements"] = [
            "verified backup and separate master key",
            "stop API/workers and prevent reconnects",
            "personal Kubernetes authorization again",
        ]
        if version == BASELINE_VERSION:
            preview["requirements"].append(
                "reconfigure/import Kubernetes egress policy"
            )
        if not apply:
            return preview
        if not backup_confirmed or not offline_confirmed:
            raise DomainError(
                "Upgrade requires --backup-confirmed and --offline-confirmed after stopping API/workers.",
                "maintenance_required",
            )
        require_offline(connection)
        config = _config(connection)
        # Only the exact unversioned 0.1 schema may be adopted. Existing Alembic
        # revisions (including B1) advance directly; never stamp over their history.
        if version == BASELINE_VERSION:
            command.stamp(config, BASELINE_REVISION)
        command.upgrade(config, HEAD_REVISION)
        require_latest(connection)
        preview["applied"] = True
        return preview
