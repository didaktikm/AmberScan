"""Offline bootstrap: no default password and no public setup endpoint."""

import argparse
import getpass
import json
import sys

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from workbench.backup import backup_database, restore_database, verify_database_key
from workbench.config import Settings
from workbench.db import Cluster, ClusterGrant, User, audit, database
from workbench.domain import DomainError
from workbench.migrations import (
    SCHEMA_VERSION,
    guarded_transaction,
    init_database,  # re-export for existing bootstrap callers
    require_latest,
    require_offline,
    schema_status,
    upgrade_database,
)
from workbench.security import Vault, password_hash

ROLES = ("administrator", "auditor", "viewer", "security_lead")


def create_user(session, username: str, password: str, role: str) -> None:
    if (
        not username
        or len(username) > 100
        or username != username.strip()
        or any(ord(c) < 32 for c in username)
    ):
        raise DomainError(
            "Username must be 1..100 visible characters without outer spaces."
        )
    if role not in ROLES:
        raise DomainError("Unknown role.")
    if not 14 <= len(password) <= 256:
        raise DomainError("Password length must be 14..256 characters.")
    if session.scalar(select(User.id).where(User.username == username)):
        raise DomainError("User already exists; password was not changed.")
    session.add(
        User(username=username, role=role, password_hash=password_hash(password))
    )
    audit(session, "offline-admin", "user_created", username, role=role)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Workbench local administration; secrets are read only from configured files"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "init-db",
        help="Create latest schema in an empty dedicated database; never auto-upgrade",
    )
    commands.add_parser(
        "status", help="Read-only schema and encryption-key verification"
    )
    upgrade = commands.add_parser(
        "upgrade",
        help="Preview 0.1/0.2/0.3/0.4 to 0.5 migration; apply requires explicit backup and stop acknowledgements",
    )
    upgrade.add_argument("--apply", action="store_true")
    upgrade.add_argument("--backup-confirmed", action="store_true")
    upgrade.add_argument("--offline-confirmed", action="store_true")
    legacy = commands.add_parser(
        "import-legacy",
        help="Preview static legacy Kubernetes egress import; no automatic startup merge",
    )
    legacy.add_argument("--apply", action="store_true")
    legacy.add_argument("--offline-confirmed", action="store_true")
    for name in ("backup", "restore"):
        operation = commands.add_parser(
            name,
            help=f"Offline PostgreSQL {name}; external master key is never included",
        )
        operation.add_argument(
            "path", help="Custom archive path; adjacent .manifest.json is required"
        )
        operation.add_argument("--offline-confirmed", action="store_true")
        operation.add_argument("--timeout", type=int, default=300)
        operation.add_argument(
            "--pg-dump" if name == "backup" else "--pg-restore",
            default="pg_dump" if name == "backup" else "pg_restore",
            help="PostgreSQL client executable, not a shell command",
        )
    create = commands.add_parser(
        "create-user", help="Create a local account; password prompted without echo"
    )
    create.add_argument("username")
    create.add_argument("--role", choices=ROLES, required=True)
    grant = commands.add_parser(
        "grant", help="Grant an existing user access to an existing cluster"
    )
    grant.add_argument("username")
    grant.add_argument("cluster_id")
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    vault = Vault(settings.master_key)
    engine, sessions = database(settings.database_url)
    try:
        if args.command == "init-db":
            init_database(engine)
            print(
                f"Schema {SCHEMA_VERSION} ready. Existing legacy databases require explicit upgrade."
            )
            return
        if args.command == "status":
            with engine.connect() as connection:
                version = schema_status(connection)
                checked = (
                    verify_database_key(connection, settings.master_key)
                    if version != "empty"
                    else 0
                )
            print(
                json.dumps(
                    {
                        "schema_version": version,
                        "encrypted_values_checked": checked,
                        "key_evidence": "verified ciphertext"
                        if checked
                        else "no encrypted values; historical key cannot be verified",
                    }
                )
            )
            return
        if args.command == "upgrade":
            result = upgrade_database(
                engine,
                apply=args.apply,
                backup_confirmed=args.backup_confirmed,
                offline_confirmed=args.offline_confirmed,
            )
            print(json.dumps(result, indent=2))
            return
        if args.command in {"backup", "restore"}:
            operation = (
                backup_database if args.command == "backup" else restore_database
            )
            tool = (
                {"pg_dump": args.pg_dump}
                if args.command == "backup"
                else {"pg_restore": args.pg_restore}
            )
            result = operation(
                engine,
                args.path,
                settings.master_key,
                offline_confirmed=args.offline_confirmed,
                timeout=args.timeout,
                **tool,
            )
            print(json.dumps(result))
            return
        if args.command == "import-legacy":
            from sqlalchemy.orm import Session

            from workbench.configuration import import_legacy_configuration

            with guarded_transaction(engine) as connection:
                require_latest(connection)
                if args.apply:
                    if not args.offline_confirmed:
                        raise DomainError(
                            "Legacy import requires stopped API/workers and --offline-confirmed."
                        )
                    require_offline(connection)
                with Session(bind=connection) as session:
                    result = import_legacy_configuration(
                        session, settings, vault, apply=args.apply
                    )
                    session.flush()
            print(json.dumps(result, indent=2))
            return
        with sessions.begin() as session:
            require_latest(session.connection())
            if args.command == "create-user":
                if session.scalar(
                    select(User.id).where(User.username == args.username)
                ):
                    raise DomainError("User already exists; password was not changed.")
                if not sys.stdin.isatty():
                    raise DomainError(
                        "Interactive terminal required. Do not pipe passwords or pass them in argv."
                    )
                password = getpass.getpass("New password (14..256 characters): ")
                if getpass.getpass("Repeat password: ") != password:
                    raise DomainError("Passwords differ.")
                create_user(session, args.username, password, args.role)
                print("Local account created.")
            elif args.command == "grant":
                user = session.scalar(
                    select(User).where(User.username == args.username)
                )
                cluster = session.get(Cluster, args.cluster_id)
                if not user or not cluster:
                    raise DomainError("User or cluster not found.")
                if cluster.lifecycle != "ready":
                    raise DomainError(
                        "Cluster drafts cannot be granted; finalize the connection first.",
                        "connection_not_ready",
                    )
                session.merge(ClusterGrant(user_id=user.id, cluster_id=args.cluster_id))
                audit(
                    session,
                    "offline-admin",
                    "cluster_grant",
                    args.cluster_id,
                    username=user.username,
                )
                print(
                    "Cluster access granted; Kubernetes authentication remains personal."
                )
    finally:
        engine.dispose()


def cli() -> None:
    """Sanitized error boundary for both module and installed console entrypoints."""
    try:
        main()
    except DomainError as exc:
        raise SystemExit(exc.message) from None
    except (SQLAlchemyError, OSError, ValueError):
        raise SystemExit(
            "Storage or secret file unavailable. Check configuration; no secret values printed."
        ) from None


if __name__ == "__main__":
    cli()
