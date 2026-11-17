"""Small offline PostgreSQL recovery utility, not a backup orchestration service.

Archives contain sensitive database state, but never the external master key.
Only trusted archives produced by this module are accepted for restore. PostgreSQL
archive restore executes SQL, so access to both archives and the key is privileged.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.engine import make_url

from workbench.domain import DomainError
from workbench.migrations import (
    SUPPORTED_VERSIONS,
    assert_empty_database,
    guarded_transaction,
    require_offline,
    schema_metadata,
    verify_schema,
)
from workbench.security import Vault

MANIFEST_FORMAT = "workbench-backup-v1"
KEY_PURPOSE = "backup-manifest:v1"
MANIFEST_LIMIT = 16 * 1024
MAX_TIMEOUT = 3600


def _error(message: str) -> DomainError:
    return DomainError(message, "recovery_failed")


def _manifest_path(path: Path) -> Path:
    return path.with_name(path.name + ".manifest.json")


def _check_parent(path: Path) -> None:
    # Resolve neither the output nor symlinks: do not follow a link into a secret
    # directory or replace another file. Operators create a dedicated directory.
    if any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise _error("Use a real dedicated backup directory, not a symlink.")
    if not path.parent.is_dir():
        raise _error("Create the backup directory before running this command.")
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o022:
        raise _error("Backup directory must not be group/world writable.")


def _exclusive_file(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        raise _error(
            "Cannot create backup output; existing files are never overwritten."
        ) from None
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "wb")


def _read_file(path: Path):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise _error("Backup inputs must be regular files with mode 0600.")
        # pg_restore inherits the raw descriptor. A BufferedReader may seek only
        # inside its Python buffer, leaving the inherited OS offset past PGDMP.
        return os.fdopen(descriptor, "rb", buffering=0)
    except OSError:
        raise _error("Backup input unavailable; symlinks are not accepted.") from None


def _checksum(handle) -> tuple[str, int]:
    handle.seek(0)
    digest = hashlib.sha256()
    size = 0
    while block := handle.read(1024 * 1024):
        digest.update(block)
        size += len(block)
    handle.seek(0)
    return digest.hexdigest(), size


def verify_database_key(connection, master_key: str) -> int:
    """Decrypt all stored encrypted values without returning/logging plaintext.

    A source with no encrypted values has no historical key evidence. The backup
    manifest still binds its supplied key so wrong-key restore fails even then.
    Obsolete OIDC tables below are an offline archive-compatibility allowlist only:
    all ciphertext in supported 0.1–0.4 backups must still authenticate before
    restore/upgrade, even though the 0.5 runtime has no such models or flows.
    """
    vault = Vault(master_key)
    tables = set(sa.inspect(connection).get_table_names())
    checked = 0
    queries = [
        (
            "cluster_credentials",
            "SELECT user_id, cluster_id, encrypted FROM cluster_credentials",
            lambda row: f"credential:{row.user_id}:{row.cluster_id}",
            "encrypted",
        ),
        (
            "oidc_transactions",
            "SELECT state_hash, encrypted FROM oidc_transactions",
            lambda row: f"oidc:{row.state_hash}",
            "encrypted",
        ),
        (
            "runs",
            "SELECT id, credential FROM runs WHERE credential IS NOT NULL",
            lambda row: f"run:{row.id}",
            "credential",
        ),
        (
            "oidc_providers",
            "SELECT id, revision, encrypted_secret FROM oidc_providers WHERE encrypted_secret IS NOT NULL",
            lambda row: f"provider:{row.id}:{row.revision}",
            "encrypted_secret",
        ),
    ]
    try:
        for table, query, purpose, column in queries:
            if table not in tables:
                continue
            for row in connection.execute(
                sa.text(query), execution_options={"stream_results": True}
            ):
                vault.decrypt(getattr(row, column), purpose(row))
                checked += 1
    except DomainError:
        raise _error(
            "Master key does not decrypt database credentials; no backup/restore accepted."
        ) from None
    return checked


def _pgpass_field(value: str) -> str:
    if any(character in value for character in ("\n", "\r", "\x00")):
        raise _error("PostgreSQL connection settings contain unsupported characters.")
    return value.replace("\\", "\\\\").replace(":", "\\:")


@contextmanager
def postgres_environment(url):
    """Credentials live only in a temporary 0600 pgpass, never argv or diagnostics."""
    try:
        parsed = make_url(url) if isinstance(url, str) else url
        if parsed.get_backend_name() != "postgresql" or not all(
            (parsed.host, parsed.username, parsed.database)
        ):
            raise ValueError
        host, user, dbname = (
            str(parsed.host),
            str(parsed.username),
            str(parsed.database),
        )
        port = str(parsed.port or 5432)
        password = str(parsed.password or "")
        options = {
            "sslmode": "PGSSLMODE",
            "sslrootcert": "PGSSLROOTCERT",
            "sslcert": "PGSSLCERT",
            "sslkey": "PGSSLKEY",
            "channel_binding": "PGCHANNELBINDING",
        }
        if set(parsed.query) - set(options):
            raise ValueError
        if any(not isinstance(value, str) for value in parsed.query.values()):
            raise ValueError
        # Do not allow environment DBNAME to be reinterpreted as a conninfo URI.
        if "=" in dbname or dbname.startswith(("postgres://", "postgresql://")):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise _error(
            "Unsupported PostgreSQL connection configuration for recovery."
        ) from None
    fields = [_pgpass_field(value) for value in (host, port, dbname, user, password)]
    with tempfile.TemporaryDirectory(prefix="workbench-pgpass-") as temporary:
        os.chmod(temporary, 0o700)
        pgpass = Path(temporary) / "pgpass"
        with _exclusive_file(pgpass) as handle:
            handle.write((":".join(fields) + "\n").encode("utf-8"))
        # Deliberate allowlist: no inherited PGPASSWORD, PGOPTIONS, service files,
        # application master key, database URL or legacy OIDC secret environment.
        environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": temporary,
            "PGHOST": host,
            "PGPORT": port,
            "PGDATABASE": dbname,
            "PGUSER": user,
            "PGPASSFILE": str(pgpass),
            "PGCONNECT_TIMEOUT": "10",
            "PGAPPNAME": "workbench-offline-recovery",
            "LC_ALL": "C",
        }
        environment.update({options[key]: value for key, value in parsed.query.items()})
        yield environment


def _run(
    argv: list[str], *, environment: dict, timeout: int, stdin=None, stdout=None
) -> None:
    if not 1 <= timeout <= MAX_TIMEOUT:
        raise _error(f"Timeout must be between 1 and {MAX_TIMEOUT} seconds.")
    try:
        result = subprocess.run(
            argv,
            env=environment,
            stdin=stdin if stdin is not None else subprocess.DEVNULL,
            stdout=stdout if stdout is not None else subprocess.DEVNULL,
            # Never collect unbounded diagnostics (which may contain secrets).
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        raise _error(
            "PostgreSQL client tool missing; use the maintenance image with matching pg_dump/pg_restore."
        ) from None
    except subprocess.TimeoutExpired:
        raise _error(
            "PostgreSQL recovery command timed out; operation not accepted."
        ) from None
    except OSError:
        raise _error("PostgreSQL recovery command could not start.") from None
    if result.returncode != 0:
        raise _error(
            "PostgreSQL recovery command failed; check server/tool compatibility and database permissions."
        )


def _postgres_only(engine, offline_confirmed: bool) -> None:
    if engine.dialect.name != "postgresql":
        raise _error(
            "Backup and restore require PostgreSQL; SQLite is only for migration tests."
        )
    if not offline_confirmed:
        raise _error(
            "Stop API/workers, prevent reconnects, then pass --offline-confirmed."
        )


def backup_database(
    engine,
    path,
    master_key: str,
    *,
    offline_confirmed: bool = False,
    pg_dump: str = "pg_dump",
    timeout: int = 300,
) -> dict:
    _postgres_only(engine, offline_confirmed)
    Vault(master_key)
    path = Path(path).absolute()
    _check_parent(path)
    manifest_path = _manifest_path(path)
    created = []
    try:
        # Reserve BOTH files before any external command. O_EXCL also rejects links.
        with _exclusive_file(path) as archive:
            created.append(path)
            with _exclusive_file(manifest_path) as manifest_file:
                created.append(manifest_path)
                with guarded_transaction(engine) as connection:
                    require_offline(connection)
                    version = verify_schema(connection)
                    schema = schema_metadata(version)
                    names = ", ".join(
                        connection.dialect.identifier_preparer.quote(name)
                        for name in sorted(schema.tables)
                    )
                    # Lock all known tables against mutation/DDL for key validation.
                    # pg_dump uses ACCESS SHARE and can use this exported snapshot.
                    connection.execute(sa.text(f"LOCK TABLE {names} IN SHARE MODE"))
                    checked = verify_database_key(connection, master_key)
                    snapshot = connection.execute(
                        sa.text("SELECT pg_export_snapshot()")
                    ).scalar_one()
                    with postgres_environment(engine.url) as environment:
                        _run(
                            [
                                pg_dump,
                                "--format=custom",
                                "--no-owner",
                                "--no-acl",
                                "--no-password",
                                f"--snapshot={snapshot}",
                            ],
                            environment=environment,
                            timeout=timeout,
                            stdout=archive,
                        )
                archive.flush()
                os.fsync(archive.fileno())
                with _read_file(path) as input_file:
                    digest, size = _checksum(input_file)
                    if size < 5 or input_file.read(5) != b"PGDMP":
                        raise _error(
                            "PostgreSQL client did not produce a custom archive."
                        )
                claims = {
                    "format": MANIFEST_FORMAT,
                    "schema_version": version,
                    "sha256": digest,
                    "size": size,
                    "created_at": datetime.now(UTC).isoformat(),
                    "encrypted_values_checked": checked,
                }
                manifest = dict(
                    claims, key_check=Vault(master_key).encrypt(claims, KEY_PURPOSE)
                )
                manifest_file.write(
                    json.dumps(manifest, sort_keys=True).encode("utf-8") + b"\n"
                )
                manifest_file.flush()
                os.fsync(manifest_file.fileno())
        return {
            "schema_version": version,
            "size": size,
            "encrypted_values_checked": checked,
            "master_key_included": False,
        }
    except BaseException:
        # Only remove outputs created in this call, never preexisting paths.
        for output in reversed(created):
            output.unlink(missing_ok=True)
        raise


def _verify_archive(archive, manifest_file, master_key: str) -> dict:
    try:
        raw = manifest_file.read(MANIFEST_LIMIT + 1)
        if len(raw) > MANIFEST_LIMIT:
            raise ValueError
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise TypeError
        claims = {key: value for key, value in manifest.items() if key != "key_check"}
        if set(claims) != {
            "format",
            "schema_version",
            "sha256",
            "size",
            "created_at",
            "encrypted_values_checked",
        }:
            raise ValueError
        if (
            claims["format"] != MANIFEST_FORMAT
            or claims["schema_version"] not in SUPPORTED_VERSIONS
        ):
            raise ValueError
        if Vault(master_key).decrypt(manifest["key_check"], KEY_PURPOSE) != claims:
            raise ValueError
    except (DomainError, KeyError, ValueError, TypeError, UnicodeError):
        raise _error(
            "Backup manifest or master key verification failed; target unchanged."
        ) from None
    digest, size = _checksum(archive)
    if (
        digest != claims["sha256"]
        or size != claims["size"]
        or archive.read(5) != b"PGDMP"
    ):
        raise _error(
            "Backup archive checksum/format verification failed; target unchanged."
        )
    archive.seek(0)
    return claims


def restore_database(
    engine,
    path,
    master_key: str,
    *,
    offline_confirmed: bool = False,
    pg_restore: str = "pg_restore",
    timeout: int = 300,
) -> dict:
    _postgres_only(engine, offline_confirmed)
    path = Path(path).absolute()
    _check_parent(path)
    with _read_file(path) as archive, _read_file(_manifest_path(path)) as manifest_file:
        # Reject wrong keys and tampered archives BEFORE connecting to the target.
        claims = _verify_archive(archive, manifest_file, master_key)
        with guarded_transaction(engine) as connection:
            require_offline(connection)
            assert_empty_database(connection)
            with postgres_environment(engine.url) as environment:
                # Input fd avoids shell/path parsing. No --clean or --create: never
                # drop another database. pg_restore's transaction rolls back errors.
                _run(
                    [
                        pg_restore,
                        "--dbname=" + str(engine.url.database),
                        "--single-transaction",
                        "--exit-on-error",
                        "--no-owner",
                        "--no-acl",
                        "--no-password",
                    ],
                    environment=environment,
                    timeout=timeout,
                    stdin=archive,
                )
            # pg_restore owns its separate transaction. Failure of checks here must
            # quarantine the restored target, not erase potentially valuable data.
            version = verify_schema(connection)
            checked = verify_database_key(connection, master_key)
            if (
                version != claims["schema_version"]
                or checked != claims["encrypted_values_checked"]
            ):
                raise _error(
                    "Restored database verification failed; keep target offline and investigate. No data was deleted."
                )
    return {
        "schema_version": version,
        "encrypted_values_checked": checked,
        "verified": True,
    }
