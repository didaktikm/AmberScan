"""Generate local-only configuration without connecting to any service."""

import argparse
import base64
import json
import os
import secrets
import stat
from pathlib import Path

from workbench.domain import DomainError

FILES = {"master-key", "database-url", "postgres-password", "config.json"}


def prepare_local(directory: Path) -> bool:
    if directory.is_symlink():
        raise DomainError("Refusing a symlink as local configuration directory.")
    if directory.exists():
        if not directory.is_dir():
            raise DomainError("Local configuration path is not a directory.")
        existing = {path.name for path in directory.iterdir()}
        if existing:
            if not FILES <= existing:
                raise DomainError(
                    "Partial local configuration exists. Nothing overwritten; inspect it before continuing."
                )
            for name in FILES:
                path = directory / name
                if path.is_symlink() or not path.is_file() or not path.stat().st_size:
                    raise DomainError(
                        "Existing local configuration is incomplete or unsafe; nothing overwritten."
                    )
                if stat.S_IMODE(path.stat().st_mode) & 0o077:
                    raise DomainError(
                        "Local secret files must have mode 0600; nothing changed."
                    )
            return False
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    password = secrets.token_urlsafe(36)
    contents = {
        "master-key": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode() + "\n",
        "postgres-password": password + "\n",
        "database-url": f"postgresql+psycopg://workbench:{password}@db:5432/workbench\n",
        "config.json": json.dumps(
            {
                "public_origin": "http://127.0.0.1:8080",
                "allowed_hosts": [],
                "allowed_cidrs": [],
                "retention_days": 90,
            },
            indent=2,
        )
        + "\n",
    }
    for name, content in contents.items():
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create local Compose secrets; never print or replace them"
    )
    parser.add_argument("--directory", type=Path, default=Path(".local"))
    args = parser.parse_args()
    try:
        created = prepare_local(args.directory)
    except (DomainError, OSError) as exc:
        message = (
            exc.message
            if isinstance(exc, DomainError)
            else "Cannot create local configuration. No secrets printed."
        )
        raise SystemExit(message) from None
    print(
        "Local configuration created."
        if created
        else "Existing local configuration kept; no secrets changed."
    )
    print(
        "Back up master-key separately from database backups. Network access is disabled until configured."
    )


if __name__ == "__main__":
    main()
