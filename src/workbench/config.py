"""Explicit configuration; no credentials or network destinations by default."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from workbench.domain import DomainError


def read_secret(variable: str) -> str:
    path = os.environ.get(variable)
    if not path:
        raise DomainError(f"Required secret file: {variable}", "configuration_required")
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise DomainError(f"Empty secret file: {variable}", "configuration_required")
    return value


@dataclass(frozen=True)
class Settings:
    database_url: str
    master_key: str
    public_origin: str = "http://127.0.0.1:8080"
    secure_cookie: bool = True
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    web_dist_dir: str = "frontend/dist"
    max_body_bytes: int = 1_048_576
    session_seconds: int = 28_800
    lease_seconds: int = 60
    max_queued_runs: int = 20
    retention_days: int = 90
    # Optional immutable ceiling; None allows explicit administrator configuration.
    egress_ceiling: list[dict] | None = None
    trivy_path: str | None = None
    kubescape_path: str | None = None
    operator_image: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        config_path = os.environ.get("WORKBENCH_CONFIG_FILE")
        config = json.loads(Path(config_path).read_text()) if config_path else {}
        database_url = read_secret("WORKBENCH_DATABASE_URL_FILE")
        if not database_url.startswith("postgresql+psycopg://"):
            raise DomainError(
                "PostgreSQL is required outside tests", "configuration_required"
            )
        origin = config.get("public_origin", "http://127.0.0.1:8080").rstrip("/")
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise DomainError("Invalid public_origin", "configuration_required")
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "127.0.0.1",
            "localhost",
            "::1",
        }
        if parsed.scheme != "https" and not local_http:
            raise DomainError(
                "HTTP is allowed only on loopback", "configuration_required"
            )
        # Project obsolete purpose rules without opening legacy provider secret files.
        # An explicitly empty ceiling remains deny-all, never unrestricted.
        ceiling = config.get("egress_ceiling")
        if ceiling is not None:
            from workbench.configuration import PURPOSES, validate_rules

            # Validate the full legacy ceiling before projection: dropping an invalid
            # rule or duplicate ID must not turn a formerly rejected policy usable.
            validate_rules(ceiling, allowed_purposes=PURPOSES | {"oidc"})
            ceiling = [rule for rule in ceiling if rule["purpose"] != "oidc"]
        return cls(
            database_url=database_url,
            master_key=read_secret("WORKBENCH_MASTER_KEY_FILE"),
            public_origin=origin,
            secure_cookie=not local_http,
            allowed_hosts=config.get("allowed_hosts", []),
            allowed_cidrs=config.get("allowed_cidrs", []),
            web_dist_dir=os.environ.get("WEB_DIST_DIR", "frontend/dist"),
            retention_days=int(config.get("retention_days", 90)),
            egress_ceiling=ceiling,
            trivy_path=_optional_absolute("WORKBENCH_TRIVY_BIN"),
            kubescape_path=_optional_absolute("WORKBENCH_KUBESCAPE_BIN"),
            operator_image=_optional_image("WORKBENCH_OPERATOR_IMAGE"),
        )


def _optional_absolute(variable: str) -> str | None:
    value = os.environ.get(variable, "").strip()
    if not value:
        return None
    if not value.startswith("/") or ".." in Path(value).parts:
        raise DomainError("Недопустимый путь закреплённого файла", "configuration_required")
    return value


def _optional_image(variable: str) -> str | None:
    value = os.environ.get(variable, "").strip()
    if not value:
        return None
    if (
        len(value) > 200
        or value.endswith(":latest")
        or ".." in value
        or any(char.isspace() for char in value)
        or (":" not in value and "@" not in value)
    ):
        raise DomainError("Нужен образ с явным тегом, не latest", "configuration_required")
    return value
