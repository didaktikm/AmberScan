"""Remove obsolete authentication and invalidate ALL Kubernetes authorizations."""

import ipaddress
import re
import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

from workbench.alembic.schema_v04 import metadata as previous_metadata
from workbench.alembic.schema_v05 import AUTH_TYPE_CHECK
from workbench.domain import DomainError

revision = "0005_remove_oidc"
down_revision = "0004_kubeconfig_auth"
branch_labels = None
depends_on = None


# Freeze the historical syntax/security guards: importing mutable runtime helpers
# would make the same archive migrate differently after a future application change.
_DENIED_ADDRESSES = frozenset(
    ipaddress.ip_address(value)
    for value in ("100.100.100.200", "168.63.129.16", "fd00:ec2::254")
)
_TRANSLATION_RANGES = tuple(
    ipaddress.ip_network(value) for value in ("64:ff9b::/96", "64:ff9b:1::/48")
)


def _canonical_host(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError
    if (
        value.endswith(".")
        or any(char in value for char in "%/@\\?#[]")
        or any(char.isspace() for char in value)
    ):
        raise ValueError
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if ":" in value:
            raise ValueError from None
        host = value.encode("idna").decode("ascii").lower()
        if len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError from None
        return host


def _intrinsically_denied(address) -> bool:
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address in _DENIED_ADDRESSES
    ):
        return True
    if address.version == 6:
        return bool(address.ipv4_mapped or address.sixtofour or address.teredo) or any(
            address in network for network in _TRANSLATION_RANGES
        )
    return False


def _retained_rules(rules: object) -> list[dict]:
    """Reject ambiguous policy data; delete only explicit obsolete-purpose rules.

    Frozen validation deliberately neither imports runtime policy code nor rewrites
    retained endpoints/CIDRs. An empty result remains deny-all, never unrestricted.
    """
    try:
        if not isinstance(rules, list) or len(rules) > 128:
            raise ValueError
        ids, endpoints = set(), set()
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {
                "id",
                "purpose",
                "host",
                "port",
                "cidrs",
            }:
                raise ValueError
            if rule["purpose"] not in {"oidc", "kubernetes", "registry", "database"}:
                raise ValueError
            if not isinstance(rule["id"], str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", rule["id"]
            ):
                raise ValueError
            host = _canonical_host(rule["host"])
            if (
                host == "localhost"
                or host.endswith(".localhost")
                or host in {"metadata.google.internal", "metadata.goog"}
            ):
                raise ValueError
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and _intrinsically_denied(address):
                raise ValueError
            if type(rule["port"]) is not int or not 1 <= rule["port"] <= 65535:
                raise ValueError
            if not isinstance(rule["cidrs"], list) or not 1 <= len(rule["cidrs"]) <= 64:
                raise ValueError
            networks = []
            for cidr in rule["cidrs"]:
                if not isinstance(cidr, str) or "/" not in cidr:
                    raise ValueError
                network = ipaddress.ip_network(cidr, strict=True)
                if _intrinsically_denied(network.network_address):
                    raise ValueError
                networks.append(str(network))
            endpoint = (rule["purpose"], host, rule["port"])
            if (
                len(networks) != len(set(networks))
                or rule["id"] in ids
                or endpoint in endpoints
            ):
                raise ValueError
            ids.add(rule["id"])
            endpoints.add(endpoint)
        return [rule for rule in rules if rule["purpose"] != "oidc"]
    except (ValueError, TypeError, UnicodeError, KeyError):
        raise DomainError(
            "Malformed persisted egress policy; migration refused without changes.",
            "schema_unsupported",
        ) from None


def upgrade() -> None:
    connection = op.get_bind()
    schema = previous_metadata()
    timestamp = datetime.now(UTC)
    policy = schema.tables["integration_policy"]
    # Validate all rows before mutation; do not silently discard malformed rules.
    policies = [
        (row.id, row.revision, _retained_rules(row.rules))
        for row in connection.execute(sa.select(policy))
    ]
    for policy_id, policy_revision, rules in policies:
        connection.execute(
            policy.update()
            .where(policy.c.id == policy_id)
            .values(
                rules=rules,
                # Revision zero is an unconfigured policy, eligible for offline import.
                revision=policy_revision + 1 if policy_revision else 0,
                updated_at=timestamp,
            )
        )
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
                error="Stopped for kubeconfig-only authentication upgrade; import kubeconfig again before a new run.",
            )
        )
    connection.execute(
        runs.update()
        .where(runs.c.lease_until.is_not(None))
        .values(lease_until=None, worker_id=None)
    )
    connection.execute(
        runs.update().where(runs.c.credential.is_not(None)).values(credential=None)
    )
    connection.execute(schema.tables["cluster_credentials"].delete())
    op.drop_table("oidc_transactions")
    op.drop_table("oidc_providers")
    clusters = schema.tables["clusters"]
    # This transition satisfies the OLD check too; no identity is synthesized.
    connection.execute(
        clusters.update().values(
            auth_type="kubeconfig",
            oidc_provider_id=None,
            auth_generation=clusters.c.auth_generation + 1,
        )
    )
    bindings = schema.tables["authorization_bindings"]
    connection.execute(bindings.update().values(generation=bindings.c.generation + 1))

    if connection.dialect.name == "sqlite":
        if connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 0:
            raise DomainError(
                "SQLite parent rebuild requires the guarded offline migration entrypoint."
            )
        # Frozen copy keeps FK actions; entrypoint disables them BEFORE BEGIN and
        # verifies all dependents before committing the parent rebuild.
        with op.batch_alter_table(
            "clusters", recreate="always", copy_from=clusters
        ) as batch:
            batch.drop_constraint("ck_clusters_auth_provider", type_="check")
            batch.drop_column("oidc_provider_id")
            batch.alter_column(
                "auth_type", existing_type=sa.String(20), server_default="kubeconfig"
            )
            batch.create_check_constraint("ck_clusters_auth_type", AUTH_TYPE_CHECK)
        op.create_index(
            "ix_clusters_draft_expires_at", "clusters", ["draft_expires_at"]
        )
        for name in ("cluster_credentials", "runs"):
            with op.batch_alter_table(
                name, recreate="always", copy_from=schema.tables[name]
            ) as batch:
                batch.drop_column("provider_revision")
        for column in ("cluster_id", "status", "lease_until"):
            op.create_index(f"ix_runs_{column}", "runs", [column])
    else:
        op.drop_constraint("ck_clusters_auth_provider", "clusters", type_="check")
        op.drop_column("clusters", "oidc_provider_id")
        op.alter_column(
            "clusters",
            "auth_type",
            existing_type=sa.String(20),
            server_default="kubeconfig",
        )
        op.create_check_constraint("ck_clusters_auth_type", "clusters", AUTH_TYPE_CHECK)
        for name in ("cluster_credentials", "runs"):
            op.drop_column(name, "provider_revision")
    connection.execute(
        schema.tables["audit_events"]
        .insert()
        .values(
            id=str(uuid.uuid4()),
            created_at=timestamp,
            actor="offline-admin",
            action="schema_upgraded",
            target="0.5.0",
            detail={"from": "0.4.0", "authorization_invalidated": True},
        )
    )
    connection.execute(sa.text("UPDATE workbench_schema SET version='0.5.0'"))


def downgrade() -> None:
    raise DomainError(
        "Authorization invalidation is irreversible; restore a verified backup into an empty database."
    )
