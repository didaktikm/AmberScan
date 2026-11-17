"""0.5 invalidates every identity; frozen historical schemas remain recoverable."""

import json

import pytest
import sqlalchemy as sa
from test_namespace_migrations import KEY, all_rows, table_rows
from test_namespace_migrations import b1 as source_database

from workbench import migrations
from workbench.backup import verify_database_key
from workbench.domain import DomainError
from workbench.security import Vault

b1 = source_database


@pytest.mark.parametrize("b1", ["0.4.0"], indirect=True)
@pytest.mark.parametrize("auth_type", ["oidc", "kubeconfig"])
@pytest.mark.parametrize("kind", ["token", "client_certificate"])
def test_04_upgrade_invalidates_all_modes_and_preserves_history(b1, auth_type, kind):
    vault = Vault(KEY)
    with b1.begin() as connection:
        old = migrations.schema_metadata("0.4.0")
        connection.execute(
            old.tables["clusters"]
            .update()
            .values(
                auth_type=auth_type,
                oidc_provider_id="idp" if auth_type == "oidc" else None,
            )
        )
        auth = (
            {"version": 1, "kind": kind, "token": "synthetic-only"}
            if kind == "token"
            else {
                "version": 1,
                "kind": kind,
                "certificate_pem": "synthetic-cert",
                "private_key_pem": "synthetic-key",
            }
        )
        for user_id in ("owner", "auditor"):
            connection.execute(
                old.tables["cluster_credentials"]
                .update()
                .where(old.tables["cluster_credentials"].c.user_id == user_id)
                .values(encrypted=vault.encrypt(auth, f"credential:{user_id}:cluster"))
            )
        for row in connection.execute(sa.select(old.tables["runs"].c.id)):
            connection.execute(
                old.tables["runs"]
                .update()
                .where(old.tables["runs"].c.id == row.id)
                .values(credential=vault.encrypt({"auth": auth}, f"run:{row.id}"))
            )
        kube_rule = {
            "id": "kube",
            "purpose": "kubernetes",
            "host": "kube.example.test",
            "port": 443,
            "cidrs": ["192.0.2.0/24"],
        }
        obsolete_rule = {**kube_rule, "id": "old", "purpose": "oidc"}
        connection.execute(
            old.tables["integration_policy"]
            .update()
            .values(rules=[obsolete_rule, kube_rule])
        )
        before = all_rows(connection)
        assert verify_database_key(connection, KEY) == 10
    preview = migrations.upgrade_database(b1)
    assert preview["invalidate"] == {"cluster_credentials": 2, "oidc_transactions": 1}
    assert preview["clear_run_credentials"] == 6
    with b1.connect() as connection:
        assert all_rows(connection) == before
    migrations.upgrade_database(
        b1, apply=True, backup_confirmed=True, offline_confirmed=True
    )
    with b1.connect() as connection:
        assert migrations.verify_schema(connection) == "0.5.0"
        assert not connection.exec_driver_sql("PRAGMA foreign_key_check").all()
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert not {"oidc_providers", "oidc_transactions"} & set(
            sa.inspect(connection).get_table_names()
        )
        assert not table_rows(connection, "cluster_credentials")
        assert verify_database_key(connection, KEY) == 0
        for name in (
            "users",
            "sessions",
            "cluster_grants",
            "findings",
            "observations",
            "workers",
        ):
            assert table_rows(connection, name) == before[name]
        cluster = table_rows(connection, "clusters")[0]
        assert cluster == {
            **{
                k: v
                for k, v in before["clusters"][0].items()
                if k != "oidc_provider_id"
            },
            "auth_type": "kubeconfig",
            "auth_generation": 5,
        }
        assert table_rows(connection, "authorization_bindings") == [
            {**row, "generation": 7} for row in before["authorization_bindings"]
        ]
        policy = table_rows(connection, "integration_policy")[0]
        assert policy["revision"] == 8
        assert json.loads(policy["rules"]) == [kube_rule]
        assert (
            policy["legacy_imported"]
            == before["integration_policy"][0]["legacy_imported"]
        )
        after = {row["id"]: row for row in table_rows(connection, "runs")}
        for original in before["runs"]:
            run = after[original["id"]]
            assert "provider_revision" not in run
            assert run["credential"] is None and run["lease_until"] is None
            if original["status"] in {"queued", "running"}:
                assert (
                    run["status"]
                    == {"queued": "cancelled", "running": "interrupted"}[
                        original["status"]
                    ]
                )
                assert run["stage"] == "cleanup" and run["cancel_requested"]
                assert run["finished_at"] and run["credential_expires_at"] is None
                assert run["worker_id"] is None
                assert "import kubeconfig again" in run["error"]
                for field in (
                    "scope",
                    "coverage",
                    "limitations",
                    "versions",
                    "created_at",
                    "started_at",
                    "source",
                ):
                    assert run[field] == original[field]
            else:
                expected = {
                    k: v for k, v in original.items() if k != "provider_revision"
                }
                expected["credential"] = None
                if original["lease_until"]:
                    expected.update(lease_until=None, worker_id=None)
                assert run == expected
        assert before["audit_events"][0] in table_rows(connection, "audit_events")
        assert len(table_rows(connection, "audit_events")) == 2


VALID_KUBE_RULE = {
    "id": "kube",
    "purpose": "kubernetes",
    "host": "kube.example.test",
    "port": 443,
    "cidrs": ["192.0.2.0/24"],
}
VALID_OLD_RULE = {**VALID_KUBE_RULE, "id": "old", "purpose": "oidc"}
MALFORMED_POLICIES = [
    None,
    {},
    "invalid",
    [None],
    [{"purpose": "oidc"}],
    [{"purpose": "unknown"}],
    # Filtering must never turn a previously invalid policy into working egress.
    [VALID_KUBE_RULE, {**VALID_OLD_RULE, "id": "kube"}],
    [
        VALID_KUBE_RULE,
        VALID_OLD_RULE,
        {**VALID_OLD_RULE, "id": "another", "host": "KUBE.EXAMPLE.TEST"},
    ],
    *[
        [VALID_KUBE_RULE, {**VALID_OLD_RULE, "host": host}]
        for host in (
            "localhost",
            "foo.localhost",
            "metadata.google.internal",
            "metadata.goog",
            "127.0.0.1",
            "169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
            "fd00:ec2::254",
            "64:ff9b::c000:201",
            "https://idp.example.test",
            "idp.example.test.",
            "bad host",
            "bad/host",
            "bad\\host",
            "-bad.test",
        )
    ],
    *[
        [VALID_KUBE_RULE, {**VALID_OLD_RULE, "id": value}]
        for value in ("", "bad id", "a" * 101)
    ],
    *[
        [VALID_KUBE_RULE, {**VALID_OLD_RULE, "cidrs": value}]
        for value in (
            [],
            ["192.0.2.1"],
            ["192.0.2.0/24"] * 2,
            ["127.0.0.0/8"],
            ["192.0.2.0/24"] * 65,
            ["192.0.2.1/24"],
        )
    ],
    [VALID_KUBE_RULE, {**VALID_OLD_RULE, "port": True}],
    [VALID_KUBE_RULE, {**VALID_OLD_RULE, "purpose": []}],
]


@pytest.mark.parametrize("b1", ["0.2.0", "0.3.0", "0.4.0"], indirect=True)
@pytest.mark.parametrize("rules", MALFORMED_POLICIES)
def test_malformed_policy_refuses_without_schema_or_data_changes(b1, rules):
    with b1.begin() as connection:
        policy = migrations.schema_metadata(
            migrations.verify_schema(connection)
        ).tables["integration_policy"]
        connection.execute(policy.update().values(rules=rules))
        before = all_rows(connection)
    with pytest.raises(DomainError, match="Malformed persisted egress policy"):
        migrations.upgrade_database(
            b1, apply=True, backup_confirmed=True, offline_confirmed=True
        )
    with b1.connect() as connection:
        assert all_rows(connection) == before
        assert verify_database_key(connection, KEY) == 10
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1


@pytest.mark.parametrize("b1", ["0.4.0"], indirect=True)
@pytest.mark.parametrize(
    "rules",
    [
        [],
        [
            {
                "id": "old",
                "purpose": "oidc",
                "host": "idp.example.test",
                "port": 443,
                "cidrs": ["192.0.2.0/24"],
            }
        ],
    ],
)
def test_empty_or_obsolete_only_policy_remains_deny_all(b1, rules):
    with b1.begin() as connection:
        policy = migrations.schema_metadata("0.4.0").tables["integration_policy"]
        connection.execute(policy.update().values(rules=rules))
    migrations.upgrade_database(
        b1, apply=True, backup_confirmed=True, offline_confirmed=True
    )
    with b1.connect() as connection:
        row = table_rows(connection, "integration_policy")[0]
        assert json.loads(row["rules"]) == []
        assert row["revision"] == 8


@pytest.mark.parametrize("b1", ["0.2.0", "0.3.0", "0.4.0"], indirect=True)
def test_non_oidc_purposes_and_exact_retained_values_survive(b1):
    retained = [
        {
            **VALID_KUBE_RULE,
            "id": purpose,
            "purpose": purpose,
            "host": "KUBE.EXAMPLE.TEST",
            "cidrs": ["198.51.100.0/24", "192.0.2.0/24"],
        }
        for purpose in ("kubernetes", "registry", "database")
    ]
    with b1.begin() as connection:
        policy = migrations.schema_metadata(
            migrations.verify_schema(connection)
        ).tables["integration_policy"]
        connection.execute(policy.update().values(rules=[VALID_OLD_RULE, *retained]))
    migrations.upgrade_database(
        b1, apply=True, backup_confirmed=True, offline_confirmed=True
    )
    with b1.connect() as connection:
        assert (
            json.loads(table_rows(connection, "integration_policy")[0]["rules"])
            == retained
        )


@pytest.mark.parametrize("b1", ["0.2.0", "0.3.0", "0.4.0"], indirect=True)
@pytest.mark.parametrize(
    "table,column",
    [
        ("oidc_providers", "encrypted_secret"),
        ("oidc_transactions", "encrypted"),
        ("cluster_credentials", "encrypted"),
        ("runs", "credential"),
    ],
)
def test_historical_key_verification_never_skips_obsolete_ciphertext(b1, table, column):
    with b1.begin() as connection:
        assert verify_database_key(connection, KEY) == 10
        connection.execute(sa.text(f"UPDATE {table} SET {column}='invalid-ciphertext'"))
        with pytest.raises(DomainError, match="Master key"):
            verify_database_key(connection, KEY)
