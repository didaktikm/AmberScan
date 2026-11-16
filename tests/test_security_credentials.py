"""Synthetic inline credentials and mTLS tests; no network or personal files."""

import base64
import copy
import json
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from workbench import configuration, scanners, security
from workbench.domain import DomainError


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", Mock(side_effect=AssertionError("No DNS"))
    )
    monkeypatch.setattr(
        socket, "socket", Mock(side_effect=AssertionError("No sockets"))
    )


@pytest.fixture
def config():
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {"name": "cluster", "cluster": {"server": "https://cluster.test:6443"}}
        ],
        "users": [
            {"name": "selected", "user": {"token": "selected-secret"}},
            {"name": "other", "user": {"token": "other-secret"}},
        ],
        "contexts": [
            {"name": "selected", "context": {"cluster": "cluster", "user": "selected"}},
            {"name": "other", "context": {"cluster": "cluster", "user": "other"}},
        ],
    }


def make_identity(
    *,
    before=-1,
    after=1,
    eku=ExtendedKeyUsageOID.CLIENT_AUTH,
    ca=False,
    digital_signature=True,
    issuer=None,
    key=None,
):
    key = key or ec.generate_private_key(ec.SECP256R1())
    common_name = (
        "synthetic-ca"
        if ca
        else "cluster.test"
        if eku == ExtendedKeyUsageOID.SERVER_AUTH
        else "synthetic-client"
    )
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    current = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer[0].subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current + timedelta(days=before))
        .not_valid_after(current + timedelta(days=after))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    if eku == ExtendedKeyUsageOID.SERVER_AUTH:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("cluster.test")]), critical=False
        )
    cert = builder.sign(issuer[1] if issuer else key, hashes.SHA256())
    auth = {
        "version": 1,
        "kind": "client_certificate",
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "private_key_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    }
    return auth, cert, key


@pytest.fixture
def identity():
    return make_identity()[0]


def install_identity(config, identity):
    config["users"][0]["user"] = {
        "client-certificate-data": base64.b64encode(
            identity["certificate_pem"].encode()
        ).decode(),
        "client-key-data": base64.b64encode(
            identity["private_key_pem"].encode()
        ).decode(),
    }


def test_only_selected_token_extracted_inspection_stays_secret_free(config):
    text = yaml.safe_dump(config)
    result = security.extract_kubeconfig_credentials(text, "selected")
    assert result == {
        "metadata": security.inspect_kubeconfig(text)[0],
        "auth": {"version": 1, "kind": "token", "token": "selected-secret"},
        "source_expires_at": None,
    }
    assert "other-secret" not in str(result)
    assert "secret" not in json.dumps(security.inspect_kubeconfig(text))
    with pytest.raises(DomainError, match="context"):
        security.extract_kubeconfig_credentials(text, "absent")


@pytest.mark.parametrize("plugin", ["exec", "auth-provider", "basic", "none"])
def test_unsupported_selected_method_never_executes(config, monkeypatch, plugin):
    import subprocess

    run = Mock(side_effect=AssertionError("No exec"))
    monkeypatch.setattr(subprocess, "Popen", run)
    user = (
        {"username": "name", "password": "synthetic-secret"}
        if plugin == "basic"
        else {}
        if plugin == "none"
        else {plugin: {"command": "/forbidden", "args": ["synthetic-secret"]}}
    )
    config["users"][0]["user"] = user
    text = yaml.safe_dump(config)
    assert "synthetic-secret" not in str(security.inspect_kubeconfig(text))
    with pytest.raises(DomainError) as error:
        security.extract_kubeconfig_credentials(text, "selected")
    assert error.value.code == "credential_unsupported"
    assert "synthetic-secret" not in str(error.value)
    run.assert_not_called()
    # Unselected plugins are inspected but cannot influence the selected token.
    assert (
        security.extract_kubeconfig_credentials(text, "other")["auth"]["token"]
        == "other-secret"
    )


@pytest.mark.parametrize(
    "field", ["tokenFile", "client-key", "client-certificate", "as", "proxy-url"]
)
def test_extraction_validates_unselected_fields_without_opening_paths(
    config, monkeypatch, field
):
    config["users"][1]["user"][field] = "/forbidden/secret"
    opener = Mock(side_effect=AssertionError("No imported paths"))
    monkeypatch.setattr("builtins.open", opener)
    with pytest.raises(DomainError) as error:
        security.extract_kubeconfig_credentials(yaml.safe_dump(config), "selected")
    assert error.value.code == "invalid_kubeconfig"
    assert "/forbidden" not in str(error.value)
    opener.assert_not_called()


@pytest.mark.parametrize(
    "suffix", ["\n---\n{}", "\nalias: &a [1]\nother: *a", "\nkind: Config"]
)
def test_extraction_retains_strict_yaml_validation(config, suffix):
    with pytest.raises(DomainError) as error:
        security.extract_kubeconfig_credentials(
            yaml.safe_dump(config) + suffix, "selected"
        )
    assert error.value.code == "invalid_kubeconfig"


def test_certificate_extraction_normalizes_and_caps_source_expiry(config, identity):
    install_identity(config, identity)
    text = yaml.safe_dump(config)
    result = security.extract_kubeconfig_credentials(text, "selected")
    assert result["auth"] == identity
    assert (
        result["source_expires_at"]
        == x509.load_pem_x509_certificate(
            identity["certificate_pem"].encode()
        ).not_valid_after_utc
    )
    assert result["metadata"] == security.inspect_kubeconfig(text)[0]
    assert "BEGIN" not in json.dumps(security.inspect_kubeconfig(text))
    assert "BEGIN" not in str(result["metadata"])
    assert security.connection_headers({"auth_type": "kubeconfig", "auth": identity}) == {
        "Accept": "application/json"
    }
    assert security.connection_tls({"auth_type": "kubeconfig", "auth": identity}) == identity


@pytest.mark.parametrize(
    "options",
    [
        {"before": -3, "after": -1},
        {"before": 1, "after": 2},
        {"eku": ExtendedKeyUsageOID.SERVER_AUTH},
        {"ca": True},
        {"digital_signature": False},
    ],
)
def test_reject_invalid_certificate_validity_or_usage(config, options):
    identity = make_identity(**options)[0]
    install_identity(config, identity)
    with pytest.raises(DomainError) as error:
        security.extract_kubeconfig_credentials(yaml.safe_dump(config), "selected")
    assert error.value.code == "credential_invalid"
    assert "BEGIN" not in str(error.value)


def test_common_kubernetes_certificate_without_eku_is_supported(config):
    identity = make_identity(eku=None)[0]
    install_identity(config, identity)
    assert (
        security.extract_kubeconfig_credentials(yaml.safe_dump(config), "selected")[
            "auth"
        ]
        == identity
    )


@pytest.mark.parametrize(
    "damage",
    [
        "mismatch",
        "encrypted",
        "bad-cert",
        "bad-key",
        "base64",
        "incomplete",
        "ambiguous",
    ],
)
def test_reject_malformed_certificates_and_keys(config, identity, damage):
    if damage == "mismatch":
        identity["private_key_pem"] = make_identity()[0]["private_key_pem"]
    elif damage == "encrypted":
        key = serialization.load_pem_private_key(
            identity["private_key_pem"].encode(), None
        )
        identity["private_key_pem"] = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"synthetic-secret"),
        ).decode()
    elif damage == "bad-cert":
        identity["certificate_pem"] = (
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
        )
    elif damage == "bad-key":
        identity["private_key_pem"] = "/forbidden/secret"
    install_identity(config, identity)
    user = config["users"][0]["user"]
    if damage == "base64":
        user["client-key-data"] = "!not-base64!"
    elif damage == "incomplete":
        user.pop("client-key-data")
    elif damage == "ambiguous":
        user["token"] = "synthetic-secret"
    with pytest.raises(DomainError) as error:
        security.extract_kubeconfig_credentials(yaml.safe_dump(config), "selected")
    assert "BEGIN" not in str(error.value) and "synthetic-secret" not in str(
        error.value
    )
    assert "/forbidden" not in str(error.value)


@pytest.mark.parametrize(
    "auth",
    [
        None,
        {},
        [],
        {"version": True, "kind": "token", "token": "ok"},
        {"version": 2, "kind": "token", "token": "ok"},
        {"version": 1, "kind": "token", "token": "bad\r\nheader"},
        {"version": 1, "kind": "token", "token": "ok", "extra": "secret"},
        {"version": 1, "kind": "other", "token": "ok"},
    ],
)
def test_malformed_supplied_auth_never_falls_back(auth):
    connection = {"auth_type": "kubeconfig", "auth": auth, "id_token": "valid.legacy.token"}
    for helper in (security.connection_headers, security.connection_tls):
        with pytest.raises(DomainError) as error:
            helper(connection)
        assert error.value.code == "credential_invalid"


def test_only_normalized_kubeconfig_helpers_accept_identity():
    connection = {"auth_type": "kubeconfig", "auth": {"version": 1, "kind": "token", "token": "imported.token"}}
    assert security.connection_headers(connection) == {"Accept": "application/json", "Authorization": "Bearer imported.token"}
    assert security.connection_tls(connection) is None
    for legacy in ({"id_token": "old.token"}, {"auth_type": "oidc", "id_token": "old.token"}, {"auth_type": "kubeconfig", "id_token": "old.token"}):
        for helper in (security.connection_headers, security.connection_tls):
            with pytest.raises(DomainError):
                helper(legacy)


@pytest.mark.parametrize("expiry", [None, "later", True, 10**100, 4102444800])
def test_jwt_hint_never_verifies_or_extends_any_lease(config, expiry):
    payload = (
        base64.urlsafe_b64encode(json.dumps({"exp": expiry}).encode())
        .decode()
        .rstrip("=")
    )
    config["users"][0]["user"]["token"] = "e30." + payload + ".unsigned"
    result = security.extract_kubeconfig_credentials(yaml.safe_dump(config), "selected")
    assert result["source_expires_at"] == (
        datetime.fromtimestamp(expiry, UTC) if expiry == 4102444800 else None
    )


def test_expired_jwt_hint_rejected(config):
    config["users"][0]["user"]["token"] = "e30.eyJleHAiOjF9.unsigned"
    with pytest.raises(DomainError) as error:
        security.extract_kubeconfig_credentials(yaml.safe_dump(config), "selected")
    assert error.value.code == "credential_invalid"


@pytest.mark.parametrize("fail", [False, True])
def test_mtls_tempfiles_protected_and_removed_on_success_or_load_failure(
    identity, monkeypatch, tmp_path, fail
):
    monkeypatch.setattr(security.tempfile, "tempdir", str(tmp_path))
    paths = []
    real_load = ssl.SSLContext.load_cert_chain

    def load(context, certfile, keyfile, password=None):
        paths.extend([Path(certfile), Path(keyfile)])
        assert Path(certfile).parent.stat().st_mode & 0o777 == 0o700
        for path in paths:
            assert path.stat().st_mode & 0o777 == 0o600
        assert paths[0].read_text() == identity["certificate_pem"]
        assert paths[1].read_text() == identity["private_key_pem"]
        if fail:
            raise ssl.SSLError(identity["private_key_pem"])
        return real_load(context, certfile, keyfile, password=password)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", load)
    if fail:
        with pytest.raises(DomainError) as error:
            security.PinnedHTTP(
                ["192.0.2.0/24"], ["cluster.test"], client_identity=identity
            )
        assert "BEGIN" not in str(error.value)
    else:
        client = security.PinnedHTTP(
            ["192.0.2.0/24"], ["cluster.test"], client_identity=identity
        )
        assert (
            client._context.check_hostname
            and client._context.verify_mode == ssl.CERT_REQUIRED
        )
    assert paths and all(not path.exists() for path in paths)
    assert list(tmp_path.iterdir()) == []


def test_mtls_cleanup_if_second_tempfile_creation_fails(
    identity, monkeypatch, tmp_path
):
    monkeypatch.setattr(security.tempfile, "tempdir", str(tmp_path))
    original = security.tempfile.NamedTemporaryFile
    calls = []

    def create(**kwargs):
        if calls:
            raise OSError("synthetic-secret")
        result = original(**kwargs)
        calls.append(result.name)
        return result

    monkeypatch.setattr(security.tempfile, "NamedTemporaryFile", create)
    with pytest.raises(DomainError) as error:
        security.PinnedHTTP(
            ["192.0.2.0/24"], ["cluster.test"], client_identity=identity
        )
    assert "synthetic-secret" not in str(error.value)
    assert list(tmp_path.iterdir()) == []


def test_policy_forwards_identity_only_for_kubernetes(identity, monkeypatch):
    rules = [
        {
            "id": "cluster",
            "purpose": "kubernetes",
            "host": "cluster.test",
            "port": 6443,
            "cidrs": ["192.0.2.0/24"],
        }
    ]
    factory = Mock()
    monkeypatch.setattr(configuration, "PinnedHTTP", factory)
    client = configuration.PolicyHTTP(rules, "kubernetes", client_identity=identity)
    identity["private_key_pem"] = "mutated-after-construction"
    client.get_json("https://cluster.test:6443/api/v1/namespaces")
    assert (
        factory.call_args.kwargs["client_identity"]["private_key_pem"]
        != identity["private_key_pem"]
    )
    for purpose in ("oidc", "registry", "database"):
        with pytest.raises(DomainError):
            configuration.PolicyHTTP(rules, purpose, client_identity=identity)
    with pytest.raises(DomainError):
        client.get_json("https://cluster.test:443/")
    with pytest.raises(DomainError):
        client.get_json("https://other.test:6443/")
    configuration.PolicyHTTP(rules, "kubernetes").get_json("https://cluster.test:6443/")
    assert factory.call_args.kwargs == {}
    monkeypatch.setattr(configuration, "policy_view", lambda session: {"rules": rules})
    forwarded = configuration.policy_http(
        None,
        SimpleNamespace(egress_ceiling=None),
        "kubernetes",
        client_identity=identity,
    )
    assert forwarded.client_identity == identity


@pytest.mark.parametrize("kind", ["token", "client_certificate"])
def test_scanner_and_preflight_apply_normalized_auth_without_scope_changes(
    identity, kind
):
    auth = (
        identity
        if kind == "client_certificate"
        else {"version": 1, "kind": "token", "token": "synthetic-token"}
    )
    connection = {
        "server": "https://cluster.test",
        "auth_type": "kubeconfig",
        "auth": auth,
    }

    class HTTP:
        def __init__(self):
            self.calls = []

        def get_json(self, url, headers=None):
            self.calls.append((url, headers))
            resource = next(
                r
                for r in scanners.RESOURCES
                if url.split("?")[0].endswith("/" + r.plural)
            )
            return {
                "kind": resource.kind + "List",
                "apiVersion": resource.api,
                "metadata": {"resourceVersion": "1"},
                "items": [],
            }

    http = HTTP()
    coverage = scanners.preflight(connection, {"namespaces": ["selected"]}, http)
    result = scanners.scan_inventory(
        connection, {"namespaces": ["selected"]}, http, lambda: False
    )
    assert all(c["status"] == "completed" for c in coverage)
    assert not result.findings
    assert len(http.calls) == 2 * len(scanners.RESOURCES)
    for url, headers in http.calls:
        assert "/namespaces/selected/" in url
        assert headers == security.connection_headers(connection)
        assert "BEGIN" not in str(headers)
    malformed = copy.deepcopy(connection)
    malformed["auth"] = None
    malformed["id_token"] = "legacy-must-not-rescue"
    with pytest.raises(DomainError):
        scanners.preflight(malformed, {"namespaces": ["selected"]}, http)


@pytest.mark.parametrize(
    "failure", [None, "hostname", "server-trust", "client-trust", "missing-client"]
)
def test_real_openssl_mutual_tls_handshake_in_memory(tmp_path, failure):
    """Real SSL verification and mutual authentication, with no DNS/listening sockets."""
    _, ca, ca_key = make_identity(ca=True, eku=None)
    client_auth, client_cert, _ = make_identity(issuer=(ca, ca_key))
    server_auth, _, _ = make_identity(
        issuer=(ca, ca_key), eku=ExtendedKeyUsageOID.SERVER_AUTH
    )
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    other_ca = make_identity(ca=True, eku=None)[1].public_bytes(
        serialization.Encoding.PEM
    )
    client = security.PinnedHTTP(
        ["192.0.2.0/24"],
        ["cluster.test"],
        base64.b64encode(other_ca if failure == "server-trust" else ca_pem).decode(),
        client_identity=None if failure == "missing-client" else client_auth,
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.verify_mode = ssl.CERT_REQUIRED
    server.load_verify_locations(
        cadata=(other_ca if failure == "client-trust" else ca_pem).decode()
    )
    cert_path, key_path = tmp_path / "server.crt", tmp_path / "server.key"
    cert_path.write_text(server_auth["certificate_pem"])
    key_path.write_text(server_auth["private_key_pem"])
    key_path.chmod(0o600)
    server.load_cert_chain(cert_path, key_path)
    cert_path.unlink()
    key_path.unlink()
    cin, cout, sin, sout = (ssl.MemoryBIO() for _ in range(4))
    client_tls = client._context.wrap_bio(
        cin,
        cout,
        server_hostname="wrong.test" if failure == "hostname" else "cluster.test",
    )
    server_tls = server.wrap_bio(sin, sout, server_side=True)
    complete = set()
    for _ in range(20):
        for name, peer in (("client", client_tls), ("server", server_tls)):
            try:
                peer.do_handshake()
                complete.add(name)
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError:
                assert failure is not None
                return
        if cout.pending:
            sin.write(cout.read())
        if sout.pending:
            cin.write(sout.read())
        if len(complete) == 2:
            break
    assert failure is None, "Invalid TLS peer unexpectedly completed its handshake"
    assert complete == {"client", "server"}
    assert server_tls.getpeercert(binary_form=True) == client_cert.public_bytes(
        serialization.Encoding.DER
    )
    assert client_tls.getpeercert()["subjectAltName"] == (("DNS", "cluster.test"),)
