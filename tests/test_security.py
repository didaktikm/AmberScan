"""Security regression tests use synthetic data and no external network."""

import base64
import copy
import io
import ipaddress
import json
import socket
import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from workbench import security
from workbench.domain import DomainError
from workbench.security import (
    PinnedHTTP,
    Vault,
    inspect_kubeconfig,
    password_hash,
    password_verify,
    request_deadline,
    validate_connection_metadata,
    validate_endpoint,
)

HOST = "cluster.example.test"
ADDRESS = "192.0.2.10"
URL = "https://cluster.example.test:6443/api/v1/pods"
CIDRS = ["192.0.2.0/24"]
CANARY = "synthetic-secret-must-not-appear"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any accidental unmocked DNS/socket operation fails locally."""
    monkeypatch.setattr(
        socket, "getaddrinfo", Mock(side_effect=AssertionError("Unexpected DNS"))
    )
    monkeypatch.setattr(
        socket, "socket", Mock(side_effect=AssertionError("Unexpected socket"))
    )


@pytest.fixture
def kubeconfig():
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": "test",
        "clusters": [{"name": "test-cluster", "cluster": {"server": URL}}],
        "users": [{"name": "test-user", "user": {"token": CANARY}}],
        "contexts": [
            {
                "name": "test",
                "context": {
                    "cluster": "test-cluster",
                    "user": "test-user",
                    "namespace": "sample",
                },
            }
        ],
    }


@pytest.fixture(scope="module")
def test_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic unit-test CA")]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode(
        "ascii"
    )


def set_dns(monkeypatch, addresses):
    records = []
    for address in addresses:
        version = ipaddress.ip_address(address).version
        records.append(
            (
                socket.AF_INET6 if version == 6 else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (address, 6443, 0, 0) if version == 6 else (address, 6443),
            )
        )
    lookup = Mock(return_value=records)
    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    return lookup


def test_vault_round_trip_unique_nonce_and_purpose_binding():
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    vault = Vault(key)
    payload = {"token": CANARY, "transaction": {"nonce": "value"}}
    first = vault.encrypt(payload, "cluster:one:user:two")
    second = vault.encrypt(payload, "cluster:one:user:two")
    assert first != second and CANARY not in first
    assert vault.decrypt(first, "cluster:one:user:two") == payload
    for attempted_vault, ciphertext, purpose in (
        (vault, first, "cluster:other:user:two"),
        (
            Vault(base64.urlsafe_b64encode(b"x" * 32).decode()),
            first,
            "cluster:one:user:two",
        ),
        (vault, first[:-8] + "AAAAAAAA", "cluster:one:user:two"),
        (vault, "v0." + first[3:], "cluster:one:user:two"),
    ):
        with pytest.raises(DomainError) as error:
            attempted_vault.decrypt(ciphertext, purpose)
        assert error.value.code == "credential_invalid"
        assert CANARY not in str(error.value)
        assert error.value.__suppress_context__


@pytest.mark.parametrize(
    "key",
    [
        None,
        "",
        "x",
        "not!base64",
        base64.urlsafe_b64encode(b"k" * 31).decode(),
        "A" * 100,
    ],
)
def test_vault_rejects_missing_or_malformed_key(key):
    with pytest.raises(DomainError) as error:
        Vault(key)
    assert error.value.code == "configuration_required"


def test_vault_bounds_plaintext_and_purpose():
    vault = Vault(base64.urlsafe_b64encode(b"k" * 32).decode())
    for payload in (
        {"value": "x" * security.MAX_REQUEST_BYTES},
        {"value": float("nan")},
        ["not-object"],
    ):
        with pytest.raises(DomainError):
            vault.encrypt(payload, "test")
    for purpose in ("", None, "x" * 257):
        with pytest.raises(DomainError):
            vault.encrypt({}, purpose)


def test_scrypt_hash_verify_wrong_password_and_strict_cost_bounds():
    encoded = password_hash("unit test password Ω")
    assert encoded.startswith("$scrypt$131072$8$1$")
    assert encoded != password_hash("unit test password Ω")
    assert password_verify("unit test password Ω", encoded)
    assert not password_verify("wrong password", encoded)
    assert not password_verify(
        "unit test password Ω", encoded.replace("131072", "2147483648")
    )
    assert not password_verify("unit test password Ω", encoded.replace("$8$", "$9999$"))
    assert not password_verify("unit test password Ω", encoded + "unexpected")
    assert not password_verify("unit test password Ω", None)
    assert not password_verify("x" * 1025, encoded)


@pytest.mark.parametrize("password", ["", None, "x" * 1025, "Ω" * 600, "\ud800"])
def test_password_hash_rejects_unbounded_or_invalid_input(password):
    with pytest.raises(DomainError):
        password_hash(password)


def test_inspect_returns_only_metadata_and_never_tokens(kubeconfig):
    inspected = inspect_kubeconfig(yaml.safe_dump(kubeconfig))
    assert len(inspected) == 1
    assert inspected[0] == {
        "context": "test",
        "namespace_hint": "sample",
        "cluster_name": "test-cluster",
        "server": URL,
        "ca_data": None,
        "username": "test-user",
        "auth_type": "token",
        "warnings": [
            "Inspection does not use or store credentials. Inline token or client certificate credentials can be imported explicitly."
        ],
    }
    assert CANARY not in json.dumps(inspected)
    socket.getaddrinfo.assert_not_called()
    socket.socket.assert_not_called()


@pytest.mark.parametrize(
    "mechanism,label",
    [("exec", "unsupported_exec"), ("auth-provider", "unsupported_auth_provider")],
)
def test_inspect_auth_plugins_metadata_only_never_executes(
    kubeconfig, monkeypatch, mechanism, label
):
    import subprocess

    run = Mock(side_effect=AssertionError("A kubeconfig must never execute commands"))
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(subprocess, "Popen", run)
    kubeconfig["users"][0]["user"] = {
        mechanism: {
            "command": "/not/a/real/executable",
            "args": [CANARY],
            "config": {"id-token": CANARY},
        },
    }
    result = inspect_kubeconfig(yaml.safe_dump(kubeconfig))
    assert result[0]["auth_type"] == label
    assert "ignored" in " ".join(result[0]["warnings"]).lower()
    assert CANARY not in json.dumps(result)
    run.assert_not_called()


def test_inspect_valid_custom_ca_is_public_metadata(kubeconfig, test_ca):
    kubeconfig["clusters"][0]["cluster"]["certificate-authority-data"] = test_ca
    assert inspect_kubeconfig(yaml.safe_dump(kubeconfig))[0]["ca_data"] == test_ca
    client = PinnedHTTP(CIDRS, [HOST], ca_data=test_ca)
    assert client._context.check_hostname
    assert client._context.verify_mode == ssl.CERT_REQUIRED
    assert len(client._context.get_ca_certs()) == 1


@pytest.mark.parametrize(
    "location,key,value",
    [
        ("cluster", "certificate-authority", "/etc/passwd"),
        ("cluster", "proxy-url", "http://proxy.example.test"),
        ("cluster", "tls-server-name", "another.example.test"),
        ("cluster", "insecure-skip-tls-verify", True),
        ("cluster", "insecure-skip-tls-verify", "false"),
        ("cluster", "certificate-authority-data", "L2V0Yy9wYXNzd2Q="),
        ("cluster", "certificate-authority-data", "not-base64"),
        ("cluster", "server", "http://cluster.example.test"),
        ("cluster", "server", "https://name:password@cluster.example.test"),
        ("user", "tokenFile", "/etc/token"),
        ("user", "token-file", "/etc/token"),
        ("user", "client-key", "/etc/key"),
        ("user", "client-certificate", "/etc/cert"),
        ("user", "custom-auth", {"command": "ignored"}),
        ("user", "as", "administrator"),
        ("user", "as-groups", ["system:masters"]),
    ],
)
def test_inspect_rejects_unsafe_or_unknown_fields(kubeconfig, location, key, value):
    target = (
        kubeconfig["clusters"][0]["cluster"]
        if location == "cluster"
        else kubeconfig["users"][0]["user"]
    )
    target[key] = value
    with pytest.raises(DomainError) as error:
        inspect_kubeconfig(yaml.safe_dump(kubeconfig))
    assert error.value.code == "invalid_kubeconfig"
    assert CANARY not in str(error.value) and "/etc/" not in str(error.value)


@pytest.mark.parametrize(
    "raw",
    [
        "apiVersion: v1\napiVersion: v1\nkind: Config\n",
        "a: &anchor [1, 2]\nb: *anchor\n",
        "a: !!python/object/apply:os.system ['do-not-run']\n",
        "a: !!str x\n",
        "a: {nested: 1, nested: 2}\n",
        "a: {1: value}\n",
        "a: {<<: {field: value}}\n",
        "---\na: 1\n---\nb: 2\n",
        "[" * 25 + "]" * 25,
        "a: " + "x" * 350001,
        "a: [" + "null," * 20001 + "]",
        "x" * (security.MAX_KUBECONFIG_BYTES + 1),
        "a: \0\n",
    ],
)
def test_inspect_rejects_yaml_attacks_before_construction(raw):
    with pytest.raises(DomainError) as error:
        inspect_kubeconfig(raw)
    assert error.value.code == "invalid_kubeconfig"


def test_inspect_validates_unreferenced_entries_and_duplicate_names(kubeconfig):
    original = copy.deepcopy(kubeconfig)
    kubeconfig["clusters"].append(
        {
            "name": "unused",
            "cluster": {"server": URL, "proxy-url": "http://bad.example.test"},
        }
    )
    with pytest.raises(DomainError):
        inspect_kubeconfig(yaml.safe_dump(kubeconfig))
    original["contexts"].append(copy.deepcopy(original["contexts"][0]))
    with pytest.raises(DomainError):
        inspect_kubeconfig(yaml.safe_dump(original))


def test_inspect_rejects_unresolved_context_ambiguous_auth_and_extensions(kubeconfig):
    for mutate in (
        lambda value: value["contexts"][0]["context"].update({"cluster": "absent"}),
        lambda value: value["users"][0]["user"].update({"exec": {"command": "x"}}),
        lambda value: value.update(
            {"extensions": [{"name": "unsupported", "extension": {}}]}
        ),
    ):
        value = copy.deepcopy(kubeconfig)
        mutate(value)
        with pytest.raises(DomainError):
            inspect_kubeconfig(yaml.safe_dump(value))


def test_endpoint_requires_exact_host_and_ip_allowlist(monkeypatch):
    lookup = set_dns(monkeypatch, [ADDRESS, "192.0.2.11", ADDRESS])
    assert validate_endpoint(URL, CIDRS, [HOST]) == [ADDRESS, "192.0.2.11"]
    assert lookup.call_count == 1
    assert lookup.call_args.args == (
        HOST,
        6443,
        socket.AF_UNSPEC,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
    )
    for hosts, cidrs in (
        (["other.example.test"], CIDRS),
        (["*.example.test"], CIDRS),
        ([HOST], ["198.51.100.0/24"]),
        ([HOST], []),
    ):
        with pytest.raises(DomainError) as error:
            validate_endpoint(URL, cidrs, hosts)
        assert error.value.code == "endpoint_denied"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "100.100.100.200",
        "168.63.129.16",
        "::1",
        "::",
        "fe80::1",
        "ff02::1",
        "fd00:ec2::254",
        "::ffff:192.0.2.10",
        "2002:c000:020a::1",
        "64:ff9b::c000:20a",
    ],
)
def test_endpoint_denies_special_and_metadata_addresses_even_allowlisted(
    monkeypatch, address
):
    set_dns(monkeypatch, [address])
    cidr = f"{address}/{'128' if ':' in address else '32'}"
    with pytest.raises(DomainError) as error:
        validate_endpoint(URL, [cidr], [HOST])
    assert error.value.code == "endpoint_denied"


def test_endpoint_rejects_mixed_safe_and_unsafe_dns_answers(monkeypatch):
    set_dns(monkeypatch, [ADDRESS, "127.0.0.1"])
    with pytest.raises(DomainError):
        validate_endpoint(URL, CIDRS + ["127.0.0.1/32"], [HOST])


def test_endpoint_private_network_requires_explicit_private_cidr(monkeypatch):
    set_dns(monkeypatch, ["10.20.30.40"])
    with pytest.raises(DomainError):
        validate_endpoint(URL, ["0.0.0.0/0"], [HOST])
    assert validate_endpoint(URL, ["10.20.30.0/24"], [HOST]) == ["10.20.30.40"]


def test_endpoint_numeric_ipv6_skips_dns():
    assert validate_endpoint(
        "https://[fd12:3456::10]:6443", ["fd12:3456::/48"], ["fd12:3456::10"]
    ) == ["fd12:3456::10"]
    socket.getaddrinfo.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        "http://cluster.example.test",
        "https://u:p@cluster.example.test",
        "https://cluster.example.test?q=secret",
        "https://cluster.example.test?",
        "https://cluster.example.test#fragment",
        "https://cluster.example.test#",
        "https://cluster.example.test:0",
        "https://cluster.example.test:65536",
        "https://cluster.example.test:",
        "https://cluster.example.test./",
        "https://cluster.example.test\\@other.example.test",
        "https://cluster.example.test\n/",
        " https://cluster.example.test/",
        "https://[fe80::1%en0]/",
    ],
)
def test_endpoint_rejects_ambiguous_urls_without_dns(url):
    with pytest.raises(DomainError):
        validate_endpoint(url, CIDRS, [HOST])
    socket.getaddrinfo.assert_not_called()


def test_dns_failure_is_sanitized(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", Mock(side_effect=socket.gaierror(CANARY))
    )
    with pytest.raises(DomainError) as error:
        validate_endpoint(URL, CIDRS, [HOST])
    assert CANARY not in str(error.value)
    assert error.value.code == "http_dns"


def test_dns_wait_is_bounded_and_pool_saturation_fails_closed(monkeypatch):
    future = Mock()
    future.result.side_effect = TimeoutError(CANARY)
    pool = Mock()
    pool.submit.return_value = future
    slots = Mock()
    slots.acquire.return_value = True
    monkeypatch.setattr(security, "_DNS_POOL", pool)
    monkeypatch.setattr(security, "_DNS_SLOTS", slots)
    with pytest.raises(DomainError):
        validate_endpoint(URL, CIDRS, [HOST])
    future.result.assert_called_once_with(timeout=security.DNS_TIMEOUT)
    slots.release.assert_not_called()  # Released only when the OS resolver finishes.
    future.add_done_callback.call_args.args[0](future)
    slots.release.assert_called_once()
    slots.acquire.return_value = False
    with pytest.raises(DomainError):
        validate_endpoint(URL, CIDRS, [HOST])
    assert pool.submit.call_count == 1


@pytest.mark.parametrize("address", [ADDRESS, "fd12:3456::10"])
def test_real_connection_implementation_pins_numeric_ip_and_original_tls_host(
    monkeypatch, address
):
    transport = Mock()
    factory = Mock(return_value=transport)
    monkeypatch.setattr(socket, "socket", factory)
    context = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
    wrapped = Mock()
    context.wrap_socket.return_value = wrapped
    connection = security._PinnedHTTPSConnection(HOST, 6443, address, context, 5)
    connection.connect()
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    factory.assert_called_once_with(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    transport.connect.assert_called_once_with(
        (address, 6443, 0, 0) if ":" in address else (address, 6443)
    )
    context.wrap_socket.assert_called_once_with(transport, server_hostname=HOST)
    assert connection.sock is wrapped
    socket.getaddrinfo.assert_not_called()


def test_real_connection_rejects_insecure_context_and_closes_on_certificate_failure(
    monkeypatch,
):
    with pytest.raises(ValueError):
        security._PinnedHTTPSConnection(
            HOST, 443, ADDRESS, Mock(check_hostname=False), 5
        )
    transport = Mock()
    monkeypatch.setattr(socket, "socket", Mock(return_value=transport))
    context = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
    context.wrap_socket.side_effect = ssl.SSLCertVerificationError(CANARY)
    connection = security._PinnedHTTPSConnection(HOST, 443, ADDRESS, context, 5)
    with pytest.raises(ssl.SSLCertVerificationError):
        connection.connect()
    transport.close.assert_called_once()


class FakeResponse:
    def __init__(self, body=b'{"items":[]}', status=200, headers=None):
        self.status = status
        self.headers = (
            headers if headers is not None else [("Content-Type", "application/json")]
        )
        self.body = io.BytesIO(body)
        self.closed = False

    def getheaders(self):
        return self.headers

    def getheader(self, name, default=None):
        values = [value for key, value in self.headers if key.lower() == name.lower()]
        return ", ".join(values) if values else default

    def read1(self, amount):
        return self.body.read(amount)

    def close(self):
        self.closed = True


@pytest.fixture
def http_harness(monkeypatch):
    set_dns(monkeypatch, [ADDRESS])
    response = FakeResponse()
    connection = Mock()
    connection.getresponse.return_value = response
    factory = Mock(return_value=connection)
    monkeypatch.setattr(security, "_PinnedHTTPSConnection", factory)
    return PinnedHTTP(CIDRS, [HOST]), connection, factory, response


def test_http_uses_one_validated_resolution_preserves_host_and_query_ignores_proxies(
    http_harness, monkeypatch
):
    client, connection, factory, response = http_harness
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9999")
    assert client.get_json(
        URL + "?limit=1&continue=opaque%2Ftoken", {"Authorization": "Bearer " + CANARY}
    ) == {"items": []}
    assert socket.getaddrinfo.call_count == 1
    args = factory.call_args.args
    assert args[:3] == (HOST, 6443, ADDRESS)
    assert args[3].check_hostname and args[3].verify_mode == ssl.CERT_REQUIRED
    assert args[4] == security.SOCKET_TIMEOUT
    request = connection.request.call_args
    assert request.args[:2] == ("GET", "/api/v1/pods?limit=1&continue=opaque%2Ftoken")
    assert request.kwargs["headers"]["Host"] == HOST + ":6443"
    assert request.kwargs["headers"]["Authorization"] == "Bearer " + CANARY
    assert request.kwargs["headers"]["Accept-Encoding"] == "identity"
    assert response.closed
    connection.close.assert_called_once()


def test_http_post_encodes_form_and_json_with_credentials_in_body_only(http_harness):
    client, connection, _, _ = http_harness
    client.post_form(URL, {"client_secret": CANARY, "code": "a+b/c"})
    request = connection.request.call_args
    assert request.args == ("POST", "/api/v1/pods")
    assert CANARY.encode() in request.kwargs["body"]
    assert b"code=a%2Bb%2Fc" in request.kwargs["body"]
    assert (
        request.kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    )
    connection.getresponse.return_value = FakeResponse(b'{"ok":true}')
    assert client.post_json(URL, {"token": CANARY}) == {"ok": True}
    assert json.loads(connection.request.call_args.kwargs["body"]) == {"token": CANARY}


@pytest.mark.parametrize(
    "status", [301, 302, 303, 307, 308, 401, 403, 404, 410, 429, 500]
)
def test_http_rejects_redirects_and_errors_without_exposing_response(
    http_harness, status
):
    client, connection, factory, _ = http_harness
    response = FakeResponse(
        CANARY.encode(), status, [("Location", "https://other.example.test/" + CANARY)]
    )
    connection.getresponse.return_value = response
    with pytest.raises(DomainError) as error:
        client.get_json(URL)
    assert error.value.code == (
        "http_redirect_denied" if 300 <= status < 400 else f"http_{status}"
    )
    assert CANARY not in str(error.value)
    assert factory.call_count == 1
    assert response.body.tell() == 0


@pytest.mark.parametrize(
    "body,headers,code",
    [
        (b"secret", [("Content-Type", "text/html")], "http_invalid_json"),
        (b"[]", [("Content-Type", "application/json")], "http_invalid_json"),
        (
            b'{"key":1,"key":2}',
            [("Content-Type", "application/json")],
            "http_invalid_json",
        ),
        (b'{"key":NaN}', [("Content-Type", "application/json")], "http_invalid_json"),
        (b'{"key":1e999}', [("Content-Type", "application/json")], "http_invalid_json"),
        (
            b'{"key":' + b"[" * 40 + b"]" * 40 + b"}",
            [("Content-Type", "application/json")],
            "http_invalid_json",
        ),
        (b"\xff", [("Content-Type", "application/json")], "http_invalid_json"),
        (
            b"{}",
            [("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
            "http_invalid_json",
        ),
        (
            b"{}",
            [("Content-Type", "application/json"), ("Content-Length", "100")],
            "http_invalid_json",
        ),
        (
            b"{}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Content-Length", "2"),
            ],
            "http_invalid_json",
        ),
        (
            b"{}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Transfer-Encoding", "chunked"),
            ],
            "http_invalid_json",
        ),
        (
            b"{}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(security.MAX_RESPONSE_BYTES + 1)),
            ],
            "http_response_too_large",
        ),
        (
            b"x" * (security.MAX_RESPONSE_BYTES + 1),
            [("Content-Type", "application/json")],
            "http_response_too_large",
        ),
    ],
)
def test_http_rejects_malformed_or_oversized_responses(
    http_harness, body, headers, code
):
    client, connection, _, _ = http_harness
    response = FakeResponse(body, headers=headers)
    connection.getresponse.return_value = response
    with pytest.raises(DomainError) as error:
        client.get_json(URL)
    assert error.value.code == code
    assert response.closed


@pytest.mark.parametrize(
    "name,value",
    [
        ("Host", "other.example.test"),
        ("Proxy-Authorization", CANARY),
        ("Content-Length", "4"),
        ("Transfer-Encoding", "chunked"),
        ("Authorization", "Bearer x\r\nInjected: yes"),
        ("Bad Header", "value"),
        ("X-Test", "x" * 32769),
    ],
)
def test_http_rejects_header_injection_and_authority_override(
    http_harness, name, value
):
    client, connection, _, _ = http_harness
    with pytest.raises(DomainError) as error:
        client.get_json(URL, {name: value})
    assert error.value.code == "http_request_invalid"
    connection.request.assert_not_called()


@pytest.mark.parametrize(
    "failure,code",
    [
        (TimeoutError(CANARY), "http_timeout"),
        (ssl.SSLCertVerificationError(CANARY), "http_tls"),
        (ssl.SSLError(CANARY), "http_tls"),
        (OSError(CANARY), "http_transport"),
    ],
)
def test_http_transport_errors_sanitized_even_cleanup_failure(
    http_harness, failure, code
):
    client, connection, _, _ = http_harness
    connection.connect.side_effect = failure
    connection.close.side_effect = ValueError(CANARY)
    with pytest.raises(DomainError) as error:
        client.get_json(URL, {"Authorization": CANARY})
    assert error.value.code == code
    assert CANARY not in str(error.value)
    assert error.value.__suppress_context__


def test_http_total_deadline_enforced_for_body(http_harness, monkeypatch):
    client, connection, _, _ = http_harness
    monkeypatch.setattr(
        security.time,
        "monotonic",
        Mock(side_effect=[0, 1, security.RESPONSE_DEADLINE + 1]),
    )
    with pytest.raises(DomainError) as error:
        client.get_json(URL)
    assert error.value.code == "http_timeout"
    connection.close.assert_called_once()


def test_http_total_deadline_watchdog_interrupts_header_read(http_harness, monkeypatch):
    client, connection, _, _ = http_harness
    timers = []

    class ImmediateTimer:
        def __init__(self, seconds, callback):
            self.seconds = seconds
            self.callback = callback
            self.cancelled = False
            timers.append(self)

        def start(self):
            self.callback()

        def cancel(self):
            self.cancelled = True

    monkeypatch.setattr(security.threading, "Timer", ImmediateTimer)
    connection.getresponse.side_effect = OSError(CANARY)
    with pytest.raises(DomainError) as error:
        client.get_json(URL)
    assert error.value.code == "http_timeout"
    connection.sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
    connection.sock.close.assert_called_once()
    assert timers[0].cancelled


def test_http_real_httpclient_stack_does_not_resolve_again_after_dns_rebind(
    monkeypatch,
):
    lookup = set_dns(monkeypatch, [ADDRESS])
    socket_mock = Mock()
    socket_mock.makefile.return_value = io.BytesIO(
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{"items":[]}'
    )

    def rebind_after_connect(address):
        assert address == (ADDRESS, 6443)
        lookup.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 6443),
            )
        ]

    socket_mock.connect.side_effect = rebind_after_connect
    monkeypatch.setattr(socket, "socket", Mock(return_value=socket_mock))
    client = PinnedHTTP(CIDRS, [HOST])
    tls = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
    tls.wrap_socket.return_value = socket_mock
    client._context = tls
    assert client.get_json(URL + "?limit=1") == {"items": []}
    assert lookup.call_count == 1
    tls.wrap_socket.assert_called_once_with(socket_mock, server_hostname=HOST)
    sent = b"".join(call.args[0] for call in socket_mock.sendall.call_args_list)
    assert sent.startswith(b"GET /api/v1/pods?limit=1 HTTP/1.1\r\n")
    assert b"Host: cluster.example.test:6443\r\n" in sent
    assert b"127.0.0.1" not in sent
    socket_mock.close.assert_called()


@pytest.mark.parametrize(
    "cidrs,hosts",
    [
        (None, [HOST]),
        ([], [HOST]),
        (CIDRS, None),
        (CIDRS, []),
        (["192.0.2.1/24"], [HOST]),
        (["192.0.2.10"], [HOST]),
        (CIDRS, ["*.example.test"]),
    ],
)
def test_http_constructor_rejects_invalid_egress_configuration(cidrs, hosts):
    with pytest.raises(DomainError) as error:
        PinnedHTTP(cidrs, hosts)
    assert error.value.code == "configuration_required"
    socket.getaddrinfo.assert_not_called()


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Type", "application/json"), ("Transfer-Encoding", "gzip")],
        [
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
            ("Transfer-Encoding", "chunked"),
        ],
        [("Content-Type", "application/json"), ("Transfer-Encoding", "gzip, chunked")],
    ],
)
def test_http_rejects_ambiguous_or_unsupported_transfer_encoding(http_harness, headers):
    client, connection, _, _ = http_harness
    connection.getresponse.return_value = FakeResponse(b"{}", headers=headers)
    with pytest.raises(DomainError) as error:
        client.get_json(URL)
    assert error.value.code == "http_invalid_json"


@pytest.mark.parametrize(
    "hint",
    [
        "*",
        "",
        "UPPER",
        "a.b",
        "x" * 64,
        1,
        None,
        {},
        "private: value",
        "injected\nsecret",
    ],
)
def test_context_namespace_invalid_hint_is_ignored_with_safe_warning(kubeconfig, hint):
    kubeconfig["contexts"][0]["context"]["namespace"] = hint
    result = inspect_kubeconfig(yaml.safe_dump(kubeconfig))[0]
    assert "namespace_hint" not in result
    assert any("namespace hint is invalid" in warning for warning in result["warnings"])
    assert "private" not in json.dumps(result) and "injected" not in json.dumps(result)
    socket.getaddrinfo.assert_not_called()
    socket.socket.assert_not_called()


def test_context_without_namespace_does_not_fabricate_default(kubeconfig):
    kubeconfig["contexts"][0]["context"].pop("namespace")
    result = inspect_kubeconfig(yaml.safe_dump(kubeconfig))[0]
    assert "namespace_hint" not in result and len(result["warnings"]) == 1


@pytest.mark.parametrize(
    "server",
    [
        "https://cluster.example.test:6443",
        "https://cluster.example.test:6443/",
        "https://cluster.example.test:6443/proxy/test-cluster",
        "https://[fd12:3456::10]:6443/api-proxy/",
    ],
)
def test_connection_metadata_validation_shares_scanner_syntax_without_dns(
    server, test_ca
):
    assert validate_connection_metadata(server) is None
    assert validate_connection_metadata(server, test_ca) is None
    socket.getaddrinfo.assert_not_called()
    socket.socket.assert_not_called()


@pytest.mark.parametrize(
    "server",
    [
        None,
        "",
        "http://cluster.test",
        "https://cluster.test?",
        "https://cluster.test#",
        "https://cluster.test/%2e%2e",
        "https://cluster.test/%2fapi",
        "https://cluster.test//proxy",
        "https://cluster.test/proxy/../api",
        "https://cluster.test:0",
        "https://cluster.test:65536",
        "https://cluster.test:",
        "https://u:p@cluster.test",
        "https://cluster.test./api",
        "https://cluster.test\\api",
    ],
)
def test_connection_metadata_rejects_ambiguous_endpoint(server):
    with pytest.raises(DomainError) as error:
        validate_connection_metadata(server)
    assert error.value.code == "endpoint_denied"
    socket.getaddrinfo.assert_not_called()


@pytest.mark.parametrize(
    "ca_data",
    [
        "",
        "not-base64",
        "L2V0Yy9wYXNzd2Q=",
        base64.b64encode(
            b"-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----"
        ).decode(),
        base64.b64encode(
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
        ).decode(),
    ],
)
def test_connection_metadata_rejects_bad_ca_without_leaking_or_reading_paths(ca_data):
    with pytest.raises(DomainError) as error:
        validate_connection_metadata(URL, ca_data)
    assert error.value.code == "invalid_ca"
    assert "private" not in str(error.value) and "/etc/" not in str(error.value)
    socket.getaddrinfo.assert_not_called()


def test_request_deadline_clamps_dns_wait_and_fresh_client_socket(
    http_harness, monkeypatch
):
    _, connection, factory, _ = http_harness
    now = [100.0]
    monkeypatch.setattr(security.time, "monotonic", lambda: now[0])
    with request_deadline(101):
        client = PinnedHTTP(CIDRS, [HOST])
        client.get_json(URL)
    assert factory.call_args.args[4] == 1
    assert security._REQUEST_DEADLINE.get() is None
    connection.sock.settimeout.assert_called_with(1)
    future = Mock()
    future.result.side_effect = TimeoutError(CANARY)
    pool = Mock()
    pool.submit.return_value = future
    slots = Mock()
    slots.acquire.return_value = True
    monkeypatch.setattr(security, "_DNS_POOL", pool)
    monkeypatch.setattr(security, "_DNS_SLOTS", slots)
    with request_deadline(101), pytest.raises(DomainError) as error:
        validate_endpoint(URL, CIDRS, [HOST])
    assert error.value.code == "http_dns"
    future.result.assert_called_once_with(timeout=1)
    assert security._REQUEST_DEADLINE.get() is None


def test_request_deadline_nested_cannot_extend_and_expiry_prevents_network(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(security.time, "monotonic", lambda: now[0])
    with request_deadline(15):
        with request_deadline(20):
            assert security._REQUEST_DEADLINE.get() == 15
        with request_deadline(12):
            assert security._REQUEST_DEADLINE.get() == 12
        assert security._REQUEST_DEADLINE.get() == 15
        now[0] = 15
        with pytest.raises(DomainError) as error:
            PinnedHTTP(CIDRS, [HOST]).get_json(URL)
        assert error.value.code == "http_timeout"
    assert security._REQUEST_DEADLINE.get() is None
    socket.getaddrinfo.assert_not_called()
    socket.socket.assert_not_called()
    with pytest.raises(DomainError), request_deadline(14):
        pytest.fail("Expired deadline must not enter")
    assert security._REQUEST_DEADLINE.get() is None


def test_tls_handshake_gets_remaining_budget_after_connect(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(security.time, "monotonic", lambda: now[0])
    transport = Mock()

    def connect(_address):
        now[0] = 2.0

    transport.connect.side_effect = connect
    monkeypatch.setattr(socket, "socket", Mock(return_value=transport))
    context = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
    connection = security._PinnedHTTPSConnection(HOST, 443, ADDRESS, context, 5)
    with request_deadline(3):
        connection.connect()
    assert [call.args[0] for call in transport.settimeout.call_args_list] == [3, 1]


def test_http_real_chunked_response_enforces_dechunked_size_limit(monkeypatch):
    set_dns(monkeypatch, [ADDRESS])
    socket_mock = Mock()
    socket_mock.makefile.return_value = io.BytesIO(
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\nc\r\n{"items":[]}\r\n0\r\n\r\n'
    )
    monkeypatch.setattr(socket, "socket", Mock(return_value=socket_mock))
    monkeypatch.setattr(security, "MAX_RESPONSE_BYTES", 10)
    client = PinnedHTTP(CIDRS, [HOST])
    tls = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
    tls.wrap_socket.return_value = socket_mock
    client._context = tls
    with pytest.raises(DomainError) as error:
        client.get_json(URL)
    assert error.value.code == "http_response_too_large"
    socket_mock.close.assert_called()


@pytest.mark.parametrize(
    "body,declared,code",
    [
        (b'{"ok":true}', 11, None),
        (b'{"ok":true}', 12, "http_invalid_json"),
        (b"", 0, "http_invalid_json"),
    ],
)
def test_http_connection_close_releases_owned_socket_after_final_read(
    monkeypatch, body, declared, code
):
    """Real HTTPResponse closes its file at Content-Length, releasing the last fd owner."""
    set_dns(monkeypatch, [ADDRESS])

    class OwnedFile(io.BytesIO):
        def close(self):
            super().close()
            transport.file_closed = True

    class OwnedSocket:
        file_closed = False
        socket_closed = False

        def settimeout(self, timeout):
            if self.file_closed and self.socket_closed:
                raise OSError(9, "Bad file descriptor")

        def connect(self, address):
            assert address == (ADDRESS, 6443)

        def sendall(self, data):
            pass

        def makefile(self, mode):
            return OwnedFile(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: "
                + str(declared).encode()
                + b"\r\n\r\n"
                + body
            )

        def close(self):
            self.socket_closed = True

    transport = OwnedSocket()
    monkeypatch.setattr(socket, "socket", Mock(return_value=transport))
    client = PinnedHTTP(CIDRS, [HOST])
    tls = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
    tls.wrap_socket.return_value = transport
    client._context = tls
    if code is None:
        assert client.get_json(URL) == {"ok": True}
    else:
        with pytest.raises(DomainError) as error:
            client.get_json(URL)
        assert error.value.code == code
    assert transport.file_closed and transport.socket_closed
