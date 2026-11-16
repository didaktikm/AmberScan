"""Fail-closed credential storage, kubeconfig inspection, and pinned HTTPS.

No kubeconfig authentication plugin is executed and no kubeconfig path is opened.
The HTTP transport never consults environment proxies, follows redirects, or passes
an untrusted hostname to the socket connect operation.
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from urllib.parse import urlencode, urlsplit, urlunsplit

import yaml
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID
from yaml.events import (
    AliasEvent,
    CollectionEndEvent,
    CollectionStartEvent,
    ScalarEvent,
)

from workbench.domain import DomainError

MAX_KUBECONFIG_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
SOCKET_TIMEOUT = 5.0
RESPONSE_DEADLINE = 20.0
DNS_TIMEOUT = 5.0
_MAX_CA_BYTES = 256 * 1024
_REQUEST_DEADLINE: ContextVar[float | None] = ContextVar(
    "request_deadline", default=None
)
_DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
_DNS_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="egress-dns"
)
_DNS_SLOTS = threading.BoundedSemaphore(4)
_URLSAFE = re.compile(r"[A-Za-z0-9_-]+={0,2}\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_PRIVATE_RANGES = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "100.64.0.0/10",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/15",
        "2001:db8::/32",
    )
)
_DENIED_ADDRESSES = frozenset(
    ipaddress.ip_address(value)
    for value in ("100.100.100.200", "168.63.129.16", "fd00:ec2::254")
)
_TRANSLATION_RANGES = tuple(
    ipaddress.ip_network(value) for value in ("64:ff9b::/96", "64:ff9b:1::/48")
)


def _error(
    message: str = "Invalid security input.", code: str = "invalid_input"
) -> DomainError:
    return DomainError(message, code=code)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str, limit: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or not _URLSAFE.fullmatch(value)
    ):
        raise ValueError("Invalid encoding")
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )
    if _b64url_encode(decoded) != value.rstrip("="):
        raise ValueError("Noncanonical encoding")
    return decoded


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("Invalid JSON constant")


def _json_object(raw: bytes, limit: int = MAX_RESPONSE_BYTES) -> dict:
    if len(raw) > limit:
        raise ValueError("JSON size limit")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise TypeError("Expected object")
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100_000:
            raise ValueError("JSON complexity limit")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("Invalid JSON number")
    return value


class Vault:
    """AES-256-GCM with a versioned envelope and caller-supplied purpose AAD."""

    def __init__(self, key: str):
        try:
            decoded = _b64url_decode(key, 44)
            if len(decoded) != 32:
                raise ValueError("Invalid key length")
            self._aead = AESGCM(decoded)
        except (ValueError, TypeError):
            raise _error(
                "A valid vault encryption key is required.", "configuration_required"
            ) from None

    @staticmethod
    def _aad(purpose: str) -> bytes:
        if not isinstance(purpose, str) or not purpose or len(purpose) > 256:
            raise _error("A valid encryption purpose is required.")
        try:
            return b"workbench:v1:" + purpose.encode("utf-8")
        except UnicodeError:
            raise _error("A valid encryption purpose is required.") from None

    def encrypt(self, value: dict, purpose: str) -> str:
        aad = self._aad(purpose)
        try:
            if not isinstance(value, dict):
                raise TypeError("Expected object")
            raw = json.dumps(value, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            )
            _json_object(raw, MAX_REQUEST_BYTES)
            nonce = secrets.token_bytes(12)
            return "v1." + _b64url_encode(nonce + self._aead.encrypt(nonce, raw, aad))
        except (ValueError, TypeError, RecursionError, OverflowError):
            raise _error(
                "Credential encryption failed.", "credential_invalid"
            ) from None

    def decrypt(self, ciphertext: str, purpose: str) -> dict:
        aad = self._aad(purpose)
        try:
            if not isinstance(ciphertext, str) or not ciphertext.startswith("v1."):
                raise ValueError("Invalid envelope")
            raw = _b64url_decode(ciphertext[3:], 4 * (MAX_REQUEST_BYTES + 30) // 3 + 4)
            if len(raw) < 29:
                raise ValueError("Invalid envelope")
            return _json_object(
                self._aead.decrypt(raw[:12], raw[12:], aad), MAX_REQUEST_BYTES
            )
        except Exception:  # noqa: BLE001 - this is the credential decryption error boundary.
            # Cryptographic, parser and encoding errors must never reveal plaintext.
            raise _error(
                "Credential decryption failed.", "credential_invalid"
            ) from None


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str) or not password or len(password) > 1024:
        raise ValueError("Invalid password length")
    value = password.encode("utf-8")
    if len(value) > 1024:
        raise ValueError("Invalid password length")
    return value


def password_hash(password: str) -> str:
    try:
        value = _password_bytes(password)
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(
            value, salt=salt, n=131072, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32
        )
        return f"$scrypt$131072$8$1${_b64url_encode(salt)}${_b64url_encode(digest)}"
    except (ValueError, TypeError, UnicodeError):
        raise _error("Password does not meet input requirements.") from None


def password_verify(password: str, encoded: str) -> bool:
    try:
        value = _password_bytes(password)
        if not isinstance(encoded, str) or len(encoded) > 256:
            return False
        marker, scheme, n, r, p, salt_text, digest_text = encoded.split("$")
        # Do not allow a database value to choose unbounded memory/work parameters.
        if (marker, scheme, n, r, p) != ("", "scrypt", "131072", "8", "1"):
            return False
        salt = _b64url_decode(salt_text, 24)
        expected = _b64url_decode(digest_text, 44)
        if len(salt) != 16 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(
            value, salt=salt, n=131072, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


class _StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in mapping or key == "<<":
                raise ValueError("Invalid or duplicate YAML mapping key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _bounded_yaml(text: str) -> dict:
    if not isinstance(text, str) or not text or len(text) > MAX_KUBECONFIG_BYTES:
        raise ValueError("Invalid YAML input size")
    if len(text.encode("utf-8")) > MAX_KUBECONFIG_BYTES or "\0" in text:
        raise ValueError("Invalid YAML input")
    depth = documents = 0
    # Inspect events BEFORE construction; SafeLoader alone permits aliases and deep recursion.
    for count, event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader), start=1):
        if count > 20_000:
            raise ValueError("YAML complexity limit")
        if isinstance(event, yaml.events.DocumentStartEvent):
            documents += 1
            if documents > 1 or event.version or event.tags:
                raise ValueError("Unsupported YAML document")
        if (
            isinstance(event, AliasEvent)
            or getattr(event, "anchor", None)
            or getattr(event, "tag", None)
        ):
            raise ValueError("YAML references and explicit tags are forbidden")
        if isinstance(event, CollectionStartEvent):
            depth += 1
            if depth > 24:
                raise ValueError("YAML depth limit")
        elif isinstance(event, CollectionEndEvent):
            depth -= 1
        elif isinstance(event, ScalarEvent) and len(event.value) > 350_000:
            raise ValueError("YAML scalar limit")
    value = yaml.load(text, Loader=_StrictLoader)
    if not isinstance(value, dict):
        raise TypeError("Expected kubeconfig object")
    return value


def _text(value, limit=256, *, empty=False) -> str:
    if not isinstance(value, str) or (not empty and not value) or len(value) > limit:
        raise ValueError("Invalid text field")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Invalid text field")
    return value


def _keys(value, allowed: set[str]) -> dict:
    if not isinstance(value, dict) or not set(value).issubset(allowed):
        raise ValueError("Unsupported kubeconfig field")
    return value


def _named_entries(value, member: str) -> dict[str, dict]:
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("Invalid kubeconfig list")
    entries = {}
    for entry in value:
        _keys(entry, {"name", member})
        name = _text(entry.get("name"))
        if name in entries or not isinstance(entry.get(member), dict):
            raise ValueError("Duplicate or invalid kubeconfig entry")
        entries[name] = entry[member]
    return entries


def _ca_bytes(ca_data: str) -> bytes:
    if not isinstance(ca_data, str) or len(ca_data) > 4 * (_MAX_CA_BYTES + 2) // 3:
        raise ValueError("Invalid CA data")
    raw = base64.b64decode(ca_data, validate=True)
    if not raw or len(raw) > _MAX_CA_BYTES:
        raise ValueError("Invalid CA data")
    # Only PEM certificate blocks, not a private key, path or OpenSSL directive.
    pattern = rb"\s*(?:-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+"
    if not re.fullmatch(pattern, raw):
        raise ValueError("Invalid CA certificate")
    return raw


def _tls_context(ca_data: str | None) -> ssl.SSLContext:
    if ca_data is None:
        context = ssl.create_default_context()
    else:
        # A custom cluster CA replaces, rather than expands, system trust.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=_ca_bytes(ca_data).decode("ascii"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _cluster_endpoint(server: object) -> str:
    """Validate one unambiguous API base URL, without DNS or trust-store access."""
    if not isinstance(server, str):
        raise _error("The cluster endpoint is invalid.", "endpoint_denied")
    parts, _, _ = _https_parts(server)
    if (
        len(server) > 2048
        or not server.startswith("https://")
        or not re.fullmatch(r"(?:/[A-Za-z0-9._~-]+)*/?", parts.path)
        or any(segment in (".", "..") for segment in parts.path.split("/"))
    ):
        raise _error("The cluster endpoint is invalid.", "endpoint_denied")
    return server.rstrip("/")


def validate_connection_metadata(server: object, ca_data: str | None = None) -> None:
    """Validate public connection metadata only; CA data is base64-encoded PEM.

    Shares the scanner's exact base-URL syntax. No DNS, sockets, local kubeconfig
    paths, authentication plugins or imported credentials are consulted.
    """
    _cluster_endpoint(server)
    try:
        _tls_context(ca_data)
    except (ValueError, TypeError, UnicodeError, ssl.SSLError, OSError):
        raise _error(
            "A valid CA trust configuration is required.", "invalid_ca"
        ) from None


def _inspect_kubeconfig_document(text: str) -> tuple[list[dict], dict]:
    """Validate the whole document before exposing metadata or selected credentials."""
    try:
        config = _bounded_yaml(text)
        _keys(
            config,
            {
                "apiVersion",
                "kind",
                "preferences",
                "current-context",
                "clusters",
                "users",
                "contexts",
            },
        )
        if config.get("apiVersion") != "v1" or config.get("kind") != "Config":
            raise ValueError("Unsupported kubeconfig version")
        preferences = _keys(config.get("preferences", {}), {"colors"})
        if "colors" in preferences and type(preferences["colors"]) is not bool:
            raise ValueError("Invalid preferences")
        clusters = _named_entries(config.get("clusters"), "cluster")
        users = _named_entries(config.get("users", []), "user")
        contexts = _named_entries(config.get("contexts"), "context")
        if not contexts or not clusters:
            raise ValueError("No contexts or clusters")
        current = _text(config.get("current-context", ""), empty=True)
        if current and current not in contexts:
            raise ValueError("Unknown current context")
        for cluster in clusters.values():
            _keys(
                cluster,
                {
                    "server",
                    "certificate-authority-data",
                    "insecure-skip-tls-verify",
                    "disable-compression",
                },
            )
            if (
                "insecure-skip-tls-verify" in cluster
                and cluster["insecure-skip-tls-verify"] is not False
            ):
                raise ValueError("Insecure TLS is forbidden")
            if (
                "disable-compression" in cluster
                and type(cluster["disable-compression"]) is not bool
            ):
                raise ValueError("Invalid compression option")
            validate_connection_metadata(
                cluster.get("server"), cluster.get("certificate-authority-data")
            )
        auth = {}
        for name, user in users.items():
            _keys(
                user,
                {
                    "token",
                    "client-certificate-data",
                    "client-key-data",
                    "username",
                    "password",
                    "exec",
                    "auth-provider",
                },
            )
            methods = []
            if "exec" in user:
                if not isinstance(user["exec"], dict):
                    raise ValueError("Invalid exec metadata")
                methods.append("unsupported_exec")
            if "auth-provider" in user:
                if not isinstance(user["auth-provider"], dict):
                    raise ValueError("Invalid provider metadata")
                methods.append("unsupported_auth_provider")
            if "token" in user:
                _text(user["token"], 65536)
                methods.append("token")
            if {"client-certificate-data", "client-key-data"} & user.keys():
                for key in ("client-certificate-data", "client-key-data"):
                    _text(user.get(key), 350_000)
                methods.append("client_certificate")
            if {"username", "password"} & user.keys():
                _text(user.get("username"), 4096)
                _text(user.get("password"), 65536)
                methods.append("basic")
            if len(methods) > 1:
                raise ValueError("Ambiguous authentication")
            auth[name] = methods[0] if methods else "none"
        result = []
        for name, context in contexts.items():
            _keys(context, {"cluster", "user", "namespace"})
            cluster_name = _text(context.get("cluster"))
            username = _text(context.get("user", ""), empty=True)
            if cluster_name not in clusters or (username and username not in users):
                raise ValueError("Unresolved kubeconfig reference")
            namespace_hint = context.get("namespace")
            valid_hint = isinstance(namespace_hint, str) and bool(
                _DNS_LABEL.fullmatch(namespace_hint)
            )
            cluster = clusters[cluster_name]
            auth_type = auth.get(username, "none")
            warnings = [
                "Inspection does not use or store credentials. Inline token or client certificate credentials can be imported explicitly."
            ]
            if auth_type == "unsupported_exec":
                warnings.append(
                    "Exec authentication is unsupported. Commands and their arguments were ignored, not executed."
                )
            elif auth_type == "unsupported_auth_provider":
                warnings.append(
                    "Auth-provider authentication is unsupported. Provider instructions were ignored."
                )
            if "namespace" in context and not valid_hint:
                warnings.append(
                    "The context namespace hint is invalid and was ignored; select namespaces explicitly."
                )
            result.append(
                {
                    **({"namespace_hint": namespace_hint} if valid_hint else {}),
                    "context": name,
                    "cluster_name": cluster_name,
                    "server": cluster["server"],
                    "ca_data": cluster.get("certificate-authority-data"),
                    "username": username,
                    "auth_type": auth_type,
                    "warnings": warnings,
                }
            )
        return result, users
    except DomainError:
        raise _error(
            "Kubeconfig contains an invalid or unsupported endpoint.",
            "invalid_kubeconfig",
        ) from None
    except (
        ValueError,
        TypeError,
        UnicodeError,
        yaml.YAMLError,
        RecursionError,
        ssl.SSLError,
        OverflowError,
    ):
        raise _error(
            "Kubeconfig is malformed, unsafe, unsupported, or exceeds inspection limits.",
            "invalid_kubeconfig",
        ) from None


def inspect_kubeconfig(text: str) -> list[dict]:
    """Return safe metadata only; never return imported tokens, certificates or keys."""
    metadata, _ = _inspect_kubeconfig_document(text)
    return metadata


def _token(value: object) -> str:
    # RFC 6750 b64token; bounded well below the outbound header limit.
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9._~+/-]{1,16384}={0,2}", value
    ):
        raise ValueError("Invalid bearer token")
    return value


def _client_certificate(auth: dict) -> datetime:
    """Validate an inline identity without opening paths or asking for a password.

    This checks local identity suitability, not whether a Kubernetes server trusts
    the issuer or authorizes the subject. That remains a server-side decision.
    """
    certificate = auth.get("certificate_pem")
    private_key = auth.get("private_key_pem")
    if (
        not isinstance(certificate, str)
        or not isinstance(private_key, str)
        or not 1 <= len(certificate) <= _MAX_CA_BYTES
        or not 1 <= len(private_key) <= 65536
    ):
        raise ValueError("Invalid client identity")
    certificate_bytes = certificate.encode("ascii")
    key_bytes = private_key.encode("ascii")
    if not re.fullmatch(
        rb"\s*(?:-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+",
        certificate_bytes,
    ) or not re.fullmatch(
        rb"\s*-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\s+"
        rb"[A-Za-z0-9+/=\s]+-----END \1-----\s*",
        key_bytes,
    ):
        raise ValueError("Invalid client identity PEM")
    if certificate_bytes.count(b"-----BEGIN CERTIFICATE-----") > 16:
        raise ValueError("Client certificate chain limit")
    chain = x509.load_pem_x509_certificates(certificate_bytes)
    key = serialization.load_pem_private_key(key_bytes, password=None)
    if isinstance(key, rsa.RSAPrivateKey):
        if not 2048 <= key.key_size <= 8192:
            raise ValueError("Unsupported client key")
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if key.key_size < 256:
            raise ValueError("Unsupported client key")
    elif not isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        raise TypeError("Unsupported client key")
    leaf = chain[0]
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(
        serialization.Encoding.DER, public_format
    ) != leaf.public_key().public_bytes(serialization.Encoding.DER, public_format):
        raise ValueError("Client certificate and key mismatch")
    current = datetime.now(UTC)
    for cert in chain:
        if not cert.not_valid_before_utc <= current < cert.not_valid_after_utc:
            raise ValueError("Client certificate is outside its validity period")
    # Missing EKU means unrestricted usage, as with common Kubernetes client certs.
    try:
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in usage:
            raise ValueError("Client authentication usage is required")
    except x509.ExtensionNotFound:
        pass
    try:
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise ValueError("Client signature usage is required")
    except x509.ExtensionNotFound:
        pass
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("A client leaf certificate is required")
    except x509.ExtensionNotFound:
        pass
    return min(cert.not_valid_after_utc for cert in chain)


def _normalized_auth(auth: object) -> tuple[dict, datetime | None]:
    try:
        if not isinstance(auth, dict) or type(auth.get("version")) is not int:
            raise ValueError("Invalid credential envelope")
        if auth["version"] != 1:
            raise ValueError("Unsupported credential version")
        if auth.get("kind") == "token" and set(auth) == {"version", "kind", "token"}:
            return {"version": 1, "kind": "token", "token": _token(auth["token"])}, None
        if auth.get("kind") == "client_certificate" and set(auth) == {
            "version",
            "kind",
            "certificate_pem",
            "private_key_pem",
        }:
            expires = _client_certificate(auth)
            return dict(auth), expires
        raise ValueError("Unsupported credential envelope")
    except (
        ValueError,
        TypeError,
        UnicodeError,
        OverflowError,
        UnsupportedAlgorithm,
        x509.DuplicateExtension,
    ):
        raise _error(
            "Valid inline token or client certificate credentials are required.",
            "credential_invalid",
        ) from None


def _connection_auth(connection: dict) -> dict:
    if not isinstance(connection, dict):
        raise _error("Cluster credentials are required.", "credential_required")
    if connection.get("auth_type") != "kubeconfig":
        raise _error("Invalid cluster authentication type.", "credential_invalid")
    if "auth" not in connection:
        raise _error("Cluster credentials are required.", "credential_required")
    auth, _ = _normalized_auth(connection["auth"])
    return auth


def connection_headers(connection: dict) -> dict:
    """Return Bearer headers for tokens; mTLS identities never enter HTTP headers."""
    auth = _connection_auth(connection)
    headers = {"Accept": "application/json"}
    if auth["kind"] == "token":
        headers["Authorization"] = "Bearer " + auth["token"]
    return headers


def connection_tls(connection: dict) -> dict | None:
    """Return the validated client identity or None for token authentication."""
    auth = _connection_auth(connection)
    return auth if auth["kind"] == "client_certificate" else None


def _jwt_expiry_hint(token: str) -> datetime | None:
    """Unverified JWT expiry can shorten a lease, never authenticate or extend it."""
    try:
        pieces = token.split(".")
        if len(pieces) != 3:
            return None
        payload = _json_object(_b64url_decode(pieces[1], 16384), 16384)
        expiry = payload.get("exp")
        if (
            isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
        ):
            return None
        return datetime.fromtimestamp(expiry, UTC)
    except (ValueError, TypeError, OverflowError, OSError, RecursionError):
        return None


def extract_kubeconfig_credentials(content: str, context: str) -> dict:
    """Extract only the selected identity after bounded whole-document validation."""
    records, users = _inspect_kubeconfig_document(content)
    if not isinstance(context, str):
        raise _error("Select an existing kubeconfig context.", "invalid_kubeconfig")
    metadata = next(
        (record for record in records if record["context"] == context), None
    )
    if metadata is None:
        raise _error("Select an existing kubeconfig context.", "invalid_kubeconfig")
    user = users.get(metadata["username"], {})
    if metadata["auth_type"] == "token":
        auth, expires = _normalized_auth(
            {"version": 1, "kind": "token", "token": user.get("token")}
        )
        expires = _jwt_expiry_hint(auth["token"])
        if expires is not None and expires <= datetime.now(UTC):
            raise _error("The selected credential has expired.", "credential_invalid")
    elif metadata["auth_type"] == "client_certificate":
        try:
            decoded = {}
            for source, target, limit in (
                ("client-certificate-data", "certificate_pem", _MAX_CA_BYTES),
                ("client-key-data", "private_key_pem", 65536),
            ):
                value = user[source]
                if len(value) > 4 * (limit + 2) // 3:
                    raise ValueError("Identity size limit")
                raw = base64.b64decode(value, validate=True)
                if len(raw) > limit:
                    raise ValueError("Identity size limit")
                decoded[target] = raw.decode("ascii")
        except (ValueError, TypeError, UnicodeError):
            raise _error(
                "Invalid inline client certificate credentials.", "credential_invalid"
            ) from None
        auth, expires = _normalized_auth(
            {"version": 1, "kind": "client_certificate", **decoded}
        )
    else:
        raise _error(
            "The selected context requires an inline token or client certificate/key pair; plugins, files and basic authentication are unsupported.",
            "credential_unsupported",
        )
    return {"metadata": metadata, "auth": auth, "source_expires_at": expires}


def _load_client_identity(context: ssl.SSLContext, identity: object) -> None:
    auth, _ = _normalized_auth(identity)
    if auth["kind"] != "client_certificate":
        raise _error("A client certificate identity is required.", "credential_invalid")
    try:
        # mkdtemp creates a 0700 directory; NamedTemporaryFile uses O_EXCL and 0600.
        # Contexts unlink both files immediately after load, also on any failure.
        with (
            tempfile.TemporaryDirectory(prefix="workbench-mtls-") as directory,
            tempfile.NamedTemporaryFile(dir=directory) as certificate,
            tempfile.NamedTemporaryFile(dir=directory) as key,
        ):
            certificate.write(auth["certificate_pem"].encode("ascii"))
            certificate.flush()
            key.write(auth["private_key_pem"].encode("ascii"))
            key.flush()
            context.load_cert_chain(certificate.name, key.name, password=None)
    except (OSError, ValueError, TypeError):
        raise _error(
            "Client certificate TLS initialization failed.", "credential_invalid"
        ) from None


def _canonical_host(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("Invalid host")
    if (
        value.endswith(".")
        or any(char in value for char in "%/@\\?#[]")
        or any(char.isspace() for char in value)
    ):
        raise ValueError("Invalid host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if ":" in value:
            raise ValueError("Invalid host") from None
        host = value.encode("idna").decode("ascii").lower()
        if len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("Invalid host") from None
        return host


def _https_parts(url: object, *, allow_query: bool = False):
    try:
        if not isinstance(url, str) or not url or len(url) > 8192:
            raise ValueError("Invalid URL")
        if any(ord(char) <= 32 or ord(char) >= 127 for char in url) or "\\" in url:
            raise ValueError("Invalid URL")
        if "#" in url or (not allow_query and "?" in url):
            raise ValueError("Invalid URL")
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.netloc or "@" in parts.netloc:
            raise ValueError("HTTPS without user info is required")
        host = _canonical_host(parts.hostname)
        port = parts.port or 443
        if not 1 <= port <= 65535 or parts.netloc.endswith(":") or parts.port == 0:
            raise ValueError("Invalid port")
        return parts, host, port
    except (ValueError, TypeError, UnicodeError, AttributeError):
        raise _error("Endpoint is not permitted.", "endpoint_denied") from None


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


@contextmanager
def request_deadline(deadline: float):
    """Bound all synchronous pinned requests in this context, including fresh clients.

    A nested operation can tighten but never extend its caller's absolute monotonic
    deadline. Context-local state avoids affecting other users or concurrent runs.
    """
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise _error("Invalid request deadline.", "http_request_invalid")
    inherited = _REQUEST_DEADLINE.get()
    token = _REQUEST_DEADLINE.set(
        deadline if inherited is None else min(deadline, inherited)
    )
    try:
        _bounded_timeout(SOCKET_TIMEOUT)
        yield
    finally:
        _REQUEST_DEADLINE.reset(token)


def _bounded_timeout(maximum: float) -> float:
    deadline = _REQUEST_DEADLINE.get()
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _error("Remote request timed out.", "http_timeout")
    return min(maximum, remaining)


def _resolve(host: str, port: int) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    # getaddrinfo has no per-call deadline. Bound both waiting time AND outstanding
    # OS resolver jobs; timed-out jobs cannot enqueue unlimited background work.
    timeout = _bounded_timeout(DNS_TIMEOUT)
    if not _DNS_SLOTS.acquire(blocking=False):
        raise _error("Endpoint resolution is unavailable.", "http_dns")
    try:
        future = _DNS_POOL.submit(
            socket.getaddrinfo,
            host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
    except Exception:  # noqa: BLE001 - executor failures are sanitized and release capacity.
        _DNS_SLOTS.release()
        raise _error("Endpoint resolution failed.", "http_dns") from None
    future.add_done_callback(lambda _: _DNS_SLOTS.release())
    try:
        records = future.result(timeout=timeout)
        if not records or len(records) > 32:
            raise ValueError("Invalid DNS answer")
        addresses = []
        for family, _, _, _, sockaddr in records:
            if family not in (socket.AF_INET, socket.AF_INET6) or (
                family == socket.AF_INET6 and (len(sockaddr) != 4 or sockaddr[3] != 0)
            ):
                raise ValueError("Unsupported address family")
            address = str(ipaddress.ip_address(sockaddr[0]))
            if address not in addresses:
                addresses.append(address)
        return addresses
    except Exception:  # noqa: BLE001 - OS resolver/future failures must not reveal inputs.
        raise _error("Endpoint resolution failed.", "http_dns") from None


def validate_endpoint(
    url: str,
    allowed_cidrs: list[str] | tuple[str, ...],
    allowed_hosts: list[str] | tuple[str, ...],
) -> list[str]:
    """Require exact host AND every resolved IP to satisfy explicit egress policy."""
    _, host, port = _https_parts(url)
    try:
        if (
            not isinstance(allowed_hosts, (list, tuple))
            or not 1 <= len(allowed_hosts) <= 128
        ):
            raise ValueError("Invalid host allowlist")
        if host not in {_canonical_host(value) for value in allowed_hosts}:
            raise ValueError("Host not permitted")
        if (
            not isinstance(allowed_cidrs, (list, tuple))
            or not 1 <= len(allowed_cidrs) <= 128
        ):
            raise ValueError("Invalid network allowlist")
        networks = []
        for value in allowed_cidrs:
            if not isinstance(value, str) or "/" not in value:
                raise ValueError("CIDR is required")
            networks.append(ipaddress.ip_network(value, strict=True))
        addresses = _resolve(host, port)
        for value in addresses:
            address = ipaddress.ip_address(value)
            matches = [
                net
                for net in networks
                if net.version == address.version and address in net
            ]
            if _intrinsically_denied(address) or not matches:
                raise ValueError("Address not permitted")
            if not address.is_global and not any(
                net.version == boundary.version
                and net.prefixlen >= boundary.prefixlen
                and net.network_address in boundary
                for net in matches
                for boundary in _PRIVATE_RANGES
            ):
                raise ValueError(
                    "Nonpublic addresses require an explicit narrow network"
                )
        return addresses
    except DomainError:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise _error("Endpoint is not permitted.", "endpoint_denied") from None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect a numeric address without a second DNS lookup; verify the real host."""

    def __init__(
        self,
        host: str,
        port: int,
        address: str,
        context: ssl.SSLContext,
        timeout: float,
    ):
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("TLS verification is required")
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("A bounded connection timeout is required")
        super().__init__(host, port, timeout=timeout, context=context)
        self._connect_timeout = timeout
        self._address = ipaddress.ip_address(address)
        self._tls = context

    def connect(self):
        if getattr(self, "_tunnel_host", None):
            raise ValueError("HTTP tunnels are forbidden")
        family = socket.AF_INET6 if self._address.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            sock.settimeout(_bounded_timeout(self._connect_timeout))
            address = str(self._address)
            sock.connect(
                (address, self.port, 0, 0)
                if family == socket.AF_INET6
                else (address, self.port)
            )
            sock.settimeout(_bounded_timeout(self._connect_timeout))
            self.sock = self._tls.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class PinnedHTTP:
    """Small JSON-only HTTPS transport. No redirects, proxies, retries or cookies.

    GET query parameters are permitted for Kubernetes pagination; the standalone
    The validate_endpoint API intentionally forbids queries.
    Each request resolves once, validates all answers, and connects one numeric IP.
    """

    def __init__(
        self,
        allowed_cidrs: list[str],
        allowed_hosts: list[str],
        ca_data: str | None = None,
        *,
        client_identity: dict | None = None,
    ):
        try:
            if (
                not isinstance(allowed_cidrs, (list, tuple))
                or not 1 <= len(allowed_cidrs) <= 128
                or not isinstance(allowed_hosts, (list, tuple))
                or not 1 <= len(allowed_hosts) <= 128
            ):
                raise ValueError("Invalid egress configuration")
            self.allowed_cidrs = tuple(allowed_cidrs)
            self.allowed_hosts = tuple(allowed_hosts)
            for value in self.allowed_cidrs:
                if not isinstance(value, str) or "/" not in value:
                    raise ValueError("CIDR is required")
                ipaddress.ip_network(value, strict=True)
            for value in self.allowed_hosts:
                _canonical_host(value)
            self._context = _tls_context(ca_data)
            if client_identity is not None:
                _load_client_identity(self._context, client_identity)
        except (ValueError, TypeError, UnicodeError, OSError):
            raise _error(
                "A valid HTTPS egress and trust configuration is required.",
                "configuration_required",
            ) from None

    def get_json(self, url, headers=None) -> dict:
        return self._request("GET", url, headers=headers)

    def post_form(self, url, data: dict, headers=None) -> dict:
        try:
            if (
                not isinstance(data, dict)
                or len(data) > 64
                or any(
                    not isinstance(key, str)
                    or not isinstance(value, str)
                    or len(key) > 256
                    or len(value) > 65536
                    for key, value in data.items()
                )
            ):
                raise ValueError("Invalid form")
            body = urlencode(data).encode("ascii")
        except (ValueError, TypeError, UnicodeError):
            raise _error("Invalid outbound request.", "http_request_invalid") from None
        return self._request(
            "POST", url, body, "application/x-www-form-urlencoded", headers
        )

    def post_json(self, url, data: dict, headers=None) -> dict:
        try:
            if not isinstance(data, dict):
                raise TypeError("Invalid JSON object")
            body = json.dumps(data, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            )
            _json_object(body, MAX_REQUEST_BYTES)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise _error("Invalid outbound request.", "http_request_invalid") from None
        return self._request("POST", url, body, "application/json", headers)

    @staticmethod
    def _headers(headers, host: str, port: int, content_type: str | None) -> dict:
        result = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        authority = f"[{host}]" if ":" in host else host
        result["Host"] = f"{authority}:{port}" if port != 443 else authority
        forbidden = {
            "host",
            "connection",
            "content-length",
            "transfer-encoding",
            "proxy-authorization",
            "proxy-connection",
            "accept-encoding",
            "expect",
            "upgrade",
            "te",
            "trailer",
            "content-type",
        }
        if headers is not None:
            if not isinstance(headers, dict) or len(headers) > 64:
                raise ValueError("Invalid headers")
            seen = set()
            for name, value in headers.items():
                if (
                    not isinstance(name, str)
                    or not _HEADER_NAME.fullmatch(name)
                    or name.lower() in forbidden
                    or name.lower() in seen
                    or not isinstance(value, str)
                    or len(value) > 32768
                    or any(ord(char) < 32 or ord(char) >= 127 for char in value)
                ):
                    raise ValueError("Invalid headers")
                seen.add(name.lower())
                result[name] = value
            if sum(len(key) + len(value) for key, value in result.items()) > 65536:
                raise ValueError("Header size limit")
        if content_type:
            result["Content-Type"] = content_type
        return result

    def _request(self, method, url, body=None, content_type=None, headers=None) -> dict:
        parts, host, port = _https_parts(url, allow_query=method == "GET")
        endpoint = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        if body is not None and len(body) > MAX_REQUEST_BYTES:
            raise _error(
                "Outbound request exceeds size limits.", "http_request_invalid"
            )
        try:
            request_headers = self._headers(headers, host, port, content_type)
        except (ValueError, TypeError):
            raise _error(
                "Invalid outbound request headers.", "http_request_invalid"
            ) from None
        _bounded_timeout(SOCKET_TIMEOUT)
        addresses = validate_endpoint(endpoint, self.allowed_cidrs, self.allowed_hosts)
        connection = None
        response = None
        watchdog = None
        timed_out = threading.Event()
        try:
            deadline = time.monotonic() + RESPONSE_DEADLINE
            inherited = _REQUEST_DEADLINE.get()
            if inherited is not None:
                deadline = min(deadline, inherited)
            connection = _PinnedHTTPSConnection(
                host,
                port,
                addresses[0],
                self._context,
                _bounded_timeout(SOCKET_TIMEOUT),
            )
            target = parts.path or "/"
            if parts.query:
                target += "?" + parts.query
            connection.connect()
            transport = connection.sock

            def expire_transport():
                timed_out.set()
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    transport.close()
                except OSError:
                    pass

            # http.client's header parser can perform many successive reads. A
            # watchdog closes this specific socket even on a slow header stream.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _error("Remote request timed out.", "http_timeout")
            watchdog = threading.Timer(remaining, expire_transport)
            watchdog.daemon = True
            watchdog.start()
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise _error(
                    "HTTP redirects are not permitted.", "http_redirect_denied"
                )
            if not 200 <= response.status < 300:
                raise _error(
                    "Remote service rejected the request.", f"http_{response.status}"
                )
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise _error(
                    "Compressed responses are not supported.", "http_invalid_json"
                )
            media_type = (
                response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            )
            if media_type != "application/json" and not (
                media_type.startswith("application/") and media_type.endswith("+json")
            ):
                raise _error("Remote service did not return JSON.", "http_invalid_json")
            lengths = [
                value
                for key, value in response.getheaders()
                if key.lower() == "content-length"
            ]
            transfers = [
                value
                for key, value in response.getheaders()
                if key.lower() == "transfer-encoding"
            ]
            if (
                len(lengths) > 1
                or len(transfers) > 1
                or (lengths and transfers)
                or (transfers and transfers[0].lower() != "chunked")
            ):
                raise _error("Invalid remote response framing.", "http_invalid_json")
            if lengths:
                if not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
                    raise _error(
                        "Invalid remote response framing.", "http_invalid_json"
                    )
                if int(lengths[0]) > MAX_RESPONSE_BYTES:
                    raise _error(
                        "Remote response exceeds size limits.",
                        "http_response_too_large",
                    )
            data = bytearray()
            # HTTPResponse releases its file (and possibly the socket's last owner)
            # at Content-Length. Do not touch that closed socket for an extra EOF read.
            expected_length = int(lengths[0]) if lengths else None
            while expected_length is None or len(data) < expected_length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _error("Remote request timed out.", "http_timeout")
                transport.settimeout(min(SOCKET_TIMEOUT, remaining))
                # read1 returns after at most one underlying read, allowing a total
                # body deadline even when a peer drip-feeds bytes below socket timeout.
                chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise _error(
                        "Remote response exceeds size limits.",
                        "http_response_too_large",
                    )
            if timed_out.is_set() or time.monotonic() >= deadline:
                raise _error("Remote request timed out.", "http_timeout")
            if lengths and len(data) != int(lengths[0]):
                raise _error("Remote response was incomplete.", "http_invalid_json")
            try:
                return _json_object(bytes(data))
            except (ValueError, TypeError, UnicodeError, RecursionError):
                raise _error(
                    "Remote service returned invalid JSON.", "http_invalid_json"
                ) from None
        except DomainError:
            if timed_out.is_set():
                raise _error("Remote request timed out.", "http_timeout") from None
            raise
        except TimeoutError:
            raise _error("Remote request timed out.", "http_timeout") from None
        except ssl.SSLError:
            if timed_out.is_set():
                raise _error("Remote request timed out.", "http_timeout") from None
            raise _error(
                "Remote TLS verification or negotiation failed.", "http_tls"
            ) from None
        except Exception:  # noqa: BLE001 - never expose transport errors or credential headers.
            if timed_out.is_set():
                raise _error("Remote request timed out.", "http_timeout") from None
            raise _error("Remote HTTPS request failed.", "http_transport") from None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:  # noqa: BLE001, S110 - do not log potentially sensitive I/O exceptions.
                        # Cleanup failures must not expose remote content either.
                        pass
