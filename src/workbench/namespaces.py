"""Explicit namespace scope and bounded names-only Kubernetes discovery.

Discovery grants no scan authority. The caller supplies its own authenticated,
per-request fenced GET transport and rechecks authorization before publication.
"""

from __future__ import annotations

import re
import ssl
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from .domain import DomainError
from .security import _cluster_endpoint, _https_parts, request_deadline

INVENTORY_VERSION = 1
MAX_NAMESPACES = 100
DISCOVERY_PAGE_SIZE = 200
DISCOVERY_MAX_NAMES = 1000
DISCOVERY_MAX_PAGES = 5
DISCOVERY_TIMEOUT_SECONDS = 30
MAX_CURSOR_LENGTH = 4096
_SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
_DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
_SCOPE_KEYS = frozenset(
    {"namespaces", "max_objects", "timeout_seconds", "inventory_version"}
)


def validate_namespaces(values) -> list[str]:
    """Return a copy of 1..100 distinct explicit Kubernetes DNS-label names."""
    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= MAX_NAMESPACES
        or any(
            not isinstance(value, str) or not _DNS_LABEL.fullmatch(value)
            for value in values
        )
        or len(set(values)) != len(values)
    ):
        raise DomainError("Select between 1 and 100 distinct valid namespaces.")
    return list(values)


def validate_run_scope(scope, allowed_namespaces) -> dict:
    """Validate a sealed version-1 scope; the caller must also require ready state."""
    try:
        if not isinstance(scope, dict) or set(scope) != _SCOPE_KEYS:
            raise ValueError
        names = validate_namespaces(scope["namespaces"])
        allowed = validate_namespaces(allowed_namespaces)
        maximum, timeout = scope["max_objects"], scope["timeout_seconds"]
        if (
            type(scope["inventory_version"]) is not int
            or scope["inventory_version"] != INVENTORY_VERSION
            or type(maximum) is not int
            or not 1 <= maximum <= 10_000
            or type(timeout) is not int
            or not 1 <= timeout <= 600
            or not set(names).issubset(allowed)
        ):
            raise ValueError
    except (ValueError, TypeError, DomainError):
        raise DomainError(
            "The explicit inventory scope is invalid or no longer allowed.",
            "invalid_scope",
        ) from None
    return {
        "namespaces": names,
        "max_objects": maximum,
        "timeout_seconds": timeout,
        "inventory_version": INVENTORY_VERSION,
    }


def _valid_cursor(value: object, *, empty: bool = True) -> bool:
    return (
        isinstance(value, str)
        and (empty or bool(value))
        and len(value) <= MAX_CURSOR_LENGTH
        and all(32 <= ord(char) < 127 for char in value)
    )


def _valid_revision(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and all(33 <= ord(char) < 127 for char in value)
    )


def _list_query(query: str) -> None:
    if not query or re.search(r"%(?![A-Fa-f0-9]{2})", query):
        raise ValueError
    pairs = parse_qsl(
        query,
        keep_blank_values=True,
        strict_parsing=True,
        max_num_fields=2,
        errors="strict",
    )
    # Keys must themselves be literal, not encoded aliases; reject duplicates.
    raw_keys = [field.split("=", 1)[0] for field in query.split("&")]
    if any(key not in ("limit", "continue") for key in raw_keys) or len(
        {key for key, _ in pairs}
    ) != len(pairs):
        raise ValueError
    values = dict(pairs)
    limit = values.get("limit", "")
    if not re.fullmatch(r"[1-9][0-9]{0,2}", limit) or not 1 <= int(limit) <= 500:
        raise ValueError
    if "continue" in values and not _valid_cursor(values["continue"], empty=False):
        raise ValueError


def validate_inventory_url(url, server, namespaces) -> None:
    """Permit only exact version-1 namespaced list URLs and bounded pagination."""
    from .scanners import RESOURCES

    try:
        base = _cluster_endpoint(server)
        names = validate_namespaces(namespaces)
        parts, _, _ = _https_parts(url, allow_query=True)
        origin = urlsplit(base)
        if (
            not url.startswith(base + "/")
            or (parts.scheme, parts.netloc) != (origin.scheme, origin.netloc)
            or parts.path
            not in {
                origin.path + resource.path(namespace)
                for namespace in names
                for resource in RESOURCES
            }
        ):
            raise ValueError
        _list_query(parts.query)
    except (ValueError, TypeError, UnicodeError, DomainError):
        raise DomainError(
            "The request is outside the selected inventory scope.", "scope_denied"
        ) from None


def _invalid_discovery() -> DomainError:
    return DomainError(
        "The API returned an invalid or inconsistent namespace list.",
        "invalid_namespace_discovery",
    )


def _namespace_item(value) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get("metadata"), dict):
        raise _invalid_discovery()
    metadata = value["metadata"]
    name = metadata.get("name")
    if (
        not isinstance(name, str)
        or not _DNS_LABEL.fullmatch(name)
        or value.get("kind", "Namespace") != "Namespace"
        or value.get("apiVersion", "v1") != "v1"
        or metadata.get("namespace", "") != ""
        or (
            "resourceVersion" in metadata
            and not _valid_revision(metadata["resourceVersion"])
        )
    ):
        raise _invalid_discovery()
    status = value.get("status", {})
    if not isinstance(status, dict) or (
        "phase" in status and status["phase"] not in ("Active", "Terminating")
    ):
        raise _invalid_discovery()
    return {
        "name": name,
        "system": name in _SYSTEM_NAMESPACES,
        **({"phase": status["phase"]} if "phase" in status else {}),
    }


def _discovery_result(items: list[dict], limitation: str | None = None) -> dict:
    return {
        "status": "partial" if limitation else "complete",
        "items": sorted(items, key=lambda item: item["name"]),
        "complete": limitation is None,
        "limitation": limitation,
        "continuation": None,
    }


def _discovery_failure(error: DomainError) -> None:
    if error.code == "http_401":
        raise DomainError(
            "Kubernetes authentication was rejected; authorize this connection again.",
            "kubernetes_authentication_required",
        ) from None
    if error.code == "http_410":
        raise DomainError(
            "The namespace list snapshot expired; refresh discovery.",
            "namespace_snapshot_expired",
        ) from None
    messages = {
        "http_tls": "Kubernetes TLS verification or negotiation failed.",
        "http_dns": "Kubernetes endpoint resolution failed.",
        "http_transport": "The Kubernetes connection failed.",
        "http_timeout": "The namespace discovery request timed out.",
        "http_invalid_json": "The API returned invalid namespace discovery data.",
        "http_response_too_large": "The namespace discovery response exceeded size limits.",
        "http_redirect_denied": "A Kubernetes API redirect was rejected.",
        "endpoint_denied": "The cluster endpoint was rejected by egress policy.",
    }
    if error.code in messages:
        raise DomainError(messages[error.code], error.code) from None
    if isinstance(error.code, str) and re.fullmatch(r"http_[1-5][0-9]{2}", error.code):
        raise DomainError(
            "The Kubernetes API rejected namespace discovery.", error.code
        ) from None
    # Local session, owner, credential, policy revision and scope fences are terminal.
    raise error


def discover_namespaces(connection: dict, http, *, continuation=None, seal_continuation=None) -> dict:
    """Bound each batch; only the caller's identity-bound sealer exposes continuation.

    Replaying a sealed cursor is an idempotent read of the same snapshot, not new
    authorization. The caller must deduplicate appended names and never auto-select.
    """
    from .scanners import _BadInventory, _connection, _list_page, _Resource

    server, headers = _connection(connection)
    deadline = time.monotonic() + DISCOVERY_TIMEOUT_SECONDS
    resource = _Resource("namespaces", "Namespace", "v1")
    items: list[dict] = []
    seen_names: set[str] = set()
    seen_cursors: set[str] = set()
    cursor = continuation["cursor"] if continuation else ""
    snapshot = continuation["snapshot"] if continuation else None
    expiry = continuation["expires_at"] if continuation else None
    if continuation and (not _valid_cursor(cursor, empty=False) or not _valid_revision(snapshot)):
        raise DomainError("Invalid namespace continuation; refresh discovery.", "invalid_namespace_continuation")
    if cursor:
        seen_cursors.add(cursor)

    def partial(message):
        result = _discovery_result(items, message)
        if cursor and snapshot and seal_continuation:
            result["continuation"] = seal_continuation(cursor, snapshot, expiry)
        return result

    for _ in range(DISCOVERY_MAX_PAGES):
        if time.monotonic() >= deadline:
            return partial("Namespace discovery reached its 30-second deadline; the list is incomplete.")
        query = {"limit": DISCOVERY_PAGE_SIZE}
        if cursor:
            query["continue"] = cursor
        try:
            with request_deadline(deadline):
                data = http.get_json(
                    server + "/api/v1/namespaces?" + urlencode(query), headers=headers
                )
            values, next_cursor, revision = _list_page(
                data, resource, DISCOVERY_PAGE_SIZE
            )
            if continuation and snapshot is not None and revision != snapshot:
                raise DomainError("The namespace list snapshot expired; refresh discovery.", "namespace_snapshot_expired")
            if (
                (snapshot is not None and revision != snapshot)
                or not _valid_revision(revision)
                or not _valid_cursor(next_cursor)
            ):
                raise _invalid_discovery()
            if next_cursor and next_cursor in seen_cursors:
                raise _invalid_discovery()
            snapshot = revision
            projected = [_namespace_item(value) for value in values]
            for item in projected:
                if item["name"] in seen_names:
                    raise _invalid_discovery()
                seen_names.add(item["name"])
            items.extend(projected)
        except _BadInventory:
            raise _invalid_discovery() from None
        except DomainError as error:
            if error.code == "http_403":
                return {
                    "status": "forbidden",
                    "items": [],
                    "complete": False,
                    "limitation": "Namespace discovery is forbidden; enter explicit namespace names manually.",
                    "continuation": None,
                }
            _discovery_failure(error)
        except ssl.SSLError:
            raise DomainError(
                "Kubernetes TLS verification or negotiation failed.", "http_tls"
            ) from None
        except TimeoutError:
            raise DomainError(
                "The namespace discovery request timed out.", "http_timeout"
            ) from None
        except OSError:
            raise DomainError(
                "The Kubernetes connection failed.", "http_transport"
            ) from None
        cursor = next_cursor
        if not cursor:
            return _discovery_result(items)
        if time.monotonic() >= deadline:
            return partial("Namespace discovery reached its 30-second deadline; the list is incomplete.")
        if len(items) >= DISCOVERY_MAX_NAMES:
            break
        seen_cursors.add(cursor)
    return partial("Namespace discovery reached its 1000-name or 5-page limit; load more to continue.")
