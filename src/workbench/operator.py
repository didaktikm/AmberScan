"""In-cluster read-only loop started by the confirmed operator manifest.

This process never creates, updates, or deletes Kubernetes objects.
"""

from __future__ import annotations

import http.client
import os
import ssl
import time
from pathlib import Path

_ACCOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
_INTERVAL = 6 * 60 * 60


def read_once() -> None:
    token_file = _ACCOUNT / "token"
    ca_file = _ACCOUNT / "ca.crt"
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if not host or not token_file.is_file() or not ca_file.is_file() or not port.isdigit():
        return
    token = token_file.read_text(encoding="utf-8").strip()
    context = ssl.create_default_context(cafile=str(ca_file))
    connection = http.client.HTTPSConnection(host, int(port), context=context, timeout=10)
    try:
        connection.request(
            "GET",
            "/api/v1/namespaces?limit=1",
            headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        )
        response = connection.getresponse()
        response.read(1024)
    finally:
        connection.close()


def main() -> None:
    while True:
        try:
            read_once()
        except Exception:
            pass
        time.sleep(_INTERVAL)


if __name__ == "__main__":
    main()
