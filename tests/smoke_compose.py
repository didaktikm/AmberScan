"""Explicit opt-in Docker smoke: creates and removes its own disposable stack only.

Run from project root: PYTHONPATH=src uv run python tests/smoke_compose.py
Requires local Docker Desktop. No real cluster/IdP connections or persistent user account.
"""

import json
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

import httpx

from workbench.setup_local import prepare_local

ROOT = Path(__file__).resolve().parents[1]


def run() -> None:
    project = "amberdata-smoke-" + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        directory = Path(temporary)
        prepare_local(directory)
        config_path = directory / "config.json"
        config = json.loads(config_path.read_text())
        config["public_origin"] = "http://127.0.0.1:18080"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        environment = {
            **os.environ,
            "WORKBENCH_LOCAL_DIR": str(directory),
            "WORKBENCH_UID": str(os.getuid()),
            "WORKBENCH_GID": str(os.getgid()),
            "WORKBENCH_PORT": "18080",
        }
        if os.getuid() == 0:
            raise RuntimeError("Do not run this local smoke as root")
        command = [
            "docker",
            "--context",
            "desktop-linux",
            "compose",
            "--project-directory",
            str(ROOT),
            "--project-name",
            project,
        ]

        def compose(*args: str, input: str | None = None, capture: bool = False):
            return subprocess.run(
                [*command, *args],
                env=environment,
                text=True,
                input=input,
                check=True,
                capture_output=capture,
                timeout=240,
            )

        try:
            compose(
                "up",
                "-d",
                "--no-build",
                "--wait",
                "--wait-timeout",
                "120",
                "api",
                "worker",
            )
            with httpx.Client(
                base_url="http://127.0.0.1:18080", timeout=10, trust_env=False
            ) as client:
                assert client.get("/api/health/ready").json()["status"] == "ready"
                assert client.get("/").status_code == 200
                assert client.get("/api/session").status_code == 401
                assert (
                    client.post(
                        "/api/login",
                        json={"username": "admin", "password": "does-not-exist"},
                    ).status_code
                    == 401
                )
                print("PASS: readiness + built UI; no default credentials", flush=True)
                password = secrets.token_urlsafe(32)
                seed = "import json,sys; from workbench.config import Settings; from workbench.db import database; from workbench.admin import create_user; engine,sessions=database(Settings.from_env().database_url); data=json.load(sys.stdin);\nwith sessions.begin() as s: create_user(s,'smoke-admin',data['password'],'administrator')\nengine.dispose()"
                compose(
                    "exec",
                    "-T",
                    "api",
                    "python",
                    "-c",
                    seed,
                    input=json.dumps({"password": password}),
                    capture=True,
                )
                response = client.post(
                    "/api/login", json={"username": "smoke-admin", "password": password}
                )
                assert response.status_code == 200, response.status_code
                csrf = response.json()["csrf_token"]
                assert (
                    client.get("/api/session").json()["user"]["role"] == "administrator"
                )
                capabilities = client.get("/api/capabilities").json()
                assert capabilities["version"] == "0.5.2"
                assert "oidc_providers" not in capabilities
                assert "oidc_setup_required" not in capabilities
                overview = client.get("/api/overview").json()
                for _ in range(10):
                    if any(
                        worker["status"] == "idle" for worker in overview["workers"]
                    ):
                        break
                    time.sleep(1)
                    overview = client.get("/api/overview").json()
                assert any(worker["status"] == "idle" for worker in overview["workers"])
                assert overview["clusters"] == overview["findings"] == 0
                admin_headers = {"X-CSRF-Token": csrf}
                setup = client.get("/api/admin/setup")
                assert setup.status_code == 200
                assert "providers" not in setup.json()
                assert "redirect_uri" not in setup.json()
                policy = {
                    "expected_revision": 0,
                    "rules": [
                        {
                            "id": "smoke-kubernetes",
                            "purpose": "kubernetes",
                            "host": "kubernetes.example.test",
                            "port": 443,
                            "cidrs": ["10.42.0.10/32"],
                        }
                    ],
                }
                assert client.put(
                    "/api/admin/egress-policy", json=policy, headers=admin_headers
                ).status_code == 403
                reauth = client.post(
                    "/api/admin/reauth",
                    json={"password": password},
                    headers=admin_headers,
                )
                assert reauth.status_code == 200, reauth.status_code
                result = client.put(
                    "/api/admin/egress-policy", json=policy, headers=admin_headers
                )
                assert result.status_code == 200, result.status_code
                assert client.get("/api/admin/setup").json()["policy"]["revision"] == 1
                for method, path in (
                    ("POST", "/api/admin/oidc-providers"),
                    ("GET", "/api/oidc/callback?code=removed&state=removed"),
                    ("POST", "/api/clusters/removed/authorize"),
                ):
                    removed = client.request(method, path, headers=admin_headers)
                    assert removed.status_code == 404, (path, removed.status_code)
                    assert "application/json" in removed.headers.get("content-type", "")
                print(
                    "PASS: kubeconfig-only admin setup, recent reauthentication, saved egress; removed routes return JSON 404",
                    flush=True,
                )
                assert client.post("/api/logout").status_code == 403
                assert (
                    client.post(
                        "/api/logout",
                        headers={
                            "X-CSRF-Token": csrf,
                            "Origin": "https://untrusted.invalid",
                        },
                    ).status_code
                    == 403
                )
                assert (
                    client.post(
                        "/api/logout", headers={"X-CSRF-Token": csrf}
                    ).status_code
                    == 200
                )
                assert client.get("/api/session").status_code == 401
                print(
                    "PASS: PostgreSQL login/session/CSRF/logout and live worker heartbeat",
                    flush=True,
                )
                compose("restart", "api", "worker", capture=True)
                for _ in range(30):
                    try:
                        if client.get("/api/health/ready").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(1)
                response = client.post(
                    "/api/login", json={"username": "smoke-admin", "password": password}
                )
                assert response.status_code == 200
                assert client.get("/api/audit").status_code == 200
                after_restart = client.get("/api/admin/setup").json()
                assert "providers" not in after_restart
                assert after_restart["policy"]["revision"] == 1
                assert after_restart["policy"]["rules"] == policy["rules"]
                print(
                    "PASS: restart preserves account, audit history and integration settings",
                    flush=True,
                )
                compose(
                    "run",
                    "--rm",
                    "--no-deps",
                    "api",
                    "python",
                    "-m",
                    "workbench.admin",
                    "init-db",
                    capture=True,
                )
                print("PASS: repeat schema bootstrap is non-destructive", flush=True)
                hold_seconds = min(
                    int(os.environ.get("WORKBENCH_SMOKE_BROWSER_HOLD", "0")), 900
                )
                if hold_seconds > 0:
                    # Ephemeral test account only; never emit its password into logs.
                    login_file = directory / "browser-login.json"
                    descriptor = os.open(
                        login_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                    )
                    with os.fdopen(descriptor, "w") as output:
                        json.dump(
                            {
                                "url": "http://127.0.0.1:18080",
                                "username": "smoke-admin",
                                "password": password,
                                "done_file": str(directory / "browser.done"),
                            },
                            output,
                        )
                    print(f"BROWSER_SMOKE_LOGIN_FILE={login_file}", flush=True)
                    deadline = time.monotonic() + hold_seconds
                    while (
                        time.monotonic() < deadline
                        and not (directory / "browser.done").exists()
                    ):
                        time.sleep(1)
        finally:
            compose("down", "--volumes", "--remove-orphans")
            print(
                "Disposable smoke stack removed; no user deployment was changed.",
                flush=True,
            )


if __name__ == "__main__":
    run()
