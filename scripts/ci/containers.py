#!/usr/bin/env python3
"""Build and smoke-test a unique, disposable Compose project with fake data."""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
project = "mcpwarden-ci-" + uuid.uuid4().hex[:12]
env = dict(os.environ, MCPWARDEN_CI_TOKEN=secrets.token_urlsafe(32),
           MCPWARDEN_CI_KEY=base64.b64encode(secrets.token_bytes(32)).decode())
compose = ["docker", "compose", "--env-file", "/dev/null", "-f", "compose.ci.yaml", "-p", project]


def command(*args, capture=False):
    return subprocess.run(compose + list(args), cwd=ROOT, env=env, check=True,
                          stdout=subprocess.PIPE if capture else None, text=True).stdout


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(port, path, status=200, authenticated=False):
    headers = {"Authorization": "Bearer " + env["MCPWARDEN_CI_TOKEN"]} if authenticated else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    try:
        response = opener.open(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        if response.status != status:
            raise RuntimeError(f"Fixture {path} returned unexpected HTTP status {response.status}")
        return response.read(), response.headers


try:
    command("build", "server", "ui")
    command("up", "-d", "--no-build", "--wait")
    server_port = int(command("port", "server", "8787", capture=True).strip().rsplit(":", 1)[1])
    ui_port = int(command("port", "ui", "80", capture=True).strip().rsplit(":", 1)[1])
    deadline = time.monotonic() + 30
    while True:
        try:
            if request(server_port, "/healthz")[0] != b"ok\n":
                raise RuntimeError("Fixture health response mismatch")
            break
        except (OSError, RuntimeError):
            if time.monotonic() >= deadline:
                raise RuntimeError("Fixture did not become healthy") from None
            time.sleep(0.25)
    for port in (server_port, ui_port):
        for path in ("/api/status", "/api/access", "/api/history"):
            request(port, path, status=401)
            body, headers = request(port, path, authenticated=True)
            json.loads(body)
            if "no-store" not in headers.get("Cache-Control", ""):
                raise RuntimeError("Fixture API caching boundary missing")
    for path in ("index.html", "app.js", "security/vault-client.mjs", "security/vault-worker.mjs",
                 "security/vault-core.mjs", "security/argon2-worker.js",
                 "vendor/hash-wasm-4.12.0/argon2.umd.min.js"):
        body, headers = request(ui_port, "/" + path)
        if body != (ROOT / "ui/static" / path).read_bytes():
            raise RuntimeError("Fixture static asset mismatch: " + path)
        if path.startswith("security/"):
            if "javascript" not in headers.get("Content-Type", "") or "connect-src 'none'" not in headers.get("Content-Security-Policy", ""):
                raise RuntimeError("Fixture worker MIME/CSP boundary missing")
    request(ui_port, "/security/missing.mjs", status=404)
    print("Container health, API auth/cache boundaries, static assets and worker CSP passed.")
finally:
    # The unique project and named fixture volume cannot select deployment data.
    command("down", "--volumes", "--remove-orphans")
