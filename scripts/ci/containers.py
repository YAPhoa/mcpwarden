#!/usr/bin/env python3
"""Build and smoke-test a unique, disposable Compose project with fake data.

The project runs compose.ci.yaml with the HTTPS override (compose.tls.yaml)
and a throwaway self-signed certificate. Before building, every shipped
Compose file is checked to publish ports on 127.0.0.1 only.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
project = "mcpwarden-ci-" + uuid.uuid4().hex[:12]
tls_dir = Path(tempfile.mkdtemp(prefix="mcpwarden-ci-tls-"))
env = dict(os.environ, MCPWARDEN_CI_TOKEN=secrets.token_urlsafe(32),
           MCPWARDEN_CI_KEY=base64.b64encode(secrets.token_bytes(32)).decode(),
           MCPWARDEN_TLS_DIR=str(tls_dir))
compose = ["docker", "compose", "--env-file", "/dev/null", "-f", "compose.ci.yaml", "-f", "compose.tls.yaml", "-p", project]


def command(*args, capture=False):
    return subprocess.run(compose + list(args), cwd=ROOT, env=env, check=True,
                          stdout=subprocess.PIPE if capture else None, text=True).stdout


def loopback_ports():
    """Every published port in every shipped Compose file binds 127.0.0.1."""
    fake = dict(os.environ, MCPWARDEN_TOKEN="x", MCPWARDEN_CREDENTIAL_KEY="x", MCPWARDEN_CI_TOKEN="x", MCPWARDEN_CI_KEY="x")
    for files in (["compose.yaml"], ["compose.yaml", "compose.tls.yaml"], ["compose.ci.yaml"], ["compose.postgres-test.yaml"]):
        args = [a for f in files for a in ("-f", f)]
        out = subprocess.run(["docker", "compose", "--env-file", "/dev/null"] + args + ["config", "--format", "json"],
                             cwd=ROOT, env=fake, check=True, stdout=subprocess.PIPE, text=True).stdout
        for name, service in json.loads(out)["services"].items():
            for port in service.get("ports", []):
                if port.get("host_ip") != "127.0.0.1":
                    raise RuntimeError(f"{' + '.join(files)}: service {name} publishes port {port.get('target')} beyond 127.0.0.1")
    for path in ROOT.glob("compose*.yaml"):
        if path.name not in ("compose.yaml", "compose.tls.yaml", "compose.ci.yaml", "compose.postgres-test.yaml"):
            raise RuntimeError(f"{path.name} is not covered by the loopback port check")


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
insecure = ssl.create_default_context()
insecure.check_hostname = False
insecure.verify_mode = ssl.CERT_NONE
tls_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=insecure))


def request(port, path, status=200, authenticated=False, scheme="http", headers=None):
    headers = dict(headers or {})
    if authenticated:
        headers["Authorization"] = "Bearer " + env["MCPWARDEN_CI_TOKEN"]
    req = urllib.request.Request(f"{scheme}://127.0.0.1:{port}{path}", headers=headers)
    try:
        response = (tls_opener if scheme == "https" else opener).open(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        if response.status != status:
            raise RuntimeError(f"Fixture {scheme} {path} returned unexpected HTTP status {response.status}")
        return response.read(), response.headers


def owner_error(port, scheme="http", headers=None, status=403):
    body, _ = request(port, "/api/security/csrf", status=status, scheme=scheme, headers=headers)
    return json.loads(body).get("error") if body else None


try:
    loopback_ports()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-keyout", str(tls_dir / "key.pem"), "-out", str(tls_dir / "cert.pem")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (tls_dir / "key.pem").chmod(0o644)  # read by nginx in the container; throwaway key
    command("build", "server", "ui")
    command("up", "-d", "--no-build", "--wait")
    server_port = int(command("port", "server", "8787", capture=True).strip().rsplit(":", 1)[1])
    ui_port = int(command("port", "ui", "80", capture=True).strip().rsplit(":", 1)[1])
    tls_port = int(command("port", "ui", "443", capture=True).strip().rsplit(":", 1)[1])
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
    for port, scheme in ((server_port, "http"), (ui_port, "http"), (tls_port, "https")):
        for path in ("/api/status", "/api/access", "/api/history"):
            request(port, path, status=401, scheme=scheme)
            body, headers = request(port, path, authenticated=True, scheme=scheme)
            json.loads(body)
            if "no-store" not in headers.get("Cache-Control", ""):
                raise RuntimeError("Fixture API caching boundary missing")
    for port, scheme in ((ui_port, "http"), (tls_port, "https")):
        page_policy = None
        for path in ("index.html", "app.js", "security/vault-client.mjs", "security/vault-worker.mjs",
                     "security/vault-core.mjs", "security/argon2-worker.js",
                     "vendor/hash-wasm-4.12.0/argon2.umd.min.js"):
            body, headers = request(port, "/" + path, scheme=scheme)
            if body != (ROOT / "ui/static" / path).read_bytes():
                raise RuntimeError("Fixture static asset mismatch: " + path)
            if path.startswith("security/"):
                if "javascript" not in headers.get("Content-Type", "") or "connect-src 'none'" not in headers.get("Content-Security-Policy", ""):
                    raise RuntimeError("Fixture worker MIME/CSP boundary missing")
            elif path == "index.html":
                page_policy = headers.get("Content-Security-Policy", "")
                if "script-src 'self'" not in page_policy:
                    raise RuntimeError("Fixture page CSP missing")
        request(port, "/security/missing.mjs", status=404, scheme=scheme)
    # Owner routes need HTTPS. nginx overwrites X-Forwarded-Proto with its own
    # scheme, and the gateway trusts it only from the pinned ui address.
    spoof = {"X-Forwarded-Proto": "https"}
    for port, headers in ((server_port, None), (server_port, spoof), (ui_port, None), (ui_port, spoof)):
        if owner_error(port, headers=headers) != "secure_transport_required":
            raise RuntimeError("Fixture owner route accepted plain HTTP")
    if owner_error(tls_port, scheme="https", status=401) != "sign_in_required":
        raise RuntimeError("Fixture owner route refused HTTPS through the pinned proxy")
    print("Loopback ports, container health, API auth/cache boundaries, static assets, worker CSP and HTTPS owner transport passed.")
finally:
    # The unique project and named fixture volume cannot select deployment data.
    command("down", "--volumes", "--remove-orphans")
    for name in ("key.pem", "cert.pem"):
        (tls_dir / name).unlink(missing_ok=True)
    tls_dir.rmdir()
