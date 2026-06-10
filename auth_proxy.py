#!/usr/bin/env python3
"""OpenHost SSO auth proxy for Keycloak.

Sits on port 8080 (the OpenHost-routed port) in front of Keycloak on
loopback :8081 and:

* serves /_healthz plus a 200 "starting" placeholder while the JVM boots,
  so OpenHost's readiness probe (GET / must be < 500) passes;
* transparently proxies everything else, rewriting Host / X-Forwarded-*
  so Keycloak's hostname handling produces correct external URLs;
* auto-logs the OpenHost owner (X-OpenHost-Is-Owner: true, stamped by the
  OpenHost router, which strips any client-supplied X-OpenHost-* headers)
  into the Keycloak admin console by driving Keycloak's own browser login
  with the per-boot bootstrap admin credentials (SSO_USER / SSO_PASSWORD,
  provided via environment by start.sh) and replaying Keycloak's session
  cookies onto the visitor's browser;
* deletes stale per-boot bootstrap admins left over from previous boots.

Anonymous traffic on PUBLIC_PATHS (realm OIDC endpoints, theme assets) is
never auto-logged-in; it flows straight through so external apps can use
this Keycloak as their IdP.
"""

from __future__ import annotations

import base64
import hashlib
import html
import http.client
import http.server
import json
import os
import re
import secrets
import threading
import time
import urllib.parse

LISTEN_PORT = int(os.environ.get("PROXY_LISTEN_PORT", "8080"))
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = int(os.environ.get("KC_HTTP_PORT", "8081"))
MANAGEMENT_PORT = int(os.environ.get("KC_HTTP_MANAGEMENT_PORT", "9001"))

APP_NAME = os.environ.get("OPENHOST_APP_NAME", "keycloak")
ZONE_DOMAIN = os.environ.get("OPENHOST_ZONE_DOMAIN", "")
PUBLIC_HOST = f"{APP_NAME}.{ZONE_DOMAIN}" if ZONE_DOMAIN else "localhost"

SSO_USER = os.environ.get("SSO_USER", "")
SSO_PASSWORD = os.environ.get("SSO_PASSWORD", "")
SSO_USER_PREFIX = "openhost-sso-"

# MUST mirror routing.public_paths in openhost.toml.
PUBLIC_PATHS = ("/realms/", "/resources/", "/robots.txt")

SESSION_COOKIE = "KEYCLOAK_IDENTITY"

# Keycloak scopes its session cookies to Path=/realms/master/, so the browser
# never sends them on /admin or / navigations — the proxy cannot see them to
# know the owner is already logged in. Without a tracker the proxy would
# re-run the login dance on every owner navigation (an infinite redirect loop
# on /). We therefore set our own Path=/ marker cookie alongside the Keycloak
# cookies. It expires before Keycloak's default 30-minute SSO idle timeout so
# an expired Keycloak session simply triggers a fresh (silent) auto-login.
MARKER_COOKIE = "OPENHOST_KC_SSO"
MARKER_MAX_AGE = 25 * 60

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

STARTING_PAGE = (
    b"<!doctype html><html><head><title>Keycloak is starting</title>"
    b'<meta http-equiv="refresh" content="5"></head>'
    b'<body style="font-family:system-ui;text-align:center;margin-top:4em;">'
    b"<h1>Keycloak is starting&hellip;</h1>"
    b"<p>This page refreshes automatically.</p></body></html>"
)


def log(msg: str) -> None:
    print(f"[auth-proxy] {msg}", flush=True)


def is_public_path(path: str) -> bool:
    return any(
        path == prefix or path.startswith(prefix.rstrip("/") + "/")
        for prefix in PUBLIC_PATHS
    )


def cookie_header_from(set_cookies: list[str]) -> str:
    pairs = []
    for sc in set_cookies:
        first = sc.split(";", 1)[0].strip()
        if "=" in first:
            pairs.append(first)
    return "; ".join(pairs)


class LoginError(Exception):
    pass


def upstream_request(
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes | None = None,
) -> tuple[http.client.HTTPResponse, http.client.HTTPConnection]:
    conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=60)
    try:
        conn.request(method, path, body=body, headers=headers)
        return conn.getresponse(), conn
    except BaseException:
        conn.close()
        raise


def base_headers() -> dict[str, str]:
    return {
        "Host": PUBLIC_HOST,
        "X-Forwarded-Host": PUBLIC_HOST,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Port": "443",
        "X-Forwarded-For": "127.0.0.1",
        "Accept": "text/html,application/xhtml+xml",
        "User-Agent": "openhost-auth-proxy",
    }


def perform_admin_login() -> list[str]:
    """Drive Keycloak's browser login for the bootstrap admin.

    Returns the Set-Cookie header values that establish the session, to be
    replayed onto the visitor's browser. Raises LoginError when the flow
    fails for non-transport reasons.
    """
    if not SSO_USER or not SSO_PASSWORD:
        raise LoginError("SSO credentials not configured")

    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    redirect_uri = f"https://{PUBLIC_HOST}/admin/master/console/"
    auth_path = "/realms/master/protocol/openid-connect/auth?" + urllib.parse.urlencode(
        {
            "client_id": "security-admin-console",
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",
            "state": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )

    resp, conn = upstream_request("GET", auth_path, base_headers())
    page = resp.read().decode("utf-8", "replace")
    auth_cookies = resp.headers.get_all("Set-Cookie") or []
    conn.close()
    if resp.status != 200:
        raise LoginError(f"auth endpoint returned {resp.status}")

    match = re.search(r'<form[^>]+action="([^"]+)"', page)
    if not match:
        raise LoginError("could not find login form action")
    action = html.unescape(match.group(1))
    parsed = urllib.parse.urlparse(action)
    form_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

    form_body = urllib.parse.urlencode(
        {"username": SSO_USER, "password": SSO_PASSWORD, "credentialId": ""}
    ).encode()
    headers = base_headers()
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Cookie"] = cookie_header_from(auth_cookies)
    resp, conn = upstream_request("POST", form_path, headers, form_body)
    resp.read()
    login_cookies = resp.headers.get_all("Set-Cookie") or []
    location = resp.getheader("Location") or ""
    conn.close()

    if resp.status not in (302, 303) or "code=" not in location:
        raise LoginError(f"login POST returned {resp.status} (location={location!r})")

    # Merge by cookie name (login-response cookies win) and replay only the
    # KEYCLOAK_* session cookies. Replaying the consumed AUTH_SESSION_ID /
    # KC_AUTH_SESSION_HASH cookies breaks the browser's subsequent silent
    # SSO: Keycloak then shows the login form instead of issuing a code.
    merged: dict[str, str] = {}
    for sc in auth_cookies + login_cookies:
        name = sc.split("=", 1)[0].strip()
        if name.startswith("KEYCLOAK_"):
            merged[name] = sc
    if SESSION_COOKIE not in merged:
        raise LoginError("login flow did not produce an identity cookie")
    return list(merged.values())


# ─── stale bootstrap-admin cleanup ──────────────────────────────────────────


def admin_api(method: str, path: str, token: str) -> tuple[int, bytes]:
    headers = base_headers()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {token}"
    resp, conn = upstream_request(method, path, headers)
    data = resp.read()
    conn.close()
    return resp.status, data


def get_admin_token() -> str | None:
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": SSO_USER,
            "password": SSO_PASSWORD,
        }
    ).encode()
    headers = base_headers()
    headers["Accept"] = "application/json"
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        resp, conn = upstream_request(
            "POST", "/realms/master/protocol/openid-connect/token", headers, body
        )
        data = resp.read()
        conn.close()
        if resp.status != 200:
            log(f"token request failed: {resp.status} {data[:200]!r}")
            return None
        return json.loads(data)["access_token"]
    except (OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        log(f"token request error: {exc}")
        return None


def wait_for_keycloak_ready(timeout: float = 600.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            conn = http.client.HTTPConnection(UPSTREAM_HOST, MANAGEMENT_PORT, timeout=5)
            conn.request("GET", "/health/ready")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return True
        except OSError:
            pass
        time.sleep(3)
    return False


def cleanup_stale_sso_users() -> None:
    """Delete bootstrap admins left behind by previous container boots."""
    try:
        if not wait_for_keycloak_ready():
            log("keycloak never became ready; skipping stale-user cleanup")
            return
        token = get_admin_token()
        if token is None:
            log("could not obtain admin token; skipping stale-user cleanup")
            return
        query = urllib.parse.urlencode({"username": SSO_USER_PREFIX, "max": "200"})
        status, data = admin_api("GET", f"/admin/realms/master/users?{query}", token)
        if status != 200:
            log(f"user search failed: {status}")
            return
        removed = 0
        for user in json.loads(data):
            username = user.get("username", "")
            if username.startswith(SSO_USER_PREFIX) and username != SSO_USER:
                status, _ = admin_api(
                    "DELETE", f"/admin/realms/master/users/{user['id']}", token
                )
                if status == 204:
                    removed += 1
                else:
                    log(f"failed to delete stale user {username}: {status}")
        log(f"stale-user cleanup done ({removed} removed)")
    except Exception as exc:  # never kill the proxy over cleanup
        log(f"stale-user cleanup error: {exc}")


# ─── proxy ──────────────────────────────────────────────────────────────────


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "openhost-auth-proxy"

    def log_message(self, fmt: str, *args: object) -> None:  # quieter logs
        pass

    def do_GET(self) -> None:
        self.handle_request("GET")

    def do_HEAD(self) -> None:
        self.handle_request("HEAD")

    def do_POST(self) -> None:
        self.handle_request("POST")

    def do_PUT(self) -> None:
        self.handle_request("PUT")

    def do_DELETE(self) -> None:
        self.handle_request("DELETE")

    def do_PATCH(self) -> None:
        self.handle_request("PATCH")

    def do_OPTIONS(self) -> None:
        self.handle_request("OPTIONS")

    def handle_request(self, method: str) -> None:
        try:
            if self.path == "/_healthz":
                self.send_plain(200, b"ok", method)
                return

            if self.should_auto_login(method) and self.try_auto_login():
                return

            try:
                self.proxy_upstream(method)
            except (OSError, http.client.HTTPException):
                self.send_starting_placeholder(method)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client went away mid-response

    # ── owner auto-login ────────────────────────────────────────────────

    def should_auto_login(self, method: str) -> bool:
        if method != "GET":
            return False
        if is_public_path(self.path):
            return False
        if self.headers.get("X-OpenHost-Is-Owner", "").lower() != "true":
            return False
        if "text/html" not in self.headers.get("Accept", "").lower():
            return False
        cookies = self.headers.get("Cookie", "")
        if f"{MARKER_COOKIE}=" in cookies:
            return False
        return f"{SESSION_COOKIE}=" not in cookies

    def try_auto_login(self) -> bool:
        try:
            session_cookies = perform_admin_login()
        except LoginError as exc:
            log(f"auto-login failed, falling through to proxy: {exc}")
            return False
        except (OSError, http.client.HTTPException):
            self.send_starting_placeholder("GET")
            return True
        self.send_response(302)
        self.send_header("Location", self.path)
        for cookie in session_cookies:
            self.send_header("Set-Cookie", cookie)
        self.send_header(
            "Set-Cookie",
            f"{MARKER_COOKIE}=1;Path=/;Max-Age={MARKER_MAX_AGE};Secure;HttpOnly;SameSite=Lax",
        )
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        log("owner auto-login performed")
        return True

    # ── plain proxying ──────────────────────────────────────────────────

    def proxy_upstream(self, method: str) -> None:
        body = None
        length = self.headers.get("Content-Length")
        if length:
            body = self.rfile.read(int(length))

        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            if key.lower() in HOP_BY_HOP or key.lower() == "host":
                continue
            headers[key] = value

        forwarded_host = self.headers.get("X-Forwarded-Host", PUBLIC_HOST)
        headers["Host"] = forwarded_host
        headers["X-Forwarded-Host"] = forwarded_host
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Port"] = "443"
        headers.setdefault("X-Forwarded-For", self.client_address[0])
        headers["Connection"] = "close"

        resp, conn = upstream_request(method, self.path, headers, body)
        try:
            data = resp.read()
            self.send_response(resp.status)
            for key, value in resp.getheaders():
                if key.lower() in HOP_BY_HOP or key.lower() == "content-length":
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if method != "HEAD" and data:
                self.wfile.write(data)
        finally:
            conn.close()

    # ── fallbacks ───────────────────────────────────────────────────────

    def send_starting_placeholder(self, method: str) -> None:
        """Upstream is down (cold start). Keep the readiness probe happy."""
        accepts_html = "text/html" in self.headers.get("Accept", "").lower()
        if method in ("GET", "HEAD") and (self.path == "/" or accepts_html):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(STARTING_PAGE)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(STARTING_PAGE)
        else:
            self.send_plain(503, b"Keycloak is starting", method)

    def send_plain(self, status: int, body: bytes, method: str = "GET") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)


def main() -> None:
    threading.Thread(target=cleanup_stale_sso_users, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), ProxyHandler)
    server.daemon_threads = True
    log(f"listening on :{LISTEN_PORT}, upstream {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
