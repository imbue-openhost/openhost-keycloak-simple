# openhost-keycloak-simple

[Keycloak](https://www.keycloak.org/) 26 packaged as an OpenHost app, with
automatic owner SSO into the admin console.

## What you get

- Keycloak 26.3 (Quarkus, pre-built with `kc.sh build` for fast startup)
- H2 `dev-file` database persisted under `$OPENHOST_APP_DATA_DIR/h2`
- A stdlib-Python auth proxy on the OpenHost-routed port `8080` that:
  - auto-logs the OpenHost owner into the admin console (no password to
    remember), and
  - passes realm endpoints (`/realms/`, `/resources/`) through for
    anonymous visitors, so external apps can use this Keycloak as an
    OIDC/SAML identity provider.

## Auth model

When the OpenHost owner opens `https://keycloak.<zone>/`, the OpenHost
router stamps `X-OpenHost-Is-Owner: true` on the request (and strips any
client-supplied `X-OpenHost-*` headers, so only the real owner carries it).
On an owner HTML navigation without a Keycloak session cookie, the proxy:

1. drives Keycloak's own browser login (auth-code + PKCE against the
   `security-admin-console` client) on loopback using a per-boot bootstrap
   admin, and
2. replays the resulting Keycloak session cookies onto the visitor's
   browser and redirects back to the original URL.

The browser then completes the admin console's normal OIDC flow silently —
the owner lands in the console already logged in.

### Per-boot bootstrap admin, no secrets on disk

On every container start, `start.sh` generates a fresh admin user
(`openhost-sso-<random>`) with a random password via
`kc.sh bootstrap-admin user`. Both values live only in process
environments — **nothing secret is written to `$OPENHOST_APP_DATA_DIR`**,
which other apps (e.g. file-browser) may be able to read. Once Keycloak is
up, the proxy deletes stale `openhost-sso-*` users left over from previous
boots, so exactly one is live at any time.

Keycloak flags these as "temporary admin" accounts and shows a banner in
the console. You can create yourself a permanent admin account in the
console if you prefer logging in directly; the SSO accounts remain
rotation-safe either way.

The H2 database files under `$OPENHOST_APP_DATA_DIR/h2` contain Keycloak's
normal state (hashed credentials, realm config) — the standard for any
stateful app — but no plaintext secrets.

## Public paths

`routing.public_paths` in `openhost.toml` (mirrored by `PUBLIC_PATHS` in
`auth_proxy.py`):

- `/realms/` — OIDC/SAML endpoints, login pages, account console
- `/resources/` — theme assets (CSS/JS/images for login pages)
- `/robots.txt`

The admin console (`/admin/...`) and the root redirect stay behind
OpenHost owner auth. Note that the **master realm's** login endpoints are
public like any other realm's (this is how Keycloak normally runs); admin
access still requires valid credentials, and the only admin users are the
per-boot random ones.

## Operational notes

- First boot takes ~1–2 minutes (H2 schema creation + JVM start). The
  proxy serves a self-refreshing "starting" page until Keycloak is ready.
- Memory: the manifest reserves 2 GiB; Keycloak on H2 idles around 700 MiB.
- To use this Keycloak as an IdP for another app, create a realm + client
  in the admin console and point the app at
  `https://keycloak.<zone>/realms/<realm>`.
- H2 `dev-file` is fine for small installations (it is Keycloak's bundled
  storage); for heavy multi-realm production use you would want to move to
  an external Postgres.
