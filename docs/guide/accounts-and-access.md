# Accounts and access

Panel accounts give each person a private workspace with their own remote connections, vault credentials, and tool visibility. This page covers signing up, API keys, sessions, and limits. For upstream setup, see [Upstreams](upstreams.md).

## Enable accounts

The Compose example enables basic username/password registration. Open the panel, choose **Create an account**, and use a passphrase of at least 15 characters.

Enable accounts on an existing local-mode deployment with:

```yaml
accounts:
  allow_registration: true
```

- Accounts require `managed_upstreams`.
- Set `allow_registration: false` after the intended users register if signup should be closed.
- Accounts cannot be combined with external [OAuth mode](oauth-mode.md).
- Account registration grants a personal workspace, not global administrator privileges.
- Shared config upstreams remain available to every account, so use config entries only for intentionally shared services.
- Basic accounts do not yet include password reset, email verification, account deletion, or account administration.

## Using the panel

- The sidebar shows the current account. The dashboard is the landing page, with workspace totals and links to connectors.
- Opening an upstream shows its searchable, paginated tool list and manual enable switches. Filter by **Discoverable** or **Not discoverable**; expand **Connection settings** for endpoints, credentials, refresh and removal. The top breadcrumb links back to Upstreams.
- The separate tool directory searches across connections.
- **Refresh all** on Upstreams fetches fresh tool metadata for every enabled connector and reports individual failures.
- The bottom-left **Account & appearance** menu contains theme selection, sign out, and local-account password changes.
- MCP connection instructions live under **Access**.
- Browser Back/Forward and direct links work.

## Passwords and browser sessions

- The existing encrypted catalog stores salted PBKDF2-SHA256 password hashes (600,000 iterations).
- Browser sessions use HttpOnly, SameSite=Strict cookies, expire after 12 hours, and persist across gateway restarts.
- Cookies require HTTPS outside loopback; serve the public panel over HTTPS.
- JSON requests with a custom header and origin checks protect session mutations.
- Authentication requests have a shared limit of 30/minute and at most two password computations at a time.
- Changing a password requires the current password and revokes other browser sessions; API keys remain active.

## API keys

Use **Access** after sign-in to create a named, expiring API key for `/mcp`. Keys are shown once and only their hashes are stored.

| Role | Can use |
| --- | --- |
| **Client** | Enabled upstream tools and the per-provider refresh endpoint. No other management API. |
| **Admin** | Client tools plus provider listing, addition, removal, enable/disable, and tool visibility management. |

- Existing single client tokens migrate to client-only keys.
- Browser session cookies are not accepted for MCP connections.
- The shared operator token remains usable through **Use an access token**; existing operator connections stay in that separate shared workspace.

### Key format and public IDs

- New named keys use `mcpw_<public ID>_<secret>`.
- Access pages display a short public-ID suffix, lengthened on collisions, and the full public ID in details.
- Existing `mw_` keys retain their tokens and verifier hashes and receive independent public IDs on catalog load.
- Call history keeps the exact authenticated access ID and label snapshot across renames and reconnects; `GET /api/history?actor_access_id=...` filters that owner's calls for one access record.
- Public handles do not grant authentication or approval authority.

## The Access page and limits

The **Access** page lists named API keys, browser sessions, observed OAuth tokens, and active MCP connections. It supports rename and revocation, shows device/client names and creation/last-use/expiry times, and keeps ended/revoked history.

Server-enforced limits per workspace:

- **10 active API keys**
- **10 active browser/OAuth sessions combined**
- **10 concurrent MCP connections across all credentials**

Revocation and expiry free capacity. New keys expire after 1–365 days. MCP sessions expire with their credential and have a 30-minute idle timeout; process restart ends old MCP connections. Revoking a key closes its MCP connections; revoking an MCP connection leaves its key usable. Session IDs are bound to the exact credential and role, not just the account.

OAuth revocation blocks that observed access token locally at this gateway; it does not revoke the identity provider's grant or future tokens. The configured operator bootstrap token is managed in configuration and is outside the minted-key list and limit. Encrypted lifecycle records retain creation, update, last-use, end/revocation and deletion times where applicable; provider deletion retains a credential-free UUID tombstone.

## Workspaces and storage

Each registered upstream belongs to one gateway user. Operator-token access has one shared user named `local`; registered accounts use separate internal identities. With OAuth mode, the validated access-token `sub` identifies the user for both `/mcp` and `/api`; each user can register a separate endpoint, even under the same upstream name (only connectors without authentication, since the owner vault needs panel accounts). Static YAML upstreams remain available to every user.

By default, the gateway stores personal connections and the last successful tool discovery in an AES-GCM encrypted file under `/data`. Managed state and audit history sit behind separate backend interfaces so a database adapter can be added without changing runtime or authentication logic; a PostgreSQL driver and schema are not bundled for the catalog. See [the catalog storage contract](../catalog-storage.md) and [the history storage contract](../history-storage.md).
