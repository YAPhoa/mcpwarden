# Pending work

Current boundary: storage is a required SQLite or PostgreSQL database holding
the catalog, history, leases and vault; the file catalog and JSONL history are
gone, and the live gateway needs the fresh-start deployment. The lease engine,
browser crypto primitives, ciphertext storage, owner security API and owner
vault console are implemented and tested. The owner API and console are opt-in
(`owner_security`) and need HTTPS, which `compose.tls.yaml` adds in Compose. Personal connectors store header
names only; a connector with credentials is in vault custody from creation and
needs `owner_security`, and upstream OAuth is removed until step 6. The original
acceptance checklist remains in [spec v1.1](security/spec-v1.1/IMPLEMENTATION-CHECKLIST.md);
per-case coverage of the 68 acceptance tests is in the
[acceptance matrix](security/acceptance-matrix.md).

## Next implementation sequence

1. **Owner security API.** Implemented behind the opt-in `owner_security`
   setting; see [owner API](security/owner-api.md). Owner-scoped vault/credential
   persistence and request, confirmation, activation, revocation and
   execution-lock endpoints enforce interactive browser authentication,
   verified HTTPS transport, CSRF/Origin checks, bounded inputs, rate limits and
   mutation audit. Session authority is rechecked inside owner transactions;
   revocation and password changes share the owner gate. Approval
   `none` still requires explicit owner CEK release; MCP keys cannot activate.
2. **Vault and lease UI.** Implemented at `/vault` for the opt-in API; see
   [UI design](../ui/DESIGN.md#vault-and-access-windows-2026-09-24). It covers
   setup with a verified recovery key, passphrase or recovery unlock, passphrase
   changes, browser-encrypted credential entry and replacement for existing
   header-authenticated HTTP connectors, request review, explicit activation and
   renewal, fixed countdowns, and the separate browser lock, stop access and
   lock-all controls. Real-browser flows run against a gateway on SQLite in
   Chromium, Firefox and WebKit in CI, and on PostgreSQL in Chromium. nginx sends the same strict page CSP the
   flows use (a unit test keeps them equal), the console can remove a vault
   credential (a permanent tombstone for that connector), and the flows check
   layouts at 390, 720 (200% zoom on a 1440 px screen) and 1280 px. A
   screen-reader review by a person is still open.
3. **Database catalog and authority coordination.** Implemented; see
   [storage](storage.md). Accounts, password verifiers, keys, sessions,
   connectors, tombstones, discovery, visibility and indexed call history live
   in SQLite or PostgreSQL. Account secrets are sealed under the catalog key;
   connector credentials are only in the vault. Every catalog change commits
   with its security event and any lease revocation in one owner transaction
   and publishes after commit; storage failure stops the gateway without
   fallback. The file catalog, JSONL history and the import, cutover and
   rollback tooling were removed on 2026-09-29 (no legacy, fresh start).
4. **Startup and guarded execution integration.** Implemented; guarded
   execution is installed whenever `owner_security` runs (the `custody_mode`
   setting is gone). See
   [encrypted runtime](security/encrypted-runtime.md#startup-integration). Custody
   caches load before any runtime. Credentialed personal connectors (bearer,
   API key, custom headers) store header names only and are guarded from
   creation: the gateway never holds their credential or dials them in the
   background, refresh returns 409, and every call needs an owner-activated
   window. A restart starts locked with a new boot, and a tombstone keeps the
   connector locked. Only local-account workspaces on a gateway with
   `owner_security` can create credentialed connectors, and only for endpoints
   the vault destination accepts; everyone else gets no-auth connectors. Catalogs from older builds (header values, OAuth settings, grant
   IDs) are refused at load; there is no conversion. `--stdio` serves only
   connectors without authentication.
5. **Initial setup/discovery authorization.** Implement a bounded owner-only
   discovery capability for new providers before their tool catalog exists.
   Until then a new credentialed connector has no tools and cannot be used;
   browser flow tests seed discovery through a `flowtest`-tagged test route
   that this step removes.
   Revalidate destination/header/network policy and actual discovered definitions.
   The current per-call maintenance capability is not this registration flow.
6. **OAuth encrypted state and refresh.** Upstream OAuth for personal
   connectors is removed and returns here, vault-backed. Encrypt the whole token/client-secret
   bundle, bind refresh to current authority, commit rotated tokens with revision
   CAS and nonce/write limits, and handle concurrency/failed writes safely.
   Authentication recovery must not replay a tool operation.
7. **Vault/root recovery and rotation.** Implement recovery-key rotation and full
   root/credential replacement, including wrapping-key limits, lost-device and
   compromised-key recovery. Rewrapping a root with a new passphrase does not
   erase older wrappers or backups.
8. **Transport and process hardening.** Finish explicit maintenance/session cleanup,
   provider session/resource limits, any connection pooling, OAuth endpoint
   SSRF/redirect protection, permitted private-network selection and stdio
   process isolation. Stdio commands already receive only an allowlisted
   environment. Keep all credential use bounded by authority.
9. **Restore and rollout.** The live deployment is a fresh start (no
   migration). Still open: a full application backup and database restore
   drill, and restart-locked recovery after a restore.
10. **Release qualification.** Run complete spec acceptance families (track them
    in the [acceptance matrix](security/acceptance-matrix.md)), actual owner
    UI/device tests, Argon2/WASM review, mobile KDF measurements, load/failure tests,
    operational audit/storage health signals and a controlled production rollout.
    The browser matrix now covers the worker and the owner console's product
    flows on desktop engines, not real devices or a third-party security audit.

## GitHub follow-up

- The private repository is [YAPhoa/mcpwarden](https://github.com/YAPhoa/mcpwarden).
  Its first hosted CI run passed. GitHub requires an account upgrade to enforce
  branch rules for this private repository; until then, verify **Required checks**
  manually before merging. The workflow also handles `merge_group`.
- CodeQL runs for public repositories. For private repositories, enable GitHub
  Code Security first and set repository variable `ENABLE_CODEQL=true`.
- Dependabot updates and vulnerability alerts are enabled. Review proposed
  action/tool, Go, npm and image upgrades; the first proposal is
  [nginx 1.29, PR #1](https://github.com/YAPhoa/mcpwarden/pull/1). The reviewed
  browser Argon2 asset is vendored and needs an explicit provenance/hash review
  when updated.
- Configure deployment automation separately if desired. These workflows test
  disposable fixtures and contain no production deployment credentials.

Push approvals, TOTP and WebAuthn remain optional and unselected. An embedded
OAuth authorization server, MCP resources/prompts, and a built-in Drive adapter
are not part of this implementation queue.
