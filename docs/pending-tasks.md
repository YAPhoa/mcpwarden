# Pending work

Current boundary: the running gateway still uses the encrypted file catalog.
The lease engine, browser crypto primitives, PostgreSQL ciphertext adapter,
owner security API, owner vault console and PostgreSQL catalog backend are
implemented and tested. The owner API, console and PostgreSQL catalog are
opt-in, live data has not been migrated, and client-release execution
(`custody_mode: client_release`) is opt-in and off in the live deployment. The original
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
   Accounts, sessions and keys stay in the file catalog until step 3.
2. **Vault and lease UI.** Implemented at `/vault` for the opt-in API; see
   [UI design](../ui/DESIGN.md#vault-and-access-windows-2026-09-24). It covers
   setup with a verified recovery key, passphrase or recovery unlock, passphrase
   changes, browser-encrypted credential entry and replacement for existing
   header-authenticated HTTP connectors, request review, explicit activation and
   renewal, fixed countdowns, and the separate browser lock, stop access and
   lock-all controls. Real-browser flows run against a gateway and PostgreSQL in
   Chromium, Firefox and WebKit in CI. nginx sends the same strict page CSP the
   flows use (a unit test keeps them equal), the console can remove a vault
   credential (a permanent tombstone for that connector), and the flows check
   layouts at 390, 720 (200% zoom on a 1440 px screen) and 1280 px. A
   screen-reader review by a person is still open.
3. **Full PostgreSQL catalog and authority coordination.** Implemented behind
   `managed_upstreams.backend: postgres` (requires `owner_security`); see
   [catalog storage](catalog-storage.md) and [history storage](history-storage.md).
   Accounts, password verifiers, keys, sessions, connectors, tombstones,
   discovery, visibility and indexed call history live in PostgreSQL. Secrets
   stay sealed under the existing catalog key (legacy managed custody). Every
   catalog change commits with its security event and any lease revocation in
   one owner transaction and publishes after commit; storage failure stops the
   gateway without falling back to the file. `mcpwarden-catalog` imports from a
   protected snapshot with checkpointed, field-by-field verification, then cuts
   over. Its rollback reconciles revocations, suspends windows, requires OAuth
   reauthorization for rotated grants and keeps new history. The
   [cutover procedure](catalog-migration.md) awaits review before live data
   moves; a second import after a rollback is not supported yet.
4. **Startup and guarded execution integration.** Implemented behind
   `owner_security.custody_mode: client_release`; see
   [encrypted runtime](security/encrypted-runtime.md#startup-integration). Custody
   caches load before any runtime; an HTTP header connector with a vault
   credential runs only through the guarded proxy, its legacy session and
   reconnect stop and its server-held headers are never read for it. A restart
   starts locked with a new boot. A tombstone keeps the connector locked; nothing
   falls through to legacy execution. Setting up new providers under this custody
   requires step 5, and OAuth providers require step 6. The server-held headers
   of converted connectors are kept unused until a purge is decided.
5. **Initial setup/discovery authorization.** Implement a bounded owner-only
   discovery capability for new providers before their tool catalog exists.
   Revalidate destination/header/network policy and actual discovered definitions.
   The current per-call maintenance capability is not this registration flow.
6. **OAuth encrypted state and refresh.** Encrypt the whole token/client-secret
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
9. **Migration, restore and rollout.** The file-to-PostgreSQL catalog and
   history migration, its verification and its rollback are done (step 3).
   Still open: the live cutover itself, a full application backup and database
   restore drill, and restart-locked recovery after a restore.
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
