# Pending work

Current boundary: the running gateway still uses the encrypted file catalog.
The lease engine, browser crypto primitives and PostgreSQL ciphertext adapter are
implemented and tested, but client-release custody is not enabled. The original
acceptance checklist remains in [spec v1.1](security/spec-v1.1/IMPLEMENTATION-CHECKLIST.md);
per-case coverage of the 68 acceptance tests is in the
[acceptance matrix](security/acceptance-matrix.md).

## Next implementation sequence

1. **Owner security API.** Add owner-scoped vault/credential persistence and
   request, confirmation, activation, revocation and execution-lock endpoints.
   Enforce interactive browser authentication, CSRF/Origin checks, bounded inputs,
   rate limits and mutation audit. Approval `none` still requires explicit owner
   CEK release; an ordinary admin/client MCP key must never activate itself.
2. **Vault and lease UI.** Connect setup, recovery-key save/confirmation, unlock,
   passphrase changes, credential entry and selected CEK release to those APIs.
   Add request review, exact caller/tool scope, fixed countdowns, revoke/lock and
   explicit renewal. Clear inputs and terminate the worker on logout/navigation/
   idle lock; cover error recovery and accessibility.
3. **Full PostgreSQL catalog and authority coordination.** Preserve account/password
   verifiers, named keys, sessions, stable provider/tool IDs, visibility, discovery
   caches and lifecycle timestamps. Route every security change through the owner
   coordinator and publish metadata/ciphertext together after commit. Keep custody
   tombstones; finish mutation-specific security audit and indexed call history.
4. **Startup and guarded execution integration.** Add explicit supported custody
   configuration, load coherent caches while locked, install the guarded proxy and
   disable legacy credential resolution/reconnect for converted providers. Restart
   with a new boot and no active material. Preserve fail-closed behavior on storage,
   ownership and clock uncertainty; never fall through to legacy execution.
   The initial cutover covers only existing HTTP providers that use header
   credentials. Setting up new providers under this custody requires step 5, and
   OAuth providers require step 6.
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
9. **Migration, restore and rollout.** Implement a protected legacy export/import
   with checkpointed, interrupted-run-safe conversion. Verify counts, stable IDs,
   verifiers, scopes, hashes, lifecycle and historical audit before cutover.
   Exercise full application backup/restore, restart-locked recovery, token/access
   reconciliation and rollback without losing audit or reviving old authority.
10. **Release qualification.** Run complete spec acceptance families (track them
    in the [acceptance matrix](security/acceptance-matrix.md)), actual owner
    UI/device tests, Argon2/WASM review, mobile KDF measurements, load/failure tests,
    operational audit/storage health signals and a controlled production rollout.
    The current browser matrix covers cryptographic worker behavior, not complete
    product flows or a third-party security audit.

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
