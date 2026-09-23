# Revision history

## v1.1 — 22 September 2026

User clarification: Duo was an incidental example, not a required provider. The intended product is app/browser approval similar to 2FA, with push and OTP enabled or disabled as needed.

Changed:

- Made additional approval configurable: `none`, `confirm`, and `step_up`.
- Separated notification delivery, owner confirmation, factor verification, and client key release.
- Replaced the vendor-focused implementation section and default configuration with first-party in-app review, optional Web Push, and optional local TOTP.
- Specified the no-extra-approval branch without allowing agent self-activation or automatic window renewal.
- Added authorization-source/policy-revision storage and audit, safe toggle semantics, optional factor/push schema sketches, and 12 acceptance cases.
- Removed the vendor adapter as a dependency or release milestone; retained old vendor references only for traceability.
- Added primary references R35–R40 for browser push, Web Push transport/encryption/VAPID, TOTP, and factor administration.

Unchanged:

- Timed, multi-call windows, client-only vault root, per-credential key release to the trusted gateway, fixed expiry, restart-locked behavior, per-call scope/identity checks, no automatic tool replay, and no raw secret/payload logging.
- The credential-envelope bytes, deterministic fixture, and three interoperability test source files.
- The supplied current-state handoff, preserved byte-for-byte.

This is a targeted documentation/schema-proposal revision. It is not a new repository audit, an application implementation, or an executed database migration. The prior reference catalogue is retained, not independently revalidated in full.
