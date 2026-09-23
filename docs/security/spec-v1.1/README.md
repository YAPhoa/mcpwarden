# mcpwarden — timed access security specification

**Proposed design v1.1, 22 September 2026.** This bundle describes client-encrypted credential storage with temporary execution by the existing trusted, self-hosted gateway. Its default is a **multi-call working window**, not an approval for each MCP call.

## Read in this order

1. [Security design and implementation specification](SECURITY-DESIGN.md) — threat model, lease lifecycle, encryption/AAD formats, optional first-party push/OTP, runtime concurrency, PostgreSQL transactions, APIs, OAuth, audit, UX, recovery, migration, and acceptance tests.
2. [Implementation checklist](IMPLEMENTATION-CHECKLIST.md) — entry points and non-negotiable integration requirements.
3. [Technical references](REFERENCES.md) — 40 numbered reference entries (R11–R13 are optional historical vendor references) plus the supplied project handoff.
4. [Validation and limits](VALIDATION.md) — what was actually tested, and what was not.

The original [current-state handoff](sources/mcpwarden-current-state-2026-09-22.md) is included unchanged. It is evidence of the described baseline, not proof that its code has since remained unchanged.

## Companion material

| File | Purpose |
|---|---|
| `reference/approval-options.sql` | Optional candidate factor/push/policy storage extension; not executed or required when unused. |
| `reference/approval-config.yaml` | Provider-neutral configuration example; not accepted by the current binary until implemented. |
| `APPROVAL-OPTIONS.md` | Focused v1.1 explanation of the optional approval, push, and OTP model. |
| `CHANGELOG.md` | Exact scope of the v1.1 revision and preservation of the v1.0 baseline. |
| `reference/schema.sql` | Candidate target-state PostgreSQL schema. Review in an empty scratch database; not executed here and not a migration of the existing application. |
| `reference/envelope-vector.json` | Public, synthetic AES-256-GCM vector for the specified explicit-nonce credential envelope. |
| `tests/test_envelope.py` | Python interoperability and selected tamper checks; requires `cryptography`. |
| `tests/test_envelope.mjs` | Equivalent Node WebCrypto checks; no third-party package. |
| `tests/test_envelope.go` | Equivalent Go standard-library checks; no third-party package. |

Run the fixture checks from this directory:

```sh
python tests/test_envelope.py
node tests/test_envelope.mjs
go run tests/test_envelope.go
```

The fixture's key, nonce, and token value are **fake and public**. Deterministic test nonces must never be reused in production. The simple header sorting in these tests works only for this fixed ASCII string-only object; it is not a general RFC 8785 canonicalizer.

## Main decisions

A selected client key receives a scoped fifteen-minute window by default. Multiple permitted calls and reconnects do not prompt again. Traffic does not extend the window. The browser releases only the selected credential's CEK, never its vault root. A gateway restart starts locked. Every call has an authenticated caller, matching lease, current credential epoch, and durable admission audit before dispatch.

No external approval provider is required. `none` skips extra approval, `confirm` uses first-party owner review, and `step_up` adds an enrolled factor such as local TOTP. Push is an independent optional notification channel. Key release still requires an unlocked client. The gateway is trusted while executing and can see the selected credential during that period; time limits cannot force a malicious recipient to forget a copied secret.

The initial implementation target is HTTP MCP with local-account interactive owner sessions and named caller access keys. Other authentication/stdio deployments need an explicit, separate human-approval path; they must not silently bypass the model.

## Implementation status

This bundle does not modify the repository, install a database, enroll a factor or push subscription, or implement the proposed product features. The Go interface/configuration sketches are design contracts, not patches. Standalone fixture test results are recorded in `VALIDATION.md`; full project and live integration tests remain required.
